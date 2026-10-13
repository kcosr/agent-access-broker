use super::*;
use crate::{
    ActionIo, GitlabContentConfig, GitlabWebhooksConfig, SearchLimitsConfig, raw_download_io,
};
use agent_access_provider::test_support::{InvocationBuilder, bearer_credential, test_signing_key};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use chrono::Duration as ChronoDuration;
use wiremock::matchers::{
    body_json, body_string, method, path, query_param, query_param_is_missing,
};
use wiremock::{Mock, MockServer, ResponseTemplate};

/// Every page token failure the invoke hook can report stays within the
/// provider-reportable subset for an invocation.
#[test]
fn page_token_failures_pass_the_invocation_contract() {
    let hook = agent_access_provider::host::hook_context(
        "gitlab",
        "issue.list",
        agent_access_provider::HookPhase::Invocation,
        crate::GITLAB_BACKEND.domain_reasons(),
    );
    for error in [
        ContinuationError::Invalid,
        ContinuationError::UnsupportedVersion,
        ContinuationError::Expired,
        ContinuationError::TokenTooLarge { limit: 1 },
        ContinuationError::PayloadTooLarge { limit: 1 },
        ContinuationError::SigningUnavailable,
        ContinuationError::DurableKeyUnavailable,
    ] {
        let failure = gitlab_page_token_failure(error);
        assert_eq!(
            hook.check_failure(&failure),
            Ok(()),
            "{error:?}: {failure:?}"
        );
    }
    assert_eq!(hook.check_failure(&gitlab_page_token_error()), Ok(()));
}

fn config() -> GitlabProviderConfig {
    GitlabProviderConfig {
        provisioning: crate::GitlabProvisioningConfig::default(),
        api_base_url: "https://gitlab.example.com/api/v4".to_string(),
        web_base_url: "https://gitlab.example.com".to_string(),
        egress_proxy: None,
        allowed_upstream_hosts: vec!["https://gitlab.example.com/api/v4/**".to_string()],
        webhooks: GitlabWebhooksConfig::default(),
        attachments: crate::GitlabUploadLimitsConfig::default(),
        content: GitlabContentConfig::default(),
        search: SearchLimitsConfig { max_results: 50 },
    }
}

fn http_backend_for_base(uri: &str) -> HttpGitlabBackend {
    let mut config = config();
    config.api_base_url = format!("{uri}/api/v4");
    config.allowed_upstream_hosts = vec![format!("{uri}/api/v4/**")];
    HttpGitlabBackend::for_tests(config, ProviderLimits::default()).unwrap()
}

fn http_backend(server: &MockServer) -> HttpGitlabBackend {
    http_backend_for_base(&server.uri())
}

#[test]
fn build_creates_upload_and_request_clients_for_the_api_base() {
    let host = agent_access_provider::test_support::TestHost::default();
    config().build(&host.context()).unwrap();
    let built = host
        .built_clients()
        .into_iter()
        .map(|client| (client.label, client.base.to_string(), client.profile))
        .collect::<Vec<_>>();
    let label = "providers.gitlab.egress_proxy".to_string();
    let base = normalized_api_base(&config().api_base_url)
        .unwrap()
        .to_string();
    assert_eq!(
        built,
        [
            (label.clone(), base.clone(), ClientProfile::Upload),
            (label, base, ClientProfile::Request),
        ]
    );
}

fn upload_fixture() -> (Value, BrokerBodyPart) {
    let part = BrokerBodyPart::in_memory(
        "session".to_string(),
        Some("session.html".to_string()),
        Some("text/html".to_string()),
        b"<html>private session</html>".to_vec(),
    );
    let inputs = json!({"project": "sip/service", "attachments": [{
        "field": "session", "filename": "session.html", "contentType": "text/html",
        "size": part.size(), "sha256": part.sha256_hex(),
    }]});
    (inputs, part)
}

fn upload_response() -> Value {
    json!({"id": 17, "alt": "session", "url": "/uploads/secret/session.html",
        "full_path": "/-/project/42/uploads/secret/session.html",
        "markdown": "[session](/uploads/secret/session.html)"})
}

#[test]
fn project_upload_validates_metadata_and_file_integrity() {
    let mut config = config();
    config.attachments.media_types.push("text/html".to_string());
    let (inputs, part) = upload_fixture();
    let (_, metadata) = parse_project_upload_inputs(&inputs, &config).unwrap();
    assert!(prepare_project_upload(&metadata, std::slice::from_ref(&part)).is_ok());
    assert!(prepare_project_upload(&metadata, &[]).is_err());
    assert!(prepare_project_upload(&metadata, &[part.clone(), part.clone()]).is_err());
    for (field, value, reason) in [
        ("size", json!(0), ReasonCode::AttachmentSizeDenied),
        (
            "size",
            json!(config.attachments.max_bytes + 1),
            ReasonCode::AttachmentSizeDenied,
        ),
        (
            "contentType",
            json!("application/x-not-allowed"),
            ReasonCode::AttachmentMediaTypeDenied,
        ),
        (
            "filename",
            json!("../session.html"),
            ReasonCode::InputInvalid,
        ),
        (
            "filename",
            json!("session\r\n.html"),
            ReasonCode::InputInvalid,
        ),
        ("sha256", json!("invalid"), ReasonCode::InputInvalid),
    ] {
        let mut invalid = inputs.clone();
        invalid["attachments"][0][field] = value;
        assert_eq!(
            parse_project_upload_inputs(&invalid, &config)
                .unwrap_err()
                .reason_code(),
            reason
        );
    }
    let mut changed = part.clone();
    changed.bytes[0] ^= 1;
    assert_eq!(
        prepare_project_upload(&metadata, &[changed])
            .unwrap_err()
            .reason_code(),
        ReasonCode::AttachmentIntegrityMismatch
    );
    let mut changed = part.clone();
    changed.bytes.push(0);
    assert_eq!(
        prepare_project_upload(&metadata, &[changed])
            .unwrap_err()
            .reason_code(),
        ReasonCode::AttachmentIntegrityMismatch
    );
    let mut changed = part.clone();
    changed.name = "other".to_string();
    assert_eq!(
        prepare_project_upload(&metadata, &[changed])
            .unwrap_err()
            .reason_code(),
        ReasonCode::BodyMalformed
    );
    let mut changed = part;
    changed.content_type = Some("text/plain".to_string());
    assert_eq!(
        prepare_project_upload(&metadata, &[changed])
            .unwrap_err()
            .reason_code(),
        ReasonCode::AttachmentMediaTypeDenied
    );
    let mut invalid = inputs.clone();
    invalid["attachments"] = json!([]);
    assert!(parse_project_upload_inputs(&invalid, &config).is_err());
    let mut invalid = inputs.clone();
    invalid["url"] = json!("https://gitlab.example.com/sip/service");
    assert!(parse_project_upload_inputs(&invalid, &config).is_err());
    let mut by_url = inputs;
    by_url.as_object_mut().unwrap().remove("project");
    by_url["url"] = json!("https://gitlab.example.com/sip/service");
    assert_eq!(
        parse_project_upload_inputs(&by_url, &config)
            .unwrap()
            .0
            .project,
        "sip/service"
    );
    config.attachments.max_total_bytes = 1;
    assert_eq!(
        parse_project_upload_inputs(&by_url, &config)
            .unwrap_err()
            .reason_code(),
        ReasonCode::AttachmentSizeDenied
    );
}

#[test]
fn project_upload_default_media_types_allow_html_and_reject_invalid_mime() {
    let config = config();
    let (inputs, _) = upload_fixture();
    assert!(parse_project_upload_inputs(&inputs, &config).is_ok());
    assert!(project_upload_schema(&config.attachments)["properties"]["attachments"]["items"]["properties"]["contentType"].get("enum").is_none());
    for content_type in ["invalid", "text/html\r\nInjected: yes", ""] {
        let mut invalid = inputs.clone();
        invalid["attachments"][0]["contentType"] = json!(content_type);
        assert_eq!(
            parse_project_upload_inputs(&invalid, &config)
                .unwrap_err()
                .reason_code(),
            ReasonCode::AttachmentMediaTypeDenied
        );
    }
}

#[tokio::test]
async fn project_upload_uses_streaming_idle_budget_instead_of_json_request_timeout() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/api/v4/projects/42/uploads"))
        .respond_with(
            ResponseTemplate::new(201)
                .set_delay(Duration::from_millis(40))
                .set_body_json(upload_response()),
        )
        .mount(&server)
        .await;
    let mut config = config();
    config.api_base_url = format!("{}/api/v4", server.uri());
    config.allowed_upstream_hosts = vec![format!("{}/api/v4/**", server.uri())];
    let backend = HttpGitlabBackend::for_tests(
        config.clone(),
        ProviderLimits::default()
            .with_request_timeout_ms(10)
            .with_streaming_idle_timeout_ms(1000),
    )
    .unwrap();
    assert!(
        backend
            .upload_project(42, upload_fixture().1, &test_credential())
            .await
            .is_ok()
    );
    let backend = HttpGitlabBackend::for_tests(
        config,
        ProviderLimits::default()
            .with_request_timeout_ms(1000)
            .with_streaming_idle_timeout_ms(5),
    )
    .unwrap();
    assert!(matches!(
        backend
            .upload_project(42, upload_fixture().1, &test_credential())
            .await
            .unwrap_err(),
        GitlabBackendError::Timeout
    ));
}

#[tokio::test]
async fn project_upload_progress_extends_request_beyond_idle_window_and_stalls_fail() {
    use futures_util::StreamExt;
    for (delay_ms, idle_ms, succeeds) in [(100, 500, true), (500, 100, false)] {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/api/v4/projects/42/uploads"))
            .respond_with(ResponseTemplate::new(201).set_body_json(upload_response()))
            .mount(&server)
            .await;
        let mut config = config();
        config.api_base_url = format!("{}/api/v4", server.uri());
        config.allowed_upstream_hosts = vec![format!("{}/api/v4/**", server.uri())];
        let backend = HttpGitlabBackend::for_tests(
            config,
            ProviderLimits::default().with_streaming_idle_timeout_ms(idle_ms),
        )
        .unwrap();
        let file = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(file.path(), [b'a'; 48]).unwrap();
        let source = tokio::fs::File::open(file.path()).await.unwrap();
        let (tx, progress) = tokio::sync::watch::channel(tokio::time::Instant::now());
        // Pace file reads so the request lasts longer than the idle budget,
        // while successful transfers make progress within every window.
        let body = tokio_util::io::ReaderStream::with_capacity(source, 4).then(move |chunk| {
            let tx = tx.clone();
            async move {
                tokio::time::sleep(Duration::from_millis(delay_ms)).await;
                let _ = tx.send(tokio::time::Instant::now());
                chunk
            }
        });
        let part =
            reqwest::multipart::Part::stream_with_length(reqwest::Body::wrap_stream(body), 48)
                .file_name("session.html")
                .mime_str("text/html")
                .unwrap();
        let url = backend.endpoint("projects/42/uploads").unwrap();
        let started = Instant::now();
        let result = send_gitlab_upload(
            &backend.upload_client,
            backend
                .upload_client
                .request(Method::POST, url.clone())
                .multipart(reqwest::multipart::Form::new().part("file", part)),
            "project.upload",
            progress,
            Duration::from_millis(idle_ms),
            backend.limits.max_upstream_response_bytes,
        )
        .await;
        if succeeds {
            assert!(result.unwrap().status().is_success());
            assert!(started.elapsed() > Duration::from_millis(idle_ms));
        } else {
            assert!(matches!(result.unwrap_err(), GitlabBackendError::Timeout));
        }
    }
}

#[tokio::test]
async fn project_upload_response_reads_have_resetting_idle_deadlines() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    for (delay_ms, idle_ms, succeeds) in [(60, 300, true), (500, 100, false)] {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        let server = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut request = Vec::new();
            while !request.ends_with(b"\r\n\r\n") {
                request.push(socket.read_u8().await.unwrap());
            }
            let body = b"{\"ok\":true}";
            let headers = format!(
                "HTTP/1.1 201 Created\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                body.len()
            );
            socket.write_all(headers.as_bytes()).await.unwrap();
            for byte in body {
                tokio::time::sleep(Duration::from_millis(delay_ms)).await;
                if socket.write_all(&[*byte]).await.is_err() {
                    break;
                }
            }
        });
        let response = reqwest::Client::new().get(url).send().await.unwrap();
        let result =
            gitlab_upload_response_value(response, 1024, Duration::from_millis(idle_ms)).await;
        if succeeds {
            assert_eq!(result.unwrap(), json!({"ok":true}));
        } else {
            assert!(matches!(result.unwrap_err(), GitlabBackendError::Timeout));
        }
        server.abort();
    }
}

#[test]
fn project_upload_decoder_handles_optional_upstream_id_and_rejects_malformed_metadata() {
    let mut response = upload_response();
    assert_eq!(
        project_upload_from_value(response.clone()).unwrap().id,
        Some(17)
    );
    response.as_object_mut().unwrap().remove("id");
    let decoded = project_upload_from_value(response.clone()).unwrap();
    assert!(decoded.id.is_none());
    assert!(serde_json::to_value(decoded).unwrap().get("id").is_none());
    response["markdown"] = json!(null);
    assert!(project_upload_from_value(response).is_err());
}

#[tokio::test]
async fn project_upload_streams_html_with_selected_credential_and_sanitizes_audit() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/api/v4/projects/sip%2Fservice"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(json!({"id":42,"path_with_namespace":"sip/service"})),
        )
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/api/v4/projects/42/uploads"))
        .respond_with(ResponseTemplate::new(201).set_body_json(upload_response()))
        .expect(1)
        .mount(&server)
        .await;
    let mut config = config();
    config.attachments.media_types.push("text/html".to_string());
    let provider = GitlabProvider::with_backend(config, Arc::new(http_backend(&server)));
    let (inputs, part) = upload_fixture();
    let temp_path = std::env::temp_dir().join(format!("gitlab-upload-{}", uuid::Uuid::new_v4()));
    std::fs::write(&temp_path, &part.bytes).unwrap();
    let mut request = test_invocation("project.upload", inputs);
    assert_eq!(
        provider
            .authorize_body_parts(request.admitted(), request.state())
            .await
            .unwrap()
            .part_specs()[0]
            .name,
        "session"
    );
    request = InvocationBuilder::from(request)
        .body_part(agent_access_provider::host::spooled_body_part(
            part.name.clone(),
            part.file_name.clone(),
            part.content_type.clone(),
            temp_path.clone(),
            part.size(),
            part.sha256_hex(),
        ))
        .build();
    let result = provider.invoke(request).await.unwrap();
    assert_eq!(
        result.result["upload"]["markdown"],
        upload_response()["markdown"]
    );
    assert_eq!(
        result.result["upload"]["fullPath"],
        upload_response()["full_path"]
    );
    assert_eq!(result.upstream_status, Some(201));
    assert!(result.object_ids.is_none());
    let audit = serde_json::to_string(&result.audit).unwrap();
    for sensitive in ["private session", "gitlab-token", "secret", "session.html"] {
        assert!(!audit.contains(sensitive));
    }
    assert!(!temp_path.exists());
    let requests = server.received_requests().await.unwrap();
    let uploaded = requests
        .iter()
        .find(|request| request.method == "POST")
        .unwrap();
    assert_eq!(
        uploaded.headers.get("authorization").unwrap(),
        "Bearer gitlab-token"
    );
    let body = std::str::from_utf8(&uploaded.body).unwrap();
    assert!(body.contains("name=\"file\"; filename=\"session.html\""));
    assert!(body.contains("Content-Type: text/html"));
    assert!(body.contains("<html>private session</html>"));
}

#[tokio::test]
async fn project_upload_rechecks_authorized_repository_before_accepting_or_sending_file() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/api/v4/projects/sip%2Fservice"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(json!({"id":99,"path_with_namespace":"other/repo"})),
        )
        .mount(&server)
        .await;
    let mut config = config();
    config.attachments.media_types.push("text/html".to_string());
    let provider = GitlabProvider::with_backend(config, Arc::new(http_backend(&server)));
    let (inputs, part) = upload_fixture();
    let mut request = test_invocation("project.upload", inputs);
    assert_eq!(
        provider
            .authorize_body_parts(request.admitted(), request.state())
            .await
            .unwrap_err()
            .reason_code(),
        ReasonCode::ScopeUnresolved
    );
    request = InvocationBuilder::from(request).body_part(part).build();
    assert_eq!(
        provider.invoke(request).await.unwrap_err().reason_code(),
        ReasonCode::ScopeUnresolved
    );
    assert!(
        server
            .received_requests()
            .await
            .unwrap()
            .iter()
            .all(|request| request.method == "GET")
    );
}

#[tokio::test]
async fn project_upload_rejects_reflected_errors_redirects_and_oversized_responses() {
    for status in [302, 400, 401, 403, 413, 422, 500] {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/api/v4/projects/42/uploads"))
            .respond_with(
                ResponseTemplate::new(status)
                    .insert_header("location", "https://outside.invalid/secret")
                    .set_body_json(json!({"message":{"file":["private session gitlab-token"]}})),
            )
            .expect(1)
            .mount(&server)
            .await;
        let error = http_backend(&server)
            .upload_project(42, upload_fixture().1, &test_credential())
            .await
            .unwrap_err();
        let public = gitlab_backend_error(error);
        assert!(!public.message.contains("private session"));
        assert!(!public.message.contains("gitlab-token"));
    }
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/api/v4/projects/42/uploads"))
        .respond_with(ResponseTemplate::new(201).set_body_json(upload_response()))
        .mount(&server)
        .await;
    let mut backend = http_backend(&server);
    backend.limits.max_upstream_response_bytes = 16;
    assert!(matches!(
        backend
            .upload_project(42, upload_fixture().1, &test_credential())
            .await
            .unwrap_err(),
        GitlabBackendError::ResponseTooLarge
    ));
}

#[test]
fn webhook_decoder_pins_supported_event_semantics() {
    let base = json!({
        "id": 42,
        "project_id": 7,
        "url": "https://hooks.example.com/events",
        "push_events": true,
        "vulnerability_events": true,
        "repository_update_events": false,
    });
    let hook = webhook_from_value(base.clone()).unwrap();
    assert_eq!(
        hook.events,
        vec![
            GitlabWebhookEvent::Push,
            GitlabWebhookEvent::Vulnerabilities
        ]
    );

    let mut unsupported = base;
    unsupported["repository_update_events"] = json!(true);
    assert!(matches!(
        webhook_from_value(unsupported),
        Err(GitlabBackendError::Protocol(_))
    ));
}

#[test]
fn webhook_delivery_redacts_secrets_truncates_content_and_omits_url() {
    let event = webhook_delivery_event_from_value(
        json!({
            "id": 9001,
            "url": "https://hooks.example.com/events?variable=URL_SECRET_SENTINEL",
            "trigger": "push_hooks",
            "response_status": "200",
            "request_headers": {
                "Authorization": "HEADER_SECRET_SENTINEL",
                "X-Custom": "CUSTOM_SECRET_SENTINEL",
                "X-Safe": "visible"
            },
            "request_data": { "large": "0123456789" },
            "response_headers": { "Set-Cookie": "COOKIE_SECRET_SENTINEL" },
            "response_body": "abcdef"
        }),
        &BTreeSet::from(["x-custom".to_string()]),
        5,
    )
    .unwrap();
    assert!(event.request_data.is_none());
    assert!(event.request_data_truncated);
    assert_eq!(event.response_body.as_deref(), Some("abcde"));
    assert!(event.response_body_truncated);
    assert_eq!(event.request_headers["Authorization"], "[REDACTED]");
    assert_eq!(event.request_headers["X-Custom"], "[REDACTED]");
    assert_eq!(event.response_headers["Set-Cookie"], "[REDACTED]");
    let serialized = serde_json::to_string(&event).unwrap();
    for sentinel in [
        "URL_SECRET_SENTINEL",
        "HEADER_SECRET_SENTINEL",
        "CUSTOM_SECRET_SENTINEL",
        "COOKIE_SECRET_SENTINEL",
    ] {
        assert!(!serialized.contains(sentinel));
    }
}

#[test]
fn webhook_attempt_decoders_keep_endpoint_specific_shapes() {
    assert_eq!(
        webhook_test_attempt_from_value(json!({ "message": "201 Created" })).unwrap(),
        GitlabWebhookDeliveryAttempt {
            message: Some("201 Created".to_string()),
            response_status: None,
        }
    );
    assert!(webhook_test_attempt_from_value(json!({ "message": "200 OK" })).is_err());
    assert_eq!(
        webhook_resend_attempt_from_value(json!({ "response_status": 202 })).unwrap(),
        GitlabWebhookDeliveryAttempt {
            message: None,
            response_status: Some(202),
        }
    );
    assert!(webhook_resend_attempt_from_value(json!({ "response_status": "202" })).is_err());
}

#[test]
fn webhook_write_body_replaces_the_complete_event_set() {
    let body = webhook_write_body(&GitlabWebhookWriteRequest {
        url: "https://hooks.example.com/events".to_string(),
        events: Some(vec![
            GitlabWebhookEvent::Push,
            GitlabWebhookEvent::MergeRequests,
        ]),
        name: None,
        description: None,
        enable_ssl_verification: Some(true),
        branch_filter_strategy: None,
        push_events_branch_filter: None,
        custom_webhook_template: None,
        token: None,
        signing_token: None,
    });
    assert_eq!(body["push_events"], true);
    assert_eq!(body["merge_requests_events"], true);
    assert_eq!(body["note_events"], false);
    assert_eq!(body["vulnerability_events"], false);
}

#[test]
fn webhook_inputs_are_strict_about_ids_controls_and_test_events() {
    assert_eq!(
        webhook_update_schema()["properties"]["clearToken"]["const"],
        true
    );
    assert!(
        !webhook_test_schema()["properties"]["event"]["enum"]
            .as_array()
            .unwrap()
            .contains(&json!("deployments"))
    );
    assert!(
        parse_webhook_object_inputs(&json!({
            "project": "group/repo", "webhookId": "42"
        }))
        .is_err()
    );
    assert!(
        parse_webhook_write_inputs(
            &json!({
                "project": "group/repo", "webhookId": 42, "clearToken": false
            }),
            false,
            1024
        )
        .is_err()
    );
    assert!(
        parse_webhook_test_inputs(&json!({
            "project": "group/repo", "webhookId": 42, "event": "deployments"
        }))
        .is_err()
    );
    let oversized_page_token = "x".repeat(GITLAB_PAGE_TOKEN_MAX_BYTES + 1);
    assert!(
        parse_webhook_list_inputs(
            &json!({ "project": "group/repo", "pageToken": oversized_page_token }),
            50,
        )
        .is_err()
    );
    assert!(
        parse_webhook_write_inputs(
            &json!({
                "project": "group/repo", "url": "https://hooks.example.com/events", "events": []
            }),
            true,
            1024
        )
        .is_ok()
    );
}

#[test]
fn webhook_update_carries_disabled_tls_only_to_new_https_destinations() {
    assert_eq!(
        webhook_update_tls_field(true, Some("https"), Some(false), None),
        Some(false)
    );
    assert_eq!(
        webhook_update_tls_field(true, Some("http"), Some(false), None),
        None
    );
    assert_eq!(
        webhook_update_tls_field(true, Some("http"), Some(false), Some(true)),
        Some(true)
    );
    assert_eq!(
        webhook_update_tls_field(false, None, Some(false), None),
        None
    );
}

fn test_credential() -> ExecutionCredential {
    bearer_credential("gitlab-token")
}

fn test_invocation(action: &str, inputs: Value) -> ProviderInvocation {
    InvocationBuilder::new("gitlab", action)
        .inputs(inputs)
        .identity(crate::InvocationIdentity::new("agent-1".to_string(), true))
        .resources(repository_scopes_from_path("sip/service"))
        .credential(test_credential())
        .lookup_credential(test_credential())
        .build()
}

fn test_project() -> GitlabProject {
    GitlabProject {
        id: 42,
        path_with_namespace: "sip/service".to_string(),
        name: Some("service".to_string()),
        web_url: None,
        default_branch: None,
        visibility: None,
        archived: None,
    }
}

fn note_json(id: u64, body: &str, noteable_type: &str, iid: u64) -> Value {
    json!({
        "id": id,
        "body": body,
        "author": { "id": 314, "username": "service-user" },
        "noteable_type": noteable_type,
        "noteable_iid": iid,
        "project_id": 42
    })
}

fn discussion_json(id: &str, note_id: u64, body: &str, resolved: bool) -> Value {
    json!({
        "id": id,
        "individual_note": false,
        "notes": [{
            "id": note_id,
            "body": body,
            "author": { "id": 314, "username": "service-user" },
            "noteable_type": "MergeRequest",
            "noteable_iid": null,
            "noteable_id": 500,
            "project_id": 42,
            "resolvable": true,
            "resolved": resolved
        }]
    })
}

fn positioned_write_fixture() -> GitlabDiffPosition {
    GitlabDiffPosition {
        position_type: "text".to_string(),
        base_sha: Some("1111111111111111111111111111111111111111".to_string()),
        start_sha: "2222222222222222222222222222222222222222".to_string(),
        head_sha: "3333333333333333333333333333333333333333".to_string(),
        old_path: "src/old.rs".to_string(),
        new_path: "src/new.rs".to_string(),
        old_line: None,
        new_line: Some(34),
        line_range: None,
        width: None,
        height: None,
        x: None,
        y: None,
    }
}

fn positioned_write_body() -> Value {
    json!({
        "position_type": "text",
        "base_sha": "1111111111111111111111111111111111111111",
        "start_sha": "2222222222222222222222222222222222222222",
        "head_sha": "3333333333333333333333333333333333333333",
        "old_path": "src/old.rs",
        "new_path": "src/new.rs",
        "new_line": 34
    })
}

fn draft_note_json(id: u64, body: &str) -> Value {
    json!({
        "id": id,
        "note": body,
        "author_id": 314,
        "merge_request_id": 500,
        "resolve_discussion": false,
        "discussion_id": null,
        "commit_id": null,
        "line_code": null,
        "position": null
    })
}

#[test]
fn project_web_url_accepts_subgroups_and_rejects_untrusted_url_parts() {
    let config = config();

    assert_eq!(
        project_path_from_web_url(
            "https://gitlab.example.com/platform/runtime/service",
            &config
        )
        .unwrap(),
        "platform/runtime/service"
    );

    assert!(
        project_path_from_web_url("https://other.example.com/platform/service", &config).is_err()
    );
    assert!(
        project_path_from_web_url("https://gitlab.example.com/platform/service?x=1", &config)
            .is_err()
    );
    assert!(
        project_path_from_web_url(
            "https://gitlab.example.com/platform/service#readme",
            &config
        )
        .is_err()
    );
    assert!(project_path_from_web_url("https://gitlab.example.com/12345", &config).is_err());
}

#[test]
fn numbered_object_web_url_requires_gitlab_marker_and_expected_object_segment() {
    let config = config();

    assert_eq!(
        numbered_object_from_web_url(
            "https://gitlab.example.com/platform/runtime/service/-/issues/42",
            &config,
            "issues"
        )
        .unwrap(),
        ("platform/runtime/service".to_string(), 42)
    );
    assert_eq!(
        numbered_object_from_web_url(
            "https://gitlab.example.com/platform/runtime/service/-/merge_requests/7",
            &config,
            "merge_requests"
        )
        .unwrap(),
        ("platform/runtime/service".to_string(), 7)
    );

    assert!(
        numbered_object_from_web_url(
            "https://gitlab.example.com/platform/service/issues/42",
            &config,
            "issues"
        )
        .is_err()
    );
    assert!(
        numbered_object_from_web_url(
            "https://gitlab.example.com/platform/service/-/merge_requests/42",
            &config,
            "issues"
        )
        .is_err()
    );
    assert!(
        numbered_object_from_web_url(
            "https://gitlab.example.com/platform/service/-/issues/0",
            &config,
            "issues"
        )
        .is_err()
    );
}

#[test]
fn branch_and_commit_validation_fail_closed() {
    assert!(validate_branch_name("main").is_ok());
    assert!(validate_branch_name("feature/api-readonly").is_ok());
    assert!(validate_branch_name("").is_err());
    assert!(validate_branch_name("-bad").is_err());
    assert!(validate_branch_name("refs/heads/main").is_err());
    assert!(validate_branch_name("feature//bad").is_err());
    assert!(validate_branch_name("feature/../bad").is_err());

    assert!(validate_commit_sha("abcdef1").is_ok());
    assert!(validate_commit_sha(&"a".repeat(64)).is_ok());
    assert!(validate_commit_sha("abcdef").is_err());
    assert!(validate_commit_sha(&"a".repeat(65)).is_err());
    assert!(validate_commit_sha("not-a-sha").is_err());

    assert!(validate_full_commit_sha(&"a".repeat(40), "sha").is_ok());
    assert!(validate_full_commit_sha("abcdef1", "sha").is_err());
    assert!(link_header_has_next_relation(
        "<https://gitlab.example.com?page=2>; rel=\"next\""
    ));
    assert!(!link_header_has_next_relation(
        "<https://gitlab.example.com?page=1>; rel=\"prev\""
    ));
}

#[test]
fn gitlab_pagination_tokens_round_trip_and_reject_rebinding_tampering_and_expiry() {
    let signer = ContinuationSigner::new(None);
    let request = test_invocation(
        "issue.search",
        json!({ "project": "sip/service", "state": "opened" }),
    );
    let project = test_project();
    let now = DateTime::parse_from_rfc3339("2026-08-23T12:00:00Z")
        .unwrap()
        .with_timezone(&Utc);
    let request_hash = sha256_serialized(&BTreeMap::from([("state", "opened")]));
    let context = GitlabPageTokenContext {
        request: &request,
        project: &project,
        provider_fingerprint: "provider-fingerprint",
        request_hash: &request_hash,
        max_results: 100,
    };
    let token = encode_gitlab_page_token(&signer, &context, 2, now).unwrap();
    let decode = |request: &ProviderInvocation,
                  project: &GitlabProject,
                  provider_fingerprint: &str,
                  request_hash: &str,
                  max_results: u32,
                  now: DateTime<Utc>| {
        let context = GitlabPageTokenContext {
            request,
            project,
            provider_fingerprint,
            request_hash,
            max_results,
        };
        decode_gitlab_page_token(&signer, &token, &context, now)
    };
    assert_eq!(
        decode(
            &request,
            &project,
            "provider-fingerprint",
            &request_hash,
            100,
            now,
        )
        .unwrap(),
        2
    );
    assert_eq!(
        decode(
            &request,
            &project,
            "provider-fingerprint",
            &request_hash,
            100,
            now - ChronoDuration::seconds(30),
        )
        .unwrap(),
        2
    );
    assert!(
        decode(
            &request,
            &project,
            "provider-fingerprint",
            &request_hash,
            100,
            now - ChronoDuration::seconds(61),
        )
        .is_err()
    );

    let mut changed_request = request.clone();
    changed_request = InvocationBuilder::from(changed_request)
        .action("merge_request.search")
        .build();
    assert!(
        decode(
            &changed_request,
            &project,
            "provider-fingerprint",
            &request_hash,
            100,
            now,
        )
        .is_err()
    );
    let mut changed_principal = request.clone();
    changed_principal = InvocationBuilder::from(changed_principal)
        .principal("agent-2")
        .build();
    assert!(
        decode(
            &changed_principal,
            &project,
            "provider-fingerprint",
            &request_hash,
            100,
            now,
        )
        .is_err()
    );
    let mut changed_mode = request.clone();
    changed_mode = InvocationBuilder::from(changed_mode)
        .credential_mode(CredentialMode::PerUser)
        .build();
    assert!(
        decode(
            &changed_mode,
            &project,
            "provider-fingerprint",
            &request_hash,
            100,
            now,
        )
        .is_err()
    );
    let changed_context = InvocationBuilder::from(request.clone())
        .execution_context("external")
        .build();
    assert!(
        decode(
            &changed_context,
            &project,
            "provider-fingerprint",
            &request_hash,
            100,
            now,
        )
        .is_err()
    );
    let unauthenticated = InvocationBuilder::from(request.clone())
        .identity(crate::InvocationIdentity::new("agent-1".to_string(), false))
        .build();
    assert!(
        decode(
            &unauthenticated,
            &project,
            "provider-fingerprint",
            &request_hash,
            100,
            now,
        )
        .is_err()
    );
    let mut changed_project = project.clone();
    changed_project.id = 43;
    assert!(
        decode(
            &request,
            &changed_project,
            "provider-fingerprint",
            &request_hash,
            100,
            now,
        )
        .is_err()
    );
    assert!(
        decode(
            &request,
            &project,
            "provider-fingerprint",
            "changed-query",
            100,
            now,
        )
        .is_err()
    );
    assert!(
        decode(
            &request,
            &project,
            "provider-fingerprint",
            &request_hash,
            50,
            now,
        )
        .is_err()
    );
    assert!(
        decode(
            &request,
            &project,
            "changed-provider",
            &request_hash,
            100,
            now,
        )
        .is_err()
    );
    assert!(
        decode(
            &request,
            &project,
            "provider-fingerprint",
            &request_hash,
            100,
            now + ChronoDuration::minutes(16),
        )
        .is_err()
    );

    let mut tampered = token.clone().into_bytes();
    let middle = tampered.len() / 2;
    tampered[middle] = if tampered[middle] == b'A' { b'B' } else { b'A' };
    let tampered = String::from_utf8(tampered).unwrap();
    let context = GitlabPageTokenContext {
        request: &request,
        project: &project,
        provider_fingerprint: "provider-fingerprint",
        request_hash: &request_hash,
        max_results: 100,
    };
    assert!(decode_gitlab_page_token(&signer, &tampered, &context, now).is_err());
}

#[test]
fn gitlab_page_tokens_reject_other_versions_purposes_and_oversize_and_keep_their_lifetime() {
    let signer = ContinuationSigner::new(None);
    let request = test_invocation("issue.search", json!({ "project": "sip/service" }));
    let project = test_project();
    let now = Utc::now();
    let context = GitlabPageTokenContext {
        request: &request,
        project: &project,
        provider_fingerprint: "provider-fingerprint",
        request_hash: "request-hash",
        max_results: 20,
    };
    let token = encode_gitlab_page_token(&signer, &context, 2, now).unwrap();
    // The schema bound is the exact encoded size, and the token carries only
    // the version, expiry, next page and MAC.
    assert_eq!(token.len(), GITLAB_PAGE_TOKEN_MAX_BYTES);
    assert_eq!(GITLAB_PAGE_TOKEN_MAX_BYTES, 60);
    assert_eq!(
        URL_SAFE_NO_PAD.decode(&token).unwrap().len(),
        1 + 8 + 4 + 32
    );
    for family in [
        ContinuationFamily::new(
            "gitlab",
            "list-page",
            1,
            ContinuationLifetime::StableWhenConfigured,
            GITLAB_PAGE_TOKEN_PAYLOAD_BYTES,
        )
        .expires_after(Duration::from_secs(900)),
        ContinuationFamily::new(
            "gitlab",
            "draft-page",
            GITLAB_PAGE_TOKEN_VERSION,
            ContinuationLifetime::StableWhenConfigured,
            GITLAB_PAGE_TOKEN_PAYLOAD_BYTES,
        )
        .expires_after(Duration::from_secs(900)),
    ] {
        let foreign = signer
            .seal_at(
                &gitlab_page_token_binding(&family, &context),
                &2_u32.to_be_bytes(),
                now.into(),
            )
            .unwrap();
        let error = decode_gitlab_page_token(&signer, &foreign, &context, now).unwrap_err();
        assert_eq!(error.reason_code(), ReasonCode::InputInvalid);
        assert_eq!(error.decision(), Decision::Deny);
        assert_eq!(
            error.message,
            "GitLab pagination token is invalid or expired"
        );
    }
    let oversized = format!("{token}A");
    assert_eq!(
        decode_gitlab_page_token(&signer, &oversized, &context, now)
            .unwrap_err()
            .reason_code(),
        ReasonCode::InputInvalid
    );

    // Without a stable key another provider instance rejects the token; with
    // one, instances sharing it accept each other's tokens.
    assert!(
        decode_gitlab_page_token(&ContinuationSigner::new(None), &token, &context, now).is_err()
    );
    let key = test_signing_key(4);
    let shared = encode_gitlab_page_token(
        &ContinuationSigner::new(Some(key.clone())),
        &context,
        3,
        now,
    )
    .unwrap();
    assert_eq!(
        decode_gitlab_page_token(&ContinuationSigner::new(Some(key)), &shared, &context, now)
            .unwrap(),
        3
    );

    struct Unavailable;
    impl StableSigningKey for Unavailable {
        fn hmac_base64url(&self, _: &[u8], _: &[u8]) -> Result<String, SigningError> {
            Err(SigningError)
        }
    }
    let failing = ContinuationSigner::new(Some(Arc::new(Unavailable)));
    for error in [
        encode_gitlab_page_token(&failing, &context, 2, now).unwrap_err(),
        decode_gitlab_page_token(&failing, &shared, &context, now).unwrap_err(),
    ] {
        assert_eq!(error.reason_code(), ReasonCode::UpstreamProtocolFailed);
        assert_eq!(error.decision(), Decision::Error);
        assert_eq!(
            error.message,
            "GitLab pagination signing key is unavailable"
        );
    }
}

#[test]
fn gitlab_pagination_headers_validate_the_exact_next_collection_page() {
    let requested =
        Url::parse("https://gitlab.example.com/api/v4/projects/42/issues?per_page=100").unwrap();
    let mut headers = reqwest::header::HeaderMap::new();
    headers.insert("x-next-page", "2".parse().unwrap());
    headers.insert(
        reqwest::header::LINK,
        "<https://gitlab.example.com/api/v4/projects/42/issues?page=2&per_page=100>; rel=\"next\""
            .parse()
            .unwrap(),
    );
    assert_eq!(gitlab_next_page(&headers, &requested).unwrap(), Some(2));

    let mut explicit_end_with_link = headers.clone();
    explicit_end_with_link.insert("x-next-page", "".parse().unwrap());
    assert!(gitlab_next_page(&explicit_end_with_link, &requested).is_err());

    headers.insert("x-next-page", "3".parse().unwrap());
    assert!(gitlab_next_page(&headers, &requested).is_err());

    let requested_with_delimiters = Url::parse(
        "https://gitlab.example.com/api/v4/projects/42/issues?per_page=100&search=a,b;c",
    )
    .unwrap();
    let mut delimiter_link = reqwest::header::HeaderMap::new();
    delimiter_link.insert(
        reqwest::header::LINK,
        "<https://gitlab.example.com/api/v4/projects/42/issues?page=2&per_page=100&search=a,b;c>; title=\"next,page;label\"; rel=\"next\""
            .parse()
            .unwrap(),
    );
    assert_eq!(
        gitlab_next_page(&delimiter_link, &requested_with_delimiters).unwrap(),
        Some(2)
    );

    let mut repeated_relation = reqwest::header::HeaderMap::new();
    repeated_relation.insert(
        reqwest::header::LINK,
        "<https://gitlab.example.com/api/v4/projects/42/issues?page=2&per_page=100>; rel=prev; rel=next"
            .parse()
            .unwrap(),
    );
    assert!(gitlab_next_page(&repeated_relation, &requested).is_err());

    let mut changed_collection = reqwest::header::HeaderMap::new();
    changed_collection.insert(
        reqwest::header::LINK,
        "<https://evil.example/api/v4/projects/42/issues?page=2&per_page=100>; rel=\"next\""
            .parse()
            .unwrap(),
    );
    assert!(gitlab_next_page(&changed_collection, &requested).is_err());
    changed_collection.insert("x-next-page", "2".parse().unwrap());
    assert_eq!(
        gitlab_next_page(&changed_collection, &requested).unwrap(),
        Some(2)
    );
    assert_eq!(
        gitlab_next_page(&reqwest::header::HeaderMap::new(), &requested).unwrap(),
        None
    );
}

#[test]
fn gitlab_search_discovery_documents_project_local_filters_and_valid_examples() {
    let descriptor = gitlab_descriptor(&config());
    for (name, parse) in [
        (
            "issue.search",
            parse_issue_search_inputs as fn(&Value) -> Result<SearchInputs, ProviderError>,
        ),
        ("merge_request.search", parse_merge_request_search_inputs),
    ] {
        let action = descriptor.action(name).unwrap();
        assert_eq!(action.input_schema["required"], json!(["project"]));
        let documentation = action.documentation.as_ref().unwrap();
        assert!(
            documentation["scope"]
                .as_str()
                .unwrap()
                .contains("do not select projects")
        );
        assert_eq!(
            documentation["pagination"]["requestTokenField"],
            "pageToken"
        );
        assert_eq!(
            documentation["pagination"]["responseTokenField"],
            "nextPageToken"
        );
        for (doc_field, input_field) in [
            ("states", "state"),
            ("orderBy", "orderBy"),
            ("sort", "sort"),
        ] {
            assert_eq!(
                documentation[doc_field],
                action.input_schema["properties"][input_field]["enum"]
            );
            for value in documentation[doc_field].as_array().unwrap() {
                let mut input = json!({"project": "team/service"});
                input[input_field] = value.clone();
                parse(&input).unwrap();
            }
        }
        for field in action.input_schema["properties"]
            .as_object()
            .unwrap()
            .values()
        {
            assert!(
                field["description"]
                    .as_str()
                    .is_some_and(|description| !description.is_empty())
            );
        }
        for example in documentation["examples"].as_array().unwrap() {
            parse(example).unwrap();
            let project = project_locator_for_action(name, example, &config()).unwrap();
            assert_eq!(project.project, "team/service");
        }
        // Discovery must not imply Jira-style scope-only execution or admit a
        // query-language object in these structured project-local searches.
        assert_eq!(
            parse(&json!({})).unwrap_err().reason_code(),
            ReasonCode::InputInvalid
        );
        assert!(
            parse(&json!({"project": "team/service", "query": {"type": "jql", "value": ""}}))
                .is_err()
        );
        assert!(parse(&json!({"project": "team/service", "orderBy": "unsupported"})).is_err());
        assert!(action.input_schema.get("documentation").is_none());
    }
}

#[test]
fn gitlab_pagination_schema_and_parsers_expose_only_signed_continuations() {
    assert_eq!(
        issue_search_schema(100)["properties"]["pageToken"]["type"],
        "string"
    );
    assert_eq!(
        note_list_schema(100)["properties"]["pageToken"]["type"],
        "string"
    );
    assert_eq!(
        issue_search_schema(100)["properties"]["pageToken"]["minLength"],
        1
    );
    assert_eq!(
        issue_search_schema(100)["properties"]["pageToken"]["maxLength"],
        GITLAB_PAGE_TOKEN_MAX_BYTES
    );
    assert_eq!(
        note_list_schema(100)["properties"]["pageToken"]["minLength"],
        1
    );
    assert_eq!(
        note_list_schema(100)["properties"]["pageToken"]["maxLength"],
        GITLAB_PAGE_TOKEN_MAX_BYTES
    );
    let search = parse_issue_search_inputs(&json!({
        "project": "sip/service",
        "maxResults": 100,
        "pageToken": "opaque"
    }))
    .unwrap();
    assert_eq!(search.page_token.as_deref(), Some("opaque"));
    let notes = parse_note_list_inputs(
        &json!({
            "project": "sip/service",
            "iid": 7,
            "pageToken": "opaque"
        }),
        100,
    )
    .unwrap();
    assert_eq!(notes.page_token.as_deref(), Some("opaque"));
    assert!(
        parse_issue_search_inputs(&json!({
            "project": "sip/service",
            "page": 2
        }))
        .is_err()
    );
    assert!(
        parse_issue_search_inputs(&json!({
            "project": "sip/service",
            "nextPageToken": "legacy-alias"
        }))
        .is_err()
    );
}

#[test]
fn collection_projections_are_closed_summarized_and_token_bound() {
    let full = parse_note_list_inputs(&json!({"project":"sip/service", "iid":7}), 100).unwrap();
    assert_eq!(full.projection, GitlabCollectionProjection::Full);
    let summary = parse_note_list_inputs(
        &json!({"project":"sip/service", "iid":7, "projection":"summary"}),
        100,
    )
    .unwrap();
    assert_eq!(summary.projection, GitlabCollectionProjection::Summary);
    assert!(
        parse_note_list_inputs(
            &json!({"project":"sip/service", "iid":7, "projection":"Summary"}),
            100,
        )
        .is_err()
    );
    for schema in [
        note_list_schema(100),
        discussion_list_schema(100),
        draft_note_list_schema(100),
    ] {
        assert_eq!(schema["properties"]["projection"]["default"], "full");
        assert_eq!(
            schema["properties"]["projection"]["enum"],
            json!(["full", "summary"])
        );
    }

    let note = note_from_value(json!({
        "id": 701,
        "body": "secret",
        "author": {"id":314, "username":"review-bot"},
        "noteable_type":"MergeRequest",
        "noteable_iid":5,
        "project_id":42,
        "resolved":false,
        "resolved_by":{"id":9,"username":"resolver"},
        "resolved_at":"2026-08-30T12:00:00Z",
        "suggestions":[{
            "id":1,"from_line":1,"to_line":1,"applicable":true,"applied":false,
            "from_content":"private old","to_content":"private new"
        }]
    }))
    .unwrap();
    let summary_value = serde_json::to_value(GitlabNoteSummary::from(note)).unwrap();
    assert_eq!(summary_value["id"], 701);
    assert_eq!(summary_value["resolvedAt"], "2026-08-30T12:00:00Z");
    for omitted in [
        "body",
        "renderedBody",
        "suggestions",
        "resolvedBy",
        "noteableType",
        "noteableIid",
        "projectId",
    ] {
        assert!(summary_value.get(omitted).is_none(), "leaked {omitted}");
    }
    assert_ne!(
        note_list_request_hash(&full),
        note_list_request_hash(&summary)
    );

    let draft_full =
        parse_draft_note_list_inputs(&json!({"project":"sip/service", "iid":5}), 100).unwrap();
    let draft_summary = parse_draft_note_list_inputs(
        &json!({"project":"sip/service", "iid":5, "projection":"summary"}),
        100,
    )
    .unwrap();
    assert_ne!(
        draft_note_collection_request_hash(&draft_full, 314),
        draft_note_collection_request_hash(&draft_summary, 314)
    );
    assert_ne!(
        draft_note_collection_request_hash(&draft_summary, 314),
        draft_note_collection_request_hash(&draft_summary, 315)
    );
}

#[test]
fn exact_note_view_parsers_report_action_specific_invalid_shapes() {
    let issue_error = parse_issue_note_view_inputs(&json!({
        "project": "sip/service",
        "iid": 7,
        "noteId": 701,
        "legacy": true
    }))
    .unwrap_err();
    assert_eq!(
        issue_error.message,
        "gitlab issue note view inputs are invalid"
    );

    let merge_request_error = parse_merge_request_note_view_inputs(&json!([])).unwrap_err();
    assert_eq!(
        merge_request_error.message,
        "gitlab merge request note view inputs are invalid"
    );

    let delete_error = parse_note_delete_inputs(&json!({
        "project": "sip/service",
        "iid": 7,
        "noteId": 701,
        "legacy": true
    }))
    .unwrap_err();
    assert_eq!(
        delete_error.message,
        "gitlab note delete inputs are invalid"
    );
}

#[test]
fn max_results_never_exceeds_gitlab_page_size_limit() {
    assert_eq!(capped_max_results(None, 50).unwrap(), 50);
    assert_eq!(capped_max_results(Some(25), 50).unwrap(), 25);
    assert_eq!(capped_max_results(Some(200), 250).unwrap(), 100);
    assert!(capped_max_results(Some(0), 50).is_err());
}

#[test]
fn gitlab_note_mutation_actions_are_registered_and_project_scoped() {
    let config = config();
    let descriptor = gitlab_descriptor(&config);
    let cases = [
        (
            "issue.note.view",
            json!({ "project": "sip/service", "iid": 7, "noteId": 701 }),
        ),
        (
            "issue.note.update",
            json!({ "project": "sip/service", "iid": 7, "noteId": 701, "contentFormat": "markdown", "content": "updated" }),
        ),
        (
            "issue.note.delete",
            json!({ "project": "sip/service", "iid": 7, "noteId": 701 }),
        ),
        (
            "merge_request.note.view",
            json!({ "project": "sip/service", "iid": 5, "noteId": 501 }),
        ),
        (
            "merge_request.note.update",
            json!({ "project": "sip/service", "iid": 5, "noteId": 501, "contentFormat": "markdown", "content": "updated" }),
        ),
        (
            "merge_request.note.delete",
            json!({ "project": "sip/service", "iid": 5, "noteId": 501 }),
        ),
        (
            "merge_request.discussion.note.update",
            json!({ "project": "sip/service", "iid": 5, "discussionId": "discussion-1", "noteId": 900, "contentFormat": "markdown", "content": "updated" }),
        ),
        (
            "merge_request.discussion.note.delete",
            json!({ "project": "sip/service", "iid": 5, "discussionId": "discussion-1", "noteId": 900 }),
        ),
        (
            "merge_request.discussion.resolve",
            json!({ "project": "sip/service", "iid": 5, "discussionId": "discussion-1" }),
        ),
        (
            "merge_request.discussion.reopen",
            json!({ "project": "sip/service", "iid": 5, "discussionId": "discussion-1" }),
        ),
    ];

    for (action, inputs) in cases {
        let spec = descriptor
            .action(action)
            .unwrap_or_else(|| panic!("{action} missing descriptor entry"));
        assert_eq!(
            spec.lookup,
            LookupRequirement::ScopeResolution,
            "{action} must resolve its repository before policy"
        );
        assert_eq!(
            spec.resource_scope.as_deref(),
            Some("repository"),
            "{action}"
        );
        let locator = project_locator_for_action(action, &inputs, &config).unwrap();
        assert_eq!(locator.project, "sip/service");
    }
}

#[test]
fn acting_user_ownership_metadata_covers_exact_draft_review_actions() {
    let descriptor = gitlab_descriptor(&config());
    let marked = descriptor
        .actions
        .iter()
        .filter_map(|capability| {
            capability
                .upstream_resource_ownership
                .map(|ownership| (capability.action.as_str(), ownership))
        })
        .collect::<BTreeMap<_, _>>();
    let expected = [
        "merge_request.draft_note.list",
        "merge_request.draft_note.view",
        "merge_request.draft_note.add",
        "merge_request.draft_note.update",
        "merge_request.draft_note.delete",
        "merge_request.draft_note.publish",
        "merge_request.draft_note.publish_all",
        "merge_request.review.submit",
    ];
    assert_eq!(marked.len(), expected.len());
    for action in expected {
        assert_eq!(
            marked.get(action),
            Some(&UpstreamResourceOwnership::ActingUser),
            "{action}"
        );
    }
    assert!(!marked.contains_key("merge_request.note.list"));
}

#[test]
fn gitlab_review_attribution_capabilities_are_exact_and_exclude_updates() {
    let descriptor = gitlab_descriptor(&config());
    let actual = descriptor
        .actions
        .iter()
        .filter(|action| action.attribution.is_some())
        .map(|action| action.action.as_str())
        .collect::<BTreeSet<_>>();
    assert_eq!(
        actual,
        BTreeSet::from([
            "issue.create",
            "issue.note.add",
            "issue.update",
            "merge_request.create",
            "merge_request.discussion.add",
            "merge_request.discussion.inline.add",
            "merge_request.discussion.note.add",
            "merge_request.draft_note.add",
            "merge_request.draft_note.publish_all",
            "merge_request.note.add",
            "merge_request.review.submit",
            "merge_request.update",
        ])
    );

    let attribution =
        ProviderAttributionConfig::from_patterns(&descriptor, &["merge_request.*".to_string()]);
    for action in [
        "merge_request.discussion.inline.add",
        "merge_request.discussion.note.add",
        "merge_request.draft_note.add",
        "merge_request.draft_note.publish_all",
        "merge_request.review.submit",
    ] {
        let capability = attribution.capability(action).unwrap();
        assert_eq!(capability.verb, AttributionVerb::Add);
        assert_eq!(capability.target, "body");
        assert_eq!(
            capability.representation,
            AttributionRepresentation::GitlabMarkdown
        );
        assert!(capability.required);
    }
    assert!(
        attribution
            .capability("merge_request.draft_note.update")
            .is_none()
    );
    assert!(
        attribution
            .capability("merge_request.discussion.note.update")
            .is_none()
    );
}

#[test]
fn gitlab_webhook_actions_do_not_advertise_content_attribution() {
    let descriptor = gitlab_descriptor(&config());
    let attribution =
        ProviderAttributionConfig::from_patterns(&descriptor, &["webhook.*".to_string()]);
    for action in [
        "webhook.list",
        "webhook.view",
        "webhook.create",
        "webhook.update",
        "webhook.delete",
        "webhook.test",
        "webhook.event.list",
        "webhook.event.resend",
        "webhook.custom_header.set",
        "webhook.custom_header.delete",
    ] {
        assert!(descriptor.action(action).is_some(), "gitlab.{action}");
        assert!(
            attribution.capability(action).is_none(),
            "gitlab.{action} has no user-authored body eligible for attribution"
        );
    }
}

#[test]
fn gitlab_descriptor_marks_issued_tokens_and_transfer_io() {
    let descriptor = gitlab_descriptor(&config());
    assert_eq!(descriptor.validate(), Ok(()));

    let sensitive = descriptor
        .actions
        .iter()
        .filter(|action| !action.sensitive_output_pointers.is_empty())
        .map(|action| {
            assert_eq!(
                action.sensitive_output_pointers,
                vec!["/result/issuedToken".to_string()],
                "{}",
                action.action
            );
            action.action.as_str()
        })
        .collect::<BTreeSet<_>>();
    assert_eq!(
        sensitive,
        BTreeSet::from([
            "project.access_token.create",
            "project.access_token.rotate",
            "service_account.token.create",
            "service_account.token.rotate",
        ])
    );
    for action in PROVISIONING_ACTIONS {
        assert!(descriptor.action(action).is_some(), "{action}");
        assert_eq!(sensitive.contains(action), issues_token(action), "{action}");
    }

    let raw_downloads = [
        "file.raw.download",
        "job.trace.download",
        "merge_request.diff.raw.download",
    ];
    for action in &descriptor.actions {
        let expected = if raw_downloads.contains(&action.action.as_str()) {
            raw_download_io()
        } else if action.action == "project.upload" {
            ActionIo::MultipartUpload {
                plan: attachment_upload_plan(&["project", "url"], Some(1)),
            }
        } else {
            ActionIo::Json
        };
        assert_eq!(action.io, expected, "{}", action.action);
    }
}

#[test]
fn ci_inputs_reject_variables_and_unknown_mutation_shapes() {
    assert!(
        parse_pipeline_run_inputs(&json!({
            "project": "sip/service",
            "ref": "feature/rest",
            "variables": [{ "key": "DEPLOY_ENV", "value": "prod" }]
        }))
        .is_err()
    );
    assert!(
        parse_job_object_inputs(&json!({
            "project": "sip/service",
            "jobId": 9002,
            "job_variables_attributes": [{ "key": "DEPLOY_ENV", "value": "prod" }]
        }))
        .is_err()
    );
}

#[test]
fn gitlab_ci_object_ids_and_job_project_revalidation_are_strict() {
    let project = GitlabProject {
        id: 42,
        path_with_namespace: "sip/service".to_string(),
        name: Some("service".to_string()),
        web_url: Some("https://gitlab.example.com/sip/service".to_string()),
        default_branch: Some("main".to_string()),
        visibility: Some("private".to_string()),
        archived: Some(false),
    };
    assert_eq!(
        gitlab_pipeline_object_id(&project, 321),
        "sip/service:pipeline/321"
    );
    assert_eq!(gitlab_job_object_id(&project, 9001), "sip/service:job/9001");

    let mut job = GitlabJob {
        id: 9001,
        name: Some("test".to_string()),
        status: Some("success".to_string()),
        stage: Some("test".to_string()),
        ref_name: Some("feature/rest".to_string()),
        pipeline_id: Some(321),
        project_id: Some(42),
        trace_size: Some(10),
        web_url: Some("https://gitlab.example.com/sip/service/-/jobs/9001".to_string()),
        created_at: None,
        started_at: None,
        finished_at: None,
    };
    assert!(ensure_job_in_project(&project, &job).is_ok());
    job.project_id = None;
    assert!(ensure_job_in_project(&project, &job).is_err());
    job.project_id = Some(99);
    assert!(ensure_job_in_project(&project, &job).is_err());
}

#[test]
fn returned_issue_and_merge_request_descriptions_are_capped() {
    let issue = GitlabIssue {
        id: Some(700),
        iid: 7,
        project_id: 42,
        title: Some("Issue".to_string()),
        description: Some("short".to_string()),
        state: Some("opened".to_string()),
        created_at: None,
        updated_at: None,
        author: None,
        assignees: None,
        labels: None,
        milestone: None,
        web_url: None,
        project: None,
    };
    assert!(ensure_issue_description_within_cap(&issue, 5).is_ok());
    assert!(ensure_issue_description_within_cap(&issue, 4).is_err());

    let merge_request = GitlabMergeRequest {
        id: Some(500),
        iid: 5,
        project_id: 42,
        title: Some("MR".to_string()),
        description: Some("short".to_string()),
        state: Some("opened".to_string()),
        source_branch: Some("feature/rest".to_string()),
        target_branch: Some("main".to_string()),
        sha: Some("0123456789abcdef0123456789abcdef01234567".to_string()),
        merge_status: Some("can_be_merged".to_string()),
        detailed_merge_status: Some("mergeable".to_string()),
        merge_commit_sha: None,
        squash_commit_sha: None,
        source_project_id: None,
        target_project_id: None,
        diff_refs: None,
        changes_count: None,
        user_notes_count: None,
        discussion_locked: None,
        blocking_discussions_resolved: None,
        has_conflicts: None,
        prepared_at: None,
        head_pipeline: None,
        created_at: None,
        updated_at: None,
        author: None,
        assignees: None,
        reviewers: None,
        labels: None,
        milestone: None,
        draft: None,
        web_url: None,
        project: None,
    };
    assert!(ensure_merge_request_description_within_cap(&merge_request, 5).is_ok());
    assert!(ensure_merge_request_description_within_cap(&merge_request, 4).is_err());
}

#[test]
fn gitlab_issue_and_merge_request_parsers_expose_agent_metadata() {
    let project = GitlabProject {
        id: 42,
        path_with_namespace: "sip/service".to_string(),
        name: Some("service".to_string()),
        web_url: None,
        default_branch: None,
        visibility: None,
        archived: None,
    };
    let issue = issue_from_value(json!({
        "id": 700,
        "iid": 7,
        "project_id": 42,
        "title": "Issue",
        "description": "visible description",
        "state": "opened",
        "web_url": "https://gitlab.example.com/sip/service/-/issues/7",
        "created_at": "2026-06-01T10:00:00.000Z",
        "updated_at": "2026-06-02T11:00:00.000Z",
        "author": {
            "id": 1,
            "username": "alice",
            "name": "Alice",
            "web_url": "https://gitlab.example.com/alice"
        },
        "assignees": [{
            "id": 2,
            "username": "bob",
            "name": "Bob"
        }],
        "labels": ["bug", "triaged"],
        "milestone": {
            "id": 3,
            "iid": 4,
            "title": "M1",
            "state": "active",
            "due_date": "2026-07-01"
        }
    }))
    .unwrap();
    assert_eq!(
        issue.created_at.as_deref(),
        Some("2026-06-01T10:00:00.000Z")
    );
    assert_eq!(
        issue
            .author
            .as_ref()
            .and_then(|user| user.username.as_deref()),
        Some("alice")
    );
    assert_eq!(
        issue.labels.as_deref(),
        Some(&["bug".to_string(), "triaged".to_string()][..])
    );

    let issue_result = serde_json::to_value(issue.with_project(&project)).unwrap();
    assert_eq!(issue_result["createdAt"], "2026-06-01T10:00:00.000Z");
    assert_eq!(issue_result["author"]["username"], "alice");
    assert_eq!(issue_result["assignees"][0]["username"], "bob");
    assert_eq!(issue_result["milestone"]["dueDate"], "2026-07-01");
    assert_eq!(issue_result["project"], "sip/service");

    let merge_request = merge_request_from_value(json!({
        "id": 500,
        "iid": 5,
        "project_id": 42,
        "title": "MR",
        "description": "visible description",
        "state": "opened",
        "source_branch": "feature/rest",
        "target_branch": "main",
        "sha": "0123456789abcdef0123456789abcdef01234567",
        "merge_status": "can_be_merged",
        "detailed_merge_status": "mergeable",
        "source_project_id": 41,
        "target_project_id": 42,
        "diff_refs": {
            "base_sha": null,
            "start_sha": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
            "head_sha": "0123456789abcdef0123456789abcdef01234567"
        },
        "squash_commit_sha": "cccccccccccccccccccccccccccccccccccccccc",
        "changes_count": "12",
        "user_notes_count": 4,
        "discussion_locked": false,
        "blocking_discussions_resolved": true,
        "has_conflicts": false,
        "prepared_at": "2026-06-03T11:59:00.000Z",
        "head_pipeline": {
            "id": 9001,
            "sha": "0123456789abcdef0123456789abcdef01234567",
            "ref": "feature/rest",
            "status": "success",
            "web_url": "https://gitlab.example.com/sip/service/-/pipelines/9001"
        },
        "web_url": "https://gitlab.example.com/sip/service/-/merge_requests/5",
        "created_at": "2026-06-03T12:00:00.000Z",
        "updated_at": "2026-06-04T13:00:00.000Z",
        "author": { "id": 1, "username": "alice" },
        "assignees": [{ "id": 2, "username": "bob" }],
        "reviewers": [{ "id": 3, "username": "carol" }],
        "labels": ["review"],
        "milestone": { "title": "M2" },
        "draft": true
    }))
    .unwrap();
    assert_eq!(merge_request.draft, Some(true));
    let merge_request_result = serde_json::to_value(merge_request.with_project(&project)).unwrap();
    assert_eq!(
        merge_request_result["createdAt"],
        "2026-06-03T12:00:00.000Z"
    );
    assert_eq!(merge_request_result["reviewers"][0]["username"], "carol");
    assert_eq!(merge_request_result["labels"], json!(["review"]));
    assert_eq!(merge_request_result["draft"], true);
    assert_eq!(
        merge_request_result["diffRefs"]["headSha"],
        "0123456789abcdef0123456789abcdef01234567"
    );
    assert_eq!(merge_request_result["headPipeline"]["id"], 9001);
    assert_eq!(merge_request_result["blockingDiscussionsResolved"], true);
    assert!(merge_request_result["diffRefs"]["baseSha"].is_null());

    let malformed_issue = issue_from_value(json!({
        "id": 701,
        "iid": 8,
        "project_id": 42,
        "author": {},
        "assignees": [{ "email": "hidden@example.com" }],
        "labels": ["bug", 42],
        "milestone": {}
    }))
    .unwrap();
    assert!(malformed_issue.author.is_none());
    assert!(malformed_issue.assignees.is_none());
    assert!(malformed_issue.labels.is_none());
    assert!(malformed_issue.milestone.is_none());

    let empty_assignees = issue_from_value(json!({
        "id": 702,
        "iid": 9,
        "project_id": 42,
        "assignees": []
    }))
    .unwrap();
    assert_eq!(empty_assignees.assignees, Some(Vec::new()));
}

#[test]
fn discussion_parser_preserves_exact_diff_association_and_suggestions() {
    let discussion = discussion_from_value(json!({
        "id": "discussion-positioned",
        "individual_note": false,
        "notes": [{
            "id": 901,
            "body": "Please adjust this range",
            "type": "DiffNote",
            "commit_id": "0123456789abcdef0123456789abcdef01234567",
            "noteable_type": "MergeRequest",
            "noteable_iid": 5,
            "noteable_id": 500,
            "project_id": 42,
            "resolvable": true,
            "resolved": true,
            "resolved_by": { "id": 17, "username": "reviewer", "name": "Review User" },
            "resolved_at": "2026-08-29T12:30:00Z",
            "position": {
                "position_type": "text",
                "base_sha": null,
                "start_sha": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
                "head_sha": "0123456789abcdef0123456789abcdef01234567",
                "old_path": "src/old.rs",
                "new_path": "src/new.rs",
                "old_line": 31,
                "new_line": 34,
                "line_range": {
                    "start": { "line_code": "abc_31_34", "type": null, "old_line": 31, "new_line": 34 },
                    "end": { "line_code": "abc_32_35", "type": "new", "new_line": 35 }
                }
            },
            "suggestions": [{
                "id": 91,
                "from_line": 34,
                "to_line": 35,
                "appliable": true,
                "applied": false,
                "from_content": "old code",
                "to_content": "new code"
            }]
        }]
    }))
    .unwrap();

    let note = &discussion.notes[0];
    assert_eq!(note.note_type.as_deref(), Some("DiffNote"));
    assert_eq!(note.position.as_ref().unwrap().new_line, Some(34));
    assert_eq!(note.position.as_ref().unwrap().base_sha, None);
    assert_eq!(
        note.position
            .as_ref()
            .unwrap()
            .line_range
            .as_ref()
            .unwrap()
            .start
            .line_type,
        None
    );
    assert_eq!(
        note.position
            .as_ref()
            .unwrap()
            .line_range
            .as_ref()
            .unwrap()
            .end
            .line_code,
        "abc_32_35"
    );
    assert!(note.suggestions[0].applicable);
    let normalized = serde_json::to_value(note).unwrap();
    assert_eq!(normalized["type"], "DiffNote");
    assert_eq!(normalized["position"]["newPath"], "src/new.rs");
    assert_eq!(normalized["suggestions"][0]["applicable"], true);
    assert!(normalized["suggestions"][0].get("appliable").is_none());

    let malformed = note_from_value(json!({
        "id": 902,
        "position": { "position_type": "text" }
    }));
    assert!(matches!(malformed, Err(GitlabBackendError::Protocol(_))));

    let image = note_from_value(json!({
        "id": 903,
        "position": {
            "position_type": "image",
            "base_sha": null,
            "start_sha": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
            "head_sha": "0123456789abcdef0123456789abcdef01234567",
            "old_path": "diagram.png",
            "new_path": "diagram.png",
            "width": 1280,
            "height": 720,
            "x": 640,
            "y": 360
        }
    }))
    .unwrap();
    let image_position = image.position.unwrap();
    assert_eq!(image_position.width, Some(1280));
    assert_eq!(image_position.height, Some(720));
    assert_eq!(image_position.x, Some(640));
    assert_eq!(image_position.y, Some(360));
    assert!(matches!(
        note_from_value(json!({
            "id": 904,
            "position": {
                "position_type": "image",
                "base_sha": null,
                "start_sha": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
                "head_sha": "0123456789abcdef0123456789abcdef01234567",
                "old_path": "diagram.png",
                "new_path": "diagram.png",
                "width": 1280,
                "height": 720,
                "x": -1,
                "y": 1
            }
        })),
        Err(GitlabBackendError::Protocol(_))
    ));
    assert!(matches!(
        note_from_value(json!({
            "id": 905,
            "position": {
                "position_type": "image",
                "base_sha": null,
                "start_sha": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
                "head_sha": "0123456789abcdef0123456789abcdef01234567",
                "old_path": "diagram.png",
                "new_path": "diagram.png",
                "width": 1280,
                "height": 720,
                "x": 640.25,
                "y": 360
            }
        })),
        Err(GitlabBackendError::Protocol(_))
    ));
    assert!(matches!(
        note_from_value(json!({
            "id": 906,
            "position": {
                "position_type": "image",
                "base_sha": null,
                "start_sha": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
                "head_sha": "0123456789abcdef0123456789abcdef01234567",
                "old_path": "diagram.png",
                "new_path": "diagram.png",
                "width": 1280.5
            }
        })),
        Err(GitlabBackendError::Protocol(_))
    ));
}

#[test]
fn diff_version_list_rejects_cross_merge_request_items() {
    let merge_request = merge_request_from_value(json!({
        "id": 500,
        "iid": 5,
        "project_id": 42
    }))
    .unwrap();
    let version = GitlabDiffVersionSummary {
        id: 8,
        merge_request_id: 500,
        head_commit_sha: "0123456789abcdef0123456789abcdef01234567".to_string(),
        base_commit_sha: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_string(),
        start_commit_sha: "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb".to_string(),
        created_at: None,
        state: Some("collected".to_string()),
        real_size: Some("1".to_string()),
        patch_id_sha: None,
    };
    assert!(
        ensure_diff_versions_target_merge_request(&merge_request, std::slice::from_ref(&version),)
            .is_ok()
    );
    let mismatch = ensure_diff_versions_target_merge_request(
        &merge_request,
        &[GitlabDiffVersionSummary {
            merge_request_id: 501,
            ..version
        }],
    )
    .unwrap_err();
    assert_eq!(mismatch.reason_code(), ReasonCode::UpstreamProtocolFailed);
}

#[test]
fn collaboration_write_inputs_fail_closed_on_ambiguous_or_oversized_shapes() {
    assert!(
        parse_issue_update_inputs(&json!({ "project": "sip/service", "iid": 7 }), 100).is_err()
    );
    assert!(
        parse_issue_update_inputs(
            &json!({
                "project": "sip/service",
                "iid": 7,
                "labels": ["bug"],
                "addLabels": ["triaged"]
            }),
            100
        )
        .is_err()
    );
    assert!(
        parse_issue_note_add_inputs(
            &json!({
                "project": "sip/service",
                "iid": 7,
                "contentFormat": "markdown",
                "content": "this body is too long"
            }),
            4
        )
        .is_err()
    );
    assert!(
        parse_note_update_inputs(
            &json!({
                "project": "sip/service",
                "iid": 7,
                "noteId": 701,
                "contentFormat": "markdown",
                "content": ""
            }),
            100
        )
        .is_err()
    );
    assert!(
        parse_note_update_inputs(
            &json!({
                "project": "sip/service",
                "iid": 7,
                "noteId": 701,
                "contentFormat": "markdown",
                "content": "this body is too long"
            }),
            4
        )
        .is_err()
    );
    assert!(
        parse_note_delete_inputs(&json!({
            "project": "sip/service",
            "iid": 7,
            "noteId": 0
        }))
        .is_err()
    );
    assert!(
        parse_discussion_note_update_inputs(
            &json!({
                "project": "sip/service",
                "iid": 5,
                "discussionId": "",
                "noteId": 900,
                "contentFormat": "markdown",
                "content": "updated"
            }),
            100
        )
        .is_err()
    );
    assert!(
        parse_discussion_note_delete_inputs(&json!({
            "project": "sip/service",
            "iid": 5,
            "discussionId": "discussion-1",
            "noteId": 900,
            "resolved": true
        }))
        .is_err()
    );
    assert!(
        parse_discussion_state_change_inputs(
            &json!({
                "project": "sip/service",
                "iid": 5,
                "discussionId": "discussion-1",
                "noteId": 900
            }),
            GitlabDiscussionStateChange::Resolve
        )
        .is_err()
    );
    assert!(
        parse_merge_request_create_inputs(
            &json!({
                "project": "sip/service",
                "sourceBranch": "refs/heads/main",
                "targetBranch": "main",
                "title": "Bad branch"
            }),
            100
        )
        .is_err()
    );
    assert!(
        parse_merge_request_create_inputs(
            &json!({
                "project": "sip/service",
                "sourceBranch": "feature/rest",
                "targetBranch": "main",
                "title": "Bad assignee",
                "assignees": ["alice"]
            }),
            100
        )
        .is_err()
    );
    assert!(
        parse_discussion_list_inputs(
            &json!({
                "project": "sip/service",
                "iid": 7,
                "sort": "desc"
            }),
            50
        )
        .is_err()
    );
    assert!(
        parse_discussion_list_inputs(
            &json!({
                "project": "sip/service",
                "iid": 7,
                "orderBy": "updated_at"
            }),
            50
        )
        .is_err()
    );
    assert!(
        parse_note_list_inputs(
            &json!({
                "project": "sip/service",
                "iid": 7,
                "orderBy": "author"
            }),
            50
        )
        .is_err()
    );
    assert!(
        parse_issue_search_inputs(&json!({
            "project": "sip/service",
            "orderBy": "merged_at"
        }))
        .is_err()
    );
    assert!(
        parse_merge_request_search_inputs(&json!({
            "project": "sip/service",
            "orderBy": "relative_position"
        }))
        .is_err()
    );

    let create_schema = merge_request_create_schema();
    let create_properties = create_schema["properties"].as_object().unwrap();
    assert!(create_properties.contains_key("sourceBranch"));
    let update_schema = merge_request_update_schema();
    let update_properties = update_schema["properties"].as_object().unwrap();
    assert!(!update_properties.contains_key("sourceBranch"));

    let body = merge_request_create_body(&GitlabMergeRequestCreateRequest {
        source_branch: "feature/rest".to_string(),
        target_branch: "main".to_string(),
        title: "Created MR".to_string(),
        description: None,
        labels: vec![],
        assignee_ids: vec![],
        reviewer_ids: vec![],
        remove_source_branch: None,
        squash: None,
        draft: Some(true),
    });
    assert_eq!(body["title"], "Draft: Created MR");
    assert!(body.get("draft").is_none());

    let body = merge_request_create_body(&GitlabMergeRequestCreateRequest {
        source_branch: "feature/rest".to_string(),
        target_branch: "main".to_string(),
        title: "[Draft] Existing".to_string(),
        description: None,
        labels: vec![],
        assignee_ids: vec![],
        reviewer_ids: vec![],
        remove_source_branch: None,
        squash: None,
        draft: Some(true),
    });
    assert_eq!(body["title"], "[Draft] Existing");
}

#[test]
fn normalized_gitlab_write_contract_covers_exact_actions_and_formats() {
    let descriptor = gitlab_descriptor(&config());
    let covered = [
        "issue.create",
        "issue.update",
        "issue.note.add",
        "issue.note.update",
        "merge_request.create",
        "merge_request.update",
        "merge_request.note.add",
        "merge_request.note.update",
        "merge_request.discussion.add",
        "merge_request.discussion.inline.add",
        "merge_request.discussion.note.add",
        "merge_request.discussion.note.update",
        "merge_request.draft_note.add",
        "merge_request.draft_note.update",
        "merge_request.draft_note.publish_all",
        "merge_request.review.submit",
    ];
    for capability in &descriptor.actions {
        let properties = capability.input_schema["properties"]
            .as_object()
            .expect("action properties");
        if covered.contains(&capability.action.as_str()) {
            assert_eq!(
                properties["contentFormat"]["enum"],
                json!(["markdown", "plain_text"]),
                "{} content formats",
                capability.action
            );
            assert!(properties.contains_key("content"));
            assert!(!properties.contains_key("description"));
            assert!(!properties.contains_key("body"));
        } else {
            assert!(!properties.contains_key("contentFormat"));
        }
    }
}

#[test]
fn normalized_gitlab_content_is_explicit_literal_and_bounded() {
    let markdown = parse_issue_update_inputs(
        &json!({
            "project": "sip/service",
            "iid": 7,
            "contentFormat": "markdown",
            "content": "**exact**"
        }),
        100,
    )
    .unwrap();
    assert_eq!(markdown.description.as_deref(), Some("**exact**"));

    let plain_text = parse_note_update_inputs(
        &json!({
            "project": "sip/service",
            "iid": 7,
            "noteId": 701,
            "contentFormat": "plain_text",
            "content": "*literal* @user #1 !2 <tag>"
        }),
        100,
    )
    .unwrap();
    assert_eq!(plain_text.body, r"\*literal\* \@user \#1 \!2 \<tag\>");

    let cleared = parse_issue_update_inputs(
        &json!({
            "project": "sip/service",
            "iid": 7,
            "contentFormat": "markdown",
            "content": ""
        }),
        100,
    )
    .unwrap();
    assert_eq!(cleared.description.as_deref(), Some(""));

    let unsupported = parse_note_update_inputs(
        &json!({
            "project": "sip/service",
            "iid": 7,
            "noteId": 701,
            "contentFormat": "html",
            "content": "safe"
        }),
        100,
    )
    .unwrap_err();
    assert_eq!(unsupported.reason_code(), ReasonCode::BodyFormatUnsupported);

    let oversized = parse_note_update_inputs(
        &json!({
            "project": "sip/service",
            "iid": 7,
            "noteId": 701,
            "contentFormat": "markdown",
            "content": "five!"
        }),
        4,
    )
    .unwrap_err();
    assert_eq!(oversized.reason_code(), ReasonCode::BodySizeDenied);

    for invalid in [
        json!({ "project": "sip/service", "iid": 7, "noteId": 701, "content": "missing format" }),
        json!({ "project": "sip/service", "iid": 7, "noteId": 701, "contentFormat": "markdown" }),
        json!({ "project": "sip/service", "iid": 7, "noteId": 701, "contentFormat": "markdown", "content": "  \n" }),
        json!({ "project": "sip/service", "iid": 7, "noteId": 701, "body": "legacy" }),
    ] {
        assert_eq!(
            parse_note_update_inputs(&invalid, 100)
                .unwrap_err()
                .reason_code(),
            ReasonCode::InputInvalid
        );
    }
}

#[tokio::test]
async fn normalized_gitlab_source_failures_precede_every_action_lookup_and_hide_content() {
    let mut provider_config = config();
    provider_config.content.max_body_bytes = 8;
    let provider = GitlabProvider::new(
        provider_config,
        &agent_access_provider::test_support::TestHost::default().context(),
    )
    .expect("test provider");
    let sentinel = "SOURCE_SENTINEL_TOO_LONG";
    let cases = [
        (
            "issue.create",
            json!({ "project": "sip/service", "title": "x", "contentFormat": "markdown", "content": sentinel }),
        ),
        (
            "issue.update",
            json!({ "project": "sip/service", "iid": 7, "contentFormat": "markdown", "content": sentinel }),
        ),
        (
            "issue.note.add",
            json!({ "project": "sip/service", "iid": 7, "contentFormat": "markdown", "content": sentinel }),
        ),
        (
            "issue.note.update",
            json!({ "project": "sip/service", "iid": 7, "noteId": 701, "contentFormat": "markdown", "content": sentinel }),
        ),
        (
            "merge_request.create",
            json!({ "project": "sip/service", "sourceBranch": "feature", "targetBranch": "main", "title": "x", "contentFormat": "markdown", "content": sentinel }),
        ),
        (
            "merge_request.update",
            json!({ "project": "sip/service", "iid": 5, "contentFormat": "markdown", "content": sentinel }),
        ),
        (
            "merge_request.note.add",
            json!({ "project": "sip/service", "iid": 5, "contentFormat": "markdown", "content": sentinel }),
        ),
        (
            "merge_request.note.update",
            json!({ "project": "sip/service", "iid": 5, "noteId": 501, "contentFormat": "markdown", "content": sentinel }),
        ),
        (
            "merge_request.discussion.add",
            json!({ "project": "sip/service", "iid": 5, "contentFormat": "markdown", "content": sentinel }),
        ),
        (
            "merge_request.discussion.note.update",
            json!({ "project": "sip/service", "iid": 5, "discussionId": "d", "noteId": 900, "contentFormat": "markdown", "content": sentinel }),
        ),
    ];
    for (action, inputs) in cases {
        let error = provider
            .invoke(test_invocation(action, inputs))
            .await
            .unwrap_err();
        assert_eq!(error.reason_code(), ReasonCode::BodySizeDenied, "{action}");
        assert!(!error.message.contains(sentinel), "{action}");
    }

    let unsupported_sentinel = "UNSUPPORTED_SENTINEL";
    let error = provider
        .invoke(test_invocation(
            "issue.note.add",
            json!({
                "project": "sip/service",
                "iid": 7,
                "contentFormat": "html",
                "content": unsupported_sentinel
            }),
        ))
        .await
        .unwrap_err();
    assert_eq!(error.reason_code(), ReasonCode::BodyFormatUnsupported);
    assert!(!error.message.contains(unsupported_sentinel));

    let malformed_sentinel = "MALFORMED_SENTINEL";
    let error = provider
        .invoke(test_invocation(
            "issue.note.add",
            json!({
                "project": "sip/service",
                "iid": 7,
                "contentFormat": "markdown",
                "content": { "secret": malformed_sentinel }
            }),
        ))
        .await
        .unwrap_err();
    assert_eq!(error.reason_code(), ReasonCode::InputInvalid);
    assert!(!error.message.contains(malformed_sentinel));
}

#[test]
fn notes_and_discussions_require_authoritative_noteable_metadata() {
    let issue_note = note_from_value(json!({
        "id": 1,
        "body": "visible body",
        "author": { "id": 314, "username": "service-user" },
        "noteable_type": "Issue",
        "noteable_iid": 7
    }))
    .unwrap();
    assert_eq!(issue_note.author_user_id, Some(314));
    assert_eq!(issue_note.author_username.as_deref(), Some("service-user"));
    assert_eq!(
        serde_json::to_value(&issue_note).unwrap()["authorUserId"],
        314
    );
    assert!(ensure_note_target_issue(&issue_note, 7).is_ok());
    assert!(ensure_note_target_issue(&issue_note, 8).is_err());
    assert!(ensure_note_target_merge_request(&issue_note, 7).is_err());

    let merge_request_note = note_from_value(json!({
        "id": 2,
        "body": "visible body",
        "noteable_type": "MergeRequest",
        "noteable_iid": 7
    }))
    .unwrap();
    let discussion = GitlabDiscussion {
        id: "discussion-1".to_string(),
        individual_note: Some(false),
        notes: vec![merge_request_note],
    };
    assert!(ensure_discussion_target_merge_request(&discussion, 7).is_ok());
    let parsed_discussion =
        discussion_from_value(discussion_json("discussion-3", 4, "visible body", false)).unwrap();
    assert_eq!(parsed_discussion.notes[0].author_user_id, Some(314));

    let missing_metadata_note = note_from_value(json!({
        "id": 3,
        "body": "visible body"
    }))
    .unwrap();
    assert!(ensure_note_target_issue(&missing_metadata_note, 7).is_err());

    let empty_discussion = GitlabDiscussion {
        id: "discussion-2".to_string(),
        individual_note: None,
        notes: vec![],
    };
    assert!(ensure_discussion_target_merge_request(&empty_discussion, 7).is_err());
}

#[test]
fn note_mutation_validation_accepts_scoped_metadata_gaps_and_rejects_contradictions() {
    let project = GitlabProject {
        id: 42,
        path_with_namespace: "sip/service".to_string(),
        name: Some("service".to_string()),
        web_url: None,
        default_branch: None,
        visibility: None,
        archived: None,
    };
    let issue = GitlabIssue {
        id: Some(700),
        iid: 7,
        project_id: 42,
        title: None,
        description: None,
        state: None,
        created_at: None,
        updated_at: None,
        author: None,
        assignees: None,
        labels: None,
        milestone: None,
        web_url: None,
        project: None,
    };
    let merge_request = GitlabMergeRequest {
        id: Some(500),
        iid: 5,
        project_id: 42,
        title: None,
        description: None,
        state: None,
        source_branch: None,
        target_branch: None,
        sha: None,
        merge_status: None,
        detailed_merge_status: None,
        merge_commit_sha: None,
        squash_commit_sha: None,
        source_project_id: None,
        target_project_id: None,
        diff_refs: None,
        changes_count: None,
        user_notes_count: None,
        discussion_locked: None,
        blocking_discussions_resolved: None,
        has_conflicts: None,
        prepared_at: None,
        head_pipeline: None,
        created_at: None,
        updated_at: None,
        author: None,
        assignees: None,
        reviewers: None,
        labels: None,
        milestone: None,
        draft: None,
        web_url: None,
        project: None,
    };

    let issue_note = note_from_value(json!({
        "id": 701,
        "body": "preflight body",
        "noteable_type": "Issue",
        "project_id": 42,
        "noteable_id": 700
    }))
    .unwrap();
    assert!(ensure_issue_note_consistent(&project, &issue, &issue_note, 7, 701).is_ok());

    let discussion =
        discussion_from_value(discussion_json("discussion-1", 900, "body", true)).unwrap();
    assert!(
        ensure_merge_request_discussion_consistent(
            &project,
            &merge_request,
            &discussion,
            5,
            "discussion-1",
            Some(900),
            Some(true),
        )
        .is_ok()
    );

    let wrong_project =
        discussion_from_value(discussion_json("discussion-1", 900, "body", true)).unwrap();
    let mut wrong_project_note = wrong_project.clone();
    wrong_project_note.notes[0].project_id = Some(99);
    assert!(
        ensure_merge_request_discussion_consistent(
            &project,
            &merge_request,
            &wrong_project_note,
            5,
            "discussion-1",
            Some(900),
            None,
        )
        .is_err()
    );

    let mut wrong_noteable_id = discussion.clone();
    wrong_noteable_id.notes[0].noteable_id = Some(501);
    assert!(
        ensure_merge_request_discussion_consistent(
            &project,
            &merge_request,
            &wrong_noteable_id,
            5,
            "discussion-1",
            Some(900),
            None,
        )
        .is_err()
    );
    assert!(
        ensure_merge_request_discussion_consistent(
            &project,
            &merge_request,
            &discussion,
            5,
            "discussion-1",
            Some(901),
            None,
        )
        .is_err()
    );
    assert!(
        ensure_merge_request_discussion_consistent(
            &project,
            &merge_request,
            &discussion,
            5,
            "discussion-1",
            None,
            Some(false),
        )
        .is_err()
    );
}

#[test]
fn note_update_audit_records_body_shape_without_text() {
    let audit = request_body_audit_for_note_update(&GitlabNoteUpdateRequest {
        iid: 7,
        note_id: 701,
        body: "secret updated body".to_string(),
    });
    let audit_json = serde_json::to_string(&audit).unwrap();
    assert!(audit_json.contains("textByteCounts"));
    assert!(audit_json.contains("body"));
    assert!(!audit_json.contains("secret updated body"));
}

#[tokio::test]
async fn provider_issue_note_add_applies_configured_attribution_footer() {
    let server = MockServer::start().await;
    let mut config = config();
    config.api_base_url = format!("{}/api/v4", server.uri());
    config.allowed_upstream_hosts = vec![format!("{}/api/v4/**", server.uri())];
    let attribution = ProviderAttributionConfig::from_patterns(
        &gitlab_descriptor(&config),
        &[String::from("issue.note.add")],
    );
    let mut host = agent_access_provider::test_support::TestHost::default();
    host.attribution = attribution;
    let provider = GitlabProvider::new(config, &host.context()).unwrap();
    let broker_request_id = "550e8400-e29b-41d4-a716-446655440000";
    let attributed_body = format!(
        "note before attribution\n\n<!-- agent-access-attribution:start -->\n\n---\n\n_Added via Agent Access Broker. Request ID: {broker_request_id}_\n\n<!-- agent-access-attribution:end -->"
    );

    Mock::given(method("GET"))
        .and(path("/api/v4/projects/sip%2Fservice"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "id": 42,
            "path_with_namespace": "sip/service"
        })))
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/api/v4/projects/42/issues/7"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "id": 700,
            "iid": 7,
            "project_id": 42
        })))
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/api/v4/projects/42/issues/7/notes"))
        .and(body_json(json!({ "body": attributed_body })))
        .respond_with(ResponseTemplate::new(201).set_body_json(note_json(
            701,
            &attributed_body,
            "Issue",
            7,
        )))
        .expect(1)
        .mount(&server)
        .await;

    let result = provider
        .invoke(
            InvocationBuilder::new("gitlab", "issue.note.add")
                .inputs(json!({
                    "project": "sip/service",
                    "iid": 7,
                    "contentFormat": "markdown",
                    "content": "note before attribution"
                }))
                .correlation(crate::CorrelationContext::new(
                    "agent-request-id".to_string(),
                    broker_request_id.to_string(),
                ))
                .resources(repository_scopes_from_path("sip/service"))
                .credential(test_credential())
                .lookup_credential(test_credential())
                .build(),
        )
        .await
        .unwrap();

    let audit = result.audit.as_ref().unwrap();
    assert_eq!(audit["attribution"]["applied"], true);
    assert_eq!(audit["attribution"]["representation"], "markdown");
    assert_eq!(
        audit["gitlab"]["requestBody"]["textByteCounts"]["body"],
        attributed_body.len() as u64
    );
    assert!(!audit.to_string().contains("note before attribution"));
    assert_eq!(result.result["note"]["body"], attributed_body);
}

#[tokio::test]
async fn provider_issue_create_applies_attribution_to_supplied_description() {
    let server = MockServer::start().await;
    let mut config = config();
    config.api_base_url = format!("{}/api/v4", server.uri());
    config.allowed_upstream_hosts = vec![format!("{}/api/v4/**", server.uri())];
    let attribution = ProviderAttributionConfig::from_patterns(
        &gitlab_descriptor(&config),
        &[String::from("issue.create")],
    );
    let mut host = agent_access_provider::test_support::TestHost::default();
    host.attribution = attribution;
    let provider = GitlabProvider::new(config, &host.context()).unwrap();
    let broker_request_id = "550e8400-e29b-41d4-a716-446655440000";
    let attributed_description = format!(
        "description before attribution\n\n<!-- agent-access-attribution:start -->\n\n---\n\n_Added via Agent Access Broker. Request ID: {broker_request_id}_\n\n<!-- agent-access-attribution:end -->"
    );

    Mock::given(method("GET"))
        .and(path("/api/v4/projects/sip%2Fservice"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "id": 42,
            "path_with_namespace": "sip/service"
        })))
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/api/v4/projects/42/issues"))
        .and(body_json(json!({
            "title": "New issue",
            "description": attributed_description
        })))
        .respond_with(ResponseTemplate::new(201).set_body_json(json!({
            "id": 700,
            "iid": 7,
            "project_id": 42,
            "title": "New issue",
            "description": attributed_description
        })))
        .expect(1)
        .mount(&server)
        .await;

    let result = provider
        .invoke(
            InvocationBuilder::new("gitlab", "issue.create")
                .inputs(json!({
                    "project": "sip/service",
                    "title": "New issue",
                    "contentFormat": "markdown",
                    "content": "description before attribution"
                }))
                .correlation(crate::CorrelationContext::new(
                    "agent-request-id".to_string(),
                    broker_request_id.to_string(),
                ))
                .resources(repository_scopes_from_path("sip/service"))
                .credential(test_credential())
                .lookup_credential(test_credential())
                .build(),
        )
        .await
        .unwrap();

    let audit = result.audit.as_ref().unwrap();
    assert_eq!(audit["attribution"]["applied"], true);
    assert_eq!(audit["attribution"]["target"], "description");
    assert_eq!(
        audit["gitlab"]["requestBody"]["textByteCounts"]["description"],
        attributed_description.len() as u64
    );
    assert!(!audit.to_string().contains("description before attribution"));
    assert_eq!(
        result.result["issue"]["description"],
        attributed_description
    );
}

#[tokio::test]
async fn provider_issue_update_records_target_absent_when_description_is_omitted() {
    let server = MockServer::start().await;
    let mut config = config();
    config.api_base_url = format!("{}/api/v4", server.uri());
    config.allowed_upstream_hosts = vec![format!("{}/api/v4/**", server.uri())];
    let attribution = ProviderAttributionConfig::from_patterns(
        &gitlab_descriptor(&config),
        &[String::from("issue.update")],
    );
    let mut host = agent_access_provider::test_support::TestHost::default();
    host.attribution = attribution;
    let provider = GitlabProvider::new(config, &host.context()).unwrap();

    Mock::given(method("GET"))
        .and(path("/api/v4/projects/sip%2Fservice"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "id": 42,
            "path_with_namespace": "sip/service"
        })))
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/api/v4/projects/42/issues/7"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "id": 700,
            "iid": 7,
            "project_id": 42
        })))
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("PUT"))
        .and(path("/api/v4/projects/42/issues/7"))
        .and(body_json(json!({ "title": "New title" })))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "id": 700,
            "iid": 7,
            "project_id": 42,
            "title": "New title"
        })))
        .expect(1)
        .mount(&server)
        .await;

    let result = provider
        .invoke(
            InvocationBuilder::new("gitlab", "issue.update")
                .inputs(json!({
                    "project": "sip/service",
                    "iid": 7,
                    "title": "New title"
                }))
                .correlation(crate::CorrelationContext::new(
                    "agent-request-id".to_string(),
                    "550e8400-e29b-41d4-a716-446655440000".to_string(),
                ))
                .resources(repository_scopes_from_path("sip/service"))
                .credential(test_credential())
                .lookup_credential(test_credential())
                .build(),
        )
        .await
        .unwrap();

    let audit = result.audit.as_ref().unwrap();
    assert_eq!(audit["attribution"]["applied"], false);
    assert_eq!(audit["attribution"]["skipReason"], "target_absent");
    assert!(
        audit["gitlab"]["requestBody"]["jsonFields"]
            .as_array()
            .unwrap()
            .contains(&json!("title"))
    );
    assert!(audit["gitlab"]["requestBody"]["textByteCounts"]["description"].is_null());
}

#[tokio::test]
async fn provider_issue_note_add_reports_attribution_when_footer_exceeds_body_cap() {
    let mut config = config();
    config.content.max_body_bytes = 16;
    let attribution = ProviderAttributionConfig::from_patterns(
        &gitlab_descriptor(&config),
        &[String::from("issue.note.add")],
    );
    let mut host = agent_access_provider::test_support::TestHost::default();
    host.attribution = attribution;
    let provider = GitlabProvider::new(config, &host.context()).unwrap();

    let error = provider
        .invoke(
            InvocationBuilder::new("gitlab", "issue.note.add")
                .inputs(json!({
                    "project": "sip/service",
                    "iid": 7,
                    "contentFormat": "markdown",
                    "content": "short"
                }))
                .correlation(crate::CorrelationContext::new(
                    "agent-request-id".to_string(),
                    "550e8400-e29b-41d4-a716-446655440000".to_string(),
                ))
                .resources(repository_scopes_from_path("sip/service"))
                .credential(test_credential())
                .lookup_credential(test_credential())
                .build(),
        )
        .await
        .unwrap_err();

    assert_eq!(error.reason_code(), ReasonCode::BodySizeDenied);
    assert!(error.message.contains("after broker attribution was added"));
}

#[tokio::test]
async fn http_backend_note_and_discussion_mutations_use_exact_routes_and_bodies() {
    let server = MockServer::start().await;
    let backend = http_backend(&server);
    let credential = test_credential();

    Mock::given(method("GET"))
        .and(path("/api/v4/projects/42/issues/7/notes/701"))
        .respond_with(ResponseTemplate::new(200).set_body_json(note_json(
            701,
            "issue note",
            "Issue",
            7,
        )))
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("PUT"))
        .and(path("/api/v4/projects/42/issues/7/notes/701"))
        .and(body_json(json!({ "body": "updated issue note" })))
        .respond_with(ResponseTemplate::new(200).set_body_json(note_json(
            701,
            "updated issue note",
            "Issue",
            7,
        )))
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("DELETE"))
        .and(path("/api/v4/projects/42/issues/7/notes/701"))
        .and(body_string(""))
        .respond_with(ResponseTemplate::new(204))
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/api/v4/projects/42/merge_requests/5/notes/501"))
        .respond_with(ResponseTemplate::new(200).set_body_json(note_json(
            501,
            "merge request note",
            "MergeRequest",
            5,
        )))
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("PUT"))
        .and(path("/api/v4/projects/42/merge_requests/5/notes/501"))
        .and(body_json(json!({ "body": "updated merge request note" })))
        .respond_with(ResponseTemplate::new(200).set_body_json(note_json(
            501,
            "updated merge request note",
            "MergeRequest",
            5,
        )))
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("DELETE"))
        .and(path("/api/v4/projects/42/merge_requests/5/notes/501"))
        .and(body_string(""))
        .respond_with(ResponseTemplate::new(204))
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path(
            "/api/v4/projects/42/merge_requests/5/discussions/discussion-1",
        ))
        .respond_with(ResponseTemplate::new(200).set_body_json(discussion_json(
            "discussion-1",
            900,
            "discussion note",
            false,
        )))
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("PUT"))
        .and(path(
            "/api/v4/projects/42/merge_requests/5/discussions/discussion-1/notes/900",
        ))
        .and(body_json(json!({ "body": "updated discussion note" })))
        .respond_with(ResponseTemplate::new(200).set_body_json(note_json(
            900,
            "updated discussion note",
            "MergeRequest",
            5,
        )))
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("DELETE"))
        .and(path(
            "/api/v4/projects/42/merge_requests/5/discussions/discussion-1/notes/900",
        ))
        .and(body_string(""))
        .respond_with(ResponseTemplate::new(204))
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("PUT"))
        .and(path(
            "/api/v4/projects/42/merge_requests/5/discussions/discussion-1",
        ))
        .and(body_json(json!({ "resolved": true })))
        .respond_with(ResponseTemplate::new(200).set_body_json(discussion_json(
            "discussion-1",
            900,
            "discussion note",
            true,
        )))
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("PUT"))
        .and(path(
            "/api/v4/projects/42/merge_requests/5/discussions/discussion-1",
        ))
        .and(body_json(json!({ "resolved": false })))
        .respond_with(ResponseTemplate::new(200).set_body_json(discussion_json(
            "discussion-1",
            900,
            "discussion note",
            false,
        )))
        .expect(1)
        .mount(&server)
        .await;

    backend
        .issue_note(
            42,
            GitlabNoteDeleteRequest {
                iid: 7,
                note_id: 701,
            },
            &credential,
        )
        .await
        .unwrap();
    backend
        .update_issue_note(
            42,
            GitlabNoteUpdateRequest {
                iid: 7,
                note_id: 701,
                body: "updated issue note".to_string(),
            },
            &credential,
        )
        .await
        .unwrap();
    backend
        .delete_issue_note(
            42,
            GitlabNoteDeleteRequest {
                iid: 7,
                note_id: 701,
            },
            &credential,
        )
        .await
        .unwrap();
    backend
        .merge_request_note(
            42,
            GitlabNoteDeleteRequest {
                iid: 5,
                note_id: 501,
            },
            &credential,
        )
        .await
        .unwrap();
    backend
        .update_merge_request_note(
            42,
            GitlabNoteUpdateRequest {
                iid: 5,
                note_id: 501,
                body: "updated merge request note".to_string(),
            },
            &credential,
        )
        .await
        .unwrap();
    backend
        .delete_merge_request_note(
            42,
            GitlabNoteDeleteRequest {
                iid: 5,
                note_id: 501,
            },
            &credential,
        )
        .await
        .unwrap();
    backend
        .merge_request_discussion(42, 5, "discussion-1", &credential)
        .await
        .unwrap();
    backend
        .update_merge_request_discussion_note(
            42,
            GitlabDiscussionNoteUpdateRequest {
                iid: 5,
                discussion_id: "discussion-1".to_string(),
                note_id: 900,
                body: "updated discussion note".to_string(),
            },
            &credential,
        )
        .await
        .unwrap();
    backend
        .delete_merge_request_discussion_note(
            42,
            GitlabDiscussionNoteDeleteRequest {
                iid: 5,
                discussion_id: "discussion-1".to_string(),
                note_id: 900,
            },
            &credential,
        )
        .await
        .unwrap();
    backend
        .set_merge_request_discussion_resolved(
            42,
            GitlabDiscussionStateChangeRequest {
                iid: 5,
                discussion_id: "discussion-1".to_string(),
                change: GitlabDiscussionStateChange::Resolve,
            },
            &credential,
        )
        .await
        .unwrap();
    backend
        .set_merge_request_discussion_resolved(
            42,
            GitlabDiscussionStateChangeRequest {
                iid: 5,
                discussion_id: "discussion-1".to_string(),
                change: GitlabDiscussionStateChange::Reopen,
            },
            &credential,
        )
        .await
        .unwrap();
}

#[tokio::test]
async fn http_backend_note_deletes_reject_success_statuses_other_than_204() {
    let server = MockServer::start().await;
    let backend = http_backend(&server);
    let credential = test_credential();
    Mock::given(method("DELETE"))
        .and(path("/api/v4/projects/42/issues/7/notes/701"))
        .respond_with(ResponseTemplate::new(200))
        .expect(1)
        .mount(&server)
        .await;
    assert!(
        backend
            .delete_issue_note(
                42,
                GitlabNoteDeleteRequest {
                    iid: 7,
                    note_id: 701,
                },
                &credential,
            )
            .await
            .is_err()
    );
}

#[tokio::test]
async fn http_backend_note_deletes_reject_204_responses_with_bodies() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let uri = format!("http://{}", listener.local_addr().unwrap());
    let server = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut request = [0_u8; 4096];
        let _ = stream.read(&mut request).await.unwrap();
        stream
            .write_all(
                b"HTTP/1.1 204 No Content\r\nContent-Length: 4\r\nConnection: close\r\n\r\nbody",
            )
            .await
            .unwrap();
    });

    let backend = http_backend_for_base(&uri);
    let credential = test_credential();
    let error = backend
        .delete_issue_note(
            42,
            GitlabNoteDeleteRequest {
                iid: 7,
                note_id: 701,
            },
            &credential,
        )
        .await
        .unwrap_err();
    server.await.unwrap();
    assert!(matches!(
        error,
        GitlabBackendError::Protocol(message)
            if message.contains("no-content response included a body")
    ));
}

#[tokio::test]
async fn http_backend_pages_beyond_one_hundred_issues_and_notes() {
    let server = MockServer::start().await;
    let first_issues = (1_u64..=100)
        .map(|iid| {
            json!({
                "id": 1_000 + iid,
                "iid": iid,
                "project_id": 42,
                "updated_at": "2026-08-23T12:00:00Z"
            })
        })
        .collect::<Vec<_>>();
    let first_notes = (1_u64..=100)
        .map(|id| note_json(id, "note", "Issue", 7))
        .collect::<Vec<_>>();
    let issues_next_link = format!(
        "<{}/api/v4/projects/42/issues?page=2&per_page=100>; rel=\"next\"",
        server.uri()
    );
    let notes_next_link = format!(
        "<{}/api/v4/projects/42/issues/7/notes?page=2&per_page=100>; rel=\"next\"",
        server.uri()
    );

    Mock::given(method("GET"))
        .and(path("/api/v4/projects/42/issues"))
        .and(query_param("per_page", "100"))
        .and(query_param_is_missing("page"))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("x-next-page", "2")
                .insert_header("link", issues_next_link.as_str())
                .set_body_json(first_issues),
        )
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/api/v4/projects/42/issues"))
        .and(query_param("per_page", "100"))
        .and(query_param("page", "2"))
        .respond_with(ResponseTemplate::new(200).set_body_json(vec![json!({
            "id": 1_101,
            "iid": 101,
            "project_id": 42,
            "updated_at": "2026-08-23T12:00:00Z"
        })]))
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/api/v4/projects/42/issues/7/notes"))
        .and(query_param("per_page", "100"))
        .and(query_param_is_missing("page"))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("x-next-page", "2")
                .insert_header("link", notes_next_link.as_str())
                .set_body_json(first_notes),
        )
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/api/v4/projects/42/issues/7/notes"))
        .and(query_param("per_page", "100"))
        .and(query_param("page", "2"))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(vec![note_json(101, "note", "Issue", 7)]),
        )
        .expect(1)
        .mount(&server)
        .await;

    let backend = http_backend(&server);
    let credential = test_credential();
    let issue_request = |page| GitlabIssueSearchRequest {
        state: None,
        labels: Vec::new(),
        milestone: None,
        assignee: None,
        author: None,
        search: None,
        created_after: None,
        updated_after: None,
        sort: None,
        order_by: None,
        max_results: 100,
        page,
    };
    let first = backend
        .issues(42, issue_request(1), &credential)
        .await
        .unwrap();
    assert_eq!(first.value.items.len(), 100);
    assert_eq!(first.value.next_page, Some(2));
    let second = backend
        .issues(42, issue_request(2), &credential)
        .await
        .unwrap();
    assert_eq!(second.value.items.len(), 1);
    assert_eq!(second.value.next_page, None);

    let note_request = |page| GitlabNoteListRequest {
        iid: 7,
        max_results: 100,
        sort: None,
        order_by: None,
        projection: GitlabCollectionProjection::Full,
        page_token: None,
        page,
    };
    let first = backend
        .issue_notes(42, note_request(1), &credential)
        .await
        .unwrap();
    assert_eq!(first.value.items.len(), 100);
    assert_eq!(first.value.next_page, Some(2));
    let second = backend
        .issue_notes(42, note_request(2), &credential)
        .await
        .unwrap();
    assert_eq!(second.value.items.len(), 1);
    assert_eq!(second.value.next_page, None);
}

#[tokio::test]
async fn http_backend_exposes_only_allowlisted_structured_mutation_validation() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/api/v4/projects/42/issues"))
        .respond_with(ResponseTemplate::new(422).set_body_json(json!({
            "message": {
                "title": ["contains <b>invalid</b> characters\n"],
                "project": ["hidden scope detail"],
                "labels": ["hidden non-allowlisted detail"]
            },
            "error": "hidden raw detail"
        })))
        .mount(&server)
        .await;
    let backend = http_backend(&server);

    let backend_error = backend
        .create_issue(
            42,
            GitlabIssueCreateRequest {
                title: "invalid".to_string(),
                description: None,
                labels: Vec::new(),
                milestone: None,
                assignee_ids: Vec::new(),
                confidential: None,
            },
            &test_credential(),
        )
        .await
        .unwrap_err();

    assert_eq!(
        backend_error,
        GitlabBackendError::Validation {
            status: 422,
            message: "title: contains invalid characters".to_string(),
        }
    );
    let public = gitlab_backend_error(backend_error);
    assert_eq!(public.reason_code(), ReasonCode::InputInvalid);
    assert_eq!(public.upstream_status, Some(422));
    assert!(!public.message.contains("scope detail"));
    assert!(!public.message.contains("raw detail"));
}

#[tokio::test]
async fn http_backend_rejects_wrong_type_current_user_identity() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/api/v4/user"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "id": "sentinel-private-user-id",
            "username": "service-user"
        })))
        .expect(1)
        .mount(&server)
        .await;
    let backend = http_backend(&server);

    let error = backend.current_user(&test_credential()).await.unwrap_err();
    assert!(matches!(error, GitlabBackendError::Protocol(_)));
    let public = gitlab_backend_error(error);
    assert_eq!(public.reason_code(), ReasonCode::UpstreamProtocolFailed);
    assert_eq!(public.message, "GitLab response protocol error");
    assert!(!public.message.contains("sentinel-private-user-id"));
}

#[tokio::test]
async fn http_backend_uses_exact_review_read_routes_and_pagination() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/api/v4/projects/42/merge_requests/5/reviewers"))
        .and(query_param("per_page", "10"))
        .and(query_param("page", "2"))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("x-next-page", "3")
                .set_body_json(json!([{
                    "user": { "id": 17, "username": "reviewer" },
                    "state": "reviewed",
                    "created_at": "2026-08-29T12:30:00Z"
                }])),
        )
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/api/v4/projects/42/merge_requests/5/discussions"))
        .and(query_param("per_page", "10"))
        .and(query_param("page", "2"))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("x-next-page", "3")
                .set_body_json(json!([discussion_json("discussion-1", 901, "body", false)])),
        )
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/api/v4/projects/42/merge_requests/5/diffs"))
        .and(query_param("per_page", "10"))
        .and(query_param("page", "2"))
        .and(query_param("unidiff", "true"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!([{
            "old_path": "src/lib.rs",
            "new_path": "src/lib.rs",
            "a_mode": "100644",
            "b_mode": "100644",
            "diff": "@@ -1 +1 @@",
            "new_file": false,
            "renamed_file": false,
            "deleted_file": false,
            "collapsed": false,
            "too_large": false
        }])))
        .expect(1)
        .mount(&server)
        .await;

    let backend = http_backend(&server);
    let credential = test_credential();
    let request = GitlabMergeRequestListRequest {
        iid: 5,
        max_results: 10,
        page_token: None,
        page: 2,
        unidiff: None,
    };
    let reviewers = backend
        .merge_request_reviewers(42, request.clone(), &credential)
        .await
        .unwrap();
    assert_eq!(reviewers.value.next_page, Some(3));
    assert_eq!(reviewers.value.items[0].state, "reviewed");
    let discussions = backend
        .merge_request_discussions_page(
            42,
            GitlabDiscussionListRequest {
                iid: 5,
                max_results: 10,
                projection: GitlabCollectionProjection::Full,
                page_token: None,
                page: 2,
            },
            &credential,
        )
        .await
        .unwrap();
    assert_eq!(discussions.value.next_page, Some(3));
    let diffs = backend
        .merge_request_diffs(
            42,
            GitlabMergeRequestListRequest {
                unidiff: Some(true),
                ..request
            },
            &credential,
        )
        .await
        .unwrap();
    assert_eq!(diffs.value.items[0].old_mode.as_deref(), Some("100644"));
}

#[tokio::test]
async fn http_backend_views_exact_diff_version_and_streams_raw_diff() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/api/v4/projects/42/merge_requests/5/versions/8"))
        .and(query_param("unidiff", "true"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "id": 8,
            "merge_request_id": 500,
            "head_commit_sha": "0123456789abcdef0123456789abcdef01234567",
            "base_commit_sha": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "start_commit_sha": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
            "state": "collected",
            "real_size": "1",
            "patch_id_sha": "cccccccccccccccccccccccccccccccccccccccc",
            "commits": [],
            "diffs": []
        })))
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/api/v4/projects/42/merge_requests/5/raw_diffs"))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("content-type", "text/plain")
                .set_body_bytes(b"diff --git a/a b/a\n"),
        )
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/api/v4/projects/42/merge_requests/6/raw_diffs"))
        .respond_with(ResponseTemplate::new(200).set_body_bytes(b"oversize"))
        .expect(1)
        .mount(&server)
        .await;

    let backend = http_backend(&server);
    let credential = test_credential();
    let version = backend
        .merge_request_diff_version(
            42,
            GitlabMergeRequestObjectRequest {
                iid: 5,
                object_id: 8,
                unidiff: Some(true),
            },
            &credential,
        )
        .await
        .unwrap();
    assert_eq!(version.value.id, 8);
    assert!(version.value.commits.is_empty());
    assert!(version.value.diffs.is_empty());
    let raw = backend
        .merge_request_raw_diffs(42, 5, 1024, &credential)
        .await
        .unwrap();
    assert_eq!(raw.value.size, Some(19));
    assert_eq!(raw.value.content_type, "text/plain");
    let oversized = backend
        .merge_request_raw_diffs(42, 6, 4, &credential)
        .await
        .unwrap();
    assert_eq!(oversized.value.size, Some(8));
    let error = validate_gitlab_raw_diff_download_size(oversized.value.size, 4).unwrap_err();
    assert_eq!(error.reason_code(), ReasonCode::AttachmentSizeDenied);
}

#[tokio::test]
async fn http_backend_does_not_expose_scalar_or_lookup_validation_messages() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/api/v4/projects/42/issues"))
        .respond_with(ResponseTemplate::new(400).set_body_json(json!({
            "message": "ambiguous mutation detail"
        })))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/api/v4/projects/42/issues/7"))
        .respond_with(ResponseTemplate::new(400).set_body_json(json!({
            "message": {"title": ["lookup scope detail"]}
        })))
        .mount(&server)
        .await;
    let backend = http_backend(&server);

    let mutation_error = backend
        .create_issue(
            42,
            GitlabIssueCreateRequest {
                title: "invalid".to_string(),
                description: None,
                labels: Vec::new(),
                milestone: None,
                assignee_ids: Vec::new(),
                confidential: None,
            },
            &test_credential(),
        )
        .await
        .unwrap_err();
    assert_eq!(mutation_error, GitlabBackendError::HttpStatus(400));

    let lookup_error = backend.issue(42, 7, &test_credential()).await.unwrap_err();
    assert_eq!(lookup_error, GitlabBackendError::HttpStatus(400));
    for error in [mutation_error, lookup_error] {
        let public = gitlab_backend_error(error);
        assert_eq!(public.reason_code(), ReasonCode::UpstreamFailed);
        assert!(!public.message.contains("detail"));
    }
}

#[test]
fn positioned_writes_allow_structured_line_code_validation_only() {
    for action in [
        "merge_request.discussion.inline.add",
        "merge_request.draft_note.add",
    ] {
        let fields = gitlab_validation_fields(action).unwrap();
        assert!(fields.contains(&"line_code"));
        let message = gitlab_validation_message(
            &json!({
                "message": {
                    "line_code": ["can't be blank", "must be a valid line code"],
                    "untrusted": ["secret"]
                }
            }),
            fields,
        )
        .unwrap();
        let public = gitlab_backend_error(GitlabBackendError::Validation {
            status: 400,
            message,
        });
        assert_eq!(public.reason_code(), ReasonCode::InputInvalid);
        assert!(public.message.contains("line_code"));
        assert!(!public.message.contains("secret"));

        assert_eq!(
            gitlab_validation_message(
                &json!({"message": "Note {:line_code=>[untrusted detail]}"}),
                fields,
            ),
            None
        );
    }
}

#[tokio::test]
async fn http_backend_does_not_read_authorization_failure_bodies_as_validation() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/api/v4/projects/42/issues"))
        .respond_with(ResponseTemplate::new(403).set_body_json(json!({
            "message": {"title": ["permission and scope detail"]}
        })))
        .mount(&server)
        .await;
    let backend = http_backend(&server);

    let backend_error = backend
        .create_issue(
            42,
            GitlabIssueCreateRequest {
                title: "valid".to_string(),
                description: None,
                labels: Vec::new(),
                milestone: None,
                assignee_ids: Vec::new(),
                confidential: None,
            },
            &test_credential(),
        )
        .await
        .unwrap_err();
    assert_eq!(backend_error, GitlabBackendError::Forbidden);
    let public = gitlab_backend_error(backend_error);
    assert_eq!(public.reason_code(), ReasonCode::UpstreamForbidden);
    assert!(!public.message.contains("scope detail"));
}

#[tokio::test]
async fn http_backend_inline_and_reply_writes_use_exact_routes_and_bodies() {
    let server = MockServer::start().await;
    let backend = http_backend(&server);
    let credential = test_credential();
    Mock::given(method("POST"))
        .and(path("/api/v4/projects/42/merge_requests/5/discussions"))
        .and(body_json(json!({
            "body": "inline review",
            "position": positioned_write_body()
        })))
        .respond_with(ResponseTemplate::new(201).set_body_json(discussion_json(
            "discussion-inline",
            901,
            "inline review",
            false,
        )))
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path(
            "/api/v4/projects/42/merge_requests/5/discussions/discussion%2Fencoded/notes",
        ))
        .and(body_json(json!({ "body": "reply review" })))
        .respond_with(ResponseTemplate::new(201).set_body_json(note_json(
            902,
            "reply review",
            "MergeRequest",
            5,
        )))
        .expect(1)
        .mount(&server)
        .await;

    let discussion = backend
        .create_merge_request_inline_discussion(
            42,
            GitlabPositionedDiscussionCreateRequest {
                iid: 5,
                body: "inline review".to_string(),
                position: positioned_write_fixture(),
            },
            &credential,
        )
        .await
        .unwrap();
    assert_eq!(discussion.status, 201);
    assert_eq!(discussion.value.id, "discussion-inline");
    let reply = backend
        .create_merge_request_discussion_note(
            42,
            GitlabDiscussionReplyRequest {
                iid: 5,
                discussion_id: "discussion/encoded".to_string(),
                body: "reply review".to_string(),
            },
            &credential,
        )
        .await
        .unwrap();
    assert_eq!(reply.value.id, 902);
}

#[tokio::test]
async fn http_backend_draft_view_and_list_accept_gitlab_default_empty_positions() {
    let server = MockServer::start().await;
    let backend = http_backend(&server);
    let credential = test_credential();
    let mut damaged = draft_note_json(11963, "edited draft");
    damaged["commit_id"] = json!("048da6d085c5ad8c8c7f28f7799c9d9afb0d319e");
    damaged["line_code"] = json!("src_operator_output_109");
    damaged["position"] = json!({
        "base_sha": null,
        "start_sha": null,
        "head_sha": null,
        "old_path": null,
        "new_path": null,
        "position_type": "text",
        "old_line": null,
        "new_line": null,
        "line_range": null
    });
    Mock::given(method("GET"))
        .and(path("/api/v4/projects/42/merge_requests/5/draft_notes"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!([damaged.clone()])))
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path(
            "/api/v4/projects/42/merge_requests/5/draft_notes/11963",
        ))
        .respond_with(ResponseTemplate::new(200).set_body_json(damaged))
        .expect(1)
        .mount(&server)
        .await;

    let listed = backend
        .merge_request_draft_notes(
            42,
            GitlabDraftNoteListRequest {
                iid: 5,
                max_results: 20,
                projection: GitlabCollectionProjection::Full,
                page_token: None,
                page: 1,
            },
            &credential,
        )
        .await
        .unwrap();
    let listed = &listed.value.items[0];
    assert_eq!(listed.id, 11963);
    assert_eq!(listed.body.as_deref(), Some("edited draft"));
    assert_eq!(
        listed.commit_id.as_deref(),
        Some("048da6d085c5ad8c8c7f28f7799c9d9afb0d319e")
    );
    assert!(
        serde_json::to_value(listed)
            .unwrap()
            .get("lineCode")
            .is_none()
    );
    assert!(listed.position.is_none());

    let viewed = backend
        .merge_request_draft_note(
            42,
            GitlabDraftNoteObjectRequest {
                iid: 5,
                draft_note_id: 11963,
            },
            &credential,
        )
        .await
        .unwrap()
        .value;
    assert_eq!(viewed, listed.clone());
}

#[tokio::test]
async fn http_backend_draft_crud_and_publication_use_exact_routes_queries_and_bodies() {
    let server = MockServer::start().await;
    let backend = http_backend(&server);
    let credential = test_credential();
    Mock::given(method("GET"))
        .and(path("/api/v4/projects/42/merge_requests/5/draft_notes"))
        .and(query_param_is_missing("per_page"))
        .and(query_param_is_missing("page"))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(json!([draft_note_json(41, "listed draft")])),
        )
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/api/v4/projects/42/merge_requests/5/draft_notes/41"))
        .respond_with(ResponseTemplate::new(200).set_body_json(draft_note_json(41, "viewed draft")))
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/api/v4/projects/42/merge_requests/5/draft_notes"))
        .and(body_json(json!({
            "note": "created draft",
            "position": positioned_write_body()
        })))
        .respond_with(
            ResponseTemplate::new(201).set_body_json(draft_note_json(42, "created draft")),
        )
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("PUT"))
        .and(path("/api/v4/projects/42/merge_requests/5/draft_notes/42"))
        .and(body_json(json!({
            "note": "updated draft",
            "position": positioned_write_body()
        })))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(draft_note_json(42, "updated draft")),
        )
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("DELETE"))
        .and(path("/api/v4/projects/42/merge_requests/5/draft_notes/42"))
        .and(body_string(""))
        .respond_with(ResponseTemplate::new(204))
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("PUT"))
        .and(path(
            "/api/v4/projects/42/merge_requests/5/draft_notes/43/publish",
        ))
        .and(body_json(json!({})))
        .respond_with(ResponseTemplate::new(204))
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path(
            "/api/v4/projects/42/merge_requests/5/draft_notes/bulk_publish",
        ))
        .and(body_json(json!({})))
        .respond_with(ResponseTemplate::new(204))
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path(
            "/api/v4/projects/42/merge_requests/5/draft_notes/bulk_publish",
        ))
        .and(body_json(json!({ "reviewer_state": "requested_changes" })))
        .respond_with(ResponseTemplate::new(204))
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/api/v4/projects/42/merge_requests/5/notes"))
        .and(body_json(
            json!({ "body": "review summary", "internal": true }),
        ))
        .respond_with(ResponseTemplate::new(201).set_body_json(note_json(
            903,
            "review summary",
            "MergeRequest",
            5,
        )))
        .expect(1)
        .mount(&server)
        .await;

    let listed = backend
        .merge_request_draft_notes(
            42,
            GitlabDraftNoteListRequest {
                iid: 5,
                max_results: 17,
                projection: GitlabCollectionProjection::Full,
                page_token: None,
                page: 2,
            },
            &credential,
        )
        .await
        .unwrap();
    assert_eq!(listed.value.items[0].id, 41);
    assert_eq!(
        backend
            .merge_request_draft_note(
                42,
                GitlabDraftNoteObjectRequest {
                    iid: 5,
                    draft_note_id: 41
                },
                &credential
            )
            .await
            .unwrap()
            .value
            .id,
        41
    );
    assert_eq!(
        backend
            .create_merge_request_draft_note(
                42,
                GitlabDraftNoteCreateRequest {
                    iid: 5,
                    body: "created draft".to_string(),
                    position: Some(positioned_write_fixture()),
                    in_reply_to_discussion_id: None,
                    resolve_discussion: None,
                },
                &credential
            )
            .await
            .unwrap()
            .value
            .id,
        42
    );
    backend
        .update_merge_request_draft_note(
            42,
            GitlabDraftNoteUpdateRequest {
                iid: 5,
                draft_note_id: 42,
                body: "updated draft".to_string(),
                position: Some(positioned_write_fixture()),
            },
            &credential,
        )
        .await
        .unwrap();
    backend
        .delete_merge_request_draft_note(
            42,
            GitlabDraftNoteObjectRequest {
                iid: 5,
                draft_note_id: 42,
            },
            &credential,
        )
        .await
        .unwrap();
    backend
        .publish_merge_request_draft_note(
            42,
            GitlabDraftNoteObjectRequest {
                iid: 5,
                draft_note_id: 43,
            },
            &credential,
        )
        .await
        .unwrap();
    backend
        .bulk_publish_merge_request_draft_notes(
            42,
            GitlabDraftBulkPublishRequest {
                iid: 5,
                reviewer_state: None,
            },
            &credential,
        )
        .await
        .unwrap();
    backend
        .bulk_publish_merge_request_draft_notes(
            42,
            GitlabDraftBulkPublishRequest {
                iid: 5,
                reviewer_state: Some("requested_changes".to_string()),
            },
            &credential,
        )
        .await
        .unwrap();
    assert_eq!(
        backend
            .create_merge_request_review_summary(
                42,
                GitlabReviewSummaryNoteRequest {
                    iid: 5,
                    body: "review summary".to_string(),
                    internal: Some(true)
                },
                &credential
            )
            .await
            .unwrap()
            .value
            .id,
        903
    );
}

#[tokio::test]
async fn http_backend_review_preflight_reads_use_exact_routes_and_reviewer_query() {
    let server = MockServer::start().await;
    let backend = http_backend(&server);
    let credential = test_credential();
    Mock::given(method("GET"))
        .and(path("/api/v4/version"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({ "version": "19.2.0-ee" })))
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/api/v4/projects/42/merge_requests/5/approvals"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "approvals_required": 1,
            "approvals_left": 1,
            "approved": false,
            "approved_by": []
        })))
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/api/v4/projects/42/merge_requests/5/reviewers"))
        .and(query_param("per_page", "23"))
        .and(query_param("page", "3"))
        .and(query_param("unidiff", "false"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!([{
            "user": { "id": 314, "username": "reviewer" },
            "state": "reviewed",
            "created_at": "2026-08-29T00:00:00Z"
        }])))
        .expect(1)
        .mount(&server)
        .await;

    assert_eq!(
        backend
            .gitlab_version(&credential)
            .await
            .unwrap()
            .value
            .version,
        "19.2.0-ee"
    );
    assert_eq!(
        backend
            .merge_request_approval_summary(42, 5, &credential)
            .await
            .unwrap()
            .value
            .approved,
        Some(false)
    );
    let reviewers = backend
        .merge_request_reviewers(
            42,
            GitlabMergeRequestListRequest {
                iid: 5,
                max_results: 23,
                page_token: None,
                page: 3,
                unidiff: Some(false),
            },
            &credential,
        )
        .await
        .unwrap();
    assert_eq!(reviewers.value.items[0].state, "reviewed");
}

#[tokio::test]
async fn http_backend_suggestion_apply_uses_action_mode_for_exact_routes_and_bodies() {
    let server = MockServer::start().await;
    let backend = http_backend(&server);
    let credential = test_credential();
    let suggestion = |id| {
        json!({
            "id": id,
            "from_line": 1,
            "to_line": 1,
            "applicable": true,
            "applied": false,
            "from_content": "old",
            "to_content": "new"
        })
    };

    Mock::given(method("PUT"))
        .and(path("/api/v4/suggestions/41/apply"))
        .and(body_json(json!({ "commit_message": "single" })))
        .respond_with(ResponseTemplate::new(200).set_body_json(suggestion(41)))
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("PUT"))
        .and(path("/api/v4/suggestions/batch_apply"))
        .and(body_json(json!({ "ids": [42] })))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!([suggestion(42)])))
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("PUT"))
        .and(path("/api/v4/suggestions/batch_apply"))
        .and(body_json(json!({
            "ids": [43, 44],
            "commit_message": "batch"
        })))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(json!([suggestion(43), suggestion(44)])),
        )
        .expect(1)
        .mount(&server)
        .await;

    let cases = [
        GitlabSuggestionApplyRequest {
            suggestion_ids: vec![41],
            commit_message: Some("single".to_string()),
            batch: false,
        },
        GitlabSuggestionApplyRequest {
            suggestion_ids: vec![42],
            commit_message: None,
            batch: true,
        },
        GitlabSuggestionApplyRequest {
            suggestion_ids: vec![43, 44],
            commit_message: Some("batch".to_string()),
            batch: true,
        },
    ];
    for request in cases {
        let expected = request.suggestion_ids.clone();
        let response = backend
            .apply_suggestions(request, &credential)
            .await
            .unwrap();
        assert_eq!(
            response
                .value
                .into_iter()
                .map(|suggestion| suggestion.id)
                .collect::<Vec<_>>(),
            expected
        );
    }
}

#[tokio::test]
async fn http_backend_approval_routes_preserve_pagination_tier_errors_and_exact_bodies() {
    let server = MockServer::start().await;
    let backend = http_backend(&server);
    let credential = test_credential();
    let summary = json!({
        "approvals_required": 1,
        "approvals_left": 0,
        "approved": true,
        "approved_by": [{ "user": { "id": 9, "username": "reviewer" } }],
        "user_has_approved": true
    });
    let rule = json!({
        "id": 71,
        "name": "Code owners",
        "approvals_required": 1,
        "approved_by": [],
        "eligible_approvers": [],
        "users": [],
        "groups": []
    });

    Mock::given(method("GET"))
        .and(path("/api/v4/projects/42/merge_requests/5/approval_rules"))
        .and(query_param("per_page", "23"))
        .and(query_param("page", "2"))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("x-next-page", "3")
                .set_body_json(json!([rule])),
        )
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/api/v4/projects/42/merge_requests/5/approval_state"))
        .respond_with(ResponseTemplate::new(403))
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/api/v4/projects/42/merge_requests/5/approve"))
        .and(body_json(json!({
            "sha": "1111111111111111111111111111111111111111"
        })))
        .respond_with(ResponseTemplate::new(201).set_body_json(summary.clone()))
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/api/v4/projects/42/merge_requests/5/unapprove"))
        .and(body_json(json!({})))
        .respond_with(ResponseTemplate::new(201).set_body_json(summary))
        .expect(1)
        .mount(&server)
        .await;

    let rules = backend
        .merge_request_approval_rules(
            42,
            GitlabApprovalRuleListRequest {
                iid: 5,
                max_results: 23,
                page_token: None,
                page: 2,
            },
            &credential,
        )
        .await
        .unwrap();
    assert_eq!(rules.value.items[0].id, 71);
    assert_eq!(rules.value.next_page, Some(3));
    assert_eq!(
        backend
            .merge_request_approval_state(42, 5, &credential)
            .await,
        Err(GitlabBackendError::Forbidden)
    );
    backend
        .set_merge_request_approval(
            42,
            GitlabApprovalMutationRequest {
                iid: 5,
                head_sha: Some("1111111111111111111111111111111111111111".to_string()),
            },
            &credential,
        )
        .await
        .unwrap();
    backend
        .set_merge_request_approval(
            42,
            GitlabApprovalMutationRequest {
                iid: 5,
                head_sha: None,
            },
            &credential,
        )
        .await
        .unwrap();
}

#[test]
fn positioned_inputs_accept_strict_multiline_file_and_integer_image_variants() {
    let multiline = parse_position_input(Some(&json!({
        "positionType": "text",
        "oldPath": "src/lib.rs",
        "newPath": "src/lib.rs",
        "lineRange": {
            "start": { "oldLine": 39, "newLine": 40 },
            "end": { "newLine": 44 }
        }
    })))
    .unwrap();
    assert!(multiline.line_range.is_some());
    let file = parse_position_input(Some(&json!({
        "positionType": "file",
        "oldPath": "old/name.rs",
        "newPath": "new/name.rs"
    })))
    .unwrap();
    assert_eq!(file.position_type, "file");
    let image = parse_position_input(Some(&json!({
        "positionType": "image",
        "oldPath": "diagram.png",
        "newPath": "diagram.png",
        "width": 800,
        "height": 600,
        "x": 0,
        "y": 17
    })))
    .unwrap();
    assert_eq!(image.x, Some(0));
    assert_eq!(image.y, Some(17));
    assert!(
        parse_position_input(Some(&json!({
            "positionType": "image",
            "oldPath": "diagram.png",
            "newPath": "diagram.png",
            "width": 800,
            "height": 600,
            "x": -1,
            "y": 17
        })))
        .is_err()
    );
    assert!(
        parse_position_input(Some(&json!({
            "positionType": "image",
            "oldPath": "diagram.png",
            "newPath": "diagram.png",
            "width": 800,
            "height": 600,
            "x": 1.5,
            "y": 17
        })))
        .is_err()
    );
}

#[test]
fn multiline_patch_resolution_builds_native_anchor_types_and_line_codes() {
    let resolved = resolve_multiline_position(
        "@@ -39,5 +40,6 @@\n context\n-removed\n+added\n context two\n context three\n+tail\n",
        &GitlabLineRangeInput {
            start: GitlabLineCoordinateInput {
                old_line: Some(39),
                new_line: Some(40),
            },
            end: GitlabLineCoordinateInput {
                old_line: None,
                new_line: Some(41),
            },
        },
        "src/lib.rs",
    )
    .unwrap();
    assert_eq!(resolved.start.line_type.as_deref(), Some("old"));
    assert_eq!(resolved.end.line_type.as_deref(), Some("new"));
    assert_eq!(resolved.end.new_line, Some(41));
    assert_eq!(resolved.end.old_line, None);
    assert_eq!(
        resolved.start.line_code,
        format!("{}_39_40", sha1_hex(b"src/lib.rs"))
    );
    assert_eq!(
        resolved.end.line_code,
        format!("{}_41_41", sha1_hex(b"src/lib.rs"))
    );
}

#[test]
fn public_multiline_renamed_file_capture_matches_literal_gitlab_positions() {
    let capture: Value = serde_json::from_str(include_str!(
        "../tests/fixtures/gitlab/multiline-renamed-file-public-capture.json"
    ))
    .unwrap();
    let diff = capture["diff"]["diff"].as_str().unwrap();
    let range_input = GitlabLineRangeInput {
        start: GitlabLineCoordinateInput {
            old_line: None,
            new_line: Some(13),
        },
        end: GitlabLineCoordinateInput {
            old_line: None,
            new_line: Some(14),
        },
    };
    let resolved = resolve_multiline_position(diff, &range_input, "test.ts").unwrap();
    assert_eq!(
        serde_json::to_value(&resolved).unwrap(),
        json!({
            "start": {
                "lineCode": "5f7b6aabace88f74752a2b616628e855914e4bc7_15_13",
                "type": "new",
                "newLine": 13
            },
            "end": {
                "lineCode": "5f7b6aabace88f74752a2b616628e855914e4bc7_15_14",
                "type": "new",
                "newLine": 14
            }
        })
    );
    let refs = &capture["mergeRequest"]["diff_refs"];
    let expected = GitlabDiffPosition {
        position_type: "text".to_string(),
        base_sha: Some(refs["base_sha"].as_str().unwrap().to_string()),
        start_sha: refs["start_sha"].as_str().unwrap().to_string(),
        head_sha: refs["head_sha"].as_str().unwrap().to_string(),
        old_path: "test.js".to_string(),
        new_path: "test.ts".to_string(),
        old_line: None,
        new_line: Some(14),
        line_range: Some(resolved),
        width: None,
        height: None,
        x: None,
        y: None,
    };
    assert_eq!(
        diff_position_body(&expected),
        capture["derivedRequestPosition"]
    );
    let observed = optional_diff_position(&json!({
        "position": capture["responsePosition"].clone()
    }))
    .unwrap()
    .unwrap();
    let input = GitlabPositionInput {
        position_type: "text".to_string(),
        old_path: "test.js".to_string(),
        new_path: "test.ts".to_string(),
        old_line: None,
        new_line: None,
        line_range: Some(range_input),
        width: None,
        height: None,
        x: None,
        y: None,
    };
    assert!(position_matches_input(Some(&observed), &expected, &input));
}

#[test]
fn draft_note_parser_accepts_unpositioned_variants_but_rejects_partial_positions() {
    for position in [
        Value::Null,
        json!({}),
        json!({ "position_type": null }),
        json!({ "position_type": "text" }),
        json!({
            "base_sha": null,
            "start_sha": null,
            "head_sha": null,
            "old_path": null,
            "new_path": null,
            "position_type": "text",
            "old_line": null,
            "new_line": null,
            "line_range": null,
            "ignore_whitespace_change": false,
            "future_nullable_attribute": null
        }),
    ] {
        let mut unpositioned = draft_note_json(11963, "edited draft");
        unpositioned["position"] = position;
        let parsed = draft_note_from_value(unpositioned).unwrap();
        assert_eq!(parsed.id, 11963);
        assert_eq!(parsed.body.as_deref(), Some("edited draft"));
        assert!(parsed.position.is_none());
    }

    let mut omitted = draft_note_json(11963, "edited draft");
    omitted.as_object_mut().unwrap().remove("position");
    assert!(draft_note_from_value(omitted).unwrap().position.is_none());

    for position in [
        json!({ "position_type": "text", "head_sha": "partial" }),
        json!({ "position_type": "image" }),
        json!({ "position_type": "text", "line_range": {} }),
        json!({ "position_type": "text", "unexpected": "meaningful" }),
    ] {
        let mut malformed = draft_note_json(11963, "edited draft");
        malformed["position"] = position;
        let error = draft_note_from_value(malformed).unwrap_err();
        assert_eq!(error, GitlabBackendError::DraftPositionShapeInvalid);
        let public = gitlab_backend_error(error);
        assert_eq!(public.reason_code(), ReasonCode::UpstreamProtocolFailed);
        assert_eq!(public.message, "GitLab response protocol error");
        assert_eq!(
            public.internal_diagnostic_code,
            Some(InternalDiagnosticCode::DraftPositionShapeInvalid.as_str())
        );
    }
}

#[test]
fn gitlab_like_patch_line_codes_use_running_counters_not_nullable_display_lines() {
    let patch = "@@ -31,4 +34,4 @@ fn review() {\n context_before();\n-unsafe_call();\n+safe_call();\n context_after();\n";
    let lines = parse_unified_patch_lines(patch).unwrap();
    let hash = sha1_hex(b"src/review.rs");
    let points = lines
        .iter()
        .map(|line| patch_line_range_point(line, &hash))
        .collect::<Vec<_>>();
    assert_eq!(points[0].line_code, format!("{hash}_31_34"));
    assert_eq!(
        (points[0].old_line, points[0].new_line),
        (Some(31), Some(34))
    );
    assert_eq!(points[1].line_code, format!("{hash}_32_35"));
    assert_eq!((points[1].old_line, points[1].new_line), (Some(32), None));
    assert_eq!(points[2].line_code, format!("{hash}_33_35"));
    assert_eq!((points[2].old_line, points[2].new_line), (None, Some(35)));
    assert_eq!(points[3].line_code, format!("{hash}_33_36"));
    assert_eq!(
        (points[3].old_line, points[3].new_line),
        (Some(33), Some(36))
    );
}

#[test]
fn multiline_patch_resolution_rejects_reversed_and_missing_coordinates() {
    let patch = "@@ -1,2 +1,2 @@\n one\n two\n";
    let reversed = GitlabLineRangeInput {
        start: GitlabLineCoordinateInput {
            old_line: Some(2),
            new_line: Some(2),
        },
        end: GitlabLineCoordinateInput {
            old_line: Some(1),
            new_line: Some(1),
        },
    };
    assert!(resolve_multiline_position(patch, &reversed, "a.rs").is_err());
    let missing = GitlabLineRangeInput {
        start: GitlabLineCoordinateInput {
            old_line: Some(1),
            new_line: Some(1),
        },
        end: GitlabLineCoordinateInput {
            old_line: None,
            new_line: Some(99),
        },
    };
    assert!(resolve_multiline_position(patch, &missing, "a.rs").is_err());
    let malformed =
        resolve_multiline_position("@@ malformed @@\n+line\n", &missing, "a.rs").unwrap_err();
    assert_eq!(malformed.reason_code(), ReasonCode::InputInvalid);
    assert_eq!(
        malformed.result.as_deref(),
        Some(&json!({ "inputCategory": "patch_unavailable" }))
    );
}

#[test]
fn diff_version_terminal_missing_patch_states_are_permanent_input_failures() {
    let merge_request = merge_request_from_value(json!({
        "id": 500,
        "iid": 5,
        "project_id": 42,
        "diff_refs": {
            "base_sha": "1111111111111111111111111111111111111111",
            "start_sha": "2222222222222222222222222222222222222222",
            "head_sha": "3333333333333333333333333333333333333333"
        }
    }))
    .unwrap();
    let version = |state: &str| GitlabDiffVersionSummary {
        id: 9,
        merge_request_id: 500,
        head_commit_sha: "3333333333333333333333333333333333333333".to_string(),
        base_commit_sha: "1111111111111111111111111111111111111111".to_string(),
        start_commit_sha: "2222222222222222222222222222222222222222".to_string(),
        created_at: None,
        state: Some(state.to_string()),
        real_size: None,
        patch_id_sha: None,
    };
    assert!(ensure_current_diff_version(&version("collected"), &merge_request).is_ok());
    for state in ["overflow", "without_files"] {
        let error = ensure_current_diff_version(&version(state), &merge_request).unwrap_err();
        assert_eq!(error.reason_code(), ReasonCode::InputInvalid);
        assert_eq!(
            error.result.as_deref(),
            Some(&json!({ "inputCategory": "patch_unavailable" }))
        );
    }
    let transient =
        ensure_current_diff_version(&version("collecting"), &merge_request).unwrap_err();
    assert_eq!(transient.reason_code(), ReasonCode::VersionConflict);
}

#[test]
fn current_user_identity_and_review_context_are_closed_and_validated() {
    let actor = GitlabUser {
        id: 314,
        username: "reviewer".to_string(),
        name: Some("Review User".to_string()),
    };
    let service = test_invocation("merge_request.draft_note.list", json!({}));
    let (actor_id, context) = gitlab_review_context(&service, &actor).unwrap();
    assert_eq!(actor_id, 314);
    assert_eq!(
        context,
        json!({
            "credentialMode": "service",
            "credentialBinding": "shared",
            "upstreamActor": { "id": 314, "username": "reviewer" }
        })
    );
    let mut per_user = service.clone();
    per_user = InvocationBuilder::from(per_user)
        .credential_mode(CredentialMode::PerUser)
        .build();
    assert_eq!(
        gitlab_review_context(&per_user, &actor).unwrap().1,
        json!({
            "credentialMode": "per_user",
            "credentialBinding": "principal",
            "upstreamActor": { "id": 314, "username": "reviewer" }
        })
    );
    let error = required_gitlab_actor_id(&GitlabUser {
        id: 0,
        username: "invalid".to_string(),
        name: None,
    })
    .unwrap_err();
    assert_eq!(error.reason_code(), ReasonCode::UpstreamProtocolFailed);
    for username in ["", "   "] {
        let error = gitlab_review_context(
            &service,
            &GitlabUser {
                id: 314,
                username: username.to_string(),
                name: None,
            },
        )
        .unwrap_err();
        assert_eq!(error.reason_code(), ReasonCode::UpstreamProtocolFailed);
    }
    assert_eq!(
        acting_reviewer_not_assigned_error().reason_code(),
        ReasonCode::VersionConflict
    );
}

#[test]
fn mutation_http_5xx_is_ambiguous_but_http_4xx_remains_an_ordinary_failure() {
    let error = mutation_backend_error(
        GitlabBackendError::HttpStatus(503),
        MutationVerificationStage::MutationResponse,
        MutationSafeLocators::new()
            .with_discussion_id("discussion-9")
            .with_note_id(901),
    );
    assert_eq!(error.reason_code(), ReasonCode::MutationVerificationFailed);
    assert_eq!(
        error.result.as_deref(),
        Some(&json!({
            "mutationStatus": "applied_unverified",
            "retrySafe": false,
            "verificationStage": "mutation_response",
            "safeLocators": { "discussionId": "discussion-9", "noteId": 901 }
        }))
    );
    let ordinary = mutation_backend_error(
        GitlabBackendError::HttpStatus(422),
        MutationVerificationStage::MutationResponse,
        MutationSafeLocators::new().with_note_id(901),
    );
    assert_eq!(ordinary.reason_code(), ReasonCode::UpstreamFailed);
    assert!(ordinary.result.is_none());
}

#[test]
fn mutation_throttling_is_rejected_but_throttled_readback_is_unverified() {
    let wait = UpstreamRetryAfter::after_seconds(60);
    let rejected = mutation_backend_error(
        GitlabBackendError::RateLimited(Some(wait)),
        MutationVerificationStage::MutationResponse,
        MutationSafeLocators::new().with_webhook_ids(vec![5]),
    );
    assert_eq!(rejected.decision(), Decision::Error);
    assert_eq!(rejected.reason_code(), ReasonCode::UpstreamRateLimited);
    assert_eq!(
        rejected.message,
        format!(
            "gitlab is rate limiting requests. Retry after 60s (at {}).",
            wait.retry_at()
        )
    );
    assert_eq!(
        rejected.result.as_deref(),
        Some(&json!({
            "limitScope": "upstream",
            "service": "gitlab",
            "retryAfterSeconds": 60,
            "retryAt": wait.retry_at(),
        }))
    );

    // A throttled readback after an applied mutation is a verification
    // failure like any other: no rate-limit code and no wait that would
    // invite repeating the write.
    for retry_after in [Some(wait), None] {
        let unverified = mutation_backend_error(
            GitlabBackendError::RateLimited(retry_after),
            MutationVerificationStage::MutationReadback,
            MutationSafeLocators::new().with_webhook_ids(vec![5]),
        );
        assert_eq!(unverified.decision(), Decision::Error);
        assert_eq!(
            unverified.reason_code(),
            ReasonCode::MutationVerificationFailed
        );
        assert_eq!(
            unverified.message,
            "upstream mutation could not be fully verified"
        );
        assert_eq!(
            unverified.result.as_deref(),
            Some(&json!({
                "mutationStatus": "applied_unverified",
                "retrySafe": false,
                "verificationStage": "mutation_readback",
                "safeLocators": { "webhookIds": [5] },
            }))
        );
    }
    assert_eq!(
        gitlab_review_submit_version_backend_error(GitlabBackendError::RateLimited(None))
            .reason_code(),
        ReasonCode::UpstreamRateLimited
    );
}

#[tokio::test]
async fn http_backend_maps_upstream_429_to_upstream_rate_limited() {
    let date = UpstreamRetryAfter::after_seconds(300)
        .at()
        .format("%a, %d %b %Y %H:%M:%S GMT")
        .to_string();
    for (retry_after, expected) in [
        (Some("17".to_string()), Some(17..=17)),
        (Some(date), Some(298..=301)),
        (Some("172800".to_string()), Some(86_400..=86_400)),
        (None, None),
    ] {
        let server = MockServer::start().await;
        let mut template = ResponseTemplate::new(429)
            .set_body_json(json!({"message": "Retry later secret detail"}));
        if let Some(value) = &retry_after {
            template = template.insert_header("Retry-After", value.as_str());
        }
        Mock::given(method("GET"))
            .and(path("/api/v4/projects/42/issues/7"))
            .respond_with(template)
            .expect(1)
            .mount(&server)
            .await;
        let backend_error = http_backend(&server)
            .issue(42, 7, &test_credential())
            .await
            .unwrap_err();
        let GitlabBackendError::RateLimited(wait) = &backend_error else {
            panic!("expected a rate limit, got {backend_error:?}");
        };
        assert_eq!(wait.is_some(), expected.is_some(), "{retry_after:?}");
        let error = gitlab_backend_error(backend_error.clone());
        assert_eq!(error.reason_code(), ReasonCode::UpstreamRateLimited);
        assert!(!error.message.contains("secret"));
        let result = error.result.as_deref().unwrap();
        assert_eq!(result["limitScope"], "upstream");
        assert_eq!(result["service"], "gitlab");
        assert!(result.get("retrySafe").is_none());
        match expected {
            Some(range) => {
                let seconds = result["retryAfterSeconds"].as_u64().unwrap();
                assert!(range.contains(&seconds), "{retry_after:?}: {seconds}");
                assert_eq!(result["retryAt"], wait.unwrap().retry_at());
            }
            None => {
                assert!(result.get("retryAfterSeconds").is_none());
                assert_eq!(
                    error.message,
                    "gitlab is rate limiting requests. Retry later."
                );
            }
        }
    }
}

#[test]
fn mutation_readback_translation_preserves_only_the_closed_internal_diagnostic() {
    for (stage, expected_stage) in [
        (
            MutationVerificationStage::MutationReadback,
            "mutation_readback",
        ),
        (
            MutationVerificationStage::DraftAbsenceReadback,
            "draft_absence_readback",
        ),
        (
            MutationVerificationStage::BulkPublishReadback,
            "bulk_publish_readback",
        ),
    ] {
        let error = mutation_readback_error(
            gitlab_backend_error(GitlabBackendError::DraftPositionShapeInvalid),
            stage,
            MutationSafeLocators::new().with_draft_note_ids(vec![11963]),
        );
        assert_eq!(error.reason_code(), ReasonCode::MutationVerificationFailed);
        assert_eq!(
            error.internal_diagnostic_code,
            Some(InternalDiagnosticCode::DraftPositionShapeInvalid.as_str())
        );
        assert_eq!(
            error.result.as_deref().unwrap()["verificationStage"],
            expected_stage
        );
        let public = serde_json::to_string(&error.result).unwrap();
        assert!(!public.contains("draft_position_shape_invalid"));
    }

    let ordinary = mutation_readback_error(
        gitlab_backend_error(GitlabBackendError::Protocol(
            "sentinel-private-protocol-detail".to_string(),
        )),
        MutationVerificationStage::DraftAbsenceReadback,
        MutationSafeLocators::new(),
    );
    assert!(ordinary.internal_diagnostic_code.is_none());
    assert!(
        !ordinary
            .message
            .contains("sentinel-private-protocol-detail")
    );
}

#[test]
fn rich_content_quick_action_guard_is_deterministic_and_preserves_paths_and_prose() {
    for denied in [
        "/approve",
        "  /assign @reviewer",
        "\t/request_changes because this is unsafe",
        "before\n/label ~security\nafter",
        "```suggestion\nsafe_call();\n```\n/approve",
        "```invalid`info\n/approve\n```",
    ] {
        assert!(reject_gitlab_quick_actions(denied).is_err(), "{denied}");
    }
    for allowed in [
        "Please run /approve only after checking",
        "https://gitlab.example.com/group/project",
        "/usr/bin/env bash",
        "/docs/review.md",
        "`/approve` inline code",
        "```suggestion\n/approve\n```",
        "   ~~~markdown\n  /assign @reviewer\n   ~~~",
        "````\n```\n/request_changes\n```\n````",
        "- ```suggestion\n  /approve\n  ```",
        "> ```suggestion\n> /approve\n> ```",
    ] {
        assert!(reject_gitlab_quick_actions(allowed).is_ok(), "{allowed}");
    }
    for action in [
        "issue.create",
        "issue.update",
        "issue.note.add",
        "issue.note.update",
        "merge_request.create",
        "merge_request.update",
        "merge_request.note.add",
        "merge_request.note.update",
        "merge_request.discussion.add",
        "merge_request.discussion.note.update",
        "merge_request.discussion.inline.add",
        "merge_request.discussion.note.add",
        "merge_request.draft_note.add",
        "merge_request.draft_note.update",
        "merge_request.draft_note.publish_all",
        "merge_request.review.submit",
    ] {
        assert!(
            prepare_gitlab_content(action, &json!("markdown"), &json!("/approve"), 100, false,)
                .is_err(),
            "{action}"
        );
    }
    assert_eq!(
        prepare_gitlab_content(
            "merge_request.note.add",
            &json!("plain_text"),
            &json!("/approve"),
            100,
            false,
        )
        .unwrap(),
        "\\/approve"
    );
}

#[test]
fn note_body_readback_matches_gitlab_carriage_return_and_trailing_space_normalization() {
    assert!(gitlab_note_body_matches(
        Some("first line\nsecond line"),
        "first line\r\nsecond line\r\n"
    ));
    assert!(gitlab_note_body_matches(
        Some("review body"),
        "review body \t\r\n"
    ));
    assert!(gitlab_note_body_matches(
        Some("first line\nsecond line"),
        "first\r line\r\nsecond line"
    ));
    assert!(!gitlab_note_body_matches(
        Some("first line\nsecond line"),
        "first line\nchanged line\n"
    ));
    assert!(!gitlab_note_body_matches(None, "review body\n"));
}

#[test]
fn published_note_position_matching_ignores_only_multiline_anchor_serialization() {
    let mut expected = positioned_write_fixture();
    expected.old_line = Some(31);
    expected.new_line = Some(36);
    expected.line_range = Some(GitlabLineRange {
        start: GitlabLineRangePoint {
            line_code: "old-anchor".to_string(),
            line_type: Some("old".to_string()),
            old_line: Some(31),
            new_line: Some(34),
        },
        end: GitlabLineRangePoint {
            line_code: "new-anchor".to_string(),
            line_type: Some("new".to_string()),
            old_line: Some(33),
            new_line: Some(36),
        },
    });
    let mut observed = expected.clone();
    let range = observed.line_range.as_mut().unwrap();
    range.start.line_code = "different-anchor".to_string();
    range.start.line_type = None;
    range.end.line_code = "another-anchor".to_string();
    range.end.line_type = Some("old".to_string());
    assert!(semantic_gitlab_position_matches(
        Some(&observed),
        Some(&expected)
    ));
    observed.line_range.as_mut().unwrap().end.new_line = Some(37);
    assert!(!semantic_gitlab_position_matches(
        Some(&observed),
        Some(&expected)
    ));
    assert!(semantic_gitlab_position_matches(None, None));
    assert!(!semantic_gitlab_position_matches(Some(&expected), None));
}

#[test]
fn publication_snapshots_dedupe_identities_and_reject_cross_discussion_note_ids() {
    let project = test_project();
    let merge_request = merge_request_from_value(json!({
        "id": 500,
        "iid": 5,
        "project_id": 42
    }))
    .unwrap();
    let discussion =
        discussion_from_value(discussion_json("discussion-a", 901, "body", false)).unwrap();
    let snapshot = publication_snapshot_from_discussions(
        &project,
        &merge_request,
        5,
        vec![discussion.clone(), discussion],
    )
    .unwrap();
    assert_eq!(snapshot.notes.len(), 1);
    let contradictory =
        discussion_from_value(discussion_json("discussion-b", 901, "other body", false)).unwrap();
    assert!(
        publication_snapshot_from_discussions(
            &project,
            &merge_request,
            5,
            vec![
                discussion_from_value(discussion_json("discussion-a", 901, "body", false,))
                    .unwrap(),
                contradictory,
            ],
        )
        .is_err()
    );
}

#[test]
fn published_note_candidate_selection_requires_one_strict_new_match() {
    let project = test_project();
    let merge_request = merge_request_from_value(json!({
        "id": 500,
        "iid": 5,
        "project_id": 42
    }))
    .unwrap();
    let mut snapshot = publication_snapshot_from_discussions(
        &project,
        &merge_request,
        5,
        vec![
            discussion_from_value(discussion_json(
                "discussion-a",
                901,
                "published body",
                false,
            ))
            .unwrap(),
        ],
    )
    .unwrap();
    snapshot.notes.values_mut().for_each(|note| {
        note.system = Some(false);
    });
    let identity = PublishedNoteIdentity {
        discussion_id: "discussion-a".to_string(),
        note_id: 901,
    };
    assert_eq!(
        select_published_note_candidate(
            &snapshot.notes,
            &BTreeSet::new(),
            None,
            314,
            "published body",
            None,
            true,
        ),
        Some(identity.clone())
    );
    assert!(
        select_published_note_candidate(
            &snapshot.notes,
            &BTreeSet::from([identity.clone()]),
            None,
            314,
            "published body",
            None,
            true,
        )
        .is_none()
    );
    assert!(
        select_published_note_candidate(
            &snapshot.notes,
            &BTreeSet::new(),
            Some("different-discussion"),
            314,
            "published body",
            None,
            true,
        )
        .is_none()
    );
    assert!(
        select_published_note_candidate(
            &snapshot.notes,
            &BTreeSet::new(),
            None,
            999,
            "published body",
            None,
            true,
        )
        .is_none()
    );
    let mut ambiguous = snapshot.notes.clone();
    ambiguous.insert(
        PublishedNoteIdentity {
            discussion_id: "discussion-b".to_string(),
            note_id: 902,
        },
        snapshot.notes.get(&identity).unwrap().clone(),
    );
    assert!(
        select_published_note_candidate(
            &ambiguous,
            &BTreeSet::new(),
            None,
            314,
            "published body",
            None,
            true,
        )
        .is_none()
    );
}

#[test]
fn published_reply_candidate_does_not_require_position_echo() {
    let project = test_project();
    let merge_request = merge_request_from_value(json!({
        "id": 500,
        "iid": 5,
        "project_id": 42
    }))
    .unwrap();
    let mut snapshot = publication_snapshot_from_discussions(
        &project,
        &merge_request,
        5,
        vec![
            discussion_from_value(discussion_json("discussion-a", 901, "reply body", false))
                .unwrap(),
        ],
    )
    .unwrap();
    snapshot.notes.values_mut().for_each(|note| {
        note.system = Some(false);
        note.position = None;
    });
    let expected_position = positioned_write_fixture();
    assert_eq!(
        select_published_note_candidate(
            &snapshot.notes,
            &BTreeSet::new(),
            Some("discussion-a"),
            314,
            "reply body",
            Some(&expected_position),
            false,
        ),
        Some(PublishedNoteIdentity {
            discussion_id: "discussion-a".to_string(),
            note_id: 901,
        })
    );
    assert!(
        select_published_note_candidate(
            &snapshot.notes,
            &BTreeSet::new(),
            None,
            314,
            "reply body",
            Some(&expected_position),
            true,
        )
        .is_none()
    );
}

#[test]
fn draft_page_token_and_integer_image_schemas_are_bounded_and_numeric() {
    let draft_schema = draft_note_list_schema(50);
    assert_eq!(
        draft_schema["properties"]["pageToken"]["maxLength"],
        GITLAB_PAGE_TOKEN_MAX_BYTES
    );
    assert_eq!(draft_schema["properties"]["pageToken"]["minLength"], 1);
    let position = position_schema();
    let image = position["oneOf"]
        .as_array()
        .unwrap()
        .iter()
        .find(|variant| variant["properties"]["positionType"]["const"] == "image")
        .unwrap();
    assert_eq!(image["properties"]["x"]["type"], "integer");
    assert_eq!(image["properties"]["y"]["type"], "integer");
    let input = parse_position_input(Some(&json!({
        "positionType": "image",
        "oldPath": "diagram.png",
        "newPath": "diagram.png",
        "width": 800,
        "height": 600,
        "x": 12,
        "y": 24
    })))
    .unwrap();
    let expected = GitlabDiffPosition {
        position_type: input.position_type.clone(),
        base_sha: Some("1111111111111111111111111111111111111111".to_string()),
        start_sha: "2222222222222222222222222222222222222222".to_string(),
        head_sha: "3333333333333333333333333333333333333333".to_string(),
        old_path: input.old_path.clone(),
        new_path: input.new_path.clone(),
        old_line: None,
        new_line: None,
        line_range: None,
        width: input.width,
        height: input.height,
        x: input.x,
        y: input.y,
    };
    let body = diff_position_body(&expected);
    assert_eq!(body["x"], 12);
    assert_eq!(body["y"], 24);
    assert!(position_matches_input(Some(&expected), &expected, &input));
    let mut changed = expected.clone();
    changed.x = Some(13);
    assert!(!position_matches_input(Some(&changed), &expected, &input));
}

#[test]
fn review_attribution_footer_stays_outside_suggestion_fence_and_dedupes() {
    let actions = [
        "merge_request.discussion.inline.add",
        "merge_request.discussion.note.add",
        "merge_request.draft_note.add",
        "merge_request.draft_note.publish_all",
        "merge_request.review.submit",
    ]
    .map(str::to_string);
    let mut provider = GitlabProvider::with_backend(
        config(),
        Arc::new(http_backend_for_base("http://127.0.0.1:9")),
    );
    provider.attribution =
        ProviderAttributionConfig::from_patterns(&gitlab_descriptor(&provider.config), &actions);
    for action in &actions {
        assert!(
            provider.attribution.capability(action).is_some(),
            "{action}"
        );
        let request = test_invocation(action, json!({ "project": "sip/service", "iid": 5 }));
        let mut body = if action == "merge_request.discussion.inline.add" {
            "Review suggestion:\n```suggestion\nsafe_call();\n```".to_string()
        } else {
            "Review body".to_string()
        };
        let first = provider
            .apply_markdown_attribution(action, &mut body, &request)
            .unwrap();
        assert_eq!(first["applied"], true);
        assert_eq!(first["deduped"], false);
        if action == "merge_request.discussion.inline.add" {
            assert!(
                body.rfind("```").unwrap() < body.find("agent-access-attribution:start").unwrap()
            );
        }
        let second = provider
            .apply_markdown_attribution(action, &mut body, &request)
            .unwrap();
        assert_eq!(second["deduped"], true);
        assert_eq!(body.matches("agent-access-attribution:start").count(), 1);
    }
}

#[test]
fn gitlab_review_submit_version_guard_handles_editions_and_prereleases() {
    assert_eq!(sha1_hex(b"abc"), "a9993e364706816aba3e25717850c26c9cd0d89d");
    assert!(require_gitlab_review_submit_version("19.2.0-ee").is_ok());
    assert!(require_gitlab_review_submit_version("v19.3.0-ce").is_ok());
    assert!(require_gitlab_review_submit_version("19.2.0-pre").is_err());
    assert!(require_gitlab_review_submit_version("19.1.9").is_err());
    assert!(require_gitlab_review_submit_version("19.2").is_err());
}

#[test]
fn gitlab_review_submit_unreadable_version_is_always_a_protocol_failure() {
    for error in [
        GitlabBackendError::Unauthorized,
        GitlabBackendError::Forbidden,
        GitlabBackendError::NotFound,
        GitlabBackendError::HttpStatus(500),
        GitlabBackendError::Transport("network detail".to_string()),
        GitlabBackendError::Timeout,
        GitlabBackendError::ResponseTooLarge,
        GitlabBackendError::Protocol("parse detail".to_string()),
    ] {
        let public = gitlab_review_submit_version_backend_error(error);
        assert_eq!(public.reason_code(), ReasonCode::UpstreamProtocolFailed);
        assert_eq!(public.message, "GitLab version discovery failed");
    }
}

#[test]
fn draft_target_and_publication_parsers_reject_mixed_or_orphan_fields() {
    assert!(
        parse_draft_note_add_inputs(
            &json!({
                "project": "group/repo", "iid": 7,
                "content": "draft", "contentFormat": "markdown",
                "position": { "positionType": "file", "oldPath": "a", "newPath": "a" }
            }),
            1024
        )
        .is_err()
    );
    assert!(parse_draft_note_add_inputs(&json!({
        "project": "group/repo", "iid": 7,
        "content": "draft", "contentFormat": "markdown",
        "inReplyToDiscussionId": "abc", "expectedHeadSha": "1111111111111111111111111111111111111111",
        "position": { "positionType": "file", "oldPath": "a", "newPath": "a" }
    }), 1024).is_err());
    assert!(
        parse_draft_publication_inputs(
            &json!({
                "project": "group/repo", "iid": 7, "internal": true
            }),
            1024,
            false
        )
        .is_err()
    );
}

#[test]
fn suggestion_apply_parser_enforces_bounded_unique_scoped_locators() {
    let sha = "1111111111111111111111111111111111111111";
    let single = parse_suggestion_apply_inputs(
        &json!({
            "project": "group/repo", "iid": 7, "expectedHeadSha": sha,
            "discussionId": "d1", "noteId": 2, "suggestionId": 3,
            "commitMessage": "Apply %{suggestions_count} suggestion"
        }),
        false,
        1024,
    )
    .unwrap();
    assert_eq!(single.locators[0].suggestion_id, 3);
    let same_id_distinct_scope = parse_suggestion_apply_inputs(
        &json!({
            "project": "group/repo", "iid": 7, "expectedHeadSha": sha,
            "suggestions": [
                { "discussionId": "d1", "noteId": 2, "suggestionId": 3 },
                { "discussionId": "d2", "noteId": 4, "suggestionId": 3 }
            ]
        }),
        true,
        1024,
    )
    .unwrap();
    assert_eq!(same_id_distinct_scope.locators.len(), 2);
    assert!(
        parse_suggestion_apply_inputs(
            &json!({
                "project": "group/repo", "iid": 7, "expectedHeadSha": sha,
                "suggestions": [
                    { "discussionId": "d1", "noteId": 2, "suggestionId": 3 },
                    { "discussionId": "d1", "noteId": 2, "suggestionId": 3 }
                ]
            }),
            true,
            1024,
        )
        .is_err()
    );
    let too_many = (0..=GITLAB_MAX_SUGGESTIONS_PER_APPLY)
        .map(|id| json!({ "discussionId": format!("d{id}"), "noteId": id + 1, "suggestionId": id + 1 }))
        .collect::<Vec<_>>();
    assert!(
        parse_suggestion_apply_inputs(
            &json!({
                "project": "group/repo", "iid": 7, "expectedHeadSha": sha,
                "suggestions": too_many
            }),
            true,
            1024,
        )
        .is_err()
    );
}

#[test]
fn approval_models_preserve_actor_and_rule_metadata() {
    let summary = approval_summary_from_value(json!({
        "approvals_required": 2,
        "approvals_left": 1,
        "approved": false,
        "user_has_approved": true,
        "user_can_approve": false,
        "approved_by": [{ "user": { "id": 9, "username": "reviewer" } }]
    }))
    .unwrap();
    assert_eq!(summary.user_has_approved, Some(true));
    assert_eq!(summary.user_can_approve, Some(false));
    assert!(actor_has_approved(&summary, 9).unwrap());

    let state = approval_state_from_value(json!({
        "approval_rules_overwritten": true,
        "rules": [{
            "id": 5, "name": "Code owners", "rule_type": "code_owner",
            "approvals_required": 1, "approved": false,
            "code_owner": true, "section": "Backend",
            "source_rule": { "approvals_required": 2 },
            "eligible_approvers": [], "approved_by": [], "users": [], "groups": []
        }]
    }))
    .unwrap();
    assert_eq!(state.approval_rules_overwritten, Some(true));
    assert_eq!(state.rules[0].section.as_deref(), Some("Backend"));
    assert_eq!(
        state.rules[0]
            .source_rule
            .as_ref()
            .unwrap()
            .approvals_required,
        2
    );
}

#[test]
fn project_metadata_requires_canonical_repository_identity() {
    for invalid in [
        "",
        "42",
        "repo",
        "private/",
        "/private/repo",
        " private/repo",
        "private/repo ",
        "private//repo",
        "private/../repo",
        "private/repo?other",
        "private/repo#other",
        "private/repo%2Fother",
    ] {
        let result = project_from_value(json!({"id": 42, "path_with_namespace": invalid}));
        assert!(
            matches!(result, Err(GitlabBackendError::Protocol(_))),
            "accepted malformed repository identity {invalid:?}"
        );
    }
    assert!(project_from_value(json!({"id": 42})).is_err());
    assert!(project_from_value(json!({"id": 42, "path_with_namespace": null})).is_err());
    for valid in ["engineering/payments", "engineering/platform/api"] {
        let project = project_from_value(json!({"id": 42, "path_with_namespace": valid})).unwrap();
        assert_eq!(project.path_with_namespace, valid);
    }
}

#[test]
fn fork_repository_scopes_are_sorted_and_same_project_is_deduplicated() {
    let target = GitlabProject {
        id: 1,
        path_with_namespace: "target/repo".to_string(),
        name: None,
        web_url: None,
        default_branch: None,
        visibility: None,
        archived: None,
    };
    let source = GitlabProject {
        id: 2,
        path_with_namespace: "fork/repo".to_string(),
        ..target.clone()
    };
    let scopes = repository_scopes_from_projects([&target, &source, &target]);
    assert_eq!(
        scopes["repository"],
        vec!["fork/repo".to_string(), "target/repo".to_string()]
    );
    assert!(!scopes.contains_key("namespace"));
}

#[test]
fn internal_diagnostic_codes_are_closed_and_exact() {
    let codes = [InternalDiagnosticCode::DraftPositionShapeInvalid];
    let strings = codes.map(InternalDiagnosticCode::as_str);
    assert_eq!(strings, ["draft_position_shape_invalid"]);
    assert_eq!(
        strings.into_iter().collect::<BTreeSet<_>>().len(),
        codes.len()
    );
}

#[test]
fn mutation_verification_failure_is_closed_and_unsafe_to_retry() {
    let error = mutation_verification_failed(
        MutationVerificationStage::MutationReadback,
        MutationSafeLocators::new()
            .with_discussion_id("discussion-7")
            .with_note_id(17)
            .with_draft_note_ids(vec![23, 29])
            .with_suggestion_ids(vec![31])
            .with_webhook_ids(vec![42, 7, 42, 0])
            .with_webhook_event_ids(vec![9002, 9001, 9002]),
    );

    assert_eq!(error.decision(), crate::Decision::Error);
    assert_eq!(error.reason_code(), ReasonCode::MutationVerificationFailed);
    assert_eq!(error.reason_code().http_status(), 409);
    assert_eq!(
        error.message,
        "upstream mutation could not be fully verified"
    );
    assert_eq!(
        error.result.as_deref(),
        Some(&json!({
            "mutationStatus": "applied_unverified",
            "retrySafe": false,
            "verificationStage": "mutation_readback",
            "safeLocators": {
                "discussionId": "discussion-7",
                "noteId": 17,
                "draftNoteIds": [23, 29],
                "suggestionIds": [31],
                "webhookIds": [7, 42],
                "webhookEventIds": [9001, 9002]
            }
        }))
    );
    assert_eq!(
        serde_json::from_value::<MutationSafeLocators>(json!({
            "webhookIds": [3, 2, 3, 0],
            "webhookEventIds": [8, 7, 8]
        }))
        .unwrap(),
        MutationSafeLocators::new()
            .with_webhook_ids(vec![2, 3])
            .with_webhook_event_ids(vec![7, 8])
    );
    let bounded = MutationSafeLocators::new()
        .with_webhook_ids((1..=150).rev().collect())
        .with_webhook_event_ids((1..=150).rev().collect());
    let bounded = serde_json::to_value(bounded).unwrap();
    assert_eq!(bounded["webhookIds"].as_array().unwrap().len(), 100);
    assert_eq!(bounded["webhookIds"][0], json!(1));
    assert_eq!(bounded["webhookIds"][99], json!(100));
    assert_eq!(bounded["webhookEventIds"].as_array().unwrap().len(), 100);
    assert!(
        serde_json::from_value::<MutationSafeLocators>(json!({
            "discussionId": "discussion-7",
            "content": "must not be accepted"
        }))
        .is_err()
    );
    for (stage, encoded) in [
        (
            MutationVerificationStage::MutationResponse,
            "mutation_response",
        ),
        (
            MutationVerificationStage::MutationReadback,
            "mutation_readback",
        ),
        (
            MutationVerificationStage::PublishedNoteReadback,
            "published_note_readback",
        ),
        (
            MutationVerificationStage::DraftAbsenceReadback,
            "draft_absence_readback",
        ),
        (
            MutationVerificationStage::BulkPublishReadback,
            "bulk_publish_readback",
        ),
        (
            MutationVerificationStage::ReviewerStateReadback,
            "reviewer_state_readback",
        ),
        (
            MutationVerificationStage::SummaryNoteResponse,
            "summary_note_response",
        ),
    ] {
        assert_eq!(serde_json::to_value(stage).unwrap(), json!(encoded));
    }
    assert!(
        serde_json::from_value::<MutationVerificationStage>(json!("provider_error_text")).is_err()
    );
}

#[test]
fn position_input_failure_categories_are_closed_and_non_refreshable() {
    for (category, encoded) in [
        (
            PositionInputCategory::CoordinatesUnresolved,
            "coordinates_unresolved",
        ),
        (PositionInputCategory::PatchUnavailable, "patch_unavailable"),
        (
            PositionInputCategory::SuggestionOutdated,
            "suggestion_outdated",
        ),
    ] {
        assert_eq!(serde_json::to_value(category).unwrap(), json!(encoded),);
        assert_eq!(
            serde_json::from_value::<PositionInputCategory>(json!(encoded)).unwrap(),
            category,
        );
        let error = position_input_invalid(category);
        assert_eq!(error.decision(), crate::Decision::Deny);
        assert_eq!(error.reason_code(), ReasonCode::InputInvalid);
        assert_eq!(error.reason_code().http_status(), 400);
        assert_eq!(
            error.result.as_deref(),
            Some(&json!({ "inputCategory": encoded }))
        );
    }

    assert!(
        serde_json::from_value::<PositionInputFailureResult>(json!({
            "inputCategory": "coordinates_unresolved",
            "path": "must not be accepted"
        }))
        .is_err()
    );
    assert!(
        serde_json::from_value::<PositionInputFailureResult>(json!({
            "inputCategory": "unknown"
        }))
        .is_err()
    );
}

fn provider_for_server(server: &MockServer) -> GitlabProvider {
    let mut config = config();
    config.api_base_url = format!("{}/api/v4", server.uri());
    config.allowed_upstream_hosts = vec![format!("{}/api/v4/**", server.uri())];
    let host = agent_access_provider::test_support::TestHost::default();
    GitlabProvider::new(config, &host.context()).unwrap()
}

#[test]
fn gitlab_rest_is_a_project_scoped_invoke_surface_over_the_host_repository_type() {
    // GitLab consumes the host-owned repository type and declares none itself.
    assert!(GITLAB_BACKEND.resource_types().is_empty());
    let descriptor = gitlab_descriptor(&config());
    // Native REST is an invoke surface; Git smart HTTP stays with host gateways.
    assert_eq!(descriptor.surface, ServiceSurface::Invoke);
    assert_eq!(
        descriptor.resource_scopes.keys().collect::<Vec<_>>(),
        ["repository"]
    );
    assert_eq!(
        descriptor.resource_scopes["repository"].resource_type,
        *GIT_REPOSITORY_RESOURCE.id()
    );
    for action in &descriptor.actions {
        let name = action.action.as_str();
        assert_eq!(
            action.resource_scope.as_deref(),
            Some("repository"),
            "{name}"
        );
        // Searches are ordinary project-scoped calls, not search-contained.
        assert!(!action.search_contained, "{name}");
        assert_eq!(action.lookup, LookupRequirement::ScopeResolution, "{name}");
        for transport in [
            "clone",
            "fetch",
            "push",
            "upload_pack",
            "receive_pack",
            "info_refs",
        ] {
            assert!(!name.contains(transport), "{name}");
        }
    }
}

#[tokio::test]
async fn credential_verification_reads_the_current_user_with_the_selected_bearer_only() {
    let server = MockServer::start().await;
    for (token, response) in [
        (
            "gitlab-token",
            ResponseTemplate::new(200)
                .set_body_json(json!({ "id": 314, "username": "service-user" })),
        ),
        ("revoked-token", ResponseTemplate::new(401)),
        ("forbidden-token", ResponseTemplate::new(403)),
    ] {
        Mock::given(method("GET"))
            .and(path("/api/v4/user"))
            .and(wiremock::matchers::header(
                "authorization",
                format!("Bearer {token}").as_str(),
            ))
            .respond_with(response)
            .expect(1)
            .mount(&server)
            .await;
    }
    let provider = provider_for_server(&server);
    let correlation = crate::CorrelationContext::for_tests();
    let verified = provider
        .verify_execution_credential(&test_credential(), &correlation)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(verified.upstream_status, 200);
    assert_eq!(verified.audit["gitlab"]["operation"], "credential.verify");
    assert_eq!(verified.audit["gitlab"]["userId"], 314);
    assert_eq!(verified.audit["gitlab"]["username"], "service-user");
    assert!(!verified.audit.to_string().contains("gitlab-token"));
    for (token, reason) in [
        ("revoked-token", ReasonCode::UpstreamUnauthorized),
        ("forbidden-token", ReasonCode::UpstreamForbidden),
    ] {
        let error = provider
            .verify_execution_credential(&bearer_credential(token), &correlation)
            .await
            .unwrap_err();
        assert_eq!(error.decision(), Decision::Error);
        assert_eq!(error.reason_code(), reason);
        assert!(!format!("{error:?}").contains(token));
    }
    // GitLab execution credentials are bearer tokens; Basic material is
    // rejected without contacting GitLab.
    let error = provider
        .verify_execution_credential(
            &agent_access_provider::test_support::basic_credential("user", "basic-token"),
            &correlation,
        )
        .await
        .unwrap_err();
    assert_eq!(error.reason_code(), ReasonCode::UpstreamProtocolFailed);
    assert!(!format!("{error:?}").contains("basic-token"));
    assert_eq!(server.received_requests().await.unwrap().len(), 3);
}

const FORK_SUGGESTION_SHA: &str = "0123456789abcdef0123456789abcdef01234567";

#[tokio::test]
async fn fork_suggestions_pin_numeric_scope_state_and_recheck_it_before_writing() {
    let server = MockServer::start().await;
    for (route, body) in [
        (
            "/api/v4/projects/sip%2Fservice",
            json!({ "id": 42, "path_with_namespace": "sip/service" }),
        ),
        (
            "/api/v4/projects/141",
            json!({ "id": 141, "path_with_namespace": "fork/service" }),
        ),
        (
            "/api/v4/user",
            json!({ "id": 314, "username": "service-user" }),
        ),
        (
            "/api/v4/projects/42/merge_requests/5",
            json!({
                "id": 500, "iid": 5, "project_id": 42, "source_project_id": 141,
                "target_project_id": 42, "sha": FORK_SUGGESTION_SHA
            }),
        ),
    ] {
        Mock::given(method("GET"))
            .and(path(route))
            .respond_with(ResponseTemplate::new(200).set_body_json(body))
            .mount(&server)
            .await;
    }
    let provider = provider_for_server(&server);
    let action = "merge_request.suggestion.apply";
    let inputs = json!({
        "project": "sip/service", "iid": 5, "expectedHeadSha": FORK_SUGGESTION_SHA,
        "discussionId": "discussion-1", "noteId": 900, "suggestionId": 456
    });

    // Scope resolution returns the target and source repositories together
    // and carries both numeric project IDs as typed provider state.
    let fixture = agent_access_provider::test_support::ScopeRequestFixture::new(
        "gitlab",
        action,
        inputs.clone(),
    )
    .lookup_credential(test_credential());
    let (scopes, state) = provider
        .resolve_scopes(fixture.request())
        .await
        .unwrap()
        .into_parts();
    let both = ["fork/service", "sip/service"];
    let repositories = |paths: &[&str]| {
        ResourceScopes::from([(
            "repository".to_string(),
            paths.iter().map(|path| path.to_string()).collect(),
        )])
    };
    assert_eq!(scopes, repositories(&both));
    assert_eq!(
        ProviderState::require::<GitlabSuggestionScopePreflight>(state.as_ref()).unwrap(),
        &GitlabSuggestionScopePreflight {
            target_project_id: 42,
            source_project_id: 141,
        }
    );

    let invocation = |state: Option<ProviderState>, paths: &[&str]| {
        let builder = InvocationBuilder::new("gitlab", action)
            .inputs(inputs.clone())
            .resources(repositories(paths))
            .credential(test_credential())
            .lookup_credential(test_credential());
        match state {
            Some(state) => builder.state(state).build(),
            None => builder.build(),
        }
    };
    // Missing or foreign state fails closed before any upstream request.
    let before = server.received_requests().await.unwrap().len();
    for (state, diagnostic) in [
        (None, "provider_state_missing"),
        (
            Some(ProviderState::new("foreign")),
            "provider_state_type_mismatch",
        ),
    ] {
        let error = provider.invoke(invocation(state, &both)).await.unwrap_err();
        assert_eq!(error.decision(), Decision::Error);
        assert_eq!(
            error.reason_code(),
            ReasonCode::BrokerProviderContractFailed
        );
        assert_eq!(error.internal_diagnostic_code, Some(diagnostic));
    }
    assert_eq!(server.received_requests().await.unwrap().len(), before);

    // Execution rechecks the pinned target and source IDs against fresh
    // reads with the execution credential, and the admitted repositories.
    let preflight = |target_project_id, source_project_id| {
        ProviderState::new(GitlabSuggestionScopePreflight {
            target_project_id,
            source_project_id,
        })
    };
    for (state, paths) in [
        (preflight(41, 141), &both[..]),
        (preflight(42, 140), &both[..]),
        (preflight(42, 141), &["sip/service"][..]),
    ] {
        let error = provider
            .invoke(invocation(Some(state), paths))
            .await
            .unwrap_err();
        assert_eq!(error.decision(), Decision::Deny);
        assert_eq!(error.reason_code(), ReasonCode::ScopeUnresolved);
        assert_eq!(
            error.message,
            "GitLab merge request repository scope changed before suggestion apply"
        );
    }
    // Matching state passes the recheck and reaches the suggestion proof,
    // whose discussion read this fixture does not serve.
    let error = provider
        .invoke(invocation(Some(preflight(42, 141)), &both))
        .await
        .unwrap_err();
    assert_eq!(error.message, "GitLab note was not found or not permitted");
    assert!(
        server
            .received_requests()
            .await
            .unwrap()
            .iter()
            .all(|request| request.method.as_str() == "GET")
    );
}

/// One raw HTTP/1.1 response whose body ends after two of ten declared
/// bytes, either held open (a stall) or closed (a broken connection).
fn truncated_download_server(hold: bool) -> String {
    use std::io::{Read, Write};
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    std::thread::spawn(move || {
        let (mut socket, _) = listener.accept().unwrap();
        let mut request = Vec::new();
        let mut buffer = [0_u8; 1024];
        while !request.windows(4).any(|window| window == b"\r\n\r\n") {
            match socket.read(&mut buffer) {
                Ok(0) | Err(_) => return,
                Ok(read) => request.extend_from_slice(&buffer[..read]),
            }
        }
        socket
            .write_all(
                b"HTTP/1.1 200 OK\r\ncontent-type: text/plain\r\ncontent-length: 10\r\n\r\nab",
            )
            .unwrap();
        socket.flush().unwrap();
        if hold {
            // Longer than any test step; the detached thread ends with the
            // test binary.
            std::thread::sleep(std::time::Duration::from_secs(30));
        }
        let _ = socket.shutdown(std::net::Shutdown::Both);
    });
    format!("http://{address}/projects/42/repository/files/private%2Fpath/raw")
}

#[tokio::test]
async fn raw_download_streams_fail_late_only_with_code_only_reasons() {
    use futures_util::StreamExt;
    let client = reqwest::Client::builder().no_proxy().build().unwrap();
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .respond_with(ResponseTemplate::new(200).set_body_bytes(b"oversize".to_vec()))
        .mount(&server)
        .await;
    let fetch = |url: String| {
        let client = client.clone();
        async move { client.get(url).send().await.unwrap() }
    };
    // Only the stall case relies on the idle budget expiring; the others
    // get a budget no loaded test host exhausts.
    let (stall, idle) = (
        std::time::Duration::from_millis(100),
        std::time::Duration::from_secs(10),
    );
    let cases = [
        // More bytes than the download cap.
        (
            gitlab_response_stream(
                fetch(format!("{}/oversize", server.uri())).await,
                4,
                idle,
                None,
                "text/plain".to_string(),
            ),
            ReasonCode::UpstreamProtocolFailed,
        ),
        // Fewer bytes than the response declared.
        (
            gitlab_response_stream(
                fetch(format!("{}/short", server.uri())).await,
                1024,
                idle,
                Some(10),
                "text/plain".to_string(),
            ),
            ReasonCode::UpstreamProtocolFailed,
        ),
        (
            gitlab_response_stream(
                fetch(truncated_download_server(true)).await,
                1024,
                stall,
                Some(10),
                "text/plain".to_string(),
            ),
            ReasonCode::UpstreamTimeout,
        ),
        (
            gitlab_response_stream(
                fetch(truncated_download_server(false)).await,
                1024,
                idle,
                Some(10),
                "text/plain".to_string(),
            ),
            ReasonCode::UpstreamConnectionFailed,
        ),
    ];
    for (stream, expected) in cases {
        assert!(stream.is_streaming());
        let ProviderResultStreamSource::Stream(stream) = stream.source else {
            panic!("GitLab downloads stream");
        };
        let mut stream = stream.lock().unwrap().take().unwrap();
        let mut failure = None;
        while let Some(item) = stream.next().await {
            if let Err(error) = item {
                failure = Some(error);
                break;
            }
        }
        let failure = failure.expect("the download fails after its headers");
        let code = failure.reason_code.standard().unwrap();
        assert_eq!(code, expected, "{failure:?}");
        assert!(code.permits_late_stream(), "{code:?}");
        assert!(!failure.message.contains("private"), "{failure:?}");
    }
}

#[tokio::test]
async fn body_admission_accepts_only_project_upload_and_states_its_disposition() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/api/v4/projects/sip%2Fservice"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(json!({ "id": 42, "path_with_namespace": "sip/service" })),
        )
        .expect(1)
        .mount(&server)
        .await;
    let mut config = config();
    config.attachments.media_types.push("text/html".to_string());
    let provider = GitlabProvider::with_backend(config, Arc::new(http_backend(&server)));
    let other = test_invocation("issue.view", json!({ "project": "sip/service", "iid": 7 }));
    let error = provider
        .authorize_body_parts(other.admitted(), None)
        .await
        .unwrap_err();
    assert_eq!(error.decision(), Decision::Deny);
    assert_eq!(error.reason_code(), ReasonCode::BodyMalformed);
    assert!(server.received_requests().await.unwrap().is_empty());
    let (inputs, _) = upload_fixture();
    let upload = test_invocation("project.upload", inputs);
    let admission = provider
        .authorize_body_parts(upload.admitted(), None)
        .await
        .unwrap();
    assert!(matches!(admission.state(), StateDisposition::Keep));
    assert_eq!(admission.part_specs().len(), 1);
}
