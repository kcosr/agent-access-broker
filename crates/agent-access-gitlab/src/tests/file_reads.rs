use super::*;
use futures_util::StreamExt;
use wiremock::matchers::header;

const COMMIT: &str = "1111111111111111111111111111111111111111";
const BLOB: &str = "2222222222222222222222222222222222222222";
const LAST_COMMIT: &str = "3333333333333333333333333333333333333333";
// GitLab may hash a converted representation rather than the raw bytes.
const GITLAB_CONTENT_SHA: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

fn file_provider(
    server: &MockServer,
    change: impl FnOnce(&mut GitlabProviderConfig),
) -> GitlabProvider {
    let mut config = config();
    config.api_base_url = format!("{}/api/v4", server.uri());
    config.allowed_upstream_hosts = vec![format!("{}/api/v4/**", server.uri())];
    change(&mut config);
    let host = agent_access_provider::test_support::TestHost::default();
    GitlabProvider::new(config, &host.context()).unwrap()
}

fn file_invocation(action: &str, inputs: Value) -> ProviderInvocation {
    InvocationBuilder::from(test_invocation(action, inputs))
        .credential(bearer_credential("file-execution-token"))
        .lookup_credential(bearer_credential("project-lookup-token"))
        .build()
}

fn file_inputs(file_path: &str) -> Value {
    json!({"project":"sip/service", "path":file_path, "ref":"main"})
}

fn metadata_response(file_path: &str, size: usize) -> ResponseTemplate {
    ResponseTemplate::new(200)
        .insert_header("x-gitlab-file-name", file_path.rsplit('/').next().unwrap())
        .insert_header("x-gitlab-file-path", file_path)
        .insert_header("x-gitlab-size", size.to_string())
        .insert_header("x-gitlab-commit-id", COMMIT)
        .insert_header("x-gitlab-blob-id", BLOB)
        .insert_header("x-gitlab-last-commit-id", LAST_COMMIT)
        .insert_header("x-gitlab-content-sha256", GITLAB_CONTENT_SHA)
        .insert_header("x-gitlab-ref", "main")
        .insert_header("x-gitlab-execute-filemode", "true")
}

async fn mount_project(server: &MockServer, expected: u64) {
    Mock::given(method("GET"))
        .and(path("/api/v4/projects/sip%2Fservice"))
        .and(header("authorization", "Bearer project-lookup-token"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "id":42, "path_with_namespace":"sip/service"
        })))
        .expect(expected)
        .mount(server)
        .await;
}

async fn mount_file(
    server: &MockServer,
    verb: &str,
    route: &str,
    response: ResponseTemplate,
    expected: u64,
) {
    Mock::given(method(verb))
        .and(path(route))
        .and(query_param("ref", "main"))
        .and(header("authorization", "Bearer file-execution-token"))
        .respond_with(response)
        .expect(expected)
        .mount(server)
        .await;
}

#[tokio::test]
async fn metadata_view_uses_execution_head_without_content_limits_or_get() {
    let server = MockServer::start().await;
    let provider = file_provider(&server, |config| {
        config.content.max_inline_text_bytes = 4;
        config.content.max_file_bytes = 4;
        config.content.max_raw_download_bytes = 4;
    });
    let size = 100 * 1024 * 1024;
    mount_project(&server, 1).await;
    mount_file(
        &server,
        "HEAD",
        "/api/v4/projects/42/repository/files/README.md",
        metadata_response("README.md", size).insert_header("content-length", size.to_string()),
        1,
    )
    .await;

    let result = provider
        .invoke(file_invocation("file.view", file_inputs("README.md")))
        .await
        .unwrap();
    let file = &result.result["file"];
    assert_eq!(file["contentStatus"], "not_requested");
    assert_eq!(file["size"], size);
    assert_eq!(file["filePath"], "README.md");
    assert_eq!(file["commitId"], COMMIT);
    assert_eq!(file["blobId"], BLOB);
    assert_eq!(file["lastCommitId"], LAST_COMMIT);
    assert_eq!(file["executeFilemode"], true);
    assert_eq!(file["contentSha256"], GITLAB_CONTENT_SHA);
    for absent in ["content", "contentBase64", "encoding"] {
        assert!(file.get(absent).is_none(), "{absent}");
    }
    assert!(result.stream.is_none());
    assert_eq!(
        received_requests(&server).await,
        [
            "GET /api/v4/projects/sip%2Fservice",
            "HEAD /api/v4/projects/42/repository/files/README.md"
        ]
    );
}

#[tokio::test]
async fn metadata_view_preserves_unicode_repository_paths() {
    let server = MockServer::start().await;
    let provider = file_provider(&server, |_| {});
    mount_project(&server, 1).await;
    mount_file(
        &server,
        "HEAD",
        "/api/v4/projects/42/repository/files/docs%2Fcaf%C3%A9.md",
        metadata_response("docs/café.md", 0),
        1,
    )
    .await;
    let result = provider
        .invoke(file_invocation("file.view", file_inputs("docs/café.md")))
        .await
        .unwrap();
    assert_eq!(result.result["file"]["filePath"], "docs/café.md");
    assert_eq!(result.result["file"]["fileName"], "café.md");
    assert_eq!(result.result["file"]["contentStatus"], "not_requested");
}

#[tokio::test]
async fn text_view_preserves_complete_utf8_and_explicitly_omits_unsupported_bytes() {
    let server = MockServer::start().await;
    let provider = file_provider(&server, |_| {});
    let cases: &[(&str, &[u8], Option<&str>)] = &[
        ("empty.txt", b"", Some("")),
        (
            "unicode.txt",
            "\u{feff}FILE_CONTENT_SENTINEL café\r\nlast line".as_bytes(),
            Some("\u{feff}FILE_CONTENT_SENTINEL café\r\nlast line"),
        ),
        ("nul.txt", b"abc\0def", None),
        ("latin1.txt", b"caf\xe9", None),
        ("utf16.txt", b"\xff\xfeh\0i\0", None),
    ];
    mount_project(&server, cases.len() as u64).await;
    for (file_path, bytes, _) in cases {
        mount_file(
            &server,
            "GET",
            &format!("/api/v4/projects/42/repository/files/{file_path}/raw"),
            metadata_response(file_path, bytes.len()).set_body_bytes(bytes.to_vec()),
            1,
        )
        .await;
    }
    for (file_path, bytes, text) in cases {
        let mut inputs = file_inputs(file_path);
        inputs["includeContent"] = json!(true);
        let result = provider
            .invoke(file_invocation("file.view", inputs))
            .await
            .unwrap();
        let file = &result.result["file"];
        assert_eq!(file["size"], bytes.len());
        assert_eq!(file["commitId"], COMMIT);
        assert_eq!(file["contentSha256"], GITLAB_CONTENT_SHA);
        if let Some(text) = text {
            assert_eq!(file["contentStatus"], "included", "{file_path}");
            assert_eq!(file["content"], *text, "{file_path}");
        } else {
            assert_eq!(file["contentStatus"], "unsupported_text", "{file_path}");
            assert!(file.get("content").is_none(), "{file_path}");
        }
        assert!(file.get("contentBase64").is_none());
        assert!(file.get("encoding").is_none());
        assert!(result.stream.is_none());
        assert!(
            !result
                .audit
                .unwrap()
                .to_string()
                .contains("FILE_CONTENT_SENTINEL")
        );
        assert!(
            !result
                .object_ids
                .unwrap()
                .to_string()
                .contains("FILE_CONTENT_SENTINEL")
        );
    }
    let requests = received_requests(&server).await;
    assert_eq!(requests.len(), cases.len() * 2);
    assert!(requests.iter().all(|request| request.starts_with("GET ")));
    assert_eq!(
        requests
            .iter()
            .filter(|request| request.ends_with("/raw"))
            .count(),
        cases.len()
    );
}

#[tokio::test]
async fn explicit_whole_file_budget_reads_more_than_the_default_without_a_prefix() {
    let server = MockServer::start().await;
    let bytes = "x".repeat(64 * 1024 + 1);
    let provider = file_provider(&server, |config| {
        // Write limits do not constrain inline reads.
        config.content.max_file_bytes = 1;
    });
    mount_project(&server, 2).await;
    mount_file(
        &server,
        "GET",
        "/api/v4/projects/42/repository/files/large.txt/raw",
        metadata_response("large.txt", bytes.len()).set_body_string(bytes.clone()),
        2,
    )
    .await;
    let mut inputs = file_inputs("large.txt");
    inputs["includeContent"] = json!(true);
    let omitted = provider
        .invoke(file_invocation("file.view", inputs.clone()))
        .await
        .unwrap();
    assert_eq!(omitted.result["file"]["contentStatus"], "too_large");
    assert_eq!(omitted.result["file"]["contentBudgetBytes"], 64 * 1024);
    assert_eq!(omitted.result["file"]["size"], bytes.len());
    assert!(omitted.result["file"].get("content").is_none());

    inputs["maxContentBytes"] = json!(bytes.len());
    let included = provider
        .invoke(file_invocation("file.view", inputs))
        .await
        .unwrap();
    assert_eq!(included.result["file"]["contentStatus"], "included");
    assert_eq!(included.result["file"]["content"], bytes);
    assert_eq!(received_requests(&server).await.len(), 4);
}

#[tokio::test]
async fn configured_ceiling_reduces_the_default_budget_and_is_published_in_schema() {
    let server = MockServer::start().await;
    let provider = file_provider(&server, |config| config.content.max_inline_text_bytes = 4);
    let descriptor = gitlab_descriptor(&provider.config);
    let schema = &descriptor.action("file.view").unwrap().input_schema;
    assert_eq!(schema["properties"]["maxContentBytes"]["maximum"], 4);
    mount_project(&server, 1).await;
    mount_file(
        &server,
        "GET",
        "/api/v4/projects/42/repository/files/five.txt/raw",
        metadata_response("five.txt", 5).set_body_bytes(b"abcde"),
        1,
    )
    .await;
    let mut inputs = file_inputs("five.txt");
    inputs["includeContent"] = json!(true);
    let result = provider
        .invoke(file_invocation("file.view", inputs))
        .await
        .unwrap();
    assert_eq!(result.result["file"]["contentStatus"], "too_large");
    assert_eq!(result.result["file"]["contentBudgetBytes"], 4);
    assert!(result.result["file"].get("content").is_none());
}

#[test]
fn inline_ceiling_configuration_checks_zero_overflow_and_json_boundary() {
    fn validate(inline_ceiling: u64, response_limit: u64) -> Vec<String> {
        let mut config = config();
        config.content.max_inline_text_bytes = inline_ceiling;
        let mut limits = ProviderLimits::default();
        limits.max_upstream_response_bytes = response_limit;
        let context = ValidationContext::new(
            "production",
            "managed",
            &limits,
            ServiceCredentialKinds::default()
                .with_service(Some(CredentialSource::static_kind("bearer_token"))),
        );
        let mut errors = Vec::new();
        config.validate(&context, &mut errors);
        errors
    }

    let boundary = 4 * 6 + 65_536;
    // The ordinary file/write cap stays at 10 MiB while inline reading has
    // its own tiny ceiling; equality at the response allowance is valid.
    assert!(validate(4, boundary).is_empty());
    assert!(validate(1, 6 + 65_536).is_empty());
    let errors = validate(4, boundary - 1);
    assert_eq!(errors.len(), 1, "{errors:?}");
    assert!(errors[0].contains("max_inline_text_bytes"));
    assert_eq!(
        validate(0, u64::MAX),
        ["providers.gitlab.content.max_inline_text_bytes must be non-zero"]
    );
    for ceiling in [u64::MAX, u64::MAX / 6] {
        let errors = validate(ceiling, u64::MAX);
        assert_eq!(errors.len(), 1, "{ceiling}: {errors:?}");
        assert!(errors[0].contains("max_inline_text_bytes"));
    }
    assert_eq!(
        GitlabContentConfig::default().max_inline_text_bytes,
        1024 * 1024
    );
    assert_eq!(
        GitlabContentConfig::default().max_file_bytes,
        10 * 1024 * 1024
    );
}

#[tokio::test]
async fn invalid_view_budgets_and_download_view_options_fail_before_upstream() {
    let server = MockServer::start().await;
    let provider = file_provider(&server, |config| config.content.max_inline_text_bytes = 32);
    let extras = [
        json!({"maxContentBytes": 16}),
        json!({"includeContent":false,"maxContentBytes":16}),
        json!({"includeContent":"true"}),
        json!({"includeContent":true,"maxContentBytes":0}),
        json!({"includeContent":true,"maxContentBytes":-1}),
        json!({"includeContent":true,"maxContentBytes":1.5}),
        json!({"includeContent":true,"maxContentBytes":"16"}),
        json!({"includeContent":true,"maxContentBytes":null}),
        json!({"includeContent":true,"maxContentBytes":33}),
    ];
    for extra in extras {
        let mut inputs = file_inputs("README.md");
        inputs
            .as_object_mut()
            .unwrap()
            .extend(extra.as_object().unwrap().clone());
        let error = provider
            .invoke(file_invocation("file.view", inputs))
            .await
            .unwrap_err();
        assert_eq!(error.reason_code(), ReasonCode::InputInvalid, "{extra}");
    }
    for extra in [
        json!({"includeContent":false}),
        json!({"maxContentBytes":16}),
    ] {
        let mut inputs = file_inputs("README.md");
        inputs
            .as_object_mut()
            .unwrap()
            .extend(extra.as_object().unwrap().clone());
        let error = provider
            .invoke(file_invocation("file.raw.download", inputs))
            .await
            .unwrap_err();
        assert_eq!(error.reason_code(), ReasonCode::InputInvalid, "{extra}");
    }
    assert!(received_requests(&server).await.is_empty());
}

#[tokio::test]
async fn file_reads_refuse_project_scope_changes_before_file_lookup() {
    let server = MockServer::start().await;
    let provider = file_provider(&server, |_| {});
    mount_project(&server, 1).await;
    let invocation =
        InvocationBuilder::from(file_invocation("file.view", file_inputs("README.md")))
            .resources(repository_scopes_from_path("other/repository"))
            .build();
    let error = provider.invoke(invocation).await.unwrap_err();
    assert_eq!(error.reason_code(), ReasonCode::ScopeUnresolved);
    assert_eq!(
        received_requests(&server).await,
        ["GET /api/v4/projects/sip%2Fservice"]
    );
}

#[tokio::test]
async fn file_metadata_path_mismatch_is_an_error_not_an_omission() {
    let server = MockServer::start().await;
    let provider = file_provider(&server, |_| {});
    mount_project(&server, 1).await;
    mount_file(
        &server,
        "HEAD",
        "/api/v4/projects/42/repository/files/README.md",
        metadata_response("OTHER.md", 0),
        1,
    )
    .await;
    let error = provider
        .invoke(file_invocation("file.view", file_inputs("README.md")))
        .await
        .unwrap_err();
    assert_eq!(error.reason_code(), ReasonCode::UpstreamProtocolFailed);
}

#[tokio::test]
async fn file_authorization_failures_remain_failures_in_both_view_modes() {
    let server = MockServer::start().await;
    let provider = file_provider(&server, |_| {});
    mount_project(&server, 2).await;
    for (verb, route) in [
        ("HEAD", "/api/v4/projects/42/repository/files/README.md"),
        ("GET", "/api/v4/projects/42/repository/files/README.md/raw"),
    ] {
        mount_file(&server, verb, route, ResponseTemplate::new(403), 1).await;
    }
    for include in [false, true] {
        let mut inputs = file_inputs("README.md");
        inputs["includeContent"] = json!(include);
        let error = provider
            .invoke(file_invocation("file.view", inputs))
            .await
            .unwrap_err();
        assert_eq!(error.reason_code(), ReasonCode::UpstreamForbidden);
    }
}

#[tokio::test]
async fn raw_download_uses_one_execution_get_and_never_advertises_converted_content_hash() {
    let server = MockServer::start().await;
    let provider = file_provider(&server, |_| {});
    let bytes = b"caf\xe9\r\n";
    mount_project(&server, 1).await;
    mount_file(
        &server,
        "GET",
        "/api/v4/projects/42/repository/files/source.txt/raw",
        metadata_response("source.txt", bytes.len()).set_body_bytes(bytes),
        1,
    )
    .await;
    let result = provider
        .invoke(file_invocation(
            "file.raw.download",
            file_inputs("source.txt"),
        ))
        .await
        .unwrap();
    assert_eq!(result.result["resolvedRef"], COMMIT);
    assert_eq!(result.result["size"], bytes.len());
    assert!(result.result.get("sha256").is_none());
    assert!(
        result.audit.as_ref().unwrap()["gitlab"]
            .get("sha256")
            .is_none()
    );
    let ProviderResultStreamSource::Stream(stream) = result.stream.unwrap().source else {
        panic!("raw repository files stay streamed");
    };
    let mut stream = stream.lock().unwrap().take().unwrap();
    let mut actual = Vec::new();
    while let Some(chunk) = stream.next().await {
        actual.extend_from_slice(&chunk.unwrap());
    }
    assert_eq!(actual, bytes);
    assert_ne!(format!("{:x}", Sha256::digest(&actual)), GITLAB_CONTENT_SHA);
    assert_eq!(
        received_requests(&server).await,
        [
            "GET /api/v4/projects/sip%2Fservice",
            "GET /api/v4/projects/42/repository/files/source.txt/raw"
        ]
    );
}
