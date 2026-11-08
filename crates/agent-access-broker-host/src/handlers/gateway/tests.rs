use super::*;
use crate::router::build_gateway_router;
use crate::state::ReloadableState;
use crate::tests::test_temp_dir;
use agent_access_core::{
    AuditConfig, BrokerConfig, CredentialConfig, CredentialsConfig, DEFAULT_EXECUTION_CONTEXT,
    DeploymentConfig, IdentityConfig, IdentityGroupConfig, IdentitySourceConfig, NetworkConfig,
    PolicyConfig, PolicyGrantConfig, ProvidersConfig, StateLockSet, StaticPrincipalConfig,
};
use agent_access_provider::{
    GatewayBodyFrame, GatewayForwardPlan, GatewayResponseProfile, url_allowed_by_patterns,
};
use axum::http::header::{ACCEPT, CONTENT_ENCODING, USER_AGENT};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use futures_util::StreamExt;
use std::collections::{BTreeMap, VecDeque};
use std::path::Path;
use std::task::Poll;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::sync::oneshot;
use tower::ServiceExt;

#[test]
fn execution_context_rejection_is_not_a_basic_auth_challenge() {
    let response = gateway_error_response(
        StatusCode::FORBIDDEN,
        "broker-req-context",
        Some(ReasonCode::ExecutionContextRequired.into()),
        "execution context is required",
        false,
    );

    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    assert_eq!(
        response.headers()[REASON_CODE_HEADER],
        ReasonCode::ExecutionContextRequired.as_str()
    );
    assert!(!response.headers().contains_key(WWW_AUTHENTICATE));
}

#[test]
fn gateway_authority_parser_normalizes_case_and_preserves_ports() {
    assert_eq!(
        parse_gateway_authority("GIT.EXAMPLE.TEST:9443").unwrap(),
        GatewayAuthority {
            host: "git.example.test".to_string(),
            port: Some("9443".to_string()),
        }
    );
    assert_eq!(
        parse_gateway_authority("git.example.test").unwrap(),
        GatewayAuthority {
            host: "git.example.test".to_string(),
            port: None,
        }
    );
    assert!(parse_gateway_authority("git.example.test.").is_err());
    assert!(parse_gateway_authority("127.0.0.1").is_err());
    assert!(parse_gateway_authority("[::1]").is_err());
}

#[test]
fn effective_gateway_host_rejects_spoofed_or_ambiguous_authority() {
    let absolute = Request::builder()
        .uri("http://git.example.test/sip/service.git/info/refs")
        .header(HOST, "git.example.test")
        .body(Body::empty())
        .unwrap();
    assert_eq!(
        effective_gateway_host(&absolute).unwrap_err(),
        "gateway requests must not use absolute-form targets"
    );

    let duplicate_host = Request::builder()
        .uri("/sip/service.git/info/refs?service=git-upload-pack")
        .header(HOST, "git.example.test")
        .header(HOST, "git.example.test")
        .body(Body::empty())
        .unwrap();
    assert_eq!(
        effective_gateway_host(&duplicate_host).unwrap_err(),
        "gateway Host header is ambiguous"
    );

    let missing_host = Request::builder()
        .uri("/sip/service.git/info/refs?service=git-upload-pack")
        .body(Body::empty())
        .unwrap();
    assert_eq!(
        effective_gateway_host(&missing_host).unwrap_err(),
        "gateway Host header or authority is required"
    );
}

#[tokio::test]
async fn gateway_upstream_url_normalizes_clone_bases_for_every_git_operation() {
    for base_path in ["", "/", "/git/root", "/git/root/", "/git/root%20dir/"] {
        let mut gateway = test_gateway_config();
        gateway.upstream_base_url = format!("https://gitlab.example.com{base_path}");
        gateway.protocol_fields.get_mut("git").unwrap()["allow_push"] = toml::Value::Boolean(true);
        gateway.allowed_upstream_hosts = vec![format!(
            "https://gitlab.example.com{}/**",
            base_path.trim_end_matches('/')
        )];
        let protocol = fixture_protocol(&gateway);
        for (clone_base, canonical_repository, encoded_repository) in [
            ("team/project", "team/project", "team/project"),
            ("team/project.git", "team/project", "team/project"),
            (
                "team/subgroup/proj%65ct",
                "team/subgroup/project",
                "team/subgroup/project",
            ),
            (
                "team/subgroup/project%2Egit",
                "team/subgroup/project",
                "team/subgroup/project",
            ),
            ("t%C3%A9am/project", "téam/project", "t%C3%A9am/project"),
            // A repository whose actual name ends in .git retains that
            // name; only the transport suffix is removed by classification.
            (
                "team/project.git.git",
                "team/project.git",
                "team/project.git",
            ),
        ] {
            for (method, suffix, query, content_type, expected_kind) in [
                (
                    Method::GET,
                    "info/refs",
                    "?ser%76ice=git-upload-pack",
                    None,
                    GitRequestKind::UploadPackDiscovery,
                ),
                (
                    Method::GET,
                    "info/refs",
                    "?service=git-receive-pack",
                    None,
                    GitRequestKind::ReceivePackDiscovery,
                ),
                (
                    Method::POST,
                    "git-upload-pack",
                    "",
                    Some("application/x-git-upload-pack-request"),
                    GitRequestKind::UploadPackPost,
                ),
                (
                    Method::POST,
                    "git-receive-pack",
                    "",
                    Some("application/x-git-receive-pack-request"),
                    GitRequestKind::ReceivePackPost,
                ),
            ] {
                let uri: Uri = format!("/{clone_base}/{suffix}{query}").parse().unwrap();
                let mut headers = HeaderMap::new();
                if let Some(content_type) = content_type {
                    headers.insert(CONTENT_TYPE, HeaderValue::from_static(content_type));
                }
                let classified = protocol
                    .classify(agent_access_provider::host::gateway_request_head(
                        &method,
                        &uri.to_string(),
                        &headers,
                    ))
                    .unwrap();
                assert_eq!(classified.request_kind(), expected_kind.name(), "{uri}");
                assert_eq!(expected_kind.method(), method, "{uri}");
                assert_eq!(
                    classified.scopes()["repository"],
                    [canonical_repository],
                    "{uri}"
                );
                let body = if expected_kind == GitRequestKind::ReceivePackPost {
                    Body::from("0000")
                } else {
                    Body::empty()
                };
                let plan = classified
                    .into_request()
                    .preflight(protocol_body(body, &gateway_test_limits(1024)))
                    .await
                    .unwrap();
                let url = gateway.upstream_url(&plan.relative_target).unwrap();
                let canonical_query = query.replace("ser%76ice", "service");
                assert_eq!(
                    url.as_str(),
                    format!(
                        "https://gitlab.example.com{}/{encoded_repository}.git/{suffix}{canonical_query}",
                        base_path.trim_end_matches('/')
                    ),
                    "{uri}"
                );
                assert!(url_allowed_by_patterns(
                    &url,
                    &[format!(
                        "https://gitlab.example.com{}/**",
                        base_path.trim_end_matches('/')
                    )]
                ));
            }
        }
    }
}

#[test]
fn gateway_upstream_url_rejects_escape_from_the_configured_base() {
    for target in [
        "https://other.test/",
        "//other.test/",
        "/../outside",
        "/%2e%2e/outside",
        "/team%2Fother/project",
        "/team\\other",
        "/x#fragment",
    ] {
        assert_eq!(
            test_gateway_config()
                .upstream_url(target)
                .unwrap_err()
                .reason_code(),
            ReasonCode::GatewayUpstreamDenied,
            "{target}"
        );
    }
    let mut gateway = test_gateway_config();
    gateway.allowed_upstream_hosts = vec!["https://another.example.com/**".into()];
    assert_eq!(
        gateway.upstream_url("/resource").unwrap_err().reason_code(),
        ReasonCode::GatewayUpstreamDenied
    );
}

#[test]
fn gateway_upstream_response_filters_sensitive_headers() {
    let mut upstream_headers = reqwest::header::HeaderMap::new();
    upstream_headers.insert(
        reqwest::header::CONTENT_TYPE,
        reqwest::header::HeaderValue::from_static("application/x-git-upload-pack-advertisement"),
    );
    upstream_headers.insert(
        reqwest::header::WWW_AUTHENTICATE,
        reqwest::header::HeaderValue::from_static("Basic realm=\"upstream\""),
    );
    upstream_headers.insert(
        reqwest::header::SERVER,
        reqwest::header::HeaderValue::from_static("gitlab"),
    );

    upstream_headers.insert(
        CACHE_CONTROL,
        HeaderValue::from_static("public, max-age=3600"),
    );
    upstream_headers.insert(PRAGMA, HeaderValue::from_static("public"));
    upstream_headers.insert(
        EXPIRES,
        HeaderValue::from_static("Thu, 01 Oct 2099 00:00:00 GMT"),
    );
    let response =
        fixture_upstream_response(200, "broker-req-test", &upstream_headers, Body::from("ok"));

    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response.headers()[CONTENT_TYPE],
        "application/x-git-upload-pack-advertisement"
    );
    assert_eq!(
        response.headers()[BROKER_REQUEST_ID_HEADER],
        "broker-req-test"
    );
    assert!(!response.headers().contains_key(WWW_AUTHENTICATE));
    assert!(!response.headers().contains_key("Server"));
    assert_eq!(response.headers()[CACHE_CONTROL], "private, no-store");
    assert_eq!(response.headers()[PRAGMA], "no-cache");
    assert!(!response.headers().contains_key(EXPIRES));
    let denied = gateway_error_response(StatusCode::FORBIDDEN, "denied", None, "denied", false);
    assert_eq!(denied.headers()[CACHE_CONTROL], "private, no-store");
    assert_eq!(denied.headers()[PRAGMA], "no-cache");
}

#[test]
fn gateway_upstream_throttling_forwards_only_a_bounded_retry_after() {
    let date = agent_access_provider::UpstreamRetryAfter::after_seconds(600)
        .at()
        .format("%a, %d %b %Y %H:%M:%S GMT")
        .to_string();
    for (status, retry_after, expected) in [
        (429, Some("30"), Some(30..=30)),
        (429, Some(date.as_str()), Some(598..=601)),
        (429, Some("31536000"), Some(86_400..=86_400)),
        (429, Some("soon"), None),
        (429, None, None),
        (503, Some("30"), None),
    ] {
        let mut upstream_headers = reqwest::header::HeaderMap::new();
        if let Some(value) = retry_after {
            upstream_headers.insert(
                reqwest::header::RETRY_AFTER,
                reqwest::header::HeaderValue::from_str(value).unwrap(),
            );
        }
        let response = fixture_upstream_response(
            status,
            "broker-req-test",
            &upstream_headers,
            Body::from("slow down"),
        );
        assert_eq!(response.status().as_u16(), status);
        let forwarded = response
            .headers()
            .get(axum::http::header::RETRY_AFTER)
            .map(|value| value.to_str().unwrap().parse::<u64>().unwrap());
        match expected {
            Some(range) => assert!(
                forwarded.is_some_and(|seconds| range.contains(&seconds)),
                "{retry_after:?}: {forwarded:?}"
            ),
            None => assert_eq!(forwarded, None, "{status} {retry_after:?}"),
        }
    }
}

#[tokio::test]
async fn gateway_outbound_request_filters_inbound_secrets_and_injects_execution_credential() {
    let client = reqwest::Client::new();
    let mut headers = HeaderMap::new();
    headers.insert(
        AUTHORIZATION,
        HeaderValue::from_static("Basic caller-token"),
    );
    headers.insert(HOST, HeaderValue::from_static("git.example.test"));
    headers.insert("Cookie", HeaderValue::from_static("session=secret"));
    headers.insert(
        REQUEST_ID_HEADER,
        HeaderValue::from_static("caller-request-id"),
    );
    headers.insert(
        BROKER_REQUEST_ID_HEADER,
        HeaderValue::from_static("caller-broker-id"),
    );
    headers.insert(
        agent_access_core::EXECUTION_CONTEXT_HEADER,
        HeaderValue::from_static("external"),
    );
    headers.insert("Accept", HeaderValue::from_static("*/*"));
    headers.insert("User-Agent", HeaderValue::from_static("git/2.51"));
    headers.insert("Git-Protocol", HeaderValue::from_static("version=2"));
    headers.insert(
        CONTENT_TYPE,
        HeaderValue::from_static("application/x-git-upload-pack-request"),
    );
    headers.insert(CONTENT_ENCODING, HeaderValue::from_static("GZIP"));

    // The default Bearer presentation and the configured Basic one both
    // replace the caller's Basic broker token with the upstream token.
    for (token_auth, expected) in [
        (
            agent_access_core::GatewayUpstreamTokenAuth::default(),
            "Bearer upstream-token",
        ),
        (
            agent_access_core::GatewayUpstreamTokenAuth::Basic {
                username: "oauth2".to_string(),
            },
            "Basic b2F1dGgyOnVwc3RyZWFtLXRva2Vu",
        ),
    ] {
        let builder = client
            .post("https://gitlab.example.com/sip/service.git/git-upload-pack")
            .body(Vec::new());
        let plan = fixture_git_plan(
            &test_gateway_config(),
            GitRequestKind::UploadPackPost,
            "sip/service",
            &headers,
            Body::empty(),
            &gateway_test_limits(1024),
        )
        .await
        .unwrap();
        let builder = builder.headers(plan.headers);
        let request = agent_access_provider::host::authorize_host_request(
            builder,
            &agent_access_core::gateway_upstream_authorization(
                &token_auth,
                &agent_access_provider::test_support::bearer_credential("upstream-token"),
            )
            .unwrap(),
        )
        .build()
        .unwrap();

        let authorization = request
            .headers()
            .get_all(reqwest::header::AUTHORIZATION)
            .iter()
            .collect::<Vec<_>>();
        assert_eq!(authorization, [expected]);
        assert!(authorization[0].is_sensitive());
        assert_eq!(request.headers()[reqwest::header::ACCEPT], "*/*");
        assert_eq!(request.headers()[reqwest::header::USER_AGENT], "git/2.51");
        assert_eq!(request.headers()["Git-Protocol"], "version=2");
        assert_eq!(
            request.headers()[reqwest::header::CONTENT_TYPE],
            "application/x-git-upload-pack-request"
        );
        assert_eq!(request.headers()[reqwest::header::CONTENT_ENCODING], "gzip");
        assert!(!request.headers().contains_key(reqwest::header::COOKIE));
        assert!(!request.headers().contains_key(reqwest::header::HOST));
        assert!(!request.headers().contains_key(REQUEST_ID_HEADER));
        assert!(!request.headers().contains_key(BROKER_REQUEST_ID_HEADER));
        assert!(
            !request
                .headers()
                .contains_key(agent_access_core::EXECUTION_CONTEXT_HEADER)
        );
    }
}

#[test]
fn gateway_cap_helpers_detect_declared_overflow() {
    let mut headers = HeaderMap::new();
    headers.insert(CONTENT_LENGTH, HeaderValue::from_static("11"));
    assert!(parsed_content_length(&headers).unwrap().unwrap() > 10);
    assert!(parsed_content_length(&headers).unwrap().unwrap() <= 11);

    let mut response_headers = reqwest::header::HeaderMap::new();
    response_headers.insert(
        reqwest::header::CONTENT_LENGTH,
        reqwest::header::HeaderValue::from_static("12"),
    );
    assert!(parsed_content_length(&response_headers).unwrap().unwrap() > 11);
    assert!(parsed_content_length(&response_headers).unwrap().unwrap() <= 12);
}

#[test]
fn content_length_requires_equal_decimal_values_across_all_fields() {
    for (fields, expected) in [
        (vec![], Ok(None)),
        (vec!["0"], Ok(Some(0))),
        (vec!["00012, 12", "12"], Ok(Some(12))),
        (vec!["\t12 , 12\t"], Ok(Some(12))),
        (vec!["12", "13"], Err(())),
        (vec!["12, 13"], Err(())),
        (vec!["+12"], Err(())),
        (vec!["12x"], Err(())),
        (vec!["12,"], Err(())),
        (vec![""], Err(())),
        (vec!["18446744073709551616"], Err(())),
    ] {
        let mut headers = HeaderMap::new();
        for field in &fields {
            headers.append(CONTENT_LENGTH, HeaderValue::from_str(field).unwrap());
        }
        assert_eq!(parsed_content_length(&headers), expected, "{fields:?}");
    }
}

#[test]
fn basic_only_git_preserves_required_reason_for_unsupported_authorization_schemes() {
    let matched = MatchedGateway {
        service: "gitlab_git".into(),
        config: test_gateway_config(),
    };
    for value in [
        "Bearer token",
        "Negotiate token",
        "Basic",
        "basic dXNlcjpwYXNz",
        "Digest token",
    ] {
        let headers =
            HeaderMap::from_iter([(AUTHORIZATION, HeaderValue::from_str(value).unwrap())]);
        let error = basic_broker_token(&headers, &matched).unwrap_err();
        assert_eq!(
            error.reason_code(),
            ReasonCode::GatewayAuthRequired,
            "{value}"
        );
        assert_eq!(error.message, "gateway basic auth is required");
    }
    let headers =
        HeaderMap::from_iter([(AUTHORIZATION, HeaderValue::from_static("Basic invalid"))]);
    assert_eq!(
        basic_broker_token(&headers, &matched)
            .unwrap_err()
            .reason_code(),
        ReasonCode::GatewayAuthInvalid
    );
}

#[tokio::test]
async fn git_pack_post_trailers_are_discarded_without_losing_data() {
    let limits = GatewayForwardLimits {
        request_body_max_bytes: 4096,
        response_body_max_bytes: 1024,
        idle_timeout: Duration::from_secs(1),
    };
    for kind in [
        GitRequestKind::UploadPackPost,
        GitRequestKind::ReceivePackPost,
    ] {
        let payload = if matches!(kind, GitRequestKind::ReceivePackPost) {
            receive_pack_payload(
                RECEIVE_PACK_OLD,
                RECEIVE_PACK_NEW,
                "refs/heads/main",
                Some("report-status"),
                b"PACK",
            )
        } else {
            b"want data".to_vec()
        };
        let frames = vec![
            Ok::<_, io::Error>(hyper::body::Frame::data(Bytes::copy_from_slice(&payload))),
            Ok(hyper::body::Frame::trailers(HeaderMap::from_iter([(
                axum::http::HeaderName::from_static("x-trailer"),
                HeaderValue::from_static("hidden"),
            )]))),
        ];
        let body = Body::new(http_body_util::StreamBody::new(stream::iter(frames)));
        let headers = HeaderMap::from_iter([(
            CONTENT_TYPE,
            HeaderValue::from_static(if matches!(kind, GitRequestKind::ReceivePackPost) {
                "application/x-git-receive-pack-request"
            } else {
                "application/x-git-upload-pack-request"
            }),
        )]);
        let mut gateway = test_gateway_config();
        gateway.protocol_fields.get_mut("git").unwrap()["allow_push"] = toml::Value::Boolean(true);
        let plan = fixture_git_plan(&gateway, kind, "sip/service", &headers, body, &limits)
            .await
            .unwrap();
        assert!(plan.discard_request_trailers);
        let GatewayPreparedRequestBody::Stream {
            body,
            failure,
            progress,
        } = prepare_protocol_request_body(plan.body, plan.discard_request_trailers, &limits, None)
        else {
            panic!("pack POST must retain a streamed body");
        };
        assert_eq!(&body.collect().await.unwrap().to_bytes()[..], payload);
        assert_eq!(failure.load(Ordering::Relaxed), REPLAY_FAILURE_NONE);
        assert_eq!(progress.bytes.load(Ordering::Relaxed), payload.len() as u64);
    }
}

#[tokio::test]
async fn gateway_request_body_rejects_get_bodies_and_caps_chunked_bodies() {
    let limits = GatewayForwardLimits {
        request_body_max_bytes: 4,
        response_body_max_bytes: 1024,
        idle_timeout: Duration::from_secs(1),
    };

    let mut headers = HeaderMap::new();
    headers.insert(CONTENT_LENGTH, HeaderValue::from_static("1"));
    let error = gateway_request_body_bytes(&Method::GET, &headers, Body::empty(), &limits)
        .await
        .unwrap_err();
    assert_eq!(error.reason_code(), ReasonCode::GatewayRequestBodyDenied);

    let mut headers = HeaderMap::new();
    headers.insert(CONTENT_LENGTH, HeaderValue::from_static("5"));
    let error = gateway_request_body_bytes(&Method::GET, &headers, Body::empty(), &limits)
        .await
        .unwrap_err();
    assert_eq!(error.reason_code(), ReasonCode::GatewayRequestCapExceeded);

    let mut headers = HeaderMap::new();
    headers.insert(CONTENT_LENGTH, HeaderValue::from_static("0"));
    assert_eq!(
        gateway_request_body_bytes(&Method::GET, &headers, Body::empty(), &limits)
            .await
            .unwrap(),
        Vec::<u8>::new()
    );

    let headers = HeaderMap::new();
    let error = gateway_request_body_bytes(&Method::GET, &headers, Body::from("x"), &limits)
        .await
        .unwrap_err();
    assert_eq!(error.reason_code(), ReasonCode::GatewayRequestBodyDenied);

    let headers = HeaderMap::new();
    let error =
        gateway_request_body_bytes(&Method::POST, &headers, Body::from("too large"), &limits)
            .await
            .unwrap_err();
    assert_eq!(error.reason_code(), ReasonCode::GatewayRequestCapExceeded);
}

fn managed_gateway_body_fixture(
    token_action: &str,
    startup_cap: Option<usize>,
    configure: impl FnOnce(&mut BrokerConfig),
) -> (Arc<ReloadableState>, String) {
    let temp = test_temp_dir();
    let service_token_path = temp.join("gateway-early-service-token");
    let hash_key_path = temp.join("gateway-early-hash-key");
    let store_path = temp.join("gateway-early-store.sqlite");
    let audit_path = temp.join("gateway-early.audit.jsonl");
    std::fs::write(&service_token_path, "upstream-token").unwrap();
    std::fs::write(&hash_key_path, URL_SAFE_NO_PAD.encode([29_u8; 32])).unwrap();

    let mut config = test_forwarding_config(&service_token_path, &service_token_path, &audit_path);
    config.identity = IdentityConfig {
        trusted_callers: Default::default(),
        mode: "required".to_string(),
        authority: "managed".to_string(),
        sources: vec![IdentitySourceConfig {
            name: "broker".to_string(),
            kind: "broker_tokens".to_string(),
            header: "Authorization".to_string(),
            scheme: "Bearer".to_string(),
            principals: vec![],
        }],
        groups: vec![],
    };
    let managed_store_config = agent_access_core::ManagedStoreConfig {
        kind: "sqlite".to_string(),
        path: store_path.display().to_string(),
        require_registered_principal_for_invocation: false,
        auto_migrate: true,
    };
    config.managed_store = Some(managed_store_config.clone());
    config.credential_encryption = Some(agent_access_core::CredentialEncryptionConfig {
        active_key: "fixture".into(),
        keys: vec![agent_access_core::CredentialEncryptionKeyConfig {
            id: "fixture".into(),
            provider: "file".into(),
            env: None,
            path: Some(hash_key_path.display().to_string()),
        }],
    });
    config.broker_tokens = Some(agent_access_core::BrokerTokensConfig {
        hash_key_ref: format!("file:{}", hash_key_path.display()),
        ..Default::default()
    });
    config.policy.grants[0].subjects = vec!["user:gateway-user".to_string()];
    config.policy.grants[0].actions = vec!["repo.push".to_string()];
    config
        .gateways
        .get_mut("gitlab_git")
        .unwrap()
        .protocol_fields
        .get_mut("git")
        .unwrap()["allow_push"] = toml::Value::Boolean(true);

    configure(&mut config);
    let store = agent_access_core::ManagedStore::open(
        &managed_store_config,
        &agent_access_core::ConfiguredExecutionContexts::from_config(None).unwrap(),
        agent_access_core::ManagedStoreOpenMode::Startup,
    )
    .unwrap();
    store
        .create_principal(
            agent_access_core::PrincipalWriteRequest {
                agent_token_issuance: Default::default(),
                role: agent_access_core::PrincipalRole::User,
                self_service_enabled: None,
                principal_id: "gateway-user".to_string(),
                kind: "user".to_string(),
                display_name: Some("Gateway User".to_string()),
                email: None,
                external_subject: None,
                created_by: "test".to_string(),
            },
            &agent_access_core::ConfiguredExecutionContexts::from_config(None).unwrap(),
        )
        .unwrap();
    let hasher =
        agent_access_core::BrokerTokenHasher::load(config.broker_tokens.as_ref().unwrap()).unwrap();
    let issued = store
        .issue_broker_token(
            &hasher,
            agent_access_core::BrokerTokenIssueRequest {
                principal_id: "gateway-user".to_string(),
                name: "gateway body fixture token".to_string(),
                token_class: agent_access_core::BrokerTokenClass::AgentInvoke,
                scopes: json!({
                    "allowedServices": ["gitlab_git"],
                    "readOnly": false, "allowedExecutionContexts": ["default"],
                    "serviceRestrictions": {
                        "gitlab_git": {
                            "actions": [token_action]
                        }
                    }
                }),
                expires_at: None,
                created_by: "test".to_string(),
            },
        )
        .unwrap();
    drop(store);

    let runtime = BrokerRuntime::new(config).unwrap();
    let body_hard_cap = startup_cap.unwrap_or(runtime.max_http_body_bytes());
    let audit_registry = runtime.audit_registry();
    let snapshot = RuntimeSnapshot::new(
        1,
        "sha256:gateway-early-admission-test".to_string(),
        runtime.with_config_generation(1),
        StateLockSet::empty(),
    );
    let state = Arc::new(ReloadableState::from_snapshot(
        std::path::PathBuf::new(),
        std::sync::Arc::new(crate::backend_registry()),
        crate::broker_build_status(),
        snapshot,
        body_hard_cap,
        Duration::from_secs(30),
        Duration::from_secs(30),
        audit_registry,
    ));

    let authorization = format!(
        "Basic {}",
        BASE64.encode(format!("agent-access:{}", issued.token))
    );
    (state, authorization)
}

#[tokio::test]
async fn token_disallowed_receive_pack_does_not_poll_request_body() {
    let (state, authorization) = managed_gateway_body_fixture("repo.fetch", None, |_| {});
    let body_polled = Arc::new(AtomicBool::new(false));
    let body_polled_by_stream = Arc::clone(&body_polled);
    let body = Body::from_stream(stream::poll_fn(move |_| {
        body_polled_by_stream.store(true, Ordering::SeqCst);
        Poll::Ready(Some(Ok::<Bytes, io::Error>(Bytes::from_static(
            b"malformed receive-pack body",
        ))))
    }));
    let response = build_gateway_router(state)
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/sip/service.git/git-receive-pack")
                .extension(ConnectInfo(
                    "127.0.0.1:41080".parse::<SocketAddr>().unwrap(),
                ))
                .header(HOST, "git.example.test")
                .header(REQUEST_ID_HEADER, "gateway-early-admission")
                .header(AUTHORIZATION, authorization)
                .header(CONTENT_TYPE, "application/x-git-receive-pack-request")
                .body(body)
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    assert_eq!(
        response.headers()[REASON_CODE_HEADER],
        ReasonCode::ServiceActionDenied.as_str()
    );
    assert!(
        !body_polled.load(Ordering::SeqCst),
        "token caveat denial must precede receive-pack body parsing"
    );
}

/// Git's large-push probe passes the admission, caveat, policy and
/// credential steps of the push it precedes, and is a counted pack POST.
#[tokio::test]
async fn receive_pack_probe_passes_push_admission_and_counts_as_a_pack_post() {
    let (state, authorization) = managed_gateway_body_fixture("repo.push", None, |config| {
        // Reaching forwarding fails with gateway_upstream_denied.
        config
            .gateways
            .get_mut("gitlab_git")
            .unwrap()
            .allowed_upstream_hosts = vec!["https://blocked.example.com/**".into()];
        config.limits.invocations.services.insert(
            "gitlab_git".to_string(),
            agent_access_core::InvocationLimitConfig {
                max_wait: None,
                requests: 1,
                window: "1m".to_string(),
            },
        );
    });
    let forwarded = receive_pack_response(
        Arc::clone(&state),
        authorization.clone(),
        "gateway-probe-forwarded",
        Body::from("0000"),
    )
    .await;
    assert_eq!(forwarded.status(), StatusCode::BAD_GATEWAY);
    assert_eq!(
        forwarded.headers()[REASON_CODE_HEADER],
        ReasonCode::GatewayUpstreamDenied.as_str()
    );
    // The probe spent the one pack POST the window allows.
    let limited = receive_pack_response(
        state,
        authorization,
        "gateway-probe-limited",
        Body::from("0000"),
    )
    .await;
    assert_eq!(limited.status(), StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(
        limited.headers()[REASON_CODE_HEADER],
        ReasonCode::RateLimited.as_str()
    );
}

/// The probe takes the receive-pack forwarding path: the upstream gets
/// the flush packet with the execution credential, and both audit records
/// mark the probe.
#[tokio::test]
async fn receive_pack_probe_is_forwarded_with_the_credential_and_audited() {
    let temp = test_temp_dir();
    let token_path = temp.join("gateway-probe-token");
    let identity_token_path = temp.join("identity-probe-token");
    let audit_path = temp.join("gateway-probe.audit.jsonl");
    std::fs::write(&token_path, "upstream-token").unwrap();
    std::fs::write(&identity_token_path, "identity-token").unwrap();

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let upstream_addr = listener.local_addr().unwrap();
    let upstream = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut request = Vec::new();
        let mut buffer = [0_u8; 1024];
        let head_end = loop {
            let read = stream.read(&mut buffer).await.unwrap();
            assert_ne!(read, 0, "gateway closed before sending the probe");
            request.extend_from_slice(&buffer[..read]);
            if let Some(end) = request.windows(4).position(|bytes| bytes == b"\r\n\r\n")
                && request[end + 4..].ends_with(b"0\r\n\r\n")
            {
                break end + 4;
            }
        };
        stream
                .write_all(
                    b"HTTP/1.1 200 OK\r\nContent-Type: application/x-git-receive-pack-result\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                )
                .await
                .unwrap();
        (request, head_end)
    });

    let mut gateway = test_gateway_config();
    gateway.upstream_base_url = format!("http://{upstream_addr}");
    gateway.allowed_upstream_hosts = vec![format!("http://{upstream_addr}/**")];
    gateway.protocol_fields.get_mut("git").unwrap()["allow_push"] = toml::Value::Boolean(true);
    let git = gateway.protocol_fields["git"].clone();
    let mut config = test_forwarding_config(&token_path, &identity_token_path, &audit_path);
    config.policy.grants[0].actions = vec!["repo.push".to_string()];
    config
        .gateways
        .get_mut("gitlab_git")
        .unwrap()
        .protocol_fields
        .get_mut("git")
        .unwrap()["allow_push"] = toml::Value::Boolean(true);
    let runtime = BrokerRuntime::new(config).unwrap();
    let identity = runtime.identity_from_principal_groups(
        "gateway-user".to_string(),
        None,
        Some("gateway-user".to_string()),
        vec!["gateway-users".to_string()],
        None,
        None,
    );
    let mut headers = HeaderMap::new();
    headers.insert(
        CONTENT_TYPE,
        HeaderValue::from_static("application/x-git-receive-pack-request"),
    );
    headers.insert(CONTENT_LENGTH, HeaderValue::from_static("4"));
    let receive_pack = parse_receive_pack_body(
        Body::from("0000"),
        &git,
        &headers,
        &gateway_test_limits(1024),
    )
    .await
    .unwrap();
    let prepared = runtime
        .prepare_gateway_operation(
            test_governed_operation(OperationContext {
                agent_request_id: "gateway-probe-forward".to_string(),
                broker_request_id: "broker-probe-forward".to_string(),
                identity,
                service: "gitlab_git".to_string(),
                action: "repo.push".to_string(),
                source: agent_access_core::SourceContext::unknown(),
            }),
            ResourceScopes::from([("repository".to_string(), vec!["sip/service".to_string()])]),
        )
        .await
        .unwrap();

    let response = forward_prepared_git_http(
        runtime.clone(),
        gateway,
        GatewayForwardRequest {
            git_request_kind: GitRequestKind::ReceivePackPost,
            headers,
            body: Body::empty(),
            content_encoding: None,
            receive_pack: Some(receive_pack),
        },
        prepared,
        None,
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    assert!(body.is_empty());

    let (request, head_end) = upstream.await.unwrap();
    let head = String::from_utf8_lossy(&request[..head_end]);
    assert!(head.starts_with("POST /sip/service.git/git-receive-pack HTTP/1.1"));
    assert!(head.contains("authorization: Bearer upstream-token"));
    assert!(head.contains("content-type: application/x-git-receive-pack-request"));
    // Like a push, the body is streamed: one chunk holding the flush packet.
    assert_eq!(&request[head_end..], b"4\r\n0000\r\n0\r\n\r\n");

    drain_gateway_test_audit(&runtime).await;
    let records = audit_records(&audit_path);
    let probe_git = json!({"operation": "receive-pack", "probe": true, "updates": []});
    for phase in ["started", "completed"] {
        assert!(
            records.iter().any(|record| {
                record["agentRequestId"] == "gateway-probe-forward"
                    && record["action"] == "repo.push"
                    && record["decision"] == "allow"
                    && record["providerAudit"]["gateway"]["phase"] == phase
                    && record["providerAudit"]["git"] == probe_git
            }),
            "{phase}: {records:?}"
        );
    }
}

/// A caller who could not make the push gets its refusal for the probe.
#[tokio::test]
async fn receive_pack_probe_gets_the_refusal_of_its_push() {
    let push = receive_pack_payload(
        RECEIVE_PACK_OLD,
        RECEIVE_PACK_NEW,
        "refs/heads/feature",
        Some("report-status"),
        b"PACK",
    );
    for (case, token_action, grant_action, reason) in [
        (
            "token caveat",
            "repo.fetch",
            "repo.push",
            ReasonCode::ServiceActionDenied,
        ),
        (
            "no push grant",
            "repo.push",
            "repo.fetch",
            ReasonCode::ServiceActionDenied,
        ),
    ] {
        let (state, authorization) = managed_gateway_body_fixture(token_action, None, |config| {
            config.policy.grants[0].actions = vec![grant_action.to_string()];
            // Forwarding would fail with gateway_upstream_denied.
            config
                .gateways
                .get_mut("gitlab_git")
                .unwrap()
                .allowed_upstream_hosts = vec!["https://blocked.example.com/**".into()];
        });
        let mut refusals = Vec::new();
        for (request_id, body) in [
            ("gateway-refused-push", Body::from(push.clone())),
            ("gateway-refused-probe", Body::from("0000")),
        ] {
            let response =
                receive_pack_response(Arc::clone(&state), authorization.clone(), request_id, body)
                    .await;
            refusals.push((
                response.status(),
                response.headers()[REASON_CODE_HEADER].clone(),
            ));
        }
        assert_eq!(refusals[0], refusals[1], "{case}");
        assert_eq!(
            refusals[1],
            (
                StatusCode::FORBIDDEN,
                HeaderValue::from_static(reason.as_str())
            ),
            "{case}"
        );
    }
}

async fn gateway_body_response(
    state: Arc<ReloadableState>,
    authorization: String,
    body: Body,
) -> Response<Body> {
    receive_pack_response(state, authorization, "gateway-body-bounds", body).await
}

async fn receive_pack_response(
    state: Arc<ReloadableState>,
    authorization: String,
    request_id: &str,
    body: Body,
) -> Response<Body> {
    build_gateway_router(state)
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/sip/service.git/git-receive-pack")
                .extension(ConnectInfo(
                    "127.0.0.1:41080".parse::<SocketAddr>().unwrap(),
                ))
                .header(HOST, "git.example.test")
                .header(REQUEST_ID_HEADER, request_id)
                .header(AUTHORIZATION, authorization)
                .header(CONTENT_TYPE, "application/x-git-receive-pack-request")
                .body(body)
                .unwrap(),
        )
        .await
        .unwrap()
}

#[tokio::test]
async fn gateway_readers_preserve_wrapped_total_deadline_errors() {
    fn timed_out_body() -> Body {
        Body::from_stream(stream::once(async {
            Err::<Bytes, _>(io::Error::other(crate::ingress::body::RequestBodyTimeout))
        }))
    }
    let limits = gateway_test_limits(1024);
    let error =
        gateway_request_body_bytes(&Method::GET, &HeaderMap::new(), timed_out_body(), &limits)
            .await
            .unwrap_err();
    assert_eq!(error.reason_code(), ReasonCode::GatewayRequestBodyDenied);
    let (body, failure, _) = gateway_request_stream_body(timed_out_body(), &limits);
    assert!(body.collect().await.is_err());
    assert_eq!(failure.load(Ordering::Relaxed), REPLAY_FAILURE_TIMEOUT);
}

#[tokio::test]
async fn gateway_router_streamed_receive_pack_preserves_request_cap_classification() {
    // No Content-Length: exercise the real router and incremental body admission.
    for (runtime_cap, startup_cap, gateway_cap) in [
        (256, 256, Some(256)),
        (256, 512, None),
        (512, 256, Some(512)),
        (512, 512, Some(256)),
    ] {
        let (state, authorization) =
            managed_gateway_body_fixture("repo.push", Some(startup_cap), |config| {
                config.limits.max_http_body_bytes = runtime_cap;
                config
                    .gateways
                    .get_mut("gitlab_git")
                    .unwrap()
                    .request_body_max_bytes = gateway_cap;
            });
        let payload = receive_pack_payload(
            RECEIVE_PACK_OLD,
            RECEIVE_PACK_NEW,
            "refs/heads/main",
            Some("report-status"),
            &[b'x'; 256],
        );
        let body = delayed_body(vec![
            (Duration::ZERO, Bytes::copy_from_slice(&payload[..4])),
            (Duration::ZERO, Bytes::copy_from_slice(&payload[4..])),
        ]);
        let response = gateway_body_response(state, authorization, body).await;
        assert_eq!(
            response.status(),
            StatusCode::PAYLOAD_TOO_LARGE,
            "runtime={runtime_cap}, startup={startup_cap}, gateway={gateway_cap:?}"
        );
        assert_eq!(
            response.headers()[REASON_CODE_HEADER],
            ReasonCode::GatewayRequestCapExceeded.as_str()
        );
    }
}

#[tokio::test]
async fn gateway_router_uses_matched_idle_timeout_and_explicit_total_timeout() {
    for total_timeout in [false, true] {
        let (state, authorization) = managed_gateway_body_fixture("repo.push", None, |config| {
            config.limits.streaming_idle_timeout_ms = 10;
            config.limits.request_body_timeout_ms = if total_timeout { 40 } else { 1_000 };
            let gateway = config.gateways.get_mut("gitlab_git").unwrap();
            gateway.streaming_idle_timeout_ms = Some(500);
            gateway.protocol_fields.get_mut("git").unwrap()["deny_ref_patterns"] =
                toml::Value::Array(vec![toml::Value::String("refs/heads/main".into())]);
        });
        let payload = receive_pack_payload(
            RECEIVE_PACK_OLD,
            RECEIVE_PACK_NEW,
            "refs/heads/main",
            Some("report-status"),
            b"PACK",
        );
        let response = gateway_body_response(
            state,
            authorization,
            delayed_body(vec![(Duration::from_millis(100), Bytes::from(payload))]),
        )
        .await;
        if total_timeout {
            assert_eq!(response.status(), StatusCode::BAD_REQUEST);
            assert_eq!(
                response.headers()[REASON_CODE_HEADER],
                ReasonCode::GatewayRequestBodyDenied.as_str()
            );
            let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
                .await
                .unwrap();
            assert!(
                std::str::from_utf8(&bytes)
                    .unwrap()
                    .contains("request body read timed out")
            );
        } else {
            assert_eq!(response.status(), StatusCode::FORBIDDEN);
            assert_eq!(
                response.headers()[REASON_CODE_HEADER],
                ReasonCode::GitRefDenied.as_str()
            );
        }
    }
}

#[tokio::test]
async fn token_namespace_caveat_limits_git_gateway_repository_before_forwarding() {
    let temp = test_temp_dir();
    let service_token_path = temp.join("gateway-namespace-service-token");
    let hash_key_path = temp.join("gateway-namespace-hash-key");
    let store_path = temp.join("gateway-namespace-store.sqlite");
    let audit_path = temp.join("gateway-namespace.audit.jsonl");
    std::fs::write(&service_token_path, "upstream-token").unwrap();
    std::fs::write(&hash_key_path, URL_SAFE_NO_PAD.encode([31_u8; 32])).unwrap();

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let upstream_addr = listener.local_addr().unwrap();
    let upstream = tokio::spawn(async move {
        let (_stream, _) = listener.accept().await.unwrap();
        timeout(Duration::from_millis(100), listener.accept())
            .await
            .is_ok()
    });

    let mut config = test_forwarding_config(&service_token_path, &service_token_path, &audit_path);
    config.identity = IdentityConfig {
        trusted_callers: Default::default(),
        mode: "required".to_string(),
        authority: "managed".to_string(),
        sources: vec![IdentitySourceConfig {
            name: "broker".to_string(),
            kind: "broker_tokens".to_string(),
            header: "Authorization".to_string(),
            scheme: "Bearer".to_string(),
            principals: vec![],
        }],
        groups: vec![],
    };
    let managed_store_config = agent_access_core::ManagedStoreConfig {
        kind: "sqlite".to_string(),
        path: store_path.display().to_string(),
        require_registered_principal_for_invocation: false,
        auto_migrate: true,
    };
    config.managed_store = Some(managed_store_config.clone());
    config.credential_encryption = Some(agent_access_core::CredentialEncryptionConfig {
        active_key: "fixture".into(),
        keys: vec![agent_access_core::CredentialEncryptionKeyConfig {
            id: "fixture".into(),
            provider: "file".into(),
            env: None,
            path: Some(hash_key_path.display().to_string()),
        }],
    });
    config.broker_tokens = Some(agent_access_core::BrokerTokensConfig {
        hash_key_ref: format!("file:{}", hash_key_path.display()),
        ..Default::default()
    });
    config.policy.grants[0].subjects = vec!["user:gateway-user".to_string()];
    config.policy.resources.extend([
        gateway_resource(
            "other",
            agent_access_provider::ResourceSelector::Exact {
                value: "other/tool".to_string(),
            },
        ),
        gateway_resource(
            "sip-namespace",
            agent_access_provider::ResourceSelector::Namespace {
                value: "sip".to_string(),
            },
        ),
    ]);
    config.policy.grants[0]
        .resources
        .resource_ids
        .push("other".to_string());
    let gateway = config.gateways.get_mut("gitlab_git").unwrap();
    gateway.upstream_base_url = format!("https://{upstream_addr}");
    gateway.allowed_upstream_hosts = vec![format!("https://{upstream_addr}/**")];

    let store = agent_access_core::ManagedStore::open(
        &managed_store_config,
        &agent_access_core::ConfiguredExecutionContexts::from_config(None).unwrap(),
        agent_access_core::ManagedStoreOpenMode::Startup,
    )
    .unwrap();
    store
        .create_principal(
            agent_access_core::PrincipalWriteRequest {
                agent_token_issuance: Default::default(),
                role: agent_access_core::PrincipalRole::User,
                self_service_enabled: None,
                principal_id: "gateway-user".to_string(),
                kind: "user".to_string(),
                display_name: Some("Gateway User".to_string()),
                email: None,
                external_subject: None,
                created_by: "test".to_string(),
            },
            &agent_access_core::ConfiguredExecutionContexts::from_config(None).unwrap(),
        )
        .unwrap();
    let hasher =
        agent_access_core::BrokerTokenHasher::load(config.broker_tokens.as_ref().unwrap()).unwrap();
    let issued = store
        .issue_broker_token_with_catalog(
            &hasher,
            agent_access_core::BrokerTokenIssueRequest {
                principal_id: "gateway-user".to_string(),
                name: "sip namespace gateway token".to_string(),
                token_class: agent_access_core::BrokerTokenClass::AgentInvoke,
                scopes: json!({
                    "allowedServices": ["gitlab_git"],
                    "readOnly": false, "allowedExecutionContexts": ["default"],
                    "serviceRestrictions": {
                        "gitlab_git": {
                            "actions": ["repo.fetch"],
                            "resources": {"resourceIds":["sip-namespace"]}
                        }
                    }
                }),
                expires_at: None,
                created_by: "test".to_string(),
            },
            Some(&agent_access_core::ManagedResourceCatalog {
                attribute_bindings: Vec::new(),
                resource_fences: Default::default(),
                resources: config.policy.resources.clone(),
                resource_groups: config.policy.resource_groups.clone(),
            }),
        )
        .unwrap();
    drop(store);

    let runtime = BrokerRuntime::new(config).unwrap();
    let body_hard_cap = runtime.max_http_body_bytes();
    let audit_registry = runtime.audit_registry();
    let snapshot = RuntimeSnapshot::new(
        1,
        "sha256:gateway-namespace-admission-test".to_string(),
        runtime.with_config_generation(1),
        StateLockSet::empty(),
    );
    let state = Arc::new(ReloadableState::from_snapshot(
        std::path::PathBuf::new(),
        std::sync::Arc::new(crate::backend_registry()),
        crate::broker_build_status(),
        snapshot,
        body_hard_cap,
        Duration::from_secs(30),
        Duration::from_secs(30),
        audit_registry,
    ));
    let authorization = format!(
        "Basic {}",
        BASE64.encode(format!("agent-access:{}", issued.token))
    );
    let request = |path: &'static str, request_id: &'static str| {
        Request::builder()
            .method(Method::GET)
            .uri(path)
            .extension(ConnectInfo(
                "127.0.0.1:41081".parse::<SocketAddr>().unwrap(),
            ))
            .header(HOST, "git.example.test")
            .header(REQUEST_ID_HEADER, request_id)
            .header(AUTHORIZATION, authorization.clone())
            .body(Body::empty())
            .unwrap()
    };

    let allowed = build_gateway_router(Arc::clone(&state))
        .oneshot(request(
            "/sip/service.git/info/refs?service=git-upload-pack",
            "gateway-namespace-allowed",
        ))
        .await
        .unwrap();
    assert_eq!(allowed.status(), StatusCode::BAD_GATEWAY);

    let denied = build_gateway_router(state)
        .oneshot(request(
            "/other/tool.git/info/refs?service=git-upload-pack",
            "gateway-namespace-denied",
        ))
        .await
        .unwrap();
    assert_eq!(denied.status(), StatusCode::FORBIDDEN);
    assert_eq!(
        denied.headers()[REASON_CODE_HEADER],
        ReasonCode::ServiceActionDenied.as_str()
    );
    assert!(
        !upstream.await.unwrap(),
        "resource caveat denial must precede upstream forwarding"
    );
}

#[tokio::test]
async fn prepare_gateway_request_body_streams_upload_pack_posts() {
    let limits = GatewayForwardLimits {
        request_body_max_bytes: 4,
        response_body_max_bytes: 1024,
        idle_timeout: Duration::from_secs(1),
    };

    let streamed = prepare_gateway_request_body(
        &Method::POST,
        &HeaderMap::new(),
        Body::from("want"),
        None,
        &limits,
    )
    .await
    .unwrap();
    assert!(matches!(
        streamed,
        GatewayPreparedRequestBody::Stream { .. }
    ));

    let mut headers = HeaderMap::new();
    headers.insert(CONTENT_LENGTH, HeaderValue::from_static("5"));
    let error = match prepare_gateway_request_body(
        &Method::POST,
        &headers,
        Body::from("large"),
        None,
        &limits,
    )
    .await
    {
        Ok(_) => panic!("declared oversized POST body should be rejected"),
        Err(error) => error,
    };
    assert_eq!(error.reason_code(), ReasonCode::GatewayRequestCapExceeded);
}

#[tokio::test]
async fn gateway_send_watchdog_tracks_upload_and_response_header_idle_timeouts() {
    let result = gateway_send_with_upload_watchdog(
        std::future::pending::<Result<(), ()>>(),
        None,
        Duration::from_millis(5),
    )
    .await;
    assert!(matches!(
        result,
        Err(GatewaySendError::ResponseHeadersIdleTimeout)
    ));

    let not_started = Arc::new(GatewayRequestUploadProgress::new());
    let result = tokio::time::timeout(
        Duration::from_millis(20),
        gateway_send_with_upload_watchdog(
            std::future::pending::<Result<(), ()>>(),
            Some(not_started),
            Duration::from_millis(5),
        ),
    )
    .await;
    assert!(result.is_err());

    let progress = Arc::new(GatewayRequestUploadProgress::new());
    progress.mark_progress();
    let result = gateway_send_with_upload_watchdog(
        std::future::pending::<Result<(), ()>>(),
        Some(progress),
        Duration::from_millis(5),
    )
    .await;
    assert!(matches!(
        result,
        Err(GatewaySendError::RequestUploadIdleTimeout)
    ));

    let complete = Arc::new(GatewayRequestUploadProgress::new());
    complete.mark_complete();
    let result = gateway_send_with_upload_watchdog(
        std::future::pending::<Result<(), ()>>(),
        Some(complete),
        Duration::from_millis(5),
    )
    .await;
    assert!(matches!(
        result,
        Err(GatewaySendError::ResponseHeadersIdleTimeout)
    ));
}

#[tokio::test]
async fn gateway_forwarding_maps_dispatched_upload_pack_cap_to_uncertain_error() {
    let temp = test_temp_dir();
    let token_path = temp.join("gateway-upload-cap-token");
    let identity_token_path = temp.join("identity-upload-cap-token");
    let audit_path = temp.join("gateway-upload-cap.audit.jsonl");
    std::fs::write(&token_path, "upstream-token").unwrap();
    std::fs::write(&identity_token_path, "identity-token").unwrap();

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let upstream_addr = listener.local_addr().unwrap();
    let upstream = tokio::spawn(async move {
        let (_stream, _) = listener.accept().await.unwrap();
        tokio::time::sleep(Duration::from_millis(50)).await;
    });

    let runtime = BrokerRuntime::new(test_forwarding_config(
        &token_path,
        &identity_token_path,
        &audit_path,
    ))
    .unwrap();
    let identity = runtime.identity_from_principal_groups(
        "gateway-user".to_string(),
        None,
        Some("gateway-user".to_string()),
        vec!["gateway-users".to_string()],
        None,
        None,
    );
    let mut gateway = test_gateway_config();
    gateway.upstream_base_url = format!("http://{upstream_addr}");
    gateway.allowed_upstream_hosts = vec![format!("http://{upstream_addr}/**")];
    gateway.request_body_max_bytes = Some(4);
    let prepared = runtime
        .prepare_gateway_operation(
            test_governed_operation(OperationContext {
                agent_request_id: "gateway-upload-cap-forward".to_string(),
                broker_request_id: "broker-upload-cap-forward".to_string(),
                identity,
                service: "gitlab_git".to_string(),
                action: "repo.fetch".to_string(),
                source: agent_access_core::SourceContext::unknown(),
            }),
            ResourceScopes::from([("repository".to_string(), vec!["sip/service".to_string()])]),
        )
        .await
        .unwrap();
    let mut headers = HeaderMap::new();
    headers.insert(
        CONTENT_TYPE,
        HeaderValue::from_static("application/x-git-upload-pack-request"),
    );

    let response = forward_prepared_git_http(
        runtime.clone(),
        gateway,
        GatewayForwardRequest {
            git_request_kind: GitRequestKind::UploadPackPost,
            headers,
            body: Body::from("large"),
            content_encoding: None,
            receive_pack: None,
        },
        prepared,
        None,
    )
    .await;

    assert_eq!(response.status(), StatusCode::BAD_GATEWAY);
    assert_eq!(
        response.headers()[REASON_CODE_HEADER],
        ReasonCode::GatewayRequestCapExceeded.as_str()
    );
    upstream.await.unwrap();
    drain_gateway_test_audit(&runtime).await;
    let records = audit_records(&audit_path);
    assert!(records.iter().any(|record| {
        record["agentRequestId"] == "gateway-upload-cap-forward"
            && record["decision"] == "error"
            && record["reasonCode"] == ReasonCode::GatewayRequestCapExceeded.as_str()
            && record["providerAudit"]["gateway"]["phase"] == "failed"
            && record["providerAudit"]["gateway"]["message"]
                .as_str()
                .is_some_and(|message| message.contains("partial or uncertain"))
    }));
}

#[tokio::test]
async fn unsubmitted_upload_drop_preserves_final_fence_denial() {
    let temp = test_temp_dir();
    let token_path = temp.join("upstream-token");
    let identity_path = temp.join("identity-token");
    let audit_path = temp.join("audit.jsonl");
    std::fs::write(&token_path, "upstream-token").unwrap();
    std::fs::write(&identity_path, "identity-token").unwrap();
    let runtime = BrokerRuntime::new(test_forwarding_config(
        &token_path,
        &identity_path,
        &audit_path,
    ))
    .unwrap();
    let identity = runtime.identity_from_principal_groups(
        "gateway-user".into(),
        None,
        Some("gateway-user".into()),
        vec!["gateway-users".into()],
        None,
        None,
    );
    let mut prepared = runtime
        .prepare_gateway_operation(
            test_governed_operation(OperationContext {
                agent_request_id: "unsubmitted-upload".into(),
                broker_request_id: "unsubmitted-upload".into(),
                identity,
                service: "gitlab_git".into(),
                action: "repo.fetch".into(),
                source: agent_access_core::SourceContext::unknown(),
            }),
            ResourceScopes::from([("repository".into(), vec!["sip/service".into()])]),
        )
        .await
        .unwrap();
    runtime
        .start_prepared_gateway_operation(&mut prepared, json!({"gateway":{"requestBytes":0}}))
        .await
        .unwrap();
    let progress = Arc::new(GatewayRequestUploadProgress::new());
    progress.audit.lock().unwrap().lease = prepared.retain_gateway_request_body();
    drop(GatewayUploadOwner {
        progress,
        _permits: None,
    });
    let response = runtime
        .fail_prepared_gateway_operation(
            prepared,
            ProviderError::deny(
                ReasonCode::ServiceActionDenied,
                "gateway dispatch generation retired",
            )
            .with_audit(json!({"gateway":{"requestBytes":0}})),
        )
        .await;
    assert_eq!(
        response.envelope.decision,
        agent_access_provider::Decision::Deny
    );
    drain_gateway_test_audit(&runtime).await;
    let records = audit_records(&audit_path);
    let terminal: Vec<_> = records
        .iter()
        .filter(|record| record["providerAudit"]["gateway"]["phase"] == "failed")
        .collect();
    assert_eq!(terminal.len(), 1, "{records:?}");
    assert_eq!(terminal[0]["decision"], "deny");
    assert_eq!(terminal[0]["reasonCode"], "service_action_denied");
    assert_eq!(terminal[0]["providerAudit"]["gateway"]["requestBytes"], 0);
    assert!(
        !terminal[0]["providerAudit"]["gateway"]["message"]
            .as_str()
            .unwrap_or_default()
            .contains("uncertain")
    );
}

#[tokio::test]
async fn gateway_forwarding_preserves_upload_pack_content_encoding() {
    let temp = test_temp_dir();
    let token_path = temp.join("gateway-upload-encoding-token");
    let identity_token_path = temp.join("identity-upload-encoding-token");
    let audit_path = temp.join("gateway-upload-encoding.audit.jsonl");
    std::fs::write(&token_path, "upstream-token").unwrap();
    std::fs::write(&identity_token_path, "identity-token").unwrap();

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let upstream_addr = listener.local_addr().unwrap();
    let (request_tx, request_rx) = oneshot::channel();
    let upstream = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut request = Vec::new();
        let mut buffer = [0_u8; 1024];
        loop {
            let read = stream.read(&mut buffer).await.unwrap();
            assert_ne!(
                read, 0,
                "gateway closed before sending upstream upload-pack request"
            );
            request.extend_from_slice(&buffer[..read]);
            if request.windows(9).any(|window| window == b"gzip-body") {
                break;
            }
        }
        request_tx.send(request).unwrap();
        stream
                .write_all(
                    b"HTTP/1.1 200 OK\r\nContent-Type: application/x-git-upload-pack-result\r\nContent-Length: 4\r\nConnection: close\r\n\r\n0000",
                )
                .await
                .unwrap();
    });

    let runtime = BrokerRuntime::new(test_forwarding_config(
        &token_path,
        &identity_token_path,
        &audit_path,
    ))
    .unwrap();
    let identity = runtime.identity_from_principal_groups(
        "gateway-user".to_string(),
        None,
        Some("gateway-user".to_string()),
        vec!["gateway-users".to_string()],
        None,
        None,
    );
    let mut gateway = test_gateway_config();
    gateway.upstream_base_url = format!("http://{upstream_addr}");
    gateway.allowed_upstream_hosts = vec![format!("http://{upstream_addr}/**")];
    let prepared = runtime
        .prepare_gateway_operation(
            test_governed_operation(OperationContext {
                agent_request_id: "gateway-upload-encoding-forward".to_string(),
                broker_request_id: "broker-upload-encoding-forward".to_string(),
                identity,
                service: "gitlab_git".to_string(),
                action: "repo.fetch".to_string(),
                source: agent_access_core::SourceContext::unknown(),
            }),
            ResourceScopes::from([("repository".to_string(), vec!["sip/service".to_string()])]),
        )
        .await
        .unwrap();
    let mut headers = HeaderMap::new();
    headers.insert(
        CONTENT_TYPE,
        HeaderValue::from_static("application/x-git-upload-pack-request"),
    );

    let response = forward_prepared_git_http(
        runtime.clone(),
        gateway,
        GatewayForwardRequest {
            git_request_kind: GitRequestKind::UploadPackPost,
            headers,
            body: Body::from("gzip-body"),
            content_encoding: Some(GitContentEncoding::Gzip),
            receive_pack: None,
        },
        prepared,
        None,
    )
    .await;

    let upstream_request = request_rx.await.unwrap();
    let upstream_text = String::from_utf8_lossy(&upstream_request);
    assert!(upstream_text.starts_with("POST /sip/service.git/git-upload-pack HTTP/1.1"));
    assert!(upstream_text.contains("authorization: Bearer upstream-token"));
    assert!(upstream_text.contains("content-type: application/x-git-upload-pack-request"));
    assert!(upstream_text.contains("content-encoding: gzip"));
    assert!(
        upstream_request
            .windows(9)
            .any(|window| window == b"gzip-body")
    );
    assert_eq!(response.status(), StatusCode::OK);
    upstream.await.unwrap();
    drain_gateway_test_audit(&runtime).await;
}

#[tokio::test]
async fn shared_cache_cannot_replay_git_discovery_between_broker_tokens() {
    use rustls::pki_types::{CertificateDer, PrivateKeyDer, pem::PemObject};
    use std::io::{Read, Write};

    // This deliberately identity-blind cache models RFC 9111 storage for this
    // fixture: a successful authenticated GET with explicit public freshness.
    // private/no-store must override public and prevent reuse across callers.
    fn shared_cache_can_store(headers: &HeaderMap) -> bool {
        let directives = headers
            .get_all(CACHE_CONTROL)
            .iter()
            .filter_map(|value| value.to_str().ok())
            .flat_map(|value| value.split(','))
            .map(|value| value.trim().to_ascii_lowercase())
            .collect::<Vec<_>>();
        directives.iter().any(|value| value == "public")
            && directives.iter().any(|value| value == "max-age=3600")
            && !directives
                .iter()
                .any(|value| value == "private" || value == "no-store" || value == "no-cache")
    }
    let mut public_headers = HeaderMap::new();
    public_headers.insert(
        CACHE_CONTROL,
        HeaderValue::from_static("public, max-age=3600"),
    );
    assert!(
        shared_cache_can_store(&public_headers),
        "fixture must expose the original cache vulnerability"
    );

    let temp = test_temp_dir();
    let service_token = temp.join("upstream-token");
    let hash_key = temp.join("hash-key");
    let audit_path = temp.join("cache.audit.jsonl");
    std::fs::write(&service_token, "upstream-token").unwrap();
    std::fs::write(&hash_key, URL_SAFE_NO_PAD.encode([39_u8; 32])).unwrap();
    let fixture = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../agent-access-core/tests/fixtures/outbound-tls");
    let certificate = std::fs::read(fixture.join("leaf-a.pem")).unwrap();
    let key = std::fs::read(fixture.join("leaf-a.key")).unwrap();
    let tls = Arc::new(
        rustls::ServerConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(
            CertificateDer::pem_slice_iter(&certificate)
                .collect::<Result<Vec<_>, _>>()
                .unwrap(),
            PrivateKeyDer::from_pem_slice(&key).unwrap(),
        )
        .unwrap(),
    );
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let upstream_addr = listener.local_addr().unwrap();
    // The accept deadline starts with the first Broker request, not
    // during the store and runtime setup before it. The sender drops if
    // the test fails first; the wait for it is bounded too.
    let (request_started, request_start) = std::sync::mpsc::channel::<()>();
    let upstream = std::thread::spawn(move || {
        if request_start
            .recv_timeout(Duration::from_secs(300))
            .is_err()
        {
            return;
        }
        let deadline = Instant::now() + Duration::from_secs(10);
        let (stream, _) = loop {
            match listener.accept() {
                Ok(connection) => break connection,
                Err(error)
                    if error.kind() == io::ErrorKind::WouldBlock && Instant::now() < deadline =>
                {
                    std::thread::sleep(Duration::from_millis(5))
                }
                Err(error) => panic!("upstream accept: {error}"),
            }
        };
        stream
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        stream
            .set_write_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        let mut stream =
            rustls::StreamOwned::new(rustls::ServerConnection::new(tls).unwrap(), stream);
        let mut request = Vec::new();
        let mut byte = [0; 1];
        while !request.ends_with(b"\r\n\r\n") {
            stream.read_exact(&mut byte).unwrap();
            request.extend_from_slice(&byte);
            assert!(request.len() < 16_384);
        }
        assert!(String::from_utf8_lossy(&request).contains("authorization: Bearer upstream-token"));
        stream.write_all(b"HTTP/1.1 200 OK\r\nContent-Type: application/x-git-upload-pack-advertisement\r\nCache-Control: public, max-age=3600\r\nExpires: Thu, 01 Oct 2099 00:00:00 GMT\r\nContent-Length: 4\r\nConnection: close\r\n\r\n0000").unwrap();
        stream.flush().unwrap();
    });
    let mut config = test_forwarding_config(&service_token, &service_token, &audit_path);
    config.identity = IdentityConfig {
        trusted_callers: Default::default(),
        mode: "required".into(),
        authority: "managed".into(),
        sources: vec![IdentitySourceConfig {
            name: "broker".into(),
            kind: "broker_tokens".into(),
            header: "Authorization".into(),
            scheme: "Bearer".into(),
            principals: vec![],
        }],
        groups: vec![],
    };
    let store_config = agent_access_core::ManagedStoreConfig {
        kind: "sqlite".into(),
        path: temp.join("store.sqlite").display().to_string(),
        require_registered_principal_for_invocation: false,
        auto_migrate: true,
    };
    config.managed_store = Some(store_config.clone());
    config.credential_encryption = Some(agent_access_core::CredentialEncryptionConfig {
        active_key: "fixture".into(),
        keys: vec![agent_access_core::CredentialEncryptionKeyConfig {
            id: "fixture".into(),
            provider: "file".into(),
            env: None,
            path: Some(hash_key.display().to_string()),
        }],
    });
    config.broker_tokens = Some(agent_access_core::BrokerTokensConfig {
        hash_key_ref: format!("file:{}", hash_key.display()),
        ..Default::default()
    });
    config.network.outbound_tls = agent_access_core::OutboundTlsConfig {
        trust: agent_access_core::OutboundTlsTrustMode::Custom,
        ca_certificate: Some(fixture.join("ca-a.pem")),
    };
    config.policy.grants[0].subjects = vec!["user:gateway-user".into()];
    let gateway = config.gateways.get_mut("gitlab_git").unwrap();
    gateway.upstream_base_url = format!("https://{upstream_addr}");
    gateway.allowed_upstream_hosts = vec![format!("https://{upstream_addr}/**")];
    let store = agent_access_core::ManagedStore::open(
        &store_config,
        &agent_access_core::ConfiguredExecutionContexts::from_config(None).unwrap(),
        agent_access_core::ManagedStoreOpenMode::Startup,
    )
    .unwrap();
    let hasher =
        agent_access_core::BrokerTokenHasher::load(config.broker_tokens.as_ref().unwrap()).unwrap();
    let mut tokens = Vec::new();
    for principal in ["gateway-user", "denied-user"] {
        store
            .create_principal(
                agent_access_core::PrincipalWriteRequest {
                    agent_token_issuance: Default::default(),
                    role: agent_access_core::PrincipalRole::User,
                    self_service_enabled: None,
                    principal_id: principal.into(),
                    kind: "user".into(),
                    display_name: None,
                    email: None,
                    external_subject: None,
                    created_by: "test".into(),
                },
                &agent_access_core::ConfiguredExecutionContexts::from_config(None).unwrap(),
            )
            .unwrap();
        tokens.push(store.issue_broker_token(&hasher, agent_access_core::BrokerTokenIssueRequest { principal_id: principal.into(), name: "cache test".into(), token_class: agent_access_core::BrokerTokenClass::AgentInvoke, scopes: json!({"allowedServices":["gitlab_git"], "readOnly": false, "allowedExecutionContexts":["default"]}), expires_at: None, created_by: "test".into() }).unwrap().token);
    }
    drop(store);
    let runtime = BrokerRuntime::new(config).unwrap();
    let body_hard_cap = runtime.max_http_body_bytes();
    let audit_registry = runtime.audit_registry();
    let snapshot = RuntimeSnapshot::new(
        1,
        "sha256:cache-test".into(),
        runtime.clone().with_config_generation(1),
        StateLockSet::empty(),
    );
    let state = Arc::new(ReloadableState::from_snapshot(
        std::path::PathBuf::new(),
        Arc::new(crate::backend_registry()),
        crate::broker_build_status(),
        snapshot,
        body_hard_cap,
        Duration::from_secs(30),
        Duration::from_secs(30),
        audit_registry,
    ));
    let router = build_gateway_router(state);
    let mut cache: Option<(StatusCode, HeaderMap, Bytes)> = None;
    let mut broker_calls = 0;
    for (index, token) in tokens.iter().enumerate() {
        let (status, headers, body) = if let Some(cached) = &cache {
            cached.clone()
        } else {
            broker_calls += 1;
            if index == 0 {
                request_started.send(()).unwrap();
            }
            let response = router
                .clone()
                .oneshot(
                    Request::builder()
                        .method(Method::GET)
                        .uri("/sip/service.git/info/refs?service=git-upload-pack")
                        .extension(ConnectInfo(
                            "127.0.0.1:41081".parse::<SocketAddr>().unwrap(),
                        ))
                        .header(HOST, "git.example.test")
                        .header(
                            AUTHORIZATION,
                            format!("Basic {}", BASE64.encode(format!("agent-access:{token}"))),
                        )
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();
            let status = response.status();
            let headers = response.headers().clone();
            let body = axum::body::to_bytes(response.into_body(), 4096)
                .await
                .unwrap();
            if status == StatusCode::OK && shared_cache_can_store(&headers) {
                cache = Some((status, headers.clone(), body.clone()));
            }
            (status, headers, body)
        };
        assert_eq!(headers[CACHE_CONTROL], "private, no-store");
        assert_eq!(headers[PRAGMA], "no-cache");
        assert!(!headers.contains_key(EXPIRES));
        if index == 0 {
            assert_eq!(status, StatusCode::OK, "{}", String::from_utf8_lossy(&body));
            assert_eq!(&body[..], b"0000");
        } else {
            assert_eq!(status, StatusCode::FORBIDDEN);
            assert_ne!(&body[..], b"0000");
        }
    }
    assert_eq!(
        broker_calls, 2,
        "each caller must reach broker authorization"
    );
    assert!(cache.is_none());
    upstream.join().unwrap();
    drain_gateway_test_audit(&runtime).await;
}

#[tokio::test]
async fn gateway_forwarding_sanitizes_headers_and_audits_before_upstream_response() {
    let temp = test_temp_dir();
    let token_path = temp.join("gateway-token");
    let identity_token_path = temp.join("identity-token");
    let audit_path = temp.join("gateway-forward.audit.jsonl");
    std::fs::write(&token_path, "upstream-token").unwrap();
    std::fs::write(&identity_token_path, "identity-token").unwrap();

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let upstream_addr = listener.local_addr().unwrap();
    let (request_tx, request_rx) = oneshot::channel();
    let (release_tx, release_rx) = oneshot::channel();
    let upstream = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut request = Vec::new();
        let mut buffer = [0_u8; 1024];
        loop {
            let read = stream.read(&mut buffer).await.unwrap();
            assert_ne!(read, 0, "gateway closed before sending upstream request");
            request.extend_from_slice(&buffer[..read]);
            if request.windows(4).any(|window| window == b"\r\n\r\n") {
                break;
            }
        }
        request_tx
            .send(String::from_utf8_lossy(&request).into_owned())
            .unwrap();
        release_rx.await.unwrap();
        stream
                .write_all(
                    b"HTTP/1.1 200 OK\r\nContent-Type: application/x-git-upload-pack-advertisement\r\nServer: hidden\r\nContent-Length: 4\r\nConnection: close\r\n\r\n0000",
                )
                .await
                .unwrap();
    });

    let runtime = BrokerRuntime::new(test_forwarding_config(
        &token_path,
        &identity_token_path,
        &audit_path,
    ))
    .unwrap();
    let identity = runtime.identity_from_principal_groups(
        "gateway-user".to_string(),
        None,
        Some("gateway-user".to_string()),
        vec!["gateway-users".to_string()],
        None,
        None,
    );
    let mut gateway = test_gateway_config();
    gateway.upstream_base_url = format!("http://{upstream_addr}");
    gateway.allowed_upstream_hosts = vec![format!("http://{upstream_addr}/**")];
    let prepared = runtime
        .prepare_gateway_operation(
            test_governed_operation(OperationContext {
                agent_request_id: "gateway-forward".to_string(),
                broker_request_id: "broker-forward".to_string(),
                identity,
                service: "gitlab_git".to_string(),
                action: "repo.fetch".to_string(),
                source: agent_access_core::SourceContext::unknown(),
            }),
            ResourceScopes::from([("repository".to_string(), vec!["sip/service".to_string()])]),
        )
        .await
        .unwrap();

    let mut headers = HeaderMap::new();
    headers.insert(
        AUTHORIZATION,
        HeaderValue::from_static("Basic caller-token"),
    );
    headers.insert(HOST, HeaderValue::from_static("git.example.test"));
    headers.insert("Cookie", HeaderValue::from_static("session=secret"));
    headers.insert(ACCEPT, HeaderValue::from_static("*/*"));
    headers.insert(USER_AGENT, HeaderValue::from_static("git/2.51"));
    headers.insert("Git-Protocol", HeaderValue::from_static("version=2"));

    let runtime_for_forward = runtime.clone();
    let forward = tokio::spawn(async move {
        forward_prepared_git_http(
            runtime_for_forward,
            gateway,
            GatewayForwardRequest {
                git_request_kind: GitRequestKind::UploadPackDiscovery,
                headers,
                body: Body::empty(),
                content_encoding: None,
                receive_pack: None,
            },
            prepared,
            None,
        )
        .await
    });

    let upstream_request = request_rx.await.unwrap();
    assert!(
        upstream_request
            .starts_with("GET /sip/service.git/info/refs?service=git-upload-pack HTTP/1.1")
    );
    assert!(upstream_request.contains("authorization: Bearer upstream-token"));
    assert!(!upstream_request.contains("Basic caller-token"));
    assert!(!upstream_request.to_ascii_lowercase().contains("cookie:"));
    assert!(!upstream_request.contains("git.example.test"));
    assert!(upstream_request.contains("git-protocol: version=2"));

    let started_records = audit_records(&audit_path);
    let request_records = started_records
        .iter()
        .filter(|record| record["agentRequestId"] == "gateway-forward")
        .collect::<Vec<_>>();
    assert_eq!(request_records.len(), 1);
    assert_eq!(
        request_records[0]["providerAudit"]["gateway"]["phase"],
        "started"
    );
    assert_eq!(request_records[0]["decision"], "allow");

    release_tx.send(()).unwrap();
    let response = forward.await.unwrap();
    upstream.await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response.headers()[CONTENT_TYPE],
        "application/x-git-upload-pack-advertisement"
    );
    assert!(!response.headers().contains_key("Server"));
    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    assert_eq!(&body[..], b"0000");

    drain_gateway_test_audit(&runtime).await;
    let records = audit_records(&audit_path);
    let request_records = records
        .iter()
        .filter(|record| record["agentRequestId"] == "gateway-forward")
        .collect::<Vec<_>>();
    assert_eq!(request_records.len(), 2);
    assert!(request_records.iter().any(|record| {
        record["providerAudit"]["gateway"]["phase"] == "started"
            && record["providerAudit"]["gateway"]["responseBytes"] == 0
    }));
    assert!(request_records.iter().any(|record| {
        record["upstreamStatus"] == 200
            && record["providerAudit"]["gateway"]["phase"] == "completed"
            && record["providerAudit"]["gateway"]["method"] == "GET"
            && record["providerAudit"]["gateway"]["responseBytes"] == 4
    }));
}

#[tokio::test]
async fn gateway_streaming_response_outlives_global_request_timeout_while_data_flows() {
    let temp = test_temp_dir();
    let token_path = temp.join("gateway-timeout-token");
    let identity_token_path = temp.join("identity-timeout-token");
    let audit_path = temp.join("gateway-timeout.audit.jsonl");
    std::fs::write(&token_path, "upstream-token").unwrap();
    std::fs::write(&identity_token_path, "identity-token").unwrap();

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let upstream_addr = listener.local_addr().unwrap();
    let upstream = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        read_http_request_headers(&mut stream).await;
        stream
                .write_all(
                    b"HTTP/1.1 200 OK\r\nContent-Type: application/x-git-upload-pack-advertisement\r\nContent-Length: 4\r\nConnection: close\r\n\r\n",
                )
                .await
                .unwrap();
        tokio::time::sleep(Duration::from_millis(50)).await;
        stream.write_all(b"0000").await.unwrap();
    });

    let mut config = test_forwarding_config(&token_path, &identity_token_path, &audit_path);
    config.limits.request_timeout_ms = 10;
    let runtime = BrokerRuntime::new(config).unwrap();
    let identity = runtime.identity_from_principal_groups(
        "gateway-user".to_string(),
        None,
        Some("gateway-user".to_string()),
        vec!["gateway-users".to_string()],
        None,
        None,
    );
    let mut gateway = test_gateway_config();
    gateway.upstream_base_url = format!("http://{upstream_addr}");
    gateway.allowed_upstream_hosts = vec![format!("http://{upstream_addr}/**")];
    gateway.streaming_idle_timeout_ms = Some(1_000);
    let prepared = runtime
        .prepare_gateway_operation(
            test_governed_operation(OperationContext {
                agent_request_id: "gateway-timeout-forward".to_string(),
                broker_request_id: "broker-timeout-forward".to_string(),
                identity,
                service: "gitlab_git".to_string(),
                action: "repo.fetch".to_string(),
                source: agent_access_core::SourceContext::unknown(),
            }),
            ResourceScopes::from([("repository".to_string(), vec!["sip/service".to_string()])]),
        )
        .await
        .unwrap();

    let response = forward_prepared_git_http(
        runtime.clone(),
        gateway,
        GatewayForwardRequest {
            git_request_kind: GitRequestKind::UploadPackDiscovery,
            headers: HeaderMap::new(),
            body: Body::empty(),
            content_encoding: None,
            receive_pack: None,
        },
        prepared,
        None,
    )
    .await;

    assert_eq!(response.status(), StatusCode::OK);
    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    assert_eq!(&body[..], b"0000");
    upstream.await.unwrap();
}

#[tokio::test]
async fn gateway_forwarding_holds_permits_until_response_body_finishes() {
    let temp = test_temp_dir();
    let token_path = temp.join("gateway-permit-token");
    let identity_token_path = temp.join("identity-permit-token");
    let audit_path = temp.join("gateway-permit.audit.jsonl");
    std::fs::write(&token_path, "upstream-token").unwrap();
    std::fs::write(&identity_token_path, "identity-token").unwrap();

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let upstream_addr = listener.local_addr().unwrap();
    let (release_tx, release_rx) = oneshot::channel();
    let upstream = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        read_http_request_headers(&mut stream).await;
        stream
                .write_all(
                    b"HTTP/1.1 200 OK\r\nContent-Type: application/x-git-upload-pack-advertisement\r\nContent-Length: 4\r\nConnection: close\r\n\r\n",
                )
                .await
                .unwrap();
        release_rx.await.unwrap();
        stream.write_all(b"0000").await.unwrap();
    });

    let runtime = BrokerRuntime::new(test_forwarding_config(
        &token_path,
        &identity_token_path,
        &audit_path,
    ))
    .unwrap();
    let identity = runtime.identity_from_principal_groups(
        "gateway-user".to_string(),
        None,
        Some("gateway-user".to_string()),
        vec!["gateway-users".to_string()],
        None,
        None,
    );
    let mut gateway = test_gateway_config();
    gateway.upstream_base_url = format!("http://{upstream_addr}");
    gateway.allowed_upstream_hosts = vec![format!("http://{upstream_addr}/**")];
    let prepared = runtime
        .prepare_gateway_operation(
            test_governed_operation(OperationContext {
                agent_request_id: "gateway-permit-forward".to_string(),
                broker_request_id: "broker-permit-forward".to_string(),
                identity,
                service: "gitlab_git".to_string(),
                action: "repo.fetch".to_string(),
                source: agent_access_core::SourceContext::unknown(),
            }),
            ResourceScopes::from([("repository".to_string(), vec!["sip/service".to_string()])]),
        )
        .await
        .unwrap();
    let guards = Arc::new(crate::ingress::guards::IngressGuards::new());
    let global_permit = guards.try_global_concurrency(1).unwrap();
    let principal_permit = guards.try_principal_concurrency("gateway-user", 1).unwrap();

    let response = forward_prepared_git_http(
        runtime.clone(),
        gateway,
        GatewayForwardRequest {
            git_request_kind: GitRequestKind::UploadPackDiscovery,
            headers: HeaderMap::new(),
            body: Body::empty(),
            content_encoding: None,
            receive_pack: None,
        },
        prepared,
        Some(RequestPermits {
            _global: global_permit,
            _principal: principal_permit,
        }),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    assert!(guards.try_global_concurrency(1).is_err());
    assert!(guards.try_principal_concurrency("gateway-user", 1).is_err());

    release_tx.send(()).unwrap();
    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    assert_eq!(&body[..], b"0000");
    drop(guards.try_global_concurrency(1).unwrap());
    drop(guards.try_principal_concurrency("gateway-user", 1).unwrap());
    upstream.await.unwrap();
}

#[tokio::test]
async fn gateway_upstream_429_passes_through_and_is_audited_as_upstream_rate_limited() {
    let temp = test_temp_dir();
    let token_path = temp.join("gateway-429-token");
    let identity_token_path = temp.join("identity-429-token");
    let audit_path = temp.join("gateway-429.audit.jsonl");
    std::fs::write(&token_path, "upstream-token").unwrap();
    std::fs::write(&identity_token_path, "identity-token").unwrap();

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let upstream_addr = listener.local_addr().unwrap();
    let upstream = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        read_http_request_headers(&mut stream).await;
        stream
                .write_all(
                    b"HTTP/1.1 429 Too Many Requests\r\nContent-Type: text/plain\r\nRetry-After: 30\r\nContent-Length: 10\r\nConnection: close\r\n\r\nslow down\n",
                )
                .await
                .unwrap();
    });

    let runtime = BrokerRuntime::new(test_forwarding_config(
        &token_path,
        &identity_token_path,
        &audit_path,
    ))
    .unwrap();
    let identity = runtime.identity_from_principal_groups(
        "gateway-user".to_string(),
        None,
        Some("gateway-user".to_string()),
        vec!["gateway-users".to_string()],
        None,
        None,
    );
    let mut gateway = test_gateway_config();
    gateway.upstream_base_url = format!("http://{upstream_addr}");
    gateway.allowed_upstream_hosts = vec![format!("http://{upstream_addr}/**")];
    let prepared = runtime
        .prepare_gateway_operation(
            test_governed_operation(OperationContext {
                agent_request_id: "gateway-upstream-429".to_string(),
                broker_request_id: "broker-upstream-429".to_string(),
                identity,
                service: "gitlab_git".to_string(),
                action: "repo.fetch".to_string(),
                source: agent_access_core::SourceContext::unknown(),
            }),
            ResourceScopes::from([("repository".to_string(), vec!["sip/service".to_string()])]),
        )
        .await
        .unwrap();

    let response = forward_prepared_git_http(
        runtime.clone(),
        gateway,
        GatewayForwardRequest {
            git_request_kind: GitRequestKind::UploadPackDiscovery,
            headers: HeaderMap::new(),
            body: Body::empty(),
            content_encoding: None,
            receive_pack: None,
        },
        prepared,
        None,
    )
    .await;
    // The Git client sees the upstream throttling unchanged, with a
    // bounded whole-second Retry-After.
    assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(response.headers()[axum::http::header::RETRY_AFTER], "30");
    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    assert_eq!(&body[..], b"slow down\n");
    upstream.await.unwrap();

    drain_gateway_test_audit(&runtime).await;
    let records = audit_records(&audit_path);
    let terminal = records
        .iter()
        .filter(|record| record["agentRequestId"] == "gateway-upstream-429")
        .find(|record| record["providerAudit"]["gateway"]["phase"] != "started")
        .unwrap();
    assert_eq!(terminal["decision"], "error");
    assert_eq!(terminal["reasonCode"], "upstream_rate_limited");
    assert_eq!(terminal["upstreamStatus"], 429);
    assert_eq!(terminal["providerAudit"]["gateway"]["phase"], "failed");
    assert_eq!(terminal["providerAudit"]["gateway"]["responseBytes"], 10);
}

#[tokio::test]
async fn gateway_streaming_response_cap_applies_without_content_length() {
    let temp = test_temp_dir();
    let token_path = temp.join("gateway-cap-token");
    let identity_token_path = temp.join("identity-cap-token");
    let audit_path = temp.join("gateway-cap.audit.jsonl");
    std::fs::write(&token_path, "upstream-token").unwrap();
    std::fs::write(&identity_token_path, "identity-token").unwrap();

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let upstream_addr = listener.local_addr().unwrap();
    let upstream = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        read_http_request_headers(&mut stream).await;
        stream
                .write_all(
                    b"HTTP/1.1 200 OK\r\nContent-Type: application/x-git-upload-pack-advertisement\r\nConnection: close\r\n\r\n0000",
                )
                .await
                .unwrap();
    });

    let runtime = BrokerRuntime::new(test_forwarding_config(
        &token_path,
        &identity_token_path,
        &audit_path,
    ))
    .unwrap();
    let identity = runtime.identity_from_principal_groups(
        "gateway-user".to_string(),
        None,
        Some("gateway-user".to_string()),
        vec!["gateway-users".to_string()],
        None,
        None,
    );
    let mut gateway = test_gateway_config();
    gateway.upstream_base_url = format!("http://{upstream_addr}");
    gateway.allowed_upstream_hosts = vec![format!("http://{upstream_addr}/**")];
    gateway.response_body_max_bytes = Some(3);
    let prepared = runtime
        .prepare_gateway_operation(
            test_governed_operation(OperationContext {
                agent_request_id: "gateway-cap-forward".to_string(),
                broker_request_id: "broker-cap-forward".to_string(),
                identity,
                service: "gitlab_git".to_string(),
                action: "repo.fetch".to_string(),
                source: agent_access_core::SourceContext::unknown(),
            }),
            ResourceScopes::from([("repository".to_string(), vec!["sip/service".to_string()])]),
        )
        .await
        .unwrap();

    let response = forward_prepared_git_http(
        runtime.clone(),
        gateway,
        GatewayForwardRequest {
            git_request_kind: GitRequestKind::UploadPackDiscovery,
            headers: HeaderMap::new(),
            body: Body::empty(),
            content_encoding: None,
            receive_pack: None,
        },
        prepared,
        None,
    )
    .await;

    assert_eq!(response.status(), StatusCode::OK);
    assert!(
        axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .is_err()
    );
    upstream.await.unwrap();

    drain_gateway_test_audit(&runtime).await;
    let records = audit_records(&audit_path);
    assert!(records.iter().any(|record| {
        record["agentRequestId"] == "gateway-cap-forward"
            && record["decision"] == "error"
            && record["reasonCode"] == ReasonCode::GatewayResponseCapExceeded.as_str()
            && record["providerAudit"]["gateway"]["phase"] == "failed"
    }));
}

#[tokio::test]
async fn gateway_forwarding_streams_receive_pack_after_prefix_authorization() {
    let temp = test_temp_dir();
    let token_path = temp.join("gateway-push-token");
    let identity_token_path = temp.join("identity-push-token");
    let audit_path = temp.join("gateway-push-forward.audit.jsonl");
    std::fs::write(&token_path, "upstream-token").unwrap();
    std::fs::write(&identity_token_path, "identity-token").unwrap();

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let upstream_addr = listener.local_addr().unwrap();
    let (request_tx, request_rx) = oneshot::channel();
    let (release_tx, release_rx) = oneshot::channel();
    let upstream = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut request = Vec::new();
        let mut buffer = [0_u8; 1024];
        loop {
            let read = stream.read(&mut buffer).await.unwrap();
            assert_ne!(
                read, 0,
                "gateway closed before sending upstream push request"
            );
            request.extend_from_slice(&buffer[..read]);
            if request.windows(4).any(|window| window == b"PACK") {
                break;
            }
        }
        request_tx.send(request).unwrap();
        release_rx.await.unwrap();
        stream
                .write_all(
                    b"HTTP/1.1 200 OK\r\nContent-Type: application/x-git-receive-pack-result\r\nContent-Length: 4\r\nConnection: close\r\n\r\n0000",
                )
                .await
                .unwrap();
    });

    let mut config = test_forwarding_config(&token_path, &identity_token_path, &audit_path);
    config.policy.grants[0].actions = vec!["repo.push".to_string()];
    config
        .gateways
        .get_mut("gitlab_git")
        .unwrap()
        .protocol_fields
        .get_mut("git")
        .unwrap()["allow_push"] = toml::Value::Boolean(true);
    let runtime = BrokerRuntime::new(config).unwrap();
    let identity = runtime.identity_from_principal_groups(
        "gateway-user".to_string(),
        None,
        Some("gateway-user".to_string()),
        vec!["gateway-users".to_string()],
        None,
        None,
    );
    let mut gateway = test_gateway_config();
    gateway.upstream_base_url = format!("http://{upstream_addr}");
    gateway.allowed_upstream_hosts = vec![format!("http://{upstream_addr}/**")];
    gateway.protocol_fields.get_mut("git").unwrap()["allow_push"] = toml::Value::Boolean(true);
    let prepared = runtime
        .prepare_gateway_operation(
            test_governed_operation(OperationContext {
                agent_request_id: "gateway-push-forward".to_string(),
                broker_request_id: "broker-push-forward".to_string(),
                identity,
                service: "gitlab_git".to_string(),
                action: "repo.push".to_string(),
                source: agent_access_core::SourceContext::unknown(),
            }),
            ResourceScopes::from([("repository".to_string(), vec!["sip/service".to_string()])]),
        )
        .await
        .unwrap();

    let mut headers = HeaderMap::new();
    headers.insert(
        AUTHORIZATION,
        HeaderValue::from_static("Basic caller-token"),
    );
    headers.insert(HOST, HeaderValue::from_static("git.example.test"));
    headers.insert(
        CONTENT_TYPE,
        HeaderValue::from_static("application/x-git-receive-pack-request"),
    );
    headers.insert(ACCEPT, HeaderValue::from_static("*/*"));
    headers.insert(USER_AGENT, HeaderValue::from_static("git/2.51"));
    let payload = receive_pack_payload(
        RECEIVE_PACK_OLD,
        RECEIVE_PACK_NEW,
        "refs/heads/feature",
        Some("report-status side-band-64k agent=broker-test"),
        b"PACK",
    );
    let limits = gateway_forward_limits(&runtime, &gateway);
    let receive_pack = parse_receive_pack_body(
        Body::from(payload),
        &gateway.protocol_fields["git"],
        &headers,
        &limits,
    )
    .await
    .unwrap();

    let runtime_for_forward = runtime.clone();
    let forward = tokio::spawn(async move {
        forward_prepared_git_http(
            runtime_for_forward,
            gateway,
            GatewayForwardRequest {
                git_request_kind: GitRequestKind::ReceivePackPost,
                headers,
                body: Body::empty(),
                content_encoding: None,
                receive_pack: Some(receive_pack),
            },
            prepared,
            None,
        )
        .await
    });

    let upstream_request = request_rx.await.unwrap();
    let upstream_text = String::from_utf8_lossy(&upstream_request);
    assert!(upstream_text.starts_with("POST /sip/service.git/git-receive-pack HTTP/1.1"));
    assert!(upstream_text.contains("authorization: Bearer upstream-token"));
    assert!(upstream_text.contains("content-type: application/x-git-receive-pack-request"));
    assert!(!upstream_text.contains("Basic caller-token"));
    assert!(upstream_text.contains("refs/heads/feature"));
    assert!(upstream_request.windows(4).any(|window| window == b"PACK"));

    let started_records = audit_records(&audit_path);
    assert!(started_records.iter().any(|record| {
        record["agentRequestId"] == "gateway-push-forward"
            && record["providerAudit"]["gateway"]["phase"] == "started"
            && record["providerAudit"]["git"]["updates"][0]["ref"] == "refs/heads/feature"
    }));

    release_tx.send(()).unwrap();
    let response = forward.await.unwrap();
    upstream.await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    assert_eq!(&body[..], b"0000");

    drain_gateway_test_audit(&runtime).await;
    let records = audit_records(&audit_path);
    assert!(records.iter().any(|record| {
        record["agentRequestId"] == "gateway-push-forward"
            && record["upstreamStatus"] == 200
            && record["providerAudit"]["gateway"]["phase"] == "completed"
            && record["providerAudit"]["gateway"]["method"] == "POST"
            && record["providerAudit"]["git"]["updates"][0]["ref"] == "refs/heads/feature"
    }));
}

#[tokio::test]
async fn gateway_forwarding_receive_pack_upload_outlives_idle_timeout_while_data_flows() {
    let temp = test_temp_dir();
    let token_path = temp.join("gateway-slow-push-token");
    let identity_token_path = temp.join("identity-slow-push-token");
    let audit_path = temp.join("gateway-slow-push-forward.audit.jsonl");
    std::fs::write(&token_path, "upstream-token").unwrap();
    std::fs::write(&identity_token_path, "identity-token").unwrap();

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let upstream_addr = listener.local_addr().unwrap();
    let (elapsed_tx, elapsed_rx) = oneshot::channel();
    let upstream = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let started = Instant::now();
        let mut request = read_http_request_headers(&mut stream).await;
        let mut buffer = [0_u8; 1024];
        while !request
            .windows(b"PACK-4".len())
            .any(|window| window == b"PACK-4")
        {
            let read = stream.read(&mut buffer).await.unwrap();
            assert_ne!(
                read, 0,
                "gateway closed before streaming the complete push request"
            );
            request.extend_from_slice(&buffer[..read]);
        }
        elapsed_tx.send(started.elapsed()).unwrap();
        stream
                .write_all(
                    b"HTTP/1.1 200 OK\r\nContent-Type: application/x-git-receive-pack-result\r\nContent-Length: 4\r\nConnection: close\r\n\r\n0000",
                )
                .await
                .unwrap();
    });

    let mut config = test_forwarding_config(&token_path, &identity_token_path, &audit_path);
    config.policy.grants[0].actions = vec!["repo.push".to_string()];
    config
        .gateways
        .get_mut("gitlab_git")
        .unwrap()
        .protocol_fields
        .get_mut("git")
        .unwrap()["allow_push"] = toml::Value::Boolean(true);
    let runtime = BrokerRuntime::new(config).unwrap();
    let identity = runtime.identity_from_principal_groups(
        "gateway-user".to_string(),
        None,
        Some("gateway-user".to_string()),
        vec!["gateway-users".to_string()],
        None,
        None,
    );
    let mut gateway = test_gateway_config();
    gateway.upstream_base_url = format!("http://{upstream_addr}");
    gateway.allowed_upstream_hosts = vec![format!("http://{upstream_addr}/**")];
    gateway.streaming_idle_timeout_ms = Some(80);
    gateway.protocol_fields.get_mut("git").unwrap()["allow_push"] = toml::Value::Boolean(true);
    let prepared = runtime
        .prepare_gateway_operation(
            test_governed_operation(OperationContext {
                agent_request_id: "gateway-slow-push-forward".to_string(),
                broker_request_id: "broker-slow-push-forward".to_string(),
                identity,
                service: "gitlab_git".to_string(),
                action: "repo.push".to_string(),
                source: agent_access_core::SourceContext::unknown(),
            }),
            ResourceScopes::from([("repository".to_string(), vec!["sip/service".to_string()])]),
        )
        .await
        .unwrap();

    let mut headers = HeaderMap::new();
    headers.insert(
        CONTENT_TYPE,
        HeaderValue::from_static("application/x-git-receive-pack-request"),
    );
    let prefix = receive_pack_payload(
        RECEIVE_PACK_OLD,
        RECEIVE_PACK_NEW,
        "refs/heads/feature",
        Some("report-status side-band-64k"),
        b"",
    );
    let body = delayed_body(vec![
        (Duration::ZERO, Bytes::from(prefix)),
        (Duration::from_millis(30), Bytes::from_static(b"PACK-1")),
        (Duration::from_millis(30), Bytes::from_static(b"PACK-2")),
        (Duration::from_millis(30), Bytes::from_static(b"PACK-3")),
        (Duration::from_millis(30), Bytes::from_static(b"PACK-4")),
    ]);
    let limits = gateway_forward_limits(&runtime, &gateway);
    let receive_pack =
        parse_receive_pack_body(body, &gateway.protocol_fields["git"], &headers, &limits)
            .await
            .unwrap();

    let response = forward_prepared_git_http(
        runtime.clone(),
        gateway,
        GatewayForwardRequest {
            git_request_kind: GitRequestKind::ReceivePackPost,
            headers,
            body: Body::empty(),
            content_encoding: None,
            receive_pack: Some(receive_pack),
        },
        prepared,
        None,
    )
    .await;

    let elapsed_before_response = elapsed_rx.await.unwrap();
    assert!(
        elapsed_before_response >= Duration::from_millis(100),
        "test upload completed too quickly to exceed the idle interval: {elapsed_before_response:?}"
    );
    upstream.await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    assert_eq!(&body[..], b"0000");

    drain_gateway_test_audit(&runtime).await;
    let records = audit_records(&audit_path);
    assert!(records.iter().any(|record| {
        record["agentRequestId"] == "gateway-slow-push-forward"
            && record["upstreamStatus"] == 200
            && record["providerAudit"]["gateway"]["phase"] == "completed"
            && record["providerAudit"]["gateway"]["method"] == "POST"
    }));
}

const RECEIVE_PACK_OLD: &str = "1111111111111111111111111111111111111111";
const RECEIVE_PACK_NEW: &str = "2222222222222222222222222222222222222222";

fn gateway_test_limits(request_body_max_bytes: usize) -> GatewayForwardLimits {
    GatewayForwardLimits {
        request_body_max_bytes,
        response_body_max_bytes: 1024,
        idle_timeout: Duration::from_secs(1),
    }
}

fn receive_pack_payload(
    old_id: &str,
    new_id: &str,
    ref_name: &str,
    capabilities: Option<&str>,
    trailer: &[u8],
) -> Vec<u8> {
    let mut command = format!("{old_id} {new_id} {ref_name}");
    if let Some(capabilities) = capabilities {
        command.push('\0');
        command.push_str(capabilities);
    }
    let mut payload = pkt_line(command.as_bytes());
    payload.extend_from_slice(b"0000");
    payload.extend_from_slice(trailer);
    payload
}

fn delayed_body(chunks: Vec<(Duration, Bytes)>) -> Body {
    Body::from_stream(stream::unfold(
        VecDeque::from(chunks),
        |mut chunks| async move {
            let (delay, chunk) = chunks.pop_front()?;
            if !delay.is_zero() {
                tokio::time::sleep(delay).await;
            }
            Some((Ok::<Bytes, io::Error>(chunk), chunks))
        },
    ))
}

fn pkt_line(payload: &[u8]) -> Vec<u8> {
    let mut packet = format!("{:04x}", payload.len() + 4).into_bytes();
    packet.extend_from_slice(payload);
    packet
}

/// Forwards one upload-pack discovery for `gateway-user` through
/// `runtime`, with `token_auth` on the gateway, to a loopback upstream and
/// returns the one `authorization` header line the upstream received.
async fn forwarded_upstream_authorization(
    runtime: &BrokerRuntime,
    token_auth: agent_access_core::GatewayUpstreamTokenAuth,
    request_id: &str,
) -> String {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let upstream_addr = listener.local_addr().unwrap();
    let upstream = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let request = read_http_request_headers(&mut stream).await;
        stream
                .write_all(
                    b"HTTP/1.1 200 OK\r\nContent-Type: application/x-git-upload-pack-advertisement\r\nContent-Length: 4\r\nConnection: close\r\n\r\n0000",
                )
                .await
                .unwrap();
        String::from_utf8(request).unwrap()
    });
    let identity = runtime.identity_from_principal_groups(
        "gateway-user".to_string(),
        Some(agent_access_core::PrincipalKind::User),
        Some("gateway-user".to_string()),
        vec!["gateway-users".to_string()],
        None,
        None,
    );
    let mut gateway = runtime.config().gateways["gitlab_git"].clone();
    gateway.upstream_base_url = format!("http://{upstream_addr}");
    gateway.allowed_upstream_hosts = vec![format!("http://{upstream_addr}/**")];
    gateway.upstream_token_auth = token_auth;
    let prepared = runtime
        .prepare_gateway_operation(
            test_governed_operation(OperationContext {
                agent_request_id: request_id.to_string(),
                broker_request_id: format!("broker-{request_id}"),
                identity,
                service: "gitlab_git".to_string(),
                action: "repo.fetch".to_string(),
                source: agent_access_core::SourceContext::unknown(),
            }),
            ResourceScopes::from([("repository".to_string(), vec!["sip/service".to_string()])]),
        )
        .await
        .unwrap();

    let response = forward_prepared_git_http(
        runtime.clone(),
        gateway,
        GatewayForwardRequest {
            git_request_kind: GitRequestKind::UploadPackDiscovery,
            headers: HeaderMap::new(),
            body: Body::empty(),
            content_encoding: None,
            receive_pack: None,
        },
        prepared,
        None,
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    let body = axum::body::to_bytes(response.into_body(), 1024)
        .await
        .unwrap();
    assert_eq!(&body[..], b"0000");
    let request = upstream.await.unwrap();
    let authorization = request
        .lines()
        .filter(|line| line.to_ascii_lowercase().starts_with("authorization:"))
        .collect::<Vec<_>>();
    assert_eq!(authorization.len(), 1, "{request}");
    authorization[0].to_string()
}

fn basic_token_auth(username: &str) -> agent_access_core::GatewayUpstreamTokenAuth {
    agent_access_core::GatewayUpstreamTokenAuth::Basic {
        username: username.to_string(),
    }
}

/// A static `bearer_token` service credential is a Bearer token by
/// default and the password of HTTP Basic under the configured username.
#[tokio::test]
async fn gateway_presents_a_static_bearer_service_credential_as_configured() {
    let temp = test_temp_dir();
    let token_path = temp.join("gateway-presentation-service-token");
    let identity_token_path = temp.join("gateway-presentation-identity-token");
    let audit_path = temp.join("gateway-presentation-service.audit.jsonl");
    std::fs::write(&token_path, "upstream-token").unwrap();
    std::fs::write(&identity_token_path, "identity-token").unwrap();
    let runtime = BrokerRuntime::new(test_forwarding_config(
        &token_path,
        &identity_token_path,
        &audit_path,
    ))
    .unwrap();

    assert_eq!(
        forwarded_upstream_authorization(
            &runtime,
            agent_access_core::GatewayUpstreamTokenAuth::default(),
            "gateway-presentation-service-bearer",
        )
        .await,
        "authorization: Bearer upstream-token"
    );
    assert_eq!(
        forwarded_upstream_authorization(
            &runtime,
            basic_token_auth("oauth2"),
            "gateway-presentation-service-basic",
        )
        .await,
        "authorization: Basic b2F1dGgyOnVwc3RyZWFtLXRva2Vu"
    );
    drain_gateway_test_audit(&runtime).await;
}

/// A `basic_api_token` service credential presents its own stored
/// username whatever `upstream_token_auth` selects for tokens.
#[tokio::test]
async fn gateway_basic_service_credential_keeps_its_own_username() {
    let temp = test_temp_dir();
    let username_path = temp.join("gateway-presentation-basic-username");
    let token_path = temp.join("gateway-presentation-basic-token");
    let identity_token_path = temp.join("gateway-presentation-basic-identity-token");
    let audit_path = temp.join("gateway-presentation-basic.audit.jsonl");
    std::fs::write(&username_path, "deploy-user").unwrap();
    std::fs::write(&token_path, "deploy-token").unwrap();
    std::fs::write(&identity_token_path, "identity-token").unwrap();
    let mut config = test_forwarding_config(&token_path, &identity_token_path, &audit_path);
    let credential = config.credentials.service.get_mut("gitlab_git").unwrap();
    credential.kind = "basic_api_token".to_string();
    credential.username_ref = Some(format!("file:{}", username_path.display()));
    let runtime = BrokerRuntime::new(config).unwrap();

    for (token_auth, request_id) in [
        (
            agent_access_core::GatewayUpstreamTokenAuth::default(),
            "gateway-presentation-basic-default",
        ),
        (
            basic_token_auth("oauth2"),
            "gateway-presentation-basic-configured",
        ),
    ] {
        assert_eq!(
            forwarded_upstream_authorization(&runtime, token_auth, request_id).await,
            "authorization: Basic ZGVwbG95LXVzZXI6ZGVwbG95LXRva2Vu"
        );
    }
    drain_gateway_test_audit(&runtime).await;
}

/// A per-user `git-bearer-token` credential read through the gateway's
/// credential connection, keyed by the connection's ID, is presented
/// under the configured Basic username, like a static one.
#[tokio::test]
async fn gateway_presents_a_per_user_managed_bearer_credential_as_configured() {
    let temp = test_temp_dir();
    let token_path = temp.join("gateway-presentation-unused-service-token");
    let identity_token_path = temp.join("gateway-presentation-managed-identity-token");
    let key_path = temp.join("gateway-presentation-managed-key");
    let store_path = temp.join("gateway-presentation-managed.sqlite");
    let audit_path = temp.join("gateway-presentation-managed.audit.jsonl");
    std::fs::write(&token_path, "service-token").unwrap();
    std::fs::write(&identity_token_path, "identity-token").unwrap();
    std::fs::write(&key_path, URL_SAFE_NO_PAD.encode([41_u8; 32])).unwrap();
    let mut config = test_forwarding_config(&token_path, &identity_token_path, &audit_path);
    let store_config = agent_access_core::ManagedStoreConfig {
        kind: "sqlite".to_string(),
        path: store_path.display().to_string(),
        require_registered_principal_for_invocation: false,
        auto_migrate: true,
    };
    config.managed_store = Some(store_config.clone());
    config.credential_encryption = Some(agent_access_core::CredentialEncryptionConfig {
        active_key: "fixture".into(),
        keys: vec![agent_access_core::CredentialEncryptionKeyConfig {
            id: "fixture".into(),
            provider: "file".into(),
            env: None,
            path: Some(key_path.display().to_string()),
        }],
    });
    config.credentials.service.clear();
    config.credentials.connections.insert(
        "gitlab".to_string(),
        agent_access_core::ConnectionConfig {
            display_name: None,
            token_profiles: Some(vec!["git-bearer-token".to_string()]),
            service_account_token_profiles: None,
            oauth: None,
        },
    );
    config.credentials.per_user.insert(
        "gitlab_git".to_string(),
        CredentialConfig {
            kind: "connection".to_string(),
            username_ref: None,
            token_ref: None,
            provider: None,
            path: None,
            read_only: None,
            connection: Some("gitlab".to_string()),
            profile: None,
        },
    );
    config
        .gateways
        .get_mut("gitlab_git")
        .unwrap()
        .credential_modes = vec!["per_user".to_string()];
    config.policy.grants[0].credential_mode = "per_user".to_string();
    let store = agent_access_core::ManagedStore::open(
        &store_config,
        &agent_access_core::ConfiguredExecutionContexts::from_config(None).unwrap(),
        agent_access_core::ManagedStoreOpenMode::Startup,
    )
    .unwrap();
    store
        .create_principal(
            agent_access_core::PrincipalWriteRequest {
                agent_token_issuance: Default::default(),
                role: agent_access_core::PrincipalRole::User,
                self_service_enabled: None,
                principal_id: "gateway-user".to_string(),
                kind: "user".to_string(),
                display_name: None,
                email: None,
                external_subject: None,
                created_by: "test".to_string(),
            },
            &agent_access_core::ConfiguredExecutionContexts::from_config(None).unwrap(),
        )
        .unwrap();
    drop(store);
    let runtime = BrokerRuntime::new(config).unwrap();
    runtime
        .managed_store()
        .unwrap()
        .upsert_user_credential(
            runtime.credential_key_ring().unwrap(),
            agent_access_core::CredentialWriteRequest {
                owner_principal_id: "gateway-user".to_string(),
                service: "gitlab".to_string(),
                name: "default".to_string(),
                profile: "git-bearer-token".to_string(),
                credential_kind: "bearer_token".to_string(),
                secret: json!({"token": "personal-token"}),
                metadata: json!({}),
                actor: "test".to_string(),
            },
            agent_access_core::CredentialManagementPurpose::Administrative,
        )
        .unwrap();

    assert_eq!(
        forwarded_upstream_authorization(
            &runtime,
            agent_access_core::GatewayUpstreamTokenAuth::default(),
            "gateway-presentation-managed-bearer",
        )
        .await,
        "authorization: Bearer personal-token"
    );
    assert_eq!(
        forwarded_upstream_authorization(
            &runtime,
            basic_token_auth("oauth2"),
            "gateway-presentation-managed-basic",
        )
        .await,
        "authorization: Basic b2F1dGgyOnBlcnNvbmFsLXRva2Vu"
    );
    drain_gateway_test_audit(&runtime).await;
    // Gateway records name the connection the personal token came from.
    let records = audit_records(&audit_path)
        .into_iter()
        .filter(|record| record["service"] == "gitlab_git")
        .collect::<Vec<_>>();
    assert!(!records.is_empty());
    for record in records {
        assert_eq!(record["credentialMode"], "per_user", "{record}");
        assert_eq!(record["credentialConnection"], "gitlab", "{record}");
    }
}

/// GitLab REST as the real descriptor declares it, recording the
/// credentials scope resolution and execution receive.
struct SharedGitlabRestProvider {
    descriptor: agent_access_provider::ServiceDescriptor,
    seen: std::sync::Arc<std::sync::Mutex<Vec<Option<agent_access_provider::ExecutionCredential>>>>,
}

impl agent_access_provider::test_support::DescribedProvider for SharedGitlabRestProvider {
    fn descriptor(&self) -> agent_access_provider::ServiceDescriptor {
        self.descriptor.clone()
    }
}

#[async_trait::async_trait]
impl agent_access_provider::Provider for SharedGitlabRestProvider {
    async fn resolve_scopes(
        &self,
        request: agent_access_provider::ScopeRequest<'_>,
    ) -> Result<agent_access_provider::ScopeResolution, ProviderError> {
        self.seen
            .lock()
            .unwrap()
            .push(request.lookup_access().map(|access| {
                access
                    .static_credential()
                    .expect("GitLab REST receives only static lookup access")
                    .clone()
            }));
        let project = request.inputs()["project"].as_str().unwrap().to_owned();
        Ok(agent_access_provider::ScopeResolution::resources(
            ResourceScopes::from([("repository".to_string(), vec![project])]),
        ))
    }

    async fn invoke(
        &self,
        request: agent_access_provider::ProviderInvocation,
    ) -> Result<agent_access_provider::ProviderResult, ProviderError> {
        self.seen
            .lock()
            .unwrap()
            .push(request.execution().static_credential().cloned());
        Ok(agent_access_provider::ProviderResult::new(
            json!({"id": 42}),
        ))
    }
}

/// One GitLab token stored once serves GitLab REST and the GitLab Git
/// gateway through the shared `gitlab` credential connection: the REST
/// provider receives it for scope resolution and execution, and the
/// gateway presents it as Basic `oauth2:<token>`.
#[tokio::test]
async fn a_shared_gitlab_connection_serves_rest_and_the_git_gateway() {
    let temp = test_temp_dir();
    let token_path = temp.join("shared-gitlab-unused-service-token");
    let identity_token_path = temp.join("shared-gitlab-identity-token");
    let key_path = temp.join("shared-gitlab-key");
    let store_path = temp.join("shared-gitlab.sqlite");
    let audit_path = temp.join("shared-gitlab.audit.jsonl");
    std::fs::write(&token_path, "service-token").unwrap();
    std::fs::write(&identity_token_path, "identity-token").unwrap();
    std::fs::write(&key_path, URL_SAFE_NO_PAD.encode([43_u8; 32])).unwrap();
    let mut config = test_forwarding_config(&token_path, &identity_token_path, &audit_path);
    // The REST API of the instance the gateway's upstream_base_url names.
    let gitlab_config = agent_access_gitlab::GitlabProviderConfig {
        provisioning: agent_access_gitlab::GitlabProvisioningConfig::default(),
        attachments: Default::default(),
        api_base_url: "https://gitlab.example.com/git/root/api/v4".to_string(),
        web_base_url: "https://gitlab.example.com/git/root".to_string(),
        egress_proxy: None,
        allowed_upstream_hosts: vec!["https://gitlab.example.com/git/root/api/v4/**".to_string()],
        content: agent_access_gitlab::GitlabContentConfig::default(),
        search: Default::default(),
        webhooks: agent_access_gitlab::GitlabWebhooksConfig::default(),
    };
    let descriptor = agent_access_gitlab::gitlab_descriptor(&gitlab_config);
    config.providers = agent_access_core::ProvidersConfig::new(Arc::new(crate::backend_registry()))
        .with(gitlab_config);
    let store_config = agent_access_core::ManagedStoreConfig {
        kind: "sqlite".to_string(),
        path: store_path.display().to_string(),
        require_registered_principal_for_invocation: false,
        auto_migrate: true,
    };
    config.managed_store = Some(store_config.clone());
    config.credential_encryption = Some(agent_access_core::CredentialEncryptionConfig {
        active_key: "fixture".into(),
        keys: vec![agent_access_core::CredentialEncryptionKeyConfig {
            id: "fixture".into(),
            provider: "file".into(),
            env: None,
            path: Some(key_path.display().to_string()),
        }],
    });
    config.credentials.service.clear();
    config.credentials.connections.insert(
        "gitlab".to_string(),
        agent_access_core::ConnectionConfig {
            display_name: Some("GitLab".to_string()),
            token_profiles: Some(vec!["gitlab-access-token".to_string()]),
            service_account_token_profiles: None,
            oauth: None,
        },
    );
    for service in ["gitlab", "gitlab_git"] {
        config.credentials.per_user.insert(
            service.to_string(),
            CredentialConfig {
                kind: "connection".to_string(),
                username_ref: None,
                token_ref: None,
                provider: None,
                path: None,
                read_only: None,
                connection: Some("gitlab".to_string()),
                profile: None,
            },
        );
    }
    let gateway = config.gateways.get_mut("gitlab_git").unwrap();
    gateway.credential_modes = vec!["per_user".to_string()];
    gateway.upstream_token_auth = basic_token_auth("oauth2");
    config.policy.grants[0].credential_mode = "per_user".to_string();
    let mut rest_grant = config.policy.grants[0].clone();
    rest_grant.service = "gitlab".to_string();
    rest_grant.actions = vec!["project.view".to_string()];
    config.policy.grants.push(rest_grant);
    let store = agent_access_core::ManagedStore::open(
        &store_config,
        &agent_access_core::ConfiguredExecutionContexts::from_config(None).unwrap(),
        agent_access_core::ManagedStoreOpenMode::Startup,
    )
    .unwrap();
    store
        .create_principal(
            agent_access_core::PrincipalWriteRequest {
                agent_token_issuance: Default::default(),
                role: agent_access_core::PrincipalRole::User,
                self_service_enabled: None,
                principal_id: "gateway-user".to_string(),
                kind: "user".to_string(),
                display_name: None,
                email: None,
                external_subject: None,
                created_by: "test".to_string(),
            },
            &agent_access_core::ConfiguredExecutionContexts::from_config(None).unwrap(),
        )
        .unwrap();
    drop(store);
    let seen = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
    let runtime = BrokerRuntime::with_providers(
        config,
        vec![Arc::new(SharedGitlabRestProvider {
            descriptor,
            seen: seen.clone(),
        })],
    )
    .unwrap();
    // One token, stored once under the connection's ID.
    runtime
        .managed_store()
        .unwrap()
        .upsert_user_credential(
            runtime.credential_key_ring().unwrap(),
            agent_access_core::CredentialWriteRequest {
                owner_principal_id: "gateway-user".to_string(),
                service: "gitlab".to_string(),
                name: "default".to_string(),
                profile: "gitlab-access-token".to_string(),
                credential_kind: "bearer_token".to_string(),
                secret: json!({"token": "shared-gitlab-token"}),
                metadata: json!({}),
                actor: "test".to_string(),
            },
            agent_access_core::CredentialManagementPurpose::Administrative,
        )
        .unwrap();

    let identity = runtime.identity_from_principal_groups(
        "gateway-user".to_string(),
        Some(agent_access_core::PrincipalKind::User),
        Some("gateway-user".to_string()),
        vec!["gateway-users".to_string()],
        None,
        None,
    );
    let rest = runtime
        .invoke(
            test_governed_operation(OperationContext {
                agent_request_id: "shared-gitlab-rest".to_string(),
                broker_request_id: "broker-shared-gitlab-rest".to_string(),
                identity,
                service: "gitlab".to_string(),
                action: "project.view".to_string(),
                source: agent_access_core::SourceContext::unknown(),
            }),
            agent_access_core::InvokeRequest::new(json!({"project": "sip/service"})),
        )
        .await;
    assert_eq!(rest.status, 200, "{:?}", rest.envelope);
    let token = agent_access_provider::test_support::credential_with_profile(
        agent_access_provider::test_support::bearer_credential("shared-gitlab-token"),
        "gitlab-access-token",
    );
    assert_eq!(
        *seen.lock().unwrap(),
        [Some(token.clone()), Some(token)],
        "scope resolution and execution use the connection's token"
    );

    // The Git gateway presents the same token as Basic oauth2:<token>.
    assert_eq!(
            forwarded_upstream_authorization(
                &runtime,
                basic_token_auth("oauth2"),
                "shared-gitlab-git",
            )
            .await,
            format!(
                "authorization: Basic {}",
                base64::engine::general_purpose::STANDARD.encode("oauth2:shared-gitlab-token")
            )
        );
    drain_gateway_test_audit(&runtime).await;
    let connections = audit_records(&audit_path)
        .into_iter()
        .filter(|record| record["decision"] == "allow")
        .map(|record| {
            (
                record["service"].as_str().unwrap().to_owned(),
                record["credentialConnection"].as_str().map(str::to_owned),
            )
        })
        .collect::<std::collections::BTreeSet<_>>();
    assert_eq!(
        connections,
        std::collections::BTreeSet::from([
            ("gitlab".to_owned(), Some("gitlab".to_owned())),
            ("gitlab_git".to_owned(), Some("gitlab".to_owned())),
        ])
    );
}

async fn read_http_request_headers(stream: &mut tokio::net::TcpStream) -> Vec<u8> {
    let mut request = Vec::new();
    let mut buffer = [0_u8; 1024];
    loop {
        let read = stream.read(&mut buffer).await.unwrap();
        assert_ne!(read, 0, "gateway closed before sending upstream request");
        request.extend_from_slice(&buffer[..read]);
        if request.windows(4).any(|window| window == b"\r\n\r\n") {
            return request;
        }
    }
}

fn test_gateway_config() -> GatewayConfig {
    GatewayConfig {
        allow_forwarded_identity: false,
        kind: "git_http".to_string(),
        display_name: "GitLab Git".to_string(),
        broker_hosts: vec!["git.example.test".to_string()],
        upstream_base_url: "https://gitlab.example.com/git/root".to_string(),
        allowed_upstream_hosts: vec!["https://gitlab.example.com/git/root/**".to_string()],
        egress_proxy: None,
        auth_modes: vec!["basic_broker_token".to_string()],
        basic_broker_token_username: "agent-access".to_string(),
        credential_modes: vec!["service".to_string()],
        upstream_token_auth: Default::default(),
        redirect_policy: "none".to_string(),
        request_body_max_bytes: Some(1024),
        response_body_max_bytes: Some(1024),
        streaming_idle_timeout_ms: Some(30_000),
        correlation_headers: true,
        protocol_fields: BTreeMap::from([(
            "git".into(),
            toml::Value::Table(toml::toml! { allow_fetch = true
                allow_push = false
                deny_ref_patterns = []
                deny_delete_refs = true
                receive_pack_prefix_max_bytes = 65_536
            }),
        )]),
    }
}

fn test_governed_operation(operation: OperationContext) -> GovernedOperationContext {
    GovernedOperationContext {
        admission: None,
        operation,
        execution_context: ExecutionContext::new(DEFAULT_EXECUTION_CONTEXT)
            .expect("default execution context is valid"),
    }
}

fn gateway_resource(
    id: &str,
    selector: agent_access_provider::ResourceSelector,
) -> agent_access_core::ResourceDefinition {
    agent_access_core::ResourceDefinition {
        id: id.to_string(),
        display_name: None,
        resource_type: agent_access_provider::GIT_REPOSITORY_RESOURCE.id().clone(),
        selector,
        allowed_execution_contexts: vec!["default".to_string()],
        enabled: true,
    }
}

pub(super) fn test_forwarding_config(
    token_path: &Path,
    identity_token_path: &Path,
    audit_path: &Path,
) -> BrokerConfig {
    BrokerConfig {
        imports: Default::default(),
        command_imports: Default::default(),
        oauth: Default::default(),
        deployment: DeploymentConfig::default(),
        network: NetworkConfig::default(),
        execution_context: None,
        identity: IdentityConfig {
            trusted_callers: Default::default(),
            mode: "anonymous".to_string(),
            authority: "toml".to_string(),
            sources: vec![IdentitySourceConfig {
                name: "static".to_string(),
                kind: "static_principals".to_string(),
                header: "Authorization".to_string(),
                scheme: "Bearer".to_string(),
                principals: vec![StaticPrincipalConfig {
                    principal: "gateway-user".to_string(),
                    token_refs: vec![format!("file:{}", identity_token_path.display())],
                }],
            }],
            groups: vec![IdentityGroupConfig {
                id: "gateway-users".to_string(),
                status: "active".to_string(),
                members: vec!["gateway-user".to_string()],
            }],
        },
        credentials: CredentialsConfig {
            imported_modes: Default::default(),
            connections: BTreeMap::new(),
            service: BTreeMap::from([(
                "gitlab_git".to_string(),
                CredentialConfig {
                    kind: "bearer_token".to_string(),
                    username_ref: None,
                    token_ref: Some(format!("file:{}", token_path.display())),
                    provider: None,
                    path: None,
                    read_only: None,
                    connection: None,
                    profile: None,
                },
            )]),
            per_user: BTreeMap::new(),
            lookup: BTreeMap::new(),
        },
        managed_store: None,
        credential_encryption: None,
        management: agent_access_core::ManagementConfig::default(),
        broker_tokens: None,
        browser_auth: agent_access_core::BrowserAuthConfig::default(),
        portal: agent_access_core::PortalConfig::default(),
        mcp: Default::default(),
        policy: PolicyConfig {
            authority: "toml".to_string(),
            default_decision: "deny".to_string(),
            resources: vec![gateway_resource(
                "sip-service",
                agent_access_provider::ResourceSelector::Exact {
                    value: "sip/service".to_string(),
                },
            )],
            resource_groups: vec![],
            grants: vec![PolicyGrantConfig {
                subjects: vec!["group:gateway-users".to_string()],
                service: "gitlab_git".to_string(),
                actions: vec!["repo.fetch".to_string()],
                resources: agent_access_core::ResourceSelection {
                    resource_ids: vec!["sip-service".to_string()],
                    resource_group_ids: vec![],
                },
                credential_mode: "service".to_string(),
                priority: None,
                execution_contexts: None,
            }],
        },
        attribution: Default::default(),
        providers: ProvidersConfig::new(Arc::new(crate::backend_registry())),
        gateways: BTreeMap::from([("gitlab_git".to_string(), test_gateway_config())]),
        limits: agent_access_core::LimitsConfig::new(
            audit_path
                .parent()
                .unwrap()
                .join("upload-spool")
                .display()
                .to_string(),
        ),
        audit: Some(AuditConfig::new(
            agent_access_core::AuditStoreType::Jsonl,
            audit_path.display().to_string(),
        )),
    }
}

async fn drain_gateway_test_audit(runtime: &BrokerRuntime) {
    // JSONL retention enumerates the audit directory before draining
    // terminal writes. Shared filesystems can stall that cleanup without
    // changing any gateway response or streaming idle deadline.
    let started = Instant::now();
    runtime
        .shutdown_audit(Duration::from_secs(5))
        .await
        .unwrap_or_else(|error| {
            panic!(
                "audit shutdown failed after {:?}: {error}",
                started.elapsed()
            )
        });
}

fn audit_records(path: &Path) -> Vec<serde_json::Value> {
    agent_access_core::test_support::read_audit_records(
        agent_access_core::AuditStoreType::Jsonl,
        path,
    )
}
// These fixtures ask the linked Git module for real plans. They contain no
// parser or transport implementation; the tests below exercise host ownership.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum GitRequestKind {
    UploadPackDiscovery,
    UploadPackPost,
    ReceivePackDiscovery,
    ReceivePackPost,
}
impl GitRequestKind {
    fn method(self) -> Method {
        match self {
            Self::UploadPackPost | Self::ReceivePackPost => Method::POST,
            _ => Method::GET,
        }
    }
    fn name(self) -> &'static str {
        match self {
            Self::UploadPackDiscovery => "upload-pack-discovery",
            Self::UploadPackPost => "upload-pack-post",
            Self::ReceivePackDiscovery => "receive-pack-discovery",
            Self::ReceivePackPost => "receive-pack-post",
        }
    }
    fn target(self, repository: &str) -> String {
        let suffix = match self {
            Self::UploadPackDiscovery => "info/refs?service=git-upload-pack",
            Self::ReceivePackDiscovery => "info/refs?service=git-receive-pack",
            Self::UploadPackPost => "git-upload-pack",
            Self::ReceivePackPost => "git-receive-pack",
        };
        format!("/{repository}.git/{suffix}")
    }
}
enum GitContentEncoding {
    Gzip,
}
struct GatewayForwardRequest {
    git_request_kind: GitRequestKind,
    headers: HeaderMap,
    body: Body,
    content_encoding: Option<GitContentEncoding>,
    receive_pack: Option<GatewayForwardPlan>,
}
fn fixture_protocol(gateway: &GatewayConfig) -> Arc<dyn agent_access_provider::GatewayProtocol> {
    agent_access_git_http::GIT_HTTP_GATEWAY
        .parse_config(toml::Value::Table(
            gateway.protocol_fields.clone().into_iter().collect(),
        ))
        .unwrap()
        .build(&gateway.service_context("gitlab_git"))
        .unwrap()
}
async fn fixture_git_plan(
    gateway: &GatewayConfig,
    kind: GitRequestKind,
    repository: &str,
    headers: &HeaderMap,
    body: Body,
    limits: &GatewayForwardLimits,
) -> Result<GatewayForwardPlan, ProviderError> {
    let target = kind.target(repository);
    fixture_protocol(gateway)
        .classify(agent_access_provider::host::gateway_request_head(
            &kind.method(),
            &target,
            &protocol_headers(headers),
        ))?
        .into_request()
        .preflight(protocol_body(body, limits))
        .await
}
async fn parse_receive_pack_body(
    body: Body,
    git: &toml::Value,
    headers: &HeaderMap,
    limits: &GatewayForwardLimits,
) -> Result<GatewayForwardPlan, ProviderError> {
    let mut gateway = test_gateway_config();
    gateway.protocol_fields.insert("git".into(), git.clone());
    fixture_git_plan(
        &gateway,
        GitRequestKind::ReceivePackPost,
        "sip/service",
        headers,
        body,
        limits,
    )
    .await
}
async fn forward_prepared_git_http(
    runtime: BrokerRuntime,
    gateway: GatewayConfig,
    mut request: GatewayForwardRequest,
    prepared: PreparedGatewayOperation,
    permits: Option<RequestPermits>,
) -> Response<Body> {
    if request.content_encoding.is_some() {
        request
            .headers
            .insert(CONTENT_ENCODING, HeaderValue::from_static("gzip"));
    }
    let plan = match request.receive_pack {
        Some(plan) => Ok(plan),
        None => {
            fixture_git_plan(
                &gateway,
                request.git_request_kind,
                &prepared.resource_scopes["repository"][0],
                &request.headers,
                request.body,
                &gateway_forward_limits(&runtime, &gateway),
            )
            .await
        }
    };
    let plan = match plan {
        Ok(plan) => plan,
        Err(error) => {
            return gateway_runtime_response(
                runtime
                    .fail_prepared_gateway_operation(prepared, error)
                    .await,
            );
        }
    };
    let url = match validate_forward_plan(&gateway, &request.git_request_kind.method(), &plan) {
        Ok(url) => url,
        Err(error) => {
            return gateway_runtime_response(
                runtime
                    .fail_prepared_gateway_operation(prepared, error)
                    .await,
            );
        }
    };
    forward_prepared_gateway(
        runtime,
        gateway,
        &agent_access_git_http::GIT_HTTP_GATEWAY,
        url,
        plan,
        prepared,
        GatewayForwardOwnership {
            permits,
            disposal: None,
            dispatch_identity: None,
            reloadable: None,
        },
    )
    .await
}
async fn prepare_gateway_request_body(
    method: &Method,
    headers: &HeaderMap,
    body: Body,
    receive_pack: Option<GatewayForwardPlan>,
    limits: &GatewayForwardLimits,
) -> Result<GatewayPreparedRequestBody, ProviderError> {
    let mut headers = headers.clone();
    let kind = if method == Method::POST {
        headers
            .entry(CONTENT_TYPE)
            .or_insert(HeaderValue::from_static(
                "application/x-git-upload-pack-request",
            ));
        GitRequestKind::UploadPackPost
    } else {
        GitRequestKind::UploadPackDiscovery
    };
    let plan = match receive_pack {
        Some(plan) => plan,
        None => {
            fixture_git_plan(
                &test_gateway_config(),
                kind,
                "sip/service",
                &headers,
                body,
                limits,
            )
            .await?
        }
    };
    Ok(prepare_protocol_request_body(
        plan.body,
        plan.discard_request_trailers,
        limits,
        None,
    ))
}
async fn gateway_request_body_bytes(
    method: &Method,
    headers: &HeaderMap,
    body: Body,
    limits: &GatewayForwardLimits,
) -> Result<Vec<u8>, ProviderError> {
    let mut headers = headers.clone();
    let kind = if method == Method::POST {
        headers
            .entry(CONTENT_TYPE)
            .or_insert(HeaderValue::from_static(
                "application/x-git-upload-pack-request",
            ));
        GitRequestKind::UploadPackPost
    } else {
        GitRequestKind::UploadPackDiscovery
    };
    let plan = fixture_git_plan(
        &test_gateway_config(),
        kind,
        "sip/service",
        &headers,
        body,
        limits,
    )
    .await?;
    let mut stream = agent_access_provider::host::gateway_body_stream(plan.body);
    let mut bytes = Vec::new();
    while let Some(frame) = stream.next().await {
        match frame {
            Ok(GatewayBodyFrame::Data(chunk)) => bytes.extend_from_slice(&chunk),
            Err(agent_access_provider::GatewayBodyError::TooLarge) => {
                return Err(ProviderError::deny(
                    ReasonCode::GatewayRequestCapExceeded,
                    "body cap",
                ));
            }
            Err(_) => {
                return Err(ProviderError::deny(
                    ReasonCode::GatewayRequestBodyDenied,
                    "body read",
                ));
            }
            _ => {}
        }
    }
    Ok(bytes)
}
fn fixture_upstream_response(
    status: u16,
    request_id: &str,
    headers: &HeaderMap,
    body: Body,
) -> Response<Body> {
    let profile = GatewayResponseProfile::new(vec!["content-type".into()]).bounded_retry_after();
    let headers = selected_response_headers(
        &agent_access_git_http::GIT_HTTP_GATEWAY,
        &profile,
        status,
        headers,
    )
    .unwrap();
    gateway_upstream_response(status, request_id, &headers, body)
}

fn gateway_request_stream_body(
    body: Body,
    limits: &GatewayForwardLimits,
) -> (
    reqwest::Body,
    Arc<AtomicU8>,
    Arc<GatewayRequestUploadProgress>,
) {
    match prepare_protocol_request_body(protocol_body(body, limits), false, limits, None) {
        GatewayPreparedRequestBody::Stream {
            body,
            failure,
            progress,
        } => (body, failure, progress),
        GatewayPreparedRequestBody::Bytes(_) => panic!("unread fixture body must remain streamed"),
    }
}

#[tokio::test]
async fn known_length_receive_pack_refusal_retains_head_audit_and_policy_precedence() {
    for (action, expected) in [
        ("repo.push", "gateway_request_cap_exceeded"),
        ("repo.fetch", "service_action_denied"),
    ] {
        let temp = test_temp_dir();
        let audit_path = temp.join("head-cap.jsonl");
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let upstream = format!("https://{}", listener.local_addr().unwrap());
        let (state, authorization) = managed_gateway_body_fixture(action, None, |config| {
            config.audit = Some(AuditConfig::new(
                agent_access_core::AuditStoreType::Jsonl,
                audit_path.display().to_string(),
            ));
            let gateway = config.gateways.get_mut("gitlab_git").unwrap();
            gateway.upstream_base_url = upstream.clone();
            gateway.allowed_upstream_hosts = vec![format!("{upstream}/**")];
            gateway.request_body_max_bytes = Some(8);
        });
        let runtime = state.current().runtime.clone();
        let response = build_gateway_router(state)
            .oneshot(
                Request::builder()
                    .method(Method::POST)
                    .uri("/sip/service.git/git-receive-pack")
                    .extension(ConnectInfo(
                        "127.0.0.1:41080".parse::<SocketAddr>().unwrap(),
                    ))
                    .header(HOST, "git.example.test")
                    .header(AUTHORIZATION, authorization)
                    .header(REQUEST_ID_HEADER, "receive-pack-head-cap")
                    .header(CONTENT_TYPE, "application/x-git-receive-pack-request")
                    .header(CONTENT_LENGTH, "12")
                    // Invalid Git packets would fail preflight with a different reason.
                    .body(Body::from("not-git-data"))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.headers()[REASON_CODE_HEADER], expected);
        assert!(
            timeout(Duration::from_millis(30), listener.accept())
                .await
                .is_err()
        );
        let _ = axum::body::to_bytes(response.into_body(), 4096)
            .await
            .unwrap();
        drain_gateway_test_audit(&runtime).await;
        let records = audit_records(&audit_path);
        let record = records
            .iter()
            .find(|record| record["reasonCode"] == expected)
            .unwrap();
        assert_eq!(record["decision"], "deny");
        if action == "repo.push" {
            assert_eq!(
                record["providerAudit"]["git"],
                json!({"operation":"receive-pack", "updates":[]})
            );
        }
        assert!(
            !records
                .iter()
                .any(|record| record["providerAudit"]["gateway"]["phase"] == "started")
        );
    }
}

#[tokio::test]
async fn refused_connection_does_not_claim_uncertain_upload_processing() {
    let temp = test_temp_dir();
    let token = temp.join("upstream-token");
    let identity_token = temp.join("identity-token");
    let audit_path = temp.join("connect-failure.jsonl");
    std::fs::write(&token, "upstream-token").unwrap();
    std::fs::write(&identity_token, "identity-token").unwrap();
    let runtime =
        BrokerRuntime::new(test_forwarding_config(&token, &identity_token, &audit_path)).unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    drop(listener);
    let mut gateway = test_gateway_config();
    gateway.upstream_base_url = format!("http://{address}");
    gateway.allowed_upstream_hosts = vec![format!("http://{address}/**")];
    let identity = runtime.identity_from_principal_groups(
        "gateway-user".into(),
        None,
        Some("gateway-user".into()),
        vec!["gateway-users".into()],
        None,
        None,
    );
    let prepared = runtime
        .prepare_gateway_operation(
            test_governed_operation(OperationContext {
                agent_request_id: "refused-connect".into(),
                broker_request_id: "refused-connect".into(),
                identity,
                service: "gitlab_git".into(),
                action: "repo.fetch".into(),
                source: agent_access_core::SourceContext::unknown(),
            }),
            ResourceScopes::from([("repository".into(), vec!["sip/service".into()])]),
        )
        .await
        .unwrap();
    let polled = Arc::new(AtomicBool::new(false));
    let record_poll = polled.clone();
    let body = Body::from_stream(stream::poll_fn(move |_| {
        record_poll.store(true, Ordering::Relaxed);
        Poll::Pending::<Option<Result<Bytes, io::Error>>>
    }));
    let response = forward_prepared_git_http(
        runtime.clone(),
        gateway,
        GatewayForwardRequest {
            git_request_kind: GitRequestKind::UploadPackPost,
            headers: HeaderMap::from_iter([(
                CONTENT_TYPE,
                HeaderValue::from_static("application/x-git-upload-pack-request"),
            )]),
            body,
            content_encoding: None,
            receive_pack: None,
        },
        prepared,
        None,
    )
    .await;
    assert_eq!(response.status(), StatusCode::BAD_GATEWAY);
    assert_eq!(
        response.headers()[REASON_CODE_HEADER],
        "upstream_connection_failed"
    );
    let _ = axum::body::to_bytes(response.into_body(), 4096)
        .await
        .unwrap();
    assert!(!polled.load(Ordering::Relaxed));
    drain_gateway_test_audit(&runtime).await;
    let records = audit_records(&audit_path);
    let terminal: Vec<_> = records
        .iter()
        .filter(|record| record["providerAudit"]["gateway"]["phase"] == "failed")
        .collect();
    assert_eq!(terminal.len(), 1, "{records:?}");
    let record = terminal[0];
    assert_eq!(record["decision"], "error");
    assert_eq!(record["reasonCode"], "upstream_connection_failed");
    // Git retains its existing audit shape; the body was never polled above.
    assert!(
        record["providerAudit"]["gateway"]
            .get("requestBytes")
            .is_none()
    );
    assert!(
        !record["providerAudit"]["gateway"]["message"]
            .as_str()
            .unwrap_or_default()
            .contains("uncertain")
    );
}

#[tokio::test]
async fn abandoned_pending_or_accepted_uploads_remain_uncertain_without_body_polling() {
    for accepted in [false, true] {
        let temp = test_temp_dir();
        let token = temp.join("upstream-token");
        let identity_token = temp.join("identity-token");
        let audit_path = temp.join("abandoned.jsonl");
        std::fs::write(&token, "upstream-token").unwrap();
        std::fs::write(&identity_token, "identity-token").unwrap();
        let runtime =
            BrokerRuntime::new(test_forwarding_config(&token, &identity_token, &audit_path))
                .unwrap();
        let identity = runtime.identity_from_principal_groups(
            "gateway-user".into(),
            None,
            Some("gateway-user".into()),
            vec!["gateway-users".into()],
            None,
            None,
        );
        let mut prepared = runtime
            .prepare_gateway_operation(
                test_governed_operation(OperationContext {
                    agent_request_id: "abandoned-upload".into(),
                    broker_request_id: "abandoned-upload".into(),
                    identity,
                    service: "gitlab_git".into(),
                    action: "repo.fetch".into(),
                    source: agent_access_core::SourceContext::unknown(),
                }),
                ResourceScopes::from([("repository".into(), vec!["sip/service".into()])]),
            )
            .await
            .unwrap();
        runtime
            .start_prepared_gateway_operation(&mut prepared, json!({"gateway":{"requestBytes":0}}))
            .await
            .unwrap();
        let progress = Arc::new(GatewayRequestUploadProgress::new());
        {
            let mut audit = progress.audit.lock().unwrap();
            audit.lease = prepared.retain_gateway_request_body();
            audit.send = GatewayUploadSendState::Pending;
        }
        drop(GatewayUploadOwner {
            progress: progress.clone(),
            _permits: None,
        });
        if accepted {
            progress.finish_send(false);
        }
        drop(progress);
        let _ = runtime
            .fail_prepared_gateway_operation(
                prepared,
                ProviderError::error(ReasonCode::UpstreamProtocolFailed, "gateway send ended")
                    .with_audit(json!({"gateway":{"requestBytes":0}})),
            )
            .await;
        drain_gateway_test_audit(&runtime).await;
        let records = audit_records(&audit_path);
        let terminal: Vec<_> = records
            .iter()
            .filter(|record| record["providerAudit"]["gateway"]["phase"] == "failed")
            .collect();
        assert_eq!(terminal.len(), 1, "accepted={accepted}: {records:?}");
        assert_eq!(terminal[0]["providerAudit"]["gateway"]["requestBytes"], 0);
        assert!(
            terminal[0]["providerAudit"]["gateway"]["message"]
                .as_str()
                .unwrap()
                .contains("uncertain")
        );
    }
}
