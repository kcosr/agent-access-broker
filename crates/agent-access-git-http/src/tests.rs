use super::*;
use agent_access_provider::{GatewayProbeStatus, GatewayServiceContext, test_support};
use bytes::Bytes;
use futures_util::StreamExt;
use http::{HeaderValue, Method, header::CONTENT_TYPE};

fn protocol() -> Arc<dyn GatewayProtocol> {
    let context = GatewayServiceContext::new("review_git", "Review Git", "https://git.example/api")
        .with_broker_hosts(vec!["git.gateway.example".into()])
        .with_credential_modes(vec!["service".into(), "per_user".into()])
        .with_auth_modes(vec!["basic_broker_token".into()]);
    GIT_HTTP_GATEWAY
        .parse_config(toml::from_str("[git]\nallow_fetch = true\nallow_push = true").unwrap())
        .unwrap()
        .build(&context)
        .unwrap()
}

fn push_prefix() -> Vec<u8> {
    let command = "1111111111111111111111111111111111111111 2222222222222222222222222222222222222222 refs/heads/topic\0report-status";
    let mut result = format!("{:04x}{command}", command.len() + 4).into_bytes();
    result.extend(b"0000");
    result
}

fn classify_push(protocol: &dyn GatewayProtocol) -> GatewayClassification {
    let headers = HeaderMap::from_iter([(
        CONTENT_TYPE,
        HeaderValue::from_static("application/x-git-receive-pack-request"),
    )]);
    protocol
        .classify(test_support::gateway_request_head(
            &Method::POST,
            "/team/project.git/git-receive-pack",
            &headers,
        ))
        .unwrap()
}

#[tokio::test]
async fn inspected_and_overread_bytes_are_forwarded_once_in_original_order() {
    let protocol = protocol();
    let prefix = push_prefix();
    let mut overread = prefix[13..].to_vec();
    overread.extend(b"PACK-OVERREAD");
    let frames = vec![
        Ok(GatewayBodyFrame::Data(Bytes::copy_from_slice(
            &prefix[..13],
        ))),
        Ok(GatewayBodyFrame::Data(Bytes::from(overread))),
        Ok(GatewayBodyFrame::Data(Bytes::from_static(
            b"PACK-REMAINING",
        ))),
    ];
    let classified = classify_push(protocol.as_ref());
    assert_eq!(classified.action(), "repo.push");
    assert_eq!(classified.scopes()["repository"], ["team/project"]);
    assert_eq!(
        GIT_HTTP_GATEWAY.counted(classified.request_kind()),
        Some(true)
    );
    let plan = classified
        .into_request()
        .preflight(test_support::gateway_body(frames, 4096))
        .await
        .unwrap();
    assert_eq!(plan.relative_target, "/team/project.git/git-receive-pack");
    assert_eq!(plan.replay, GatewayReplayProfile::Never);
    assert_eq!(
        plan.audit.as_ref().unwrap()["updates"][0]["ref"],
        "refs/heads/topic"
    );
    let mut replay = test_support::gateway_body_stream(plan.body);
    let mut actual = Vec::new();
    while let Some(frame) = replay.next().await {
        if let GatewayBodyFrame::Data(bytes) = frame.unwrap() {
            actual.extend(bytes);
        }
    }
    let mut expected = prefix;
    expected.extend(b"PACK-OVERREADPACK-REMAINING");
    assert_eq!(actual, expected);
}

#[tokio::test]
async fn exact_flush_probe_is_counted_and_trailers_do_not_make_it_valid() {
    let protocol = protocol();
    let frames = vec![Ok(GatewayBodyFrame::Data(Bytes::from_static(b"0000")))];
    let plan = classify_push(protocol.as_ref())
        .into_request()
        .preflight(test_support::gateway_body(frames.clone(), 4096))
        .await
        .unwrap();
    assert_eq!(plan.audit.unwrap()["probe"], true);
    assert_eq!(plan.replay, GatewayReplayProfile::Never);
    let mut frames = frames;
    frames.push(Ok(GatewayBodyFrame::Trailers));
    let error = classify_push(protocol.as_ref())
        .into_request()
        .preflight(test_support::gateway_body(frames, 4096))
        .await
        .unwrap_err();
    assert_eq!(error.reason_code(), ReasonCode::GitPktLineMalformed);
    assert_eq!(
        error.message,
        "gateway git receive-pack command list is empty"
    );
}

#[tokio::test]
async fn body_error_kind_and_parsed_audit_survive_the_sdk_port() {
    let protocol = protocol();
    let mut prefix = push_prefix();
    prefix.truncate(prefix.len() - 4);
    for (failure, reason, message) in [
        (
            GatewayBodyError::TooLarge,
            ReasonCode::GatewayRequestCapExceeded,
            "gateway request body exceeds configured cap",
        ),
        (
            GatewayBodyError::Timeout,
            ReasonCode::GatewayRequestBodyDenied,
            "gateway request body read timed out",
        ),
        (
            GatewayBodyError::IdleTimeout,
            ReasonCode::GatewayRequestBodyDenied,
            "gateway git receive-pack request body read timed out",
        ),
        (
            GatewayBodyError::Read,
            ReasonCode::GitPktLineMalformed,
            "gateway git receive-pack request body read failed",
        ),
    ] {
        let frames = vec![
            Ok(GatewayBodyFrame::Data(Bytes::copy_from_slice(&prefix))),
            Err(failure),
        ];
        let error = classify_push(protocol.as_ref())
            .into_request()
            .preflight(test_support::gateway_body(frames, 4096))
            .await
            .unwrap_err();
        assert_eq!(error.reason_code(), reason);
        assert_eq!(error.message, message);
        assert_eq!(
            error.audit.unwrap()["git"]["updates"][0]["ref"],
            "refs/heads/topic"
        );
    }
}

#[tokio::test]
async fn sdk_inspection_cap_refuses_overread_before_forwarding_and_keeps_prior_ref_audit() {
    let protocol = protocol();
    let mut command = push_prefix();
    command.truncate(command.len() - 4);
    let cap = command.len() + 5;
    let frames = vec![
        Ok(GatewayBodyFrame::Data(Bytes::from(command))),
        Ok(GatewayBodyFrame::Data(Bytes::from_static(
            b"0000PACK-OVER-CAP",
        ))),
    ];
    let error = classify_push(protocol.as_ref())
        .into_request()
        .preflight(test_support::gateway_body(frames, cap))
        .await
        .unwrap_err();
    assert_eq!(error.reason_code(), ReasonCode::GatewayRequestCapExceeded);
    assert_eq!(
        error.audit.unwrap()["git"]["updates"][0]["ref"],
        "refs/heads/topic"
    );
}

#[tokio::test]
async fn discovery_is_bodyless_exempt_and_the_only_oauth_recovery_profile() {
    let protocol = protocol();
    for service in ["git-upload-pack", "git-receive-pack"] {
        let path = format!("/team/project/info/refs?service={service}");
        let classified = protocol
            .classify(test_support::gateway_request_head(
                &Method::GET,
                &path,
                &HeaderMap::new(),
            ))
            .unwrap();
        assert_eq!(
            GIT_HTTP_GATEWAY.counted(classified.request_kind()),
            Some(false)
        );
        let plan = classified
            .into_request()
            .preflight(test_support::gateway_body(Vec::new(), 4096))
            .await
            .unwrap();
        assert_eq!(
            plan.replay,
            GatewayReplayProfile::BodylessCredentialRecovery
        );
        let classified = protocol
            .classify(test_support::gateway_request_head(
                &Method::GET,
                &path,
                &HeaderMap::new(),
            ))
            .unwrap();
        let error = classified
            .into_request()
            .preflight(test_support::gateway_body(
                vec![Ok(GatewayBodyFrame::Data(Bytes::from_static(b"x")))],
                4096,
            ))
            .await
            .unwrap_err();
        assert_eq!(error.reason_code(), ReasonCode::GatewayRequestBodyDenied);
    }
}

#[test]
fn credential_probe_declares_fetch_authority_and_validates_the_git_advertisement() {
    let protocol = protocol();
    let probe = protocol
        .verification(Some(" team/project.git "))
        .unwrap()
        .unwrap();
    let request = probe.request();
    assert_eq!(request.action, "repo.fetch");
    assert_eq!(request.normalized_input, "team/project");
    assert_eq!(request.scopes["repository"], ["team/project"]);
    assert_eq!(
        request.relative_target,
        "/team/project.git/info/refs?service=git-upload-pack"
    );
    assert_eq!(request.max_response_bytes, 1024);
    let headers = HeaderMap::from_iter([(
        CONTENT_TYPE,
        HeaderValue::from_static("application/x-git-upload-pack-advertisement"),
    )]);
    assert_eq!(
        probe
            .validate_response(200, &headers, b"001", false)
            .unwrap(),
        GatewayProbeStatus::NeedMore
    );
    assert_eq!(
        probe
            .validate_response(200, &headers, b"001e# service=git-upload-pack\n", false)
            .unwrap(),
        GatewayProbeStatus::Valid
    );
    assert_eq!(
        probe
            .validate_response(200, &headers, b"001", true)
            .unwrap_err()
            .reason_code(),
        ReasonCode::UpstreamProtocolFailed
    );
    for (status, reason) in [
        (401, ReasonCode::UpstreamUnauthorized),
        (403, ReasonCode::UpstreamForbidden),
        (404, ReasonCode::ScopeUnresolved),
        (500, ReasonCode::UpstreamFailed),
    ] {
        assert_eq!(
            probe
                .validate_response(status, &HeaderMap::new(), b"", false)
                .unwrap_err()
                .reason_code(),
            reason
        );
    }
}
