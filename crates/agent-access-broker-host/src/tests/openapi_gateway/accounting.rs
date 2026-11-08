use super::*;
use agent_access_core::imports::ImportedCredentialMode;

fn one_request(config: &mut BrokerConfig) {
    config.limits.invocations.default = Some(agent_access_core::InvocationLimitConfig {
        requests: 1,
        window: "60s".into(),
        max_wait: Some("0s".into()),
    });
}

#[tokio::test]
async fn openapi_gateway_each_get_head_and_options_admission_spends_one_allowance() {
    for method in [Method::GET, Method::HEAD, Method::OPTIONS] {
        let upstream = Upstream::start().await;
        let fixture = Fixture::ready_with(
            &upstream,
            UpstreamAuth::Anonymous,
            &["download_blob", "head_blob", "options_blob"],
            one_request,
        )
        .await;
        let response = fixture
            .gateway(method.clone(), "/blob", "first-admission")
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        response.bytes().await.unwrap();
        let terminal = fixture.terminal("first-admission").await;
        assert_eq!(
            terminal["providerAudit"]["gateway"]["method"],
            method.as_str()
        );
        let response = fixture
            .gateway(Method::GET, "/blob", "allowance-used")
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);
        assert_eq!(upstream.api_requests().len(), 1);
        fixture.stop().await;
    }
}

#[tokio::test]
async fn openapi_gateway_body_credential_and_policy_denials_after_admission_remain_charged() {
    for denied in ["body", "credential", "policy"] {
        let upstream = Upstream::start().await;
        let fixture = Fixture::start(&upstream, one_request).await;
        let auth = if denied == "credential" {
            UpstreamAuth::Bearer
        } else {
            UpstreamAuth::Anonymous
        };
        let document = document(Dialect::OpenApi31, auth, &upstream.endpoint());
        let preview = fixture
            .create_and_discover_with_bindings(
                DefinitionSource::Upload,
                auth,
                &document,
                &[
                    ImportedCredentialMode::Service,
                    ImportedCredentialMode::PerUser,
                ],
            )
            .await;
        fixture
            .accept(&preview, &["read_item", "update_item"])
            .await;
        fixture.enable().await;
        fixture
            .grant_for("alice", &["read_item"], "service", None)
            .await;
        if denied != "policy" {
            fixture
                .grant_for(
                    "alice",
                    &["update_item"],
                    if denied == "credential" {
                        "per_user"
                    } else {
                        "service"
                    },
                    None,
                )
                .await;
        }
        let mut request = fixture.gateway(Method::POST, "/items/alpha", "charged-denial");
        if denied == "body" {
            request = request
                .header(CONTENT_TYPE, "text/plain")
                .body("invalid media");
        } else {
            request = request.header(CONTENT_TYPE, "application/json").body("{}");
        }
        let response = request.send().await.unwrap();
        assert!(!response.status().is_success());
        assert_ne!(response.status(), StatusCode::TOO_MANY_REQUESTS);
        let reason = response.headers()[REASON_CODE_HEADER]
            .to_str()
            .unwrap()
            .to_owned();
        if denied == "credential" {
            assert_eq!(reason, "credential_not_provisioned");
        }
        if denied == "policy" {
            assert_eq!(reason, "service_action_denied");
        }
        response.bytes().await.unwrap();
        assert!(upstream.api_requests().is_empty());
        let response = fixture
            .gateway(Method::GET, "/items/alpha", "charged-denial-next")
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS, "{denied}");
        assert!(upstream.api_requests().is_empty());
        fixture.stop().await;
    }
}

#[tokio::test]
async fn openapi_gateway_bad_identity_and_classifier_denial_leave_allowance_for_authenticated_work()
{
    let upstream = Upstream::start().await;
    let fixture = Fixture::ready_with(
        &upstream,
        UpstreamAuth::Anonymous,
        &["read_item"],
        one_request,
    )
    .await;
    let response = fixture
        .gateway_as(
            "invalid-broker-token",
            Method::GET,
            "/items/alpha",
            "invalid-before-rate",
        )
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    let response = fixture
        .gateway(Method::GET, "/items/private", "classifier-before-rate")
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
    let response = fixture
        .gateway(Method::GET, "/items/alpha", "still-admitted")
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    response.bytes().await.unwrap();
    assert_eq!(upstream.api_requests().len(), 1);
    fixture.stop().await;
}
