use super::*;
use agent_access_core::imports::ImportedCredentialMode;

fn presented(auth: UpstreamAuth, principal: &str, token: &str) -> (&'static str, String) {
    match auth {
        UpstreamAuth::Bearer => ("authorization", format!("Bearer {token}")),
        UpstreamAuth::Basic => (
            "authorization",
            format!(
                "Basic {}",
                BASE64.encode(format!("synthetic-{principal}:{token}"))
            ),
        ),
        UpstreamAuth::Header => ("x-inventory-key", token.into()),
        UpstreamAuth::Anonymous => unreachable!(),
    }
}

#[tokio::test]
async fn openapi_gateway_selected_personal_static_credentials_never_fall_back_to_shared_material() {
    for auth in [
        UpstreamAuth::Bearer,
        UpstreamAuth::Basic,
        UpstreamAuth::Header,
    ] {
        let upstream = Upstream::start().await;
        let fixture = Fixture::start(&upstream, |_| {}).await;
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
        fixture.accept(&preview, &["read_item"]).await;
        fixture.enable().await;
        // The winning personal grant must not fall through to this valid shared grant.
        fixture
            .grant_for("alice", &["read_item"], "service", Some(-1))
            .await;
        fixture
            .grant_for("alice", &["read_item"], "per_user", Some(1))
            .await;
        fixture
            .grant_for("bob", &["read_item"], "service", None)
            .await;
        let bob = fixture.issue_agent_for("bob", false);
        let shared = fixture
            .gateway_as(&bob, Method::GET, "/items/alpha", "personal-shared-control")
            .send()
            .await
            .unwrap();
        assert_eq!(shared.status(), StatusCode::OK);
        shared.bytes().await.unwrap();
        let (carrier, expected) = if auth == UpstreamAuth::Basic {
            (
                "authorization",
                format!(
                    "Basic {}",
                    BASE64.encode(format!("synthetic-upstream-user:{UPSTREAM_TOKEN}"))
                ),
            )
        } else {
            presented(auth, "alice", UPSTREAM_TOKEN)
        };
        assert_eq!(upstream.api_requests()[0].headers[carrier], expected);

        // Alice has no personal material although the shared slot and lower grant work.
        let response = fixture
            .gateway(Method::GET, "/items/alpha", "personal-missing")
            .send()
            .await
            .unwrap();
        assert!(!response.status().is_success());
        assert_eq!(
            response.headers()[REASON_CODE_HEADER],
            "credential_not_provisioned"
        );
        response.bytes().await.unwrap();
        assert_eq!(upstream.api_requests().len(), 1);

        let personal = "synthetic-alice-private-token";
        fixture.put_personal("alice", auth, personal).await;
        let response = fixture
            .gateway(Method::GET, "/items/alpha", "personal-present")
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        response.bytes().await.unwrap();
        let (carrier, expected) = presented(auth, "alice", personal);
        assert_eq!(
            upstream.api_requests().last().unwrap().headers[carrier],
            expected
        );
        assert!(
            !upstream
                .api_requests()
                .last()
                .unwrap()
                .headers
                .values()
                .any(|value| value
                    .as_bytes()
                    .windows(UPSTREAM_TOKEN.len())
                    .any(|bytes| bytes == UPSTREAM_TOKEN.as_bytes()))
        );
        let terminal = fixture.terminal("personal-present").await;
        assert_eq!(terminal["credentialMode"], "per_user");
        assert!(!terminal.to_string().contains(personal));

        // Rotation/removal between requests takes effect immediately. In-flight
        // admission fencing is separate from this between-request check.
        let rotated = "synthetic-alice-rotated-token";
        fixture.put_personal("alice", auth, rotated).await;
        let response = fixture
            .gateway(Method::GET, "/items/alpha", "personal-rotated")
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        response.bytes().await.unwrap();
        let (carrier, expected) = presented(auth, "alice", rotated);
        assert_eq!(
            upstream.api_requests().last().unwrap().headers[carrier],
            expected
        );
        fixture.remove_personal("alice").await;
        let before = upstream.api_requests().len();
        let response = fixture
            .gateway(Method::GET, "/items/alpha", "personal-removed")
            .send()
            .await
            .unwrap();
        assert!(!response.status().is_success());
        assert_eq!(
            response.headers()[REASON_CODE_HEADER],
            "credential_not_provisioned"
        );
        response.bytes().await.unwrap();
        assert_eq!(upstream.api_requests().len(), before);
        fixture.stop().await;
    }
}

#[tokio::test]
async fn openapi_gateway_personal_credentials_refuse_explicit_and_automatic_verification_without_a_probe()
 {
    let upstream = Upstream::start().await;
    let fixture = Fixture::start(&upstream, |_| {}).await;
    let source = document(
        Dialect::OpenApi31,
        UpstreamAuth::Bearer,
        &upstream.endpoint(),
    );
    let preview = fixture
        .create_and_discover_with_bindings(
            DefinitionSource::Upload,
            UpstreamAuth::Bearer,
            &source,
            &[ImportedCredentialMode::PerUser],
        )
        .await;
    fixture.accept(&preview, &["read_item"]).await;
    fixture.enable().await;
    fixture
        .grant_for("alice", &["read_item"], "per_user", None)
        .await;
    fixture
        .put_personal("alice", UpstreamAuth::Bearer, "synthetic-personal-token")
        .await;
    assert!(upstream.api_requests().is_empty());
    assert!(
        !fixture
            .broker
            .runtime()
            .service_descriptor(SERVICE)
            .unwrap()
            .credentials
            .verification_supported
    );
    for body in [json!({"service":SERVICE}), json!({})] {
        let (status, response) = fixture
            .admin_request(
                Method::POST,
                "/v1/admin/principals/alice/credentials/connections/inventory/verify",
                Some(body),
            )
            .await;
        assert_eq!(status, StatusCode::FORBIDDEN, "{response}");
        assert_eq!(response["reasonCode"], "service_action_denied");
        assert!(
            response["error"]["message"]
                .as_str()
                .unwrap()
                .contains("no eligible credential verification consumer")
        );
        assert!(upstream.api_requests().is_empty());
    }
    // Refusing an unsupported probe does not damage a usable personal credential.
    let response = fixture
        .gateway(
            Method::GET,
            "/items/alpha",
            "after-unsupported-verification",
        )
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    response.bytes().await.unwrap();
    assert_eq!(upstream.api_requests().len(), 1);
    fixture.stop().await;
}
