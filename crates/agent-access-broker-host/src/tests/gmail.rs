//! Google consent and Gmail through the real managed broker/router.
use super::*;
use crate::test_support::{FixtureDir, RunningBroker};
use crate::{AssemblyIdentity, BrokerComposition};
use wiremock::{
    Mock, ResponseTemplate,
    matchers::{body_string_contains, method, path},
};
#[path = "../../tests/support/gmail.rs"]
mod fixture;
use fixture::{GmailFixture, body_json, gmail_fixture};

/// The fixture broker's active runtime. Drop it before the broker stops.
fn runtime(fixture: &GmailFixture) -> BrokerRuntime {
    fixture.broker.reloadable_state().current().runtime.clone()
}

/// A test broker on `config`, in the stopped fixture's `directory`, serving
/// Gmail against `server`.
async fn restart(
    config: &agent_access_core::BrokerConfig,
    directory: &FixtureDir,
    server: &wiremock::MockServer,
) -> TestBroker {
    TestBroker::start_with(with_provider_instances(
        TestBroker::config_builder(config).in_directory(directory.clone()),
        [agent_access_gmail::test_support::provider(&server.uri())],
    ))
    .await
}

#[tokio::test]
async fn gmail_browser_connect_read_refresh_disconnect_and_denied_effects() {
    let fixture = gmail_fixture().await;
    fixture.connect("").await;
    let status = runtime(&fixture)
        .oauth_manager()
        .unwrap()
        .status("alice", "google")
        .unwrap();
    assert_eq!(status.subject_id.as_deref(), Some("google-sub-alice"));
    assert_eq!(status.display_name.as_deref(), Some("alice@example.test"));
    let (code, result) = fixture.invoke("account.view", json!({})).await;
    assert_eq!(code, StatusCode::OK, "{result}");
    assert_eq!(result["result"]["emailAddress"], "alice@example.test");
    let before = fixture.server.received_requests().await.unwrap().len();
    for action in [
        "message.send",
        "message.delete",
        "thread.delete",
        "draft.create",
    ] {
        assert!(
            !fixture
                .invoke(action, json!({"id":"abc"}))
                .await
                .0
                .is_success()
        );
    }
    assert_eq!(
        fixture.server.received_requests().await.unwrap().len(),
        before
    );
    let response = fixture
        .browser(
            Method::DELETE,
            "/v1/oauth/connections/google",
            "disconnect",
            None,
        )
        .await;
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        body_json(response).await["result"]["remoteRevocation"],
        "not_requested"
    );
    assert!(
        !fixture
            .invoke("account.view", json!({}))
            .await
            .0
            .is_success()
    );
    assert_eq!(
        fixture.server.received_requests().await.unwrap().len(),
        before
    );
    fixture.stop().await;
}

#[tokio::test]
async fn gmail_refresh_reuses_material_without_requiring_a_replacement_token() {
    let fixture = gmail_fixture().await;
    fixture.connect_expiring("", 1).await;
    Mock::given(method("POST"))
        .and(path("/token"))
        .and(body_string_contains("grant_type=refresh_token"))
        .and(body_string_contains(
            "refresh_token=google-reusable-refresh",
        ))
        .respond_with(ResponseTemplate::new(200).set_body_json(
            json!({"access_token":"google-access-2","token_type":"Bearer","expires_in":3600}),
        ))
        .with_priority(1)
        .expect(1)
        .mount(&fixture.server)
        .await;
    tokio::time::sleep(Duration::from_secs(2)).await;
    let (code, result) = fixture.invoke("account.view", json!({})).await;
    assert_eq!(code, StatusCode::OK, "{result}");
    let requests = fixture.server.received_requests().await.unwrap();
    assert!(requests.iter().any(|r| r.url.path().ends_with("/profile")
        && r.headers.get("authorization").unwrap() == "Bearer google-access-2"));
    fixture.stop().await;
}

#[tokio::test]
async fn gmail_callback_validates_optional_issuer_and_rejects_duplicates_before_exchange() {
    let fixture = gmail_fixture().await;
    let response = fixture
        .browser(
            Method::POST,
            "/v1/oauth/connect",
            "begin",
            Some(json!({"registration": "google","intent":"connect"})),
        )
        .await;
    let start = body_json(response).await;
    let url = url::Url::parse(start["result"]["authorizationUrl"].as_str().unwrap()).unwrap();
    assert_eq!(url.host_str(), Some("accounts.google.com"));
    let pairs: BTreeMap<_, _> = url.query_pairs().into_owned().collect();
    assert_eq!(pairs["access_type"], "offline");
    assert_eq!(pairs["code_challenge_method"], "S256");
    for suffix in [
        "&iss=https%3A%2F%2Fevil.test",
        "&code=duplicate",
        "&scope=a&scope=b",
    ] {
        let r = fixture
            .browser(
                Method::GET,
                &format!(
                    "/v1/oauth/callback/google?state={}&code=one{suffix}",
                    pairs["state"]
                ),
                "",
                None,
            )
            .await;
        assert!(r.status().is_client_error() || r.status().is_server_error());
    }
    assert!(fixture.server.received_requests().await.unwrap().is_empty());
    fixture.stop().await;
}

#[tokio::test]
async fn gmail_other_principals_never_borrow_the_connected_mailbox() {
    use agent_access_core::{BrokerTokenClass, BrokerTokenIssueRequest};
    let f = gmail_fixture().await;
    f.connect("").await;
    let (config, token) = {
        let runtime = runtime(&f);
        let store = runtime.managed_store().unwrap();
        store
            .create_principal(PrincipalWriteRequest {
                role: agent_access_core::PrincipalRole::User,
                self_service_enabled: None,
                principal_id: "bob".into(),
                kind: "user".into(),
                display_name: None,
                email: None,
                external_subject: None,
                created_by: "test".into(),
            })
            .unwrap();
        let token = store
            .issue_broker_token(
                runtime.broker_token_hasher().unwrap(),
                BrokerTokenIssueRequest {
                    principal_id: "bob".into(),
                    name: "bob-test".into(),
                    token_class: BrokerTokenClass::AgentInvoke,
                    scopes: json!({"allowedExecutionContexts":["default"]}),
                    expires_at: None,
                    created_by: "test".into(),
                },
            )
            .unwrap()
            .token;
        (runtime.config().clone(), token)
    };
    let before = f.server.received_requests().await.unwrap().len();
    // Each configuration restarts on the connected fixture's state.
    let (directory, server) = f.stop().await;
    for with_grant in [false, true] {
        let mut config = config.clone();
        if with_grant {
            let mut grant = config
                .policy
                .grants
                .iter()
                .find(|g| g.service == "gmail")
                .unwrap()
                .clone();
            grant.subjects = vec!["user:bob".into()];
            config.policy.grants.push(grant);
        }
        let broker = restart(&config, &directory, &server).await;
        let response = authed_json_request(
            broker.app(),
            Method::POST,
            "/v1/invoke/gmail/account.view",
            "bob-read",
            "Authorization",
            format!("Bearer {token}"),
            Some(r#"{"inputs":{}}"#),
        )
        .await;
        assert!(
            !response.status().is_success(),
            "{}",
            response_json(response).await
        );
        assert_eq!(server.received_requests().await.unwrap().len(), before);
        broker.stop().await;
    }
}

#[tokio::test]
async fn gmail_partial_consent_missing_refresh_and_callback_replay_fail_closed() {
    let f = gmail_fixture().await;
    for missing_refresh in [false, true] {
        f.server.reset().await;
        let mut token = json!({"access_token":"access","refresh_token":"refresh","token_type":"Bearer","expires_in":3600,"scope":"openid"});
        if missing_refresh {
            token["scope"] = json!(format!("openid {}", agent_access_gmail::GMAIL_SCOPE));
            token.as_object_mut().unwrap().remove("refresh_token");
        }
        Mock::given(method("POST"))
            .and(path("/token"))
            .respond_with(ResponseTemplate::new(200).set_body_json(token))
            .expect(1)
            .mount(&f.server)
            .await;
        Mock::given(method("GET"))
            .and(path("/userinfo"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({"sub":"alice-sub"})))
            .mount(&f.server)
            .await;
        Mock::given(method("GET"))
            .and(path("/gmail/v1/users/me/profile"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(json!({"emailAddress":"alice@example.test"})),
            )
            .mount(&f.server)
            .await;
        let start = f
            .browser(
                Method::POST,
                "/v1/oauth/connect",
                "start",
                Some(json!({"registration": "google","intent":"connect"})),
            )
            .await;
        let start = body_json(start).await;
        let url = url::Url::parse(start["result"]["authorizationUrl"].as_str().unwrap()).unwrap();
        let state = url
            .query_pairs()
            .find(|(k, _)| k == "state")
            .unwrap()
            .1
            .to_string();
        let callback = format!(
            "/v1/oauth/callback/google?state={state}&code=one&scope=openid%20https%3A%2F%2Fwww.googleapis.com%2Fauth%2Fgmail.modify&iss=https%3A%2F%2Faccounts.google.com"
        );
        let r = f.browser(Method::GET, &callback, "", None).await;
        assert!(r.status().is_client_error() || r.status().is_server_error());
        let count = f.server.received_requests().await.unwrap().len();
        let replay = f.browser(Method::GET, &callback, "", None).await;
        assert!(replay.status().is_client_error());
        assert_eq!(f.server.received_requests().await.unwrap().len(), count);
        assert!(
            runtime(&f)
                .oauth_manager()
                .unwrap()
                .status("alice", "google")
                .unwrap()
                .connection_id
                .is_none()
        );
    }
    f.stop().await;
}

#[tokio::test]
async fn gmail_discovery_token_options_and_previews_follow_explicit_action_grants() {
    let f = gmail_fixture().await;
    let response = f
        .browser(Method::GET, "/v1/tokens/options", "options", None)
        .await;
    assert_eq!(
        response.status(),
        StatusCode::OK,
        "{}",
        body_json(response).await
    );
    let options = body_json(response).await;
    let services = options["result"]["services"].as_array().unwrap();
    let gmail = services.iter().find(|s| s["service"] == "gmail").unwrap();
    assert_eq!(gmail["actions"].as_array().unwrap().len(), 11);
    assert!(
        gmail["actions"]
            .as_array()
            .unwrap()
            .iter()
            .all(|a| a["resourceType"].is_null())
    );
    let identity = agent_access_core::IdentityContext {
        caller_id: None,
        principal: "alice".into(),
        principal_kind: None,
        principal_subject: Some("alice".into()),
        policy_groups: vec![],
        authenticated: true,
        groups: vec![],
        source: None,
    };
    let caveats=agent_access_core::AgentInvokeTokenCaveats::parse_stored(&json!({"allowedExecutionContexts":["default"],"allowedServices":["gmail"],"serviceRestrictions":{"gmail":{"actions":["thread.trash"]}}})).unwrap();
    let runtime = runtime(&f);
    let preview = runtime
        .preview_agent_token_access(&identity, &caveats)
        .unwrap();
    assert_eq!(preview.access.len(), 1);
    assert_eq!(preview.access[0].action, "thread.trash");
    assert!(preview.access[0].resource_type.is_none());
    let restricted=agent_access_core::AgentInvokeTokenCaveats::parse_stored(&json!({"allowedExecutionContexts":["default"],"allowedServices":["gmail"],"serviceRestrictions":{"gmail":{"actions":["thread.trash"],"resources":{"resourceIds":[],"resourceGroupIds":[]}}}})).unwrap();
    assert!(
        runtime
            .preview_agent_token_access(&identity, &restricted)
            .unwrap()
            .access
            .is_empty()
    );
    drop(runtime);
    f.stop().await;
}

#[tokio::test]
async fn gmail_mutations_recover_one_401_and_never_attempt_a_third_post() {
    use wiremock::matchers::header;
    for second_status in [200, 401] {
        let f = gmail_fixture().await;
        f.connect("").await;
        Mock::given(method("POST")).and(path("/token"))
            .and(body_string_contains("grant_type=refresh_token"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({"access_token":"google-access-recovered","token_type":"Bearer","expires_in":3600})))
            .with_priority(1).expect(1).mount(&f.server).await;
        Mock::given(method("POST"))
            .and(path("/gmail/v1/users/me/messages/abc/trash"))
            .respond_with(ResponseTemplate::new(401))
            .up_to_n_times(1)
            .with_priority(1)
            .expect(1)
            .mount(&f.server)
            .await;
        Mock::given(method("POST"))
            .and(path("/gmail/v1/users/me/messages/abc/trash"))
            .and(header("authorization", "Bearer google-access-recovered"))
            .respond_with(
                ResponseTemplate::new(second_status)
                    .set_body_json(json!({"id":"abc","labelIds":["TRASH"]})),
            )
            .with_priority(2)
            .expect(1)
            .mount(&f.server)
            .await;
        let (status, result) = f.invoke("message.trash", json!({"id":"abc"})).await;
        assert_eq!(status.is_success(), second_status == 200, "{result}");
        let requests = f.server.received_requests().await.unwrap();
        assert_eq!(
            requests
                .iter()
                .filter(|r| r.url.path().ends_with("/trash"))
                .count(),
            2
        );
        assert_eq!(
            requests
                .iter()
                .filter(|r| r.url.path() == "/token"
                    && String::from_utf8_lossy(&r.body).contains("grant_type=refresh_token"))
                .count(),
            1
        );
        f.stop().await;
    }
}

#[tokio::test]
async fn gmail_resource_selections_fail_validation_and_preview() {
    use agent_access_core::{ResourceSelection, validate_broker_config};
    let f = gmail_fixture().await;
    let resources = ResourceSelection {
        resource_ids: vec![],
        resource_group_ids: vec!["empty".into()],
    };
    let runtime = runtime(&f);
    assert!(
        runtime
            .preview_policy_resources(
                "gmail",
                &["message.trash".into()],
                &[agent_access_core::ExecutionContext::new("default").unwrap()],
                &resources
            )
            .is_err()
    );
    let mut config = runtime.config().clone();
    drop(runtime);
    config
        .policy
        .resource_groups
        .push(agent_access_core::ResourceGroupDefinition {
            id: "empty".into(),
            name: "Empty".into(),
            included_resource_ids: vec![],
            excluded_resource_ids: vec![],
        });
    config.policy.grants[0].resources = resources.clone();
    let error = format!("{:?}", validate_broker_config(&config).unwrap_err());
    assert!(
        error.contains("does not support resource selections"),
        "{error}"
    );
    config.policy.authority = "managed".into();
    config.policy.grants.clear();
    config.policy.resource_groups.clear();
    // The managed-policy broker restarts on the fixture's state.
    let (directory, server) = f.stop().await;
    let broker = restart(&config, &directory, &server).await;
    let runtime = broker.runtime();
    runtime
        .create_managed_resource_group(agent_access_core::CreateResourceGroupRequest {
            id: Some("empty".into()),
            name: "Empty".into(),
            included_resource_ids: vec![],
            excluded_resource_ids: vec![],
            created_by: "admin".into(),
        })
        .unwrap();
    let error = runtime
        .validate_managed_policy_grant_create(agent_access_core::ManagedPolicyGrantCreateRequest {
            grant_id: None,
            subjects: vec!["user:alice".into()],
            execution_contexts: vec!["default".into()],
            service: "gmail".into(),
            actions: vec!["message.trash".into()],
            resources,
            credential_mode: "per_user".into(),
            priority: None,
            status: None,
            description: None,
            created_by: "admin".into(),
        })
        .unwrap_err();
    assert!(
        format!("{error:?}").contains("resource_selection_unsupported"),
        "{error:?}"
    );
    drop(runtime);
    broker.stop().await;
}

#[tokio::test]
async fn gmail_search_continuations_survive_refresh_but_not_reconnect() {
    use wiremock::matchers::{header, query_param, query_param_is_missing};
    let f = gmail_fixture().await;
    f.connect("").await;
    let messages = || Mock::given(method("GET")).and(path("/gmail/v1/users/me/messages"));
    messages()
        .and(query_param_is_missing("pageToken"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(json!({"nextPageToken":"upstream-page-2","resultSizeEstimate":0})),
        )
        .mount(&f.server)
        .await;
    messages()
        .and(query_param("pageToken", "upstream-page-2"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"resultSizeEstimate":0})))
        .mount(&f.server)
        .await;
    let continued_pages = || async {
        f.server
            .received_requests()
            .await
            .unwrap()
            .into_iter()
            .filter(|r| {
                r.url
                    .query_pairs()
                    .any(|(k, v)| k == "pageToken" && v == "upstream-page-2")
            })
            .collect::<Vec<_>>()
    };
    let (status, first) = f
        .invoke("message.search", json!({"query":"in:inbox"}))
        .await;
    assert_eq!(status, StatusCode::OK, "{first}");
    let token = first["result"]["nextPageToken"]
        .as_str()
        .unwrap()
        .to_owned();
    assert_ne!(token, "upstream-page-2");

    // A committed refresh-token grant, forced here by Gmail rejecting the
    // first access once, renews access within the same connection binding.
    Mock::given(method("POST"))
        .and(path("/token"))
        .and(body_string_contains("grant_type=refresh_token"))
        .respond_with(ResponseTemplate::new(200).set_body_json(
            json!({"access_token":"google-access-2","token_type":"Bearer","expires_in":3600}),
        ))
        .with_priority(1)
        .expect(1)
        .mount(&f.server)
        .await;
    Mock::given(method("GET"))
        .and(path("/gmail/v1/users/me/profile"))
        .and(header("authorization", "Bearer google-access-1"))
        .respond_with(ResponseTemplate::new(401))
        .up_to_n_times(1)
        .with_priority(1)
        .expect(1)
        .mount(&f.server)
        .await;
    let (status, account) = f.invoke("account.view", json!({})).await;
    assert_eq!(status, StatusCode::OK, "{account}");
    let continuation = json!({"query":"in:inbox","maxResults":20,"pageToken":token});
    let (status, next) = f.invoke("message.search", continuation.clone()).await;
    assert_eq!(status, StatusCode::OK, "{next}");
    assert!(next["result"]["nextPageToken"].is_null(), "{next}");
    let pages = continued_pages().await;
    assert_eq!(pages.len(), 1);
    assert_eq!(pages[0].headers["authorization"], "Bearer google-access-2");

    // Reconnecting the same Google account creates a new connection, so the
    // continuation is rejected before Gmail sees its upstream token.
    let start = f
        .browser(
            Method::POST,
            "/v1/oauth/connect",
            "reconnect",
            Some(json!({"registration": "google","intent":"reconnect"})),
        )
        .await;
    let start = body_json(start).await;
    let url = url::Url::parse(start["result"]["authorizationUrl"].as_str().unwrap()).unwrap();
    let state = url
        .query_pairs()
        .find(|(k, _)| k == "state")
        .unwrap()
        .1
        .into_owned();
    let callback = f
        .browser(
            Method::GET,
            &format!("/v1/oauth/callback/google?state={state}&code=reconnect-code"),
            "",
            None,
        )
        .await;
    assert_eq!(callback.status(), StatusCode::OK);
    let (status, rejected) = f.invoke("message.search", continuation).await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{rejected}");
    assert_eq!(rejected["reasonCode"], "input_invalid", "{rejected}");
    assert_eq!(continued_pages().await.len(), 1);
    // A new search under the new connection works as usual.
    let (status, restarted) = f
        .invoke("message.search", json!({"query":"in:inbox"}))
        .await;
    assert_eq!(status, StatusCode::OK, "{restarted}");
    assert_ne!(restarted["result"]["nextPageToken"], json!(token));
}
