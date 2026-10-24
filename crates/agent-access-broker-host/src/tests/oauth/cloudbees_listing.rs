//! Reuses the managed token fixture; CloudBees itself uses a Basic service token,
//! and no OAuth endpoint is contacted by this test.
use super::*;
use agent_access_core::{CreateResourceRequest, ManagedPolicyGrantCreateRequest};

#[tokio::test]
async fn cloudbees_job_listing_honors_token_resource_and_action_ceilings() {
    let server = MockServer::start().await;
    let fixture=oauth_fixture_with(None, |directory, config| {
        let username=directory.join("ci-username");let token=directory.join("ci-token");
        std::fs::write(&username,"ci-service").unwrap();std::fs::write(&token,"ci-service-token").unwrap();
        config.credentials.service.insert("cloudbees_ci".into(),serde_json::from_value(json!({"type":"basic_api_token","username_ref":format!("file:{}",username.display()),"token_ref":format!("file:{}",token.display())})).unwrap());
        config.providers.insert(serde_json::from_value::<agent_access_cloudbees_ci::CloudbeesCiProviderConfig>(json!({"controllers":{"ci":{"base_url":format!("{}/ci/",server.uri())}},"allowed_upstream_hosts":[format!("{}/ci/**",server.uri())]})).unwrap());
    },Vec::new()).await;
    for name in ["A", "B"] {
        fixture
            .runtime
            .create_managed_resource(CreateResourceRequest {
                id: Some(format!("ci-{name}")),
                display_name: None,
                resource_type: agent_access_cloudbees_ci::CLOUDBEES_CI_JOB_RESOURCE
                    .id()
                    .clone(),
                selector: ResourceSelector::Exact {
                    value: format!("ci/{name}"),
                },
                allowed_execution_contexts: vec!["default".into()],
                enabled: true,
                attributes: Default::default(),
                created_by: "admin".into(),
            })
            .unwrap();
        fixture
            .runtime
            .create_managed_policy_grant(ManagedPolicyGrantCreateRequest {
                grant_id: None,
                subjects: vec!["user:alice".into()],
                service: "cloudbees_ci".into(),
                actions: vec!["job.list".into()],
                resources: ResourceSelection {
                    resource_ids: vec![format!("ci-{name}")],
                    resource_group_ids: vec![],
                },
                execution_contexts: vec!["default".into()],
                credential_mode: "service".into(),
                priority: None,
                status: None,
                description: None,
                created_by: "admin".into(),
            })
            .unwrap();
    }
    Mock::given(method("GET")).and(path("/ci/api/json")).and(header_is("authorization","Basic Y2ktc2VydmljZTpjaS1zZXJ2aWNlLXRva2Vu"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"jobs":[{"name":"A","fullName":"A","displayName":"Allowed A"},{"name":"B","fullName":"B","displayName":"Restricted B"}]}))).mount(&server).await;
    let issue = |name: &str, actions: Vec<&str>| {
        fixture.runtime.managed_store().unwrap().issue_broker_token(fixture.runtime.broker_token_hasher().unwrap(),BrokerTokenIssueRequest {
        principal_id:"alice".into(),name:name.into(),token_class:BrokerTokenClass::AgentInvoke,
        scopes:json!({"allowedExecutionContexts":["default"],"allowedServices":["cloudbees_ci"],"serviceRestrictions":{"cloudbees_ci":{"actions":actions,"resources":{"resourceIds":["ci-A"]}}}}),expires_at:None,created_by:"test".into(),
    }).unwrap().token
    };
    let narrow = issue("one job", vec!["job.list"]);
    let view_only = issue("view only", vec!["job.view"]);
    for (token, count) in [(&fixture.agent_token, 2), (&narrow, 1)] {
        let response = authed_json_request(
            fixture.app.clone(),
            Method::POST,
            "/v1/invoke/cloudbees_ci/job.list",
            &format!("ci-list-{count}"),
            "Authorization",
            format!("Bearer {token}"),
            Some(r#"{"inputs":{"controller":"ci","maxResults":3}}"#),
        )
        .await;
        let status = response.status();
        let result = response_json(response).await;
        assert_eq!(status, StatusCode::OK, "{result}");
        assert_eq!(result["result"]["count"], count, "{result}");
        if count == 1 {
            assert_eq!(result["result"]["items"][0]["resource"], "ci/A");
            assert!(!result.to_string().contains("Restricted B"));
        }
    }
    let before = server.received_requests().await.unwrap().len();
    let denied = authed_json_request(
        fixture.app.clone(),
        Method::POST,
        "/v1/invoke/cloudbees_ci/job.list",
        "ci-list-action-denied",
        "Authorization",
        format!("Bearer {view_only}"),
        Some(r#"{"inputs":{"controller":"ci"}}"#),
    )
    .await;
    assert!(!denied.status().is_success());
    assert_eq!(server.received_requests().await.unwrap().len(), before);
    assert!(
        fixture.server.received_requests().await.unwrap().is_empty(),
        "listing contacted OAuth fixture"
    );
}
