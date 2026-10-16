use super::*;

#[tokio::test]
async fn cloudbees_ci_catalog_and_discovery_follow_job_grant_and_context() {
    let mut config = context_aware_fake_config("");
    let token_path = temp_path("cloudbees-ci-discovery.identity-token");
    std::fs::write(&token_path, "ci-discovery-token").unwrap();
    config.identity = IdentityConfig {
        trusted_callers: Default::default(),
        mode: "required".into(),
        authority: "toml".into(),
        sources: vec![IdentitySourceConfig {
            name: "ci-discovery".into(),
            kind: "static_principals".into(),
            header: "Authorization".into(),
            scheme: "Bearer".into(),
            principals: vec![StaticPrincipalConfig {
                principal: "ci-user".into(),
                token_refs: vec![format!("file:{}", token_path.display())],
            }],
        }],
        groups: vec![],
    };
    install_context_caller(&mut config);
    config.policy.grants[0].subjects = vec!["user:ci-user".into()];
    config
        .providers
        .insert(agent_access_cloudbees_ci::CloudbeesCiProviderConfig {
            max_log_scan_bytes: 16 * 1024 * 1024,
            controllers: BTreeMap::from([(
                "team-ci".into(),
                agent_access_cloudbees_ci::CloudbeesCiControllerConfig {
                    base_url: "https://ci.example.com/team-ci/".into(),
                    web_base_url: None,
                },
            )]),
            egress_proxy: None,
            allowed_upstream_hosts: vec!["https://ci.example.com/team-ci/**".into()],
        });
    config.credentials.service.insert(
        "cloudbees_ci".into(),
        CredentialConfig {
            kind: "basic_api_token".into(),
            username_ref: Some(synthetic_credential_ref()),
            token_ref: Some(synthetic_credential_ref()),
            provider: None,
            path: None,
            read_only: None,
            credential_name: None,
            profile: None,
            connection: None,
        },
    );
    config.policy.resources.push(ResourceDefinition {
        id: "ci-payments".into(),
        display_name: None,
        resource_type: CLOUDBEES_CI_JOB_RESOURCE.id().clone(),
        selector: ResourceSelector::Namespace {
            value: "team-ci/payments".into(),
        },
        allowed_execution_contexts: vec!["internal".into()],
        enabled: true,
    });
    config.policy.grants.push(PolicyGrantConfig {
        subjects: vec!["user:ci-user".into()],
        service: "cloudbees_ci".into(),
        actions: vec![
            "build.artifact.list".into(),
            "build.artifact.download".into(),
        ],
        resources: ResourceSelection {
            resource_ids: vec!["ci-payments".into()],
            resource_group_ids: vec![],
        },
        execution_contexts: Some(vec!["internal".into()]),
        credential_mode: "service".into(),
        priority: None,
    });
    let broker = TestBroker::start_config(&config).await;
    let app = broker.app();
    let internal = &[
        (CONTEXT_CALLER_HEADER, CONTEXT_CALLER_AUTH),
        (EXECUTION_CONTEXT_HEADER, "internal"),
        ("Authorization", "Bearer ci-discovery-token"),
    ];
    let external = &[
        (CONTEXT_CALLER_HEADER, CONTEXT_CALLER_AUTH),
        (EXECUTION_CONTEXT_HEADER, "external"),
        ("Authorization", "Bearer ci-discovery-token"),
    ];

    let response = governed_get(
        app.clone(),
        "/v1/spec/catalog",
        "ci-internal-catalog",
        internal,
    )
    .await;
    let status = response.status();
    let catalog = response_json(response).await;
    assert_eq!(status, StatusCode::OK, "{catalog}");
    assert!(catalog_has_action(
        &catalog,
        "cloudbees_ci",
        "build.artifact.list"
    ));
    assert!(catalog_has_action(
        &catalog,
        "cloudbees_ci",
        "build.artifact.download"
    ));
    assert!(!catalog_has_action(
        &catalog,
        "cloudbees_ci",
        "build.trigger"
    ));
    let external_catalog = response_json(
        governed_get(
            app.clone(),
            "/v1/spec/catalog",
            "ci-external-catalog",
            external,
        )
        .await,
    )
    .await;
    assert!(!catalog_has_service(&external_catalog, "cloudbees_ci"));

    let actions = response_json(
        governed_get(
            app.clone(),
            "/v1/services/cloudbees_ci/actions?resource=team-ci%2Fpayments%2Fbuild-api",
            "ci-actions",
            internal,
        )
        .await,
    )
    .await;
    assert_eq!(
        actions["actions"],
        json!(["build.artifact.download", "build.artifact.list"])
    );
    let outside = response_json(
        governed_get(
            app.clone(),
            "/v1/services/cloudbees_ci/actions?resource=team-ci%2Fother%2Fbuild-api",
            "ci-outside-actions",
            internal,
        )
        .await,
    )
    .await;
    assert_eq!(outside["actions"], json!([]));
    let hidden = governed_get(
        app,
        "/v1/services/cloudbees_ci/actions?resource=team-ci%2Fpayments%2Fbuild-api",
        "ci-hidden-actions",
        external,
    )
    .await;
    assert_eq!(hidden.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn cloudbees_ci_discovery_reports_job_inputs_and_reachable_controllers() {
    let mut config = fake_config("");
    config
        .providers
        .insert(agent_access_cloudbees_ci::CloudbeesCiProviderConfig {
            max_log_scan_bytes: 16 * 1024 * 1024,
            controllers: ["team-ci", "other-ci"]
                .into_iter()
                .map(|alias| {
                    (
                        alias.to_string(),
                        agent_access_cloudbees_ci::CloudbeesCiControllerConfig {
                            base_url: format!("https://ci.example.com/{alias}/"),
                            web_base_url: None,
                        },
                    )
                })
                .collect(),
            egress_proxy: None,
            allowed_upstream_hosts: vec!["https://ci.example.com/**".into()],
        });
    config.credentials.service.insert(
        "cloudbees_ci".into(),
        CredentialConfig {
            kind: "basic_api_token".into(),
            username_ref: Some(synthetic_credential_ref()),
            token_ref: Some(synthetic_credential_ref()),
            provider: None,
            path: None,
            read_only: None,
            credential_name: None,
            profile: None,
            connection: None,
        },
    );
    for (id, selector) in [
        ("ci-all", ResourceSelector::All),
        (
            "ci-other",
            ResourceSelector::Namespace {
                value: "other-ci".into(),
            },
        ),
        (
            "ci-build-api",
            ResourceSelector::Exact {
                value: "team-ci/payments/build-api".into(),
            },
        ),
    ] {
        config.policy.resources.push(ResourceDefinition {
            id: id.into(),
            display_name: None,
            resource_type: CLOUDBEES_CI_JOB_RESOURCE.id().clone(),
            selector,
            allowed_execution_contexts: vec!["default".into()],
            enabled: true,
        });
    }
    config
        .policy
        .resource_groups
        .push(agent_access_core::ResourceGroupDefinition {
            id: "ci-visible".into(),
            name: "Visible CI".into(),
            included_resource_ids: vec!["ci-all".into()],
            excluded_resource_ids: vec!["ci-other".into()],
        });
    for (action, resources) in [
        (
            "build.view",
            ResourceSelection {
                resource_ids: vec![],
                resource_group_ids: vec!["ci-visible".into()],
            },
        ),
        (
            "job.view",
            ResourceSelection {
                resource_ids: vec!["ci-build-api".into()],
                resource_group_ids: vec![],
            },
        ),
    ] {
        config.policy.grants.push(PolicyGrantConfig {
            subjects: vec!["group:anonymous".into()],
            service: "cloudbees_ci".into(),
            actions: vec![action.into()],
            resources,
            execution_contexts: None,
            credential_mode: "service".into(),
            priority: None,
        });
    }
    let broker = TestBroker::start_config(&config).await;
    let app = broker.app();
    let response = governed_get(
        app,
        "/v1/services/cloudbees_ci/resources",
        "ci-coverage",
        &[],
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    let body = response_json(response).await;
    // `all` is reported per reachable controller; the excluded controller is
    // never named, and the registered job carries its split inputs.
    assert_eq!(
        body,
        json!({
            "service": "cloudbees_ci",
            "resources": [{
                "id": "ci-build-api", "type": "cloudbees_ci_job", "value": "team-ci/payments/build-api",
                "inputs": {"controller": "team-ci", "job": "payments/build-api"}
            }],
            "coverage": [{
                "type": "cloudbees_ci_job",
                "selector": {"kind": "namespace", "value": "team-ci"},
                "inputs": {"controller": "team-ci"},
                "restricted": false
            }],
            "nextCursor": null
        })
    );
}

#[tokio::test]
async fn discovery_routes_filter_resources_actions_and_publish_schemas() {
    let broker = TestBroker::start_config(&fake_config("")).await;
    let app = broker.app();
    let resources = governed_get(
        app.clone(),
        "/v1/services/fake/resources",
        "discovery-resources",
        &[],
    )
    .await;
    assert_eq!(resources.status(), StatusCode::OK);
    assert_eq!(
        response_json(resources).await,
        json!({
            "service":"fake", "resources":[{"id":"project-test", "type":"fake_project", "value":"TEST"}], "nextCursor":null
        })
    );
    for (query, actions) in [
        ("", json!(["echo"])),
        ("?resource=TEST", json!(["echo"])),
        ("?resource=OTHER", json!([])),
        ("?prefix=z", json!([])),
    ] {
        let response = governed_get(
            app.clone(),
            &format!("/v1/services/fake/actions{query}"),
            "discovery-actions",
            &[],
        )
        .await;
        assert_eq!(response.status(), StatusCode::OK);
        let value = response_json(response).await;
        assert_eq!(value["actions"], actions);
        assert_eq!(value.get("resource").is_some(), query.contains("resource="));
    }
    for path in [
        "/v1/services/fake/resources?limit=0",
        "/v1/services/fake/resources?limit=101",
        "/v1/services/fake/resources?limit=bogus",
        "/v1/services/fake/resources?prefix=",
        "/v1/services/fake/resources?cursor=invalid",
        "/v1/services/fake/resources?unknown=x",
        "/v1/services/fake/resources?prefix=T&prefix=T",
        "/v1/services/fake/actions?resource=bad/path",
        "/v1/services/fake/actions?resource=",
        "/v1/services/fake/actions?prefix=",
        "/v1/services/fake/actions?resource=TEST&resource=TEST",
    ] {
        let response = governed_get(app.clone(), path, "discovery-invalid", &[]).await;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST, "{path}");
        assert_eq!(response_json(response).await["reasonCode"], "input_invalid");
    }
    let fixture = spec_agent_fixture(&["fake"], false).await;
    let catalog_response = spec_get(
        fixture.app.clone(),
        "/v1/spec/catalog",
        "discovery-catalog",
        Some(&fixture.agent_token),
    )
    .await;
    assert_eq!(catalog_response.status(), StatusCode::OK);
    let catalog = response_json(catalog_response).await;
    for operation in ["resources", "actions"] {
        let route = format!("/v1/services/{{service}}/{operation}");
        assert!(catalog_has_route(&catalog, "GET", &route));
    }
    let openapi_response = spec_get(
        fixture.app,
        "/v1/spec/openapi.json",
        "discovery-openapi",
        Some(&fixture.agent_token),
    )
    .await;
    assert_eq!(openapi_response.status(), StatusCode::OK);
    let openapi = response_json(openapi_response).await;
    assert_eq!(
        openapi["paths"]["/v1/services/{service}/resources"]["get"]["responses"]["200"]["content"]
            ["application/json"]["schema"]["properties"]["nextCursor"]["type"],
        json!(["string", "null"])
    );
}

#[tokio::test]
async fn discovery_resource_type_must_name_a_type_the_service_uses() {
    let broker = TestBroker::start_config(&fake_config("")).await;
    let app = broker.app();
    for (path, key, expected) in [
        (
            "/v1/services/fake/resources?resourceType=fake_project",
            "resources",
            json!([{"id":"project-test", "type":"fake_project", "value":"TEST"}]),
        ),
        (
            "/v1/services/fake/actions?resource=TEST&resourceType=fake_project",
            "actions",
            json!(["echo"]),
        ),
    ] {
        let response = governed_get(app.clone(), path, "discovery-resource-type", &[]).await;
        assert_eq!(response.status(), StatusCode::OK, "{path}");
        assert_eq!(response_json(response).await[key], expected, "{path}");
    }
    for (path, message) in [
        (
            "/v1/services/fake/resources?resourceType=jira_project",
            "resourceType is not used by this service",
        ),
        (
            "/v1/services/fake/actions?resource=TEST&resourceType=jira_project",
            "resourceType is not used by this service",
        ),
        (
            // Well-formed but unregistered types are equally unused.
            "/v1/services/fake/resources?resourceType=jira_issue",
            "resourceType is not used by this service",
        ),
        (
            "/v1/services/fake/resources?resourceType=Fake-Project",
            "resourceType is invalid",
        ),
        (
            "/v1/services/fake/actions?resourceType=fake_project",
            "resourceType requires resource",
        ),
    ] {
        let response =
            governed_get(app.clone(), path, "discovery-resource-type-invalid", &[]).await;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST, "{path}");
        let body = response_json(response).await;
        assert_eq!(body["reasonCode"], "input_invalid", "{path}");
        assert_eq!(body["error"]["message"], message, "{path}");
    }
}

#[tokio::test]
async fn discovery_visibility_precedes_all_query_semantics() {
    let mut config = fake_config("");
    config.policy.grants.clear();
    let broker = TestBroker::start_config(&config).await;
    let app = broker.app();
    for service in ["fake", "missing"] {
        for tail in [
            "resources?limit=invalid&unknown=x",
            "resources?cursor=invalid",
            "actions?resource=bad/path",
            "actions?prefix=",
        ] {
            let response = governed_get(
                app.clone(),
                &format!("/v1/services/{service}/{tail}"),
                "discovery-hidden",
                &[],
            )
            .await;
            assert_eq!(response.status(), StatusCode::FORBIDDEN);
            let body = response_json(response).await;
            assert_eq!(body["reasonCode"], "service_action_denied");
            assert_eq!(
                body["error"]["message"],
                "service is not visible for this identity"
            );
        }
    }
}

#[tokio::test]
async fn discovery_agent_caveats_filter_resources_without_catalog_gating() {
    let fixture = spec_agent_fixture(&["fake", "gitlab_git"], true).await;
    let resources = spec_get(
        fixture.app.clone(),
        "/v1/services/fake/resources",
        "discovery-token-resources",
        Some(&fixture.agent_token),
    )
    .await;
    assert_eq!(resources.status(), StatusCode::OK);
    assert_eq!(
        response_json(resources).await["resources"][0]["value"],
        "TEST"
    );
    // Gateway remains discoverable even though it has no native invoke tools.
    let actions = spec_get(
        fixture.app.clone(),
        "/v1/services/gitlab_git/actions?resource=sip%2Fservice",
        "discovery-gateway-actions",
        Some(&fixture.agent_token),
    )
    .await;
    assert_eq!(actions.status(), StatusCode::OK);
    assert_eq!(
        response_json(actions).await["actions"],
        json!(["repo.fetch"])
    );
    let denied_fixture = spec_agent_fixture(&["gitlab"], false).await;
    let hidden = spec_get(
        denied_fixture.app,
        "/v1/services/fake/actions?resource=invalid",
        "discovery-token-hidden",
        Some(&denied_fixture.agent_token),
    )
    .await;
    assert_eq!(hidden.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn discovery_http_context_and_admission_match_existing_service_discovery() {
    let broker = TestBroker::start_config(&context_aware_fake_config("")).await;
    let app = broker.app();
    for suffix in ["resources", "actions?resource=TEST"] {
        let route = format!("/v1/services/fake/{suffix}");
        let missing = governed_get(app.clone(), &route, "discovery-context-missing", &[]).await;
        assert_eq!(missing.status(), StatusCode::FORBIDDEN);
        assert_eq!(
            response_json(missing).await["reasonCode"],
            "execution_context_required"
        );
        let internal = governed_get(
            app.clone(),
            &route,
            "discovery-context-internal",
            &[
                (CONTEXT_CALLER_HEADER, CONTEXT_CALLER_AUTH),
                (EXECUTION_CONTEXT_HEADER, "internal"),
            ],
        )
        .await;
        assert_eq!(internal.status(), StatusCode::OK);
        let external = governed_get(
            app.clone(),
            &route,
            "discovery-context-external",
            &[
                (CONTEXT_CALLER_HEADER, CONTEXT_CALLER_AUTH),
                (EXECUTION_CONTEXT_HEADER, "external"),
            ],
        )
        .await;
        assert_eq!(external.status(), StatusCode::FORBIDDEN);
        assert_eq!(
            response_json(external).await["reasonCode"],
            "service_action_denied"
        );
    }
    let mut config = fake_config("");
    config.limits.auth_requests_per_principal_per_minute = 1;
    let broker = TestBroker::start_config(&config).await;
    let app = broker.app();
    let hidden = governed_get(
        app.clone(),
        "/v1/services/missing/resources?limit=bad",
        "discovery-rate-first",
        &[],
    )
    .await;
    assert_eq!(hidden.status(), StatusCode::FORBIDDEN);
    let limited = governed_get(
        app,
        "/v1/services/fake/actions",
        "discovery-rate-second",
        &[],
    )
    .await;
    assert_eq!(limited.status(), StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(response_json(limited).await["reasonCode"], "rate_limited");
}

#[tokio::test]
async fn discovery_non_invoke_token_retains_service_visibility() {
    let fixture = spec_token_fixture(
        &[],
        false,
        agent_access_core::BrokerTokenClass::UserManage,
        false,
    )
    .await;
    let catalog = spec_get(
        fixture.app.clone(),
        "/v1/spec/catalog",
        "discovery-manage-catalog",
        Some(&fixture.agent_token),
    )
    .await;
    assert_eq!(catalog.status(), StatusCode::OK);
    assert!(
        response_json(catalog).await["services"]
            .as_array()
            .unwrap()
            .is_empty()
    );
    let actions = spec_get(
        fixture.app.clone(),
        "/v1/services/fake/actions",
        "discovery-manage-actions",
        Some(&fixture.agent_token),
    )
    .await;
    assert_eq!(actions.status(), StatusCode::OK);
    assert_eq!(response_json(actions).await["actions"], json!(["echo"]));
    let resources = spec_get(
        fixture.app,
        "/v1/services/fake/resources",
        "discovery-manage-resources",
        Some(&fixture.agent_token),
    )
    .await;
    assert_eq!(resources.status(), StatusCode::OK);
    assert_eq!(
        response_json(resources).await["resources"][0]["value"],
        "TEST"
    );
}
