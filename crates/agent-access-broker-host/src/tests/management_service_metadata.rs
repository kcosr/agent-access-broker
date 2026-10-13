//! Service metadata on management responses: display names, per-action
//! read-only classification, gateway hosts and credential verification inputs
//! are properties of the configured service, so they must not depend on the
//! caller's execution context or grants.
use super::*;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;

struct MetadataFixture {
    _broker: TestBroker,
    app: Router,
    alice_user_token: String,
    admin_token: String,
}

/// Alice's only grants are in `external`; the configured default is `internal`.
async fn metadata_fixture() -> MetadataFixture {
    let hash_key_path = temp_path("service-metadata-hash-key");
    let store_path = temp_path("service-metadata-store.sqlite");
    let audit_path = temp_path("service-metadata.audit.sqlite");
    std::fs::write(&hash_key_path, URL_SAFE_NO_PAD.encode([41_u8; 32])).unwrap();

    let mut config = fake_config(audit_path.to_str().unwrap());
    config.execution_context = Some(ExecutionContextConfig {
        allowed_values: vec!["internal".to_string(), "external".to_string()],
        default_context: Some("internal".to_string()),
    });
    config.policy.resources = fixture_resources(&["internal", "external"]);
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
    config.management.enabled = true;
    config.broker_tokens = Some(agent_access_core::BrokerTokensConfig {
        hash_key_ref: format!("file:{}", hash_key_path.display()),
        default_agent_invoke_ttl: None,
        default_user_manage_ttl: Some("8h".to_string()),
        default_admin_ttl: None,
        max_self_issued_agent_invoke_ttl: Some("30d".to_string()),
        ..Default::default()
    });
    config.providers.insert(
        serde_json::from_value::<agent_access_jira::JiraProviderConfig>(json!({
            "tenant_host": "example.atlassian.net",
            "allowed_upstream_hosts": ["https://example.atlassian.net/rest/api/3/**"]
        }))
        .unwrap(),
    );
    let mut gateway = test_git_gateway_config();
    gateway.credential_modes = vec!["per_user".to_string()];
    gateway.allowed_upstream_hosts = vec!["https://gitlab.example.com/**".to_string()];
    gateway.git.as_mut().unwrap().allow_push = true;
    config.gateways.insert("gitlab_git".to_string(), gateway);
    for (service, profile) in [
        ("gitlab_git", "git-bearer-token"),
        ("jira", "jira-cloud-api-token"),
    ] {
        config.credentials.per_user.insert(
            service.to_string(),
            CredentialConfig {
                kind: "managed_store".to_string(),
                username_ref: None,
                token_ref: None,
                provider: None,
                path: None,
                read_only: None,
                credential_name: Some("default".to_string()),
                profile: Some(profile.to_string()),
            },
        );
    }
    let grant = |service: &str, actions: &[&str], mode: &str, resources| PolicyGrantConfig {
        subjects: vec!["user:alice".to_string()],
        execution_contexts: Some(vec!["external".to_string()]),
        service: service.to_string(),
        actions: actions.iter().map(|action| action.to_string()).collect(),
        resources,
        credential_mode: mode.to_string(),
        priority: None,
    };
    config.policy.grants = vec![
        grant(
            "fake",
            &["echo"],
            "service",
            selected_resources(&[("project", &["TEST"])]),
        ),
        grant(
            "gitlab_git",
            &["repo.fetch", "repo.push"],
            "per_user",
            selected_resources(&[("repository", &["sip/service"])]),
        ),
        grant(
            "jira",
            &["issue.view", "issue.update"],
            "per_user",
            selected_resources(&[("jira-project", &["PROJ"])]),
        ),
    ];

    let store = agent_access_core::ManagedStore::open(
        &managed_store_config,
        agent_access_core::ManagedStoreOpenMode::Startup,
    )
    .unwrap();
    for principal in ["alice", "admin"] {
        store
            .create_principal(agent_access_core::PrincipalWriteRequest {
                role: agent_access_core::PrincipalRole::User,
                self_service_enabled: None,
                principal_id: principal.to_string(),
                kind: "user".to_string(),
                display_name: None,
                email: None,
                external_subject: None,
                created_by: "test".to_string(),
            })
            .unwrap();
    }
    store
        .patch_principal_access(agent_access_core::PrincipalAccessPatchRequest {
            principal_id: ("admin").into(),
            role: Some(agent_access_core::PrincipalRole::Admin),
            self_service_enabled: None,
            actor: ("test").into(),
        })
        .unwrap();
    let hasher =
        agent_access_core::BrokerTokenHasher::load(config.broker_tokens.as_ref().unwrap()).unwrap();
    let issue = |principal: &str, token_class: agent_access_core::BrokerTokenClass| {
        store
            .issue_broker_token(
                &hasher,
                agent_access_core::BrokerTokenIssueRequest {
                    principal_id: principal.to_string(),
                    name: format!("{principal} fixture"),
                    token_class,
                    scopes: json!({}),
                    expires_at: None,
                    created_by: "test".to_string(),
                },
            )
            .unwrap()
            .token
    };
    let alice_user_token = issue("alice", agent_access_core::BrokerTokenClass::UserManage);
    let admin_token = issue("admin", agent_access_core::BrokerTokenClass::Admin);
    drop(store);

    let broker = TestBroker::start_config(&config).await;
    MetadataFixture {
        app: broker.app(),
        _broker: broker,
        alice_user_token,
        admin_token,
    }
}

async fn management_result(app: &Router, token: &str, uri: &str) -> Value {
    let response = authed_json_request(
        app.clone(),
        Method::GET,
        uri,
        "service-metadata",
        "Authorization",
        format!("Bearer {token}"),
        None,
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK, "{uri}");
    let mut body = response_json(response).await;
    assert_eq!(body["ok"], true, "{uri}: {body}");
    body["result"].take()
}

fn entry<'a>(entries: &'a Value, key: &str, name: &str) -> &'a Value {
    entries
        .as_array()
        .unwrap()
        .iter()
        .find(|entry| entry[key] == name)
        .unwrap_or_else(|| panic!("{name} missing from {entries}"))
}

fn assert_token_option_metadata(options: &Value) {
    // Alice has grants only in `external`, never in the default `internal`.
    assert_eq!(options["executionContexts"], json!(["external"]));
    let services = &options["services"];
    assert_eq!(services.as_array().unwrap().len(), 3, "{services}");
    for (service, display_name, broker_hosts, actions) in [
        ("fake", "Fake Provider", json!([]), vec![("echo", true)]),
        (
            "gitlab_git",
            "GitLab Git",
            json!(["git.example.test"]),
            vec![("repo.fetch", true), ("repo.push", false)],
        ),
        (
            "jira",
            "Jira",
            json!([]),
            vec![("issue.view", true), ("issue.update", false)],
        ),
    ] {
        let option = entry(services, "service", service);
        assert_eq!(option["displayName"], display_name, "{service}");
        assert_eq!(option["brokerHosts"], broker_hosts, "{service}");
        assert_eq!(
            option["executionContexts"],
            json!(["external"]),
            "{service}"
        );
        assert_eq!(
            option["actions"].as_array().unwrap().len(),
            actions.len(),
            "{service}"
        );
        for (action, read_only) in actions {
            let action_option = entry(&option["actions"], "action", action);
            assert_eq!(action_option["readOnly"], read_only, "{service} {action}");
            assert_eq!(
                action_option["executionContexts"],
                json!(["external"]),
                "{service} {action}"
            );
        }
    }
}

fn assert_credential_target_metadata(targets: &Value) {
    assert_eq!(targets.as_array().unwrap().len(), 2, "{targets}");
    let git = entry(targets, "service", "gitlab_git");
    assert_eq!(git["displayName"], "GitLab Git");
    assert_eq!(git["credentialVerificationInputs"], json!(["repository"]));
    // Existing fields are unchanged.
    assert_eq!(git["credentialName"], "default");
    assert_eq!(git["profile"], "git-bearer-token");
    let jira = entry(targets, "service", "jira");
    assert_eq!(jira["displayName"], "Jira");
    // Always serialized, empty when verification needs no input.
    assert_eq!(jira["credentialVerificationInputs"], json!([]));
    assert_eq!(jira["credentialName"], "default");
    assert_eq!(jira["profile"], "jira-cloud-api-token");
}

#[tokio::test]
async fn token_options_carry_service_metadata_outside_the_default_context() {
    let fixture = metadata_fixture().await;
    let options = management_result(
        &fixture.app,
        &fixture.alice_user_token,
        "/v1/tokens/options",
    )
    .await;
    assert_token_option_metadata(&options);

    let admin_options = management_result(
        &fixture.app,
        &fixture.admin_token,
        "/v1/admin/principals/alice/agent-token-options",
    )
    .await;
    assert_token_option_metadata(&admin_options);
}

#[tokio::test]
async fn credential_targets_carry_service_metadata_outside_the_default_context() {
    let fixture = metadata_fixture().await;
    let targets = management_result(
        &fixture.app,
        &fixture.alice_user_token,
        "/v1/credentials/targets",
    )
    .await;
    assert_credential_target_metadata(&targets);

    let admin_targets = management_result(
        &fixture.app,
        &fixture.admin_token,
        "/v1/admin/principals/alice/credentials/targets",
    )
    .await;
    assert_credential_target_metadata(&admin_targets);
}
