//! Service metadata on management responses: display names, per-action
//! read-only classification, gateway hosts and credential verification inputs
//! are properties of the configured service, so they must not depend on the
//! caller's execution context or grants. The HTTP MCP endpoint offered with
//! token options is likewise configuration, shown only to token issuers.
use super::*;
use agent_access_core::{TrustedCallerConfig, TrustedCallerContextMode};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;

struct MetadataFixture {
    _broker: TestBroker,
    app: Router,
    alice_user_token: String,
    admin_token: String,
    auditor_token: String,
}

/// Alice's only grants are in `external`; the configured default is `internal`.
async fn metadata_fixture() -> MetadataFixture {
    metadata_fixture_with(|_| {}).await
}

/// [`metadata_fixture`] with `configure` applied to the broker configuration.
async fn metadata_fixture_with(configure: impl FnOnce(&mut BrokerConfig)) -> MetadataFixture {
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
        ("jira", "atlassian-api-token"),
    ] {
        super::use_token_connection(&mut config, service, profile, &[service]);
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
    for principal in ["alice", "admin", "auditor"] {
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
    for (principal, role) in [
        ("admin", agent_access_core::PrincipalRole::Admin),
        ("auditor", agent_access_core::PrincipalRole::Auditor),
    ] {
        store
            .patch_principal_access(agent_access_core::PrincipalAccessPatchRequest {
                principal_id: principal.into(),
                role: Some(role),
                self_service_enabled: None,
                actor: ("test").into(),
            })
            .unwrap();
    }
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
    let auditor_token = issue("auditor", agent_access_core::BrokerTokenClass::Admin);
    drop(store);

    configure(&mut config);
    let broker = TestBroker::start_config(&config).await;
    MetadataFixture {
        app: broker.app(),
        _broker: broker,
        alice_user_token,
        admin_token,
        auditor_token,
    }
}

async fn management_result(app: &Router, token: &str, uri: &str) -> Value {
    management_result_with(app, "Authorization", format!("Bearer {token}"), uri).await
}

async fn management_result_with(app: &Router, header: &str, value: String, uri: &str) -> Value {
    let response = authed_json_request(
        app.clone(),
        Method::GET,
        uri,
        "service-metadata",
        header,
        value,
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
    let git = entry(targets, "connection", "gitlab_git");
    // Without a configured display name, the connection shows its ID.
    assert_eq!(git["displayName"], "gitlab_git");
    assert_eq!(
        git["consumers"],
        json!([{"service": "gitlab_git", "displayName": "GitLab Git",
            "credentialVerificationInputs": ["repository"]}])
    );
    assert_eq!(git["otherConsumers"], 0);
    assert_eq!(git["profile"], "git-bearer-token");
    assert_eq!(git["inputSchema"]["connection"], "gitlab_git");
    let jira = entry(targets, "connection", "jira");
    assert_eq!(jira["displayName"], "jira");
    // Always serialized, empty when verification needs no input.
    assert_eq!(
        jira["consumers"][0]["credentialVerificationInputs"],
        json!([])
    );
    assert_eq!(jira["profile"], "atlassian-api-token");
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

const MCP_URL: &str = "https://broker.example.test/mcp";
const AGENT_TOKEN_OPTIONS: [&str; 2] = [
    "/v1/tokens/options",
    "/v1/admin/principals/alice/agent-token-options",
];

fn enable_mcp(config: &mut BrokerConfig) {
    config.mcp.enabled = true;
    config.mcp.public_url = Some(MCP_URL.to_string());
}

/// Options for Alice, read by Alice herself and by the administrator.
async fn issuer_token_options(fixture: &MetadataFixture) -> [Value; 2] {
    [
        management_result(
            &fixture.app,
            &fixture.alice_user_token,
            AGENT_TOKEN_OPTIONS[0],
        )
        .await,
        management_result(&fixture.app, &fixture.admin_token, AGENT_TOKEN_OPTIONS[1]).await,
    ]
}

#[tokio::test]
async fn token_options_offer_the_bearer_mcp_endpoint_to_token_issuers() {
    let fixture = metadata_fixture_with(enable_mcp).await;
    for (uri, options) in AGENT_TOKEN_OPTIONS
        .iter()
        .zip(issuer_token_options(&fixture).await)
    {
        assert_eq!(options["mcp"], json!({"url": MCP_URL}), "{uri}");
        assert_token_option_metadata(&options);
    }
    // Auditors read the same options but cannot issue the token.
    let audited =
        management_result(&fixture.app, &fixture.auditor_token, AGENT_TOKEN_OPTIONS[1]).await;
    assert_eq!(audited["mcp"], Value::Null, "{audited}");
    assert_token_option_metadata(&audited);
}

#[tokio::test]
async fn token_options_offer_the_endpoint_as_the_broker_parses_it() {
    let fixture = metadata_fixture_with(|config| {
        enable_mcp(config);
        config.mcp.public_url = Some("https://例え.test\\mcp".to_string());
    })
    .await;
    for (uri, options) in AGENT_TOKEN_OPTIONS
        .iter()
        .zip(issuer_token_options(&fixture).await)
    {
        assert_eq!(
            options["mcp"],
            json!({"url": "https://xn--r8jz45g.test/mcp"}),
            "{uri}"
        );
    }
}

#[tokio::test]
async fn token_options_offer_no_mcp_endpoint_while_it_is_disabled() {
    let fixture = metadata_fixture_with(|config| {
        enable_mcp(config);
        config.mcp.enabled = false;
    })
    .await;
    for (uri, options) in AGENT_TOKEN_OPTIONS
        .iter()
        .zip(issuer_token_options(&fixture).await)
    {
        assert_eq!(options["mcp"], Value::Null, "{uri}: {options}");
    }
}

#[tokio::test]
async fn token_options_offer_no_mcp_endpoint_when_tokens_are_not_bearer_credentials() {
    // A forwarded-identity caller keeps the endpoint enabled, but the issued
    // token is presented in another header without the Bearer scheme.
    let caller = temp_path("service-metadata-caller");
    std::fs::write(&caller, "trusted-caller-credential-0123456789").unwrap();
    let fixture = metadata_fixture_with(|config| {
        enable_mcp(config);
        config.identity.sources[0].header = "X-Broker-Token".to_string();
        config.identity.sources[0].scheme = "raw".to_string();
        config.identity.trusted_callers.insert(
            "identity_ingress".to_string(),
            TrustedCallerConfig {
                credential_ref: format!("file:{}", caller.display()),
                credential_transport: Default::default(),
                username_namespace: None,
                context_mode: TrustedCallerContextMode::Fixed,
                execution_context: Some("internal".to_string()),
                allowed_execution_contexts: None,
                allow_forwarded_identity: true,
            },
        );
    })
    .await;
    for (uri, token) in AGENT_TOKEN_OPTIONS
        .iter()
        .zip([&fixture.alice_user_token, &fixture.admin_token])
    {
        let options =
            management_result_with(&fixture.app, "X-Broker-Token", token.clone(), uri).await;
        assert_eq!(options["mcp"], Value::Null, "{uri}: {options}");
        assert_token_option_metadata(&options);
    }
}
