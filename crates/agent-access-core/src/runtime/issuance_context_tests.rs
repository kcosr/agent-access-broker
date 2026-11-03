use super::*;
use crate::{
    AgentTokenIssuanceMode, AgentTokenIssuanceSource, GroupAgentTokenIssuanceSetting,
    GroupPatchRequest, GroupWriteRequest, PrincipalAccessPatchRequest, PrincipalAgentTokenIssuance,
    PrincipalAgentTokenIssuanceSetting, PrincipalRole, PrincipalWriteRequest,
};

fn context_config(contexts: &[&str]) -> BrokerConfig {
    let mut config = base_fake_config();
    config.identity.authority = "managed".into();
    config.identity.groups.clear();
    config.policy.grants.clear();
    config.policy.resources.clear();
    config.policy.resource_groups.clear();
    config.managed_store = Some(ManagedStoreConfig {
        kind: "sqlite".into(),
        path: temp_path("issuance-contexts.sqlite").display().to_string(),
        require_registered_principal_for_invocation: false,
        auto_migrate: true,
    });
    config.execution_context = Some(crate::ExecutionContextConfig {
        allowed_values: contexts.iter().map(|value| (*value).to_string()).collect(),
        default_context: None,
    });
    config
}

fn create_principal(runtime: &BrokerRuntime, setting: PrincipalAgentTokenIssuanceSetting) {
    runtime
        .managed_store()
        .unwrap()
        .create_principal(
            PrincipalWriteRequest {
                principal_id: "alice".into(),
                kind: "user".into(),
                display_name: None,
                email: None,
                external_subject: None,
                role: PrincipalRole::User,
                self_service_enabled: Some(true),
                agent_token_issuance: setting,
                created_by: "admin".into(),
            },
            runtime.execution_context_registry(),
        )
        .unwrap();
}

fn assert_reference_rejected(result: Result<BrokerRuntime, RuntimeError>, owner: &str) {
    let Err(RuntimeError::ManagedStore { message }) = result else {
        panic!("expected managed-store context reference rejection");
    };
    assert!(message.contains(owner), "{message}");
    assert!(message.contains("retired"), "{message}");
}

#[test]
fn principal_context_retirement_checks_inactive_owners_under_supported_authorities() {
    // TOML identity with managed policy remains an invalid configuration;
    // retirement is independent of policy authority within supported combinations.
    for (identity_authority, policy_authority) in [
        ("managed", "managed"),
        ("managed", "toml"),
        ("toml", "toml"),
    ] {
        let mut config = context_config(&["retired", "retained"]);
        config.identity.authority = identity_authority.into();
        config.policy.authority = policy_authority.into();
        let runtime = BrokerRuntime::new(config.clone()).unwrap();
        create_principal(
            &runtime,
            PrincipalAgentTokenIssuanceSetting::new(
                PrincipalAgentTokenIssuance::ReadOnly,
                vec!["retired".into()],
            )
            .unwrap(),
        );
        let store = runtime.managed_store().unwrap();
        store.set_principal_enabled("alice", false).unwrap();
        config.execution_context.as_mut().unwrap().allowed_values = vec!["retained".into()];

        assert_reference_rejected(BrokerRuntime::new(config.clone()), "alice");
        assert_reference_rejected(
            BrokerRuntime::new_for_reload(config.clone(), &runtime),
            "alice",
        );
        assert!(runtime.execution_context_registry().contains("retired"));
        assert_eq!(
            store
                .principal("alice")
                .unwrap()
                .agent_token_issuance
                .allowed_execution_contexts,
            ["retired"]
        );

        store
            .patch_principal_access(
                PrincipalAccessPatchRequest {
                    principal_id: "alice".into(),
                    role: None,
                    self_service_enabled: None,
                    agent_token_issuance: Some(
                        PrincipalAgentTokenIssuanceSetting::new(
                            PrincipalAgentTokenIssuance::Disabled,
                            vec![],
                        )
                        .unwrap(),
                    ),
                    actor: "admin".into(),
                },
                runtime.execution_context_registry(),
            )
            .unwrap();
        let replacement = BrokerRuntime::new_for_reload(config, &runtime).unwrap();
        assert!(!replacement.execution_context_registry().contains("retired"));
    }
}

#[test]
fn dormant_group_context_retirement_requires_restore_switch_edit_for_managed_identity() {
    let config = context_config(&["retired", "retained"]);
    let runtime = BrokerRuntime::new(config.clone()).unwrap();
    let store = runtime.managed_store().unwrap();
    store
        .create_group(
            GroupWriteRequest {
                group_id: "disabled-readers".into(),
                display_name: None,
                description: None,
                auto_enroll_new_microsoft_users: false,
                agent_token_issuance: GroupAgentTokenIssuanceSetting::new(
                    AgentTokenIssuanceMode::ReadOnly,
                    vec!["retired".into()],
                )
                .unwrap(),
                created_by: "admin".into(),
            },
            runtime.execution_context_registry(),
        )
        .unwrap();
    store
        .patch_group(
            GroupPatchRequest {
                group_id: "disabled-readers".into(),
                display_name: None,
                description: None,
                status: Some("disabled".into()),
                auto_enroll_new_microsoft_users: None,
                agent_token_issuance: None,
                updated_by: "admin".into(),
            },
            runtime.execution_context_registry(),
        )
        .unwrap();

    let mut retired = config.clone();
    retired.execution_context.as_mut().unwrap().allowed_values = vec!["retained".into()];
    assert_reference_rejected(BrokerRuntime::new(retired.clone()), "disabled-readers");
    assert_reference_rejected(
        BrokerRuntime::new_for_reload(retired.clone(), &runtime),
        "disabled-readers",
    );

    retired.identity.authority = "toml".into();
    let toml_runtime = BrokerRuntime::new_for_reload(retired.clone(), &runtime).unwrap();
    BrokerRuntime::new(retired.clone()).unwrap();
    retired.identity.authority = "managed".into();
    assert_reference_rejected(BrokerRuntime::new(retired.clone()), "disabled-readers");
    assert_reference_rejected(
        BrokerRuntime::new_for_reload(retired.clone(), &toml_runtime),
        "disabled-readers",
    );
    assert_eq!(toml_runtime.config().identity.authority, "toml");
    assert!(
        !toml_runtime
            .execution_context_registry()
            .contains("retired")
    );

    let restored = BrokerRuntime::new_for_reload(config, &toml_runtime).unwrap();
    restored
        .managed_store()
        .unwrap()
        .patch_group(
            GroupPatchRequest {
                group_id: "disabled-readers".into(),
                display_name: None,
                description: None,
                status: None,
                auto_enroll_new_microsoft_users: None,
                agent_token_issuance: Some(GroupAgentTokenIssuanceSetting::default()),
                updated_by: "admin".into(),
            },
            restored.execution_context_registry(),
        )
        .unwrap();
    let cleaned = BrokerRuntime::new_for_reload(retired, &restored).unwrap();
    assert!(!cleaned.execution_context_registry().contains("retired"));
}

#[test]
fn registry_additions_and_order_change_projection_without_rewriting_policy() {
    let mut config = context_config(&["sandbox", "production"]);
    let runtime = BrokerRuntime::new(config.clone()).unwrap();
    create_principal(
        &runtime,
        PrincipalAgentTokenIssuanceSetting::new(
            PrincipalAgentTokenIssuance::WriteCapable,
            vec!["sandbox".into(), "production".into()],
        )
        .unwrap(),
    );
    let store = runtime.managed_store().unwrap();
    let saved = store.principal("alice").unwrap();
    let first = store
        .agent_token_issuance_policy("alice", &runtime.agent_token_issuance_environment())
        .unwrap();
    assert_eq!(first.source, AgentTokenIssuanceSource::User);
    assert_eq!(
        first
            .contexts
            .iter()
            .map(|row| row.execution_context.as_str())
            .collect::<Vec<_>>(),
        ["sandbox", "production"]
    );

    config.execution_context.as_mut().unwrap().allowed_values =
        vec!["production".into(), "new-context".into(), "sandbox".into()];
    let replacement = BrokerRuntime::new_for_reload(config, &runtime).unwrap();
    assert_eq!(
        replacement
            .execution_context_registry()
            .iter()
            .collect::<Vec<_>>(),
        ["production", "new-context", "sandbox"]
    );
    let after = replacement
        .managed_store()
        .unwrap()
        .agent_token_issuance_policy("alice", &replacement.agent_token_issuance_environment())
        .unwrap();
    assert_eq!(
        after
            .contexts
            .iter()
            .map(|row| row.execution_context.as_str())
            .collect::<Vec<_>>(),
        ["production", "sandbox"]
    );
    assert_eq!(store.principal("alice").unwrap(), saved);
}

#[tokio::test]
async fn issuance_policy_changes_preserve_existing_token_runtime_access_and_current_grants() {
    let mut config = context_config(&["default", "other"]);
    config.execution_context.as_mut().unwrap().default_context = Some("default".into());
    config.identity.mode = "required".into();
    config.identity.sources = vec![IdentitySourceConfig {
        name: "broker".into(),
        kind: "broker_tokens".into(),
        header: "Authorization".into(),
        scheme: "Bearer".into(),
        principals: vec![],
    }];
    config.broker_tokens = Some(BrokerTokensConfig {
        hash_key_ref: format!(
            "file:{}",
            write_temp_secret(
                &base64::engine::general_purpose::URL_SAFE_NO_PAD.encode([57_u8; 32]),
            )
            .display()
        ),
        ..BrokerTokensConfig::default()
    });
    config.credentials.service.insert(
        "fake".into(),
        fake_service_credential(format!(
            "file:{}",
            write_temp_secret("fixture-service-token").display()
        )),
    );
    let initial = BrokerRuntime::new(config.clone()).unwrap();
    create_principal(
        &initial,
        PrincipalAgentTokenIssuanceSetting::new(
            PrincipalAgentTokenIssuance::WriteCapable,
            vec!["default".into()],
        )
        .unwrap(),
    );
    config.policy.resources = test_resources();
    config.policy.grants = vec![PolicyGrantConfig {
        subjects: vec!["user:alice".into()],
        service: "fake".into(),
        actions: vec!["echo".into()],
        resources: resource_selection(&["fake-project-TEST"]),
        execution_contexts: Some(vec!["default".into()]),
        credential_mode: "service".into(),
        priority: None,
    }];
    // Classify this isolated fixture action as a write so a policy downgrade
    // would expose any accidental inheritance of a new read-only ceiling.
    let mut descriptor = agent_access_fake::fake_descriptor();
    descriptor.actions[0].read_only = false;
    let runtime = BrokerRuntime::with_providers(
        config.clone(),
        [ServiceProvider::new(
            descriptor,
            Arc::new(agent_access_fake::FakeProvider),
        )],
    )
    .unwrap();
    let store = runtime.managed_store().unwrap();
    let token = store
        .issue_self_agent_token(
            runtime.broker_token_hasher().unwrap(),
            crate::SelfAgentTokenIssueRequest {
                principal_id: "alice".into(),
                name: "retained".into(),
                scopes: json!({"readOnly": false, "allowedExecutionContexts": ["default"]}),
                expires_at: None,
                created_by: "alice".into(),
            },
            &runtime.agent_token_issuance_environment(),
        )
        .unwrap();
    let mut headers = HeaderMap::new();
    headers.insert(
        "authorization",
        format!("Bearer {}", token.token).parse().unwrap(),
    );
    let identity = runtime.resolve_identity(&headers).unwrap();
    let options =
        serde_json::to_value(runtime.agent_token_options_for_identity(&identity)).unwrap();
    let discovery =
        serde_json::to_value(runtime.visible_services(&identity, &default_execution_context()))
            .unwrap();
    for (mode, contexts) in [
        (
            PrincipalAgentTokenIssuance::ReadOnly,
            vec!["default".into()],
        ),
        (
            PrincipalAgentTokenIssuance::WriteCapable,
            vec!["other".into()],
        ),
        (PrincipalAgentTokenIssuance::Disabled, vec![]),
    ] {
        let before_policy_edit = store.broker_token(&token.record.token_id).unwrap();
        store
            .patch_principal_access(
                PrincipalAccessPatchRequest {
                    principal_id: "alice".into(),
                    role: None,
                    self_service_enabled: None,
                    agent_token_issuance: Some(
                        PrincipalAgentTokenIssuanceSetting::new(mode, contexts).unwrap(),
                    ),
                    actor: "admin".into(),
                },
                runtime.execution_context_registry(),
            )
            .unwrap();
        assert_eq!(
            store.broker_token(&token.record.token_id).unwrap(),
            before_policy_edit
        );
        let current = runtime.resolve_identity(&headers).unwrap();
        assert_eq!(current.principal, identity.principal);
        assert_eq!(
            serde_json::to_value(runtime.agent_token_options_for_identity(&current)).unwrap(),
            options
        );
        assert_eq!(
            serde_json::to_value(runtime.visible_services(&current, &default_execution_context()))
                .unwrap(),
            discovery
        );
        let response = runtime
            .invoke(
                governed(OperationContext {
                    agent_request_id: "agent-retained-token".into(),
                    broker_request_id: Uuid::new_v4().to_string(),
                    identity: current,
                    service: "fake".into(),
                    action: "echo".into(),
                    source: SourceContext::unknown(),
                }),
                InvokeRequest::new(json!({"project": "TEST", "message": "hello"})),
            )
            .await;
        assert_eq!(response.envelope.decision, Decision::Allow);
    }
    config.policy.grants.clear();
    let before_reload = store.broker_token(&token.record.token_id).unwrap();
    let no_grants = BrokerRuntime::new_for_reload(config, &runtime).unwrap();
    assert_eq!(
        store.broker_token(&token.record.token_id).unwrap(),
        before_reload
    );
    let current = no_grants.resolve_identity(&headers).unwrap();
    assert!(
        no_grants
            .visible_services(&current, &default_execution_context())
            .is_empty()
    );
    let response = no_grants
        .invoke(
            governed(OperationContext {
                agent_request_id: "agent-current-grants".into(),
                broker_request_id: Uuid::new_v4().to_string(),
                identity: current,
                service: "fake".into(),
                action: "echo".into(),
                source: SourceContext::unknown(),
            }),
            InvokeRequest::new(json!({"project": "TEST", "message": "hello"})),
        )
        .await;
    assert_eq!(
        response.envelope.reason_code,
        Some(ReasonCode::ServiceActionDenied.into())
    );
    let saved = store.broker_token(&token.record.token_id).unwrap();
    assert_eq!(saved.token_hash, token.record.token_hash);
    assert_eq!(saved.scopes, token.record.scopes);
}
