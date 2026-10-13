//! Database-loaded imports use the broker's normal credentials, policy and publication.
use super::conformance_import::conformance_import_action;
use super::*;
use agent_access_core::imports::{
    ImportedCredentialBinding, ImportedCredentialDelivery, ImportedCredentialMode,
    ImportedCredentialPurpose, ImportedDiscoveryCredential, ImportedServiceDefinition,
};
use agent_access_core::{
    BrokerTokenClass, BrokerTokenHasher, BrokerTokenIssueRequest, BrokerTokensConfig,
    CredentialEncryptionConfig, CredentialEncryptionKeyConfig, ImportedActionStatus,
    ImportedActionWrite, ImportedCatalog, ImportedSecretWriteRequest, ImportedServiceStatus,
    ImportedServiceUpdateRequest, ImportsConfig, ManagedPolicyGrantCreateRequest,
    ManagedStoreError, ProvidersConfig,
};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
mod mcp_names;

pub(super) struct Fixture {
    _directory: tempfile::TempDir,
    pub(super) config: BrokerConfig,
    pub(super) runtime: BrokerRuntime,
    pub(super) tokens: BTreeMap<String, String>,
}
pub(super) fn definition() -> ImportedServiceDefinition {
    ImportedServiceDefinition {
        service: "observability".into(),
        display_name: "Imported observations".into(),
        adapter_kind: "conformance_import".into(),
        endpoint: "https://synthetic.invalid/mcp".into(),
        connection_settings: BTreeMap::new(),
        execution_bindings: vec![
            ImportedCredentialBinding::token(
                ImportedCredentialMode::Service,
                ImportedCredentialDelivery::Bearer,
            ),
            ImportedCredentialBinding::token(
                ImportedCredentialMode::PerUser,
                ImportedCredentialDelivery::Bearer,
            ),
        ],
        discovery: ImportedDiscoveryCredential::Execution,
        transport_auth: false,
        invocation_limit: None,
    }
}
pub(super) fn update(
    catalog: &ImportedCatalog,
    status: ImportedServiceStatus,
) -> ImportedServiceUpdateRequest {
    let record = &catalog.services[0];
    ImportedServiceUpdateRequest {
        definition: record.definition.clone(),
        status,
        actions: record
            .actions
            .iter()
            .map(|a| ImportedActionWrite {
                definition: a.definition.clone(),
                status: a.status,
            })
            .collect(),
        expected_version: record.version,
        expected_catalog_revision: catalog.revision,
        accepted_preview: None,
        actor: "admin".into(),
    }
}
fn grant(principal: &str, mode: &str) -> ManagedPolicyGrantCreateRequest {
    ManagedPolicyGrantCreateRequest {
        grant_id: Some(format!("import-{principal}")),
        subjects: vec![format!("user:{principal}")],
        execution_contexts: vec!["default".into()],
        service: "observability".into(),
        actions: vec!["inspect".into()],
        resources: ResourceSelection::default(),
        credential_mode: mode.into(),
        priority: None,
        status: None,
        description: None,
        created_by: "admin".into(),
    }
}
pub(super) fn fixture() -> Fixture {
    let directory = tempfile::tempdir().unwrap();
    create_private_dir(directory.path());
    let key = directory.path().join("key");
    std::fs::write(&key, URL_SAFE_NO_PAD.encode([32u8; 32])).unwrap();
    let hash = directory.path().join("hash");
    std::fs::write(&hash, URL_SAFE_NO_PAD.encode([33u8; 32])).unwrap();
    let mut config = fake_config(directory.path().join("audit.jsonl").to_str().unwrap());
    config.providers = ProvidersConfig::new(Arc::new(super::conformance_import::registry()));
    config.credentials = CredentialsConfig::default();
    config.limits.upload_spool_dir = directory.path().join("spool").display().to_string();
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
    config.policy = PolicyConfig {
        authority: "managed".into(),
        default_decision: "deny".into(),
        grants: vec![],
        resources: vec![],
        resource_groups: vec![],
    };
    config.management.enabled = true;
    config.managed_store = Some(agent_access_core::ManagedStoreConfig {
        kind: "sqlite".into(),
        path: directory.path().join("store.sqlite").display().to_string(),
        auto_migrate: true,
        require_registered_principal_for_invocation: true,
    });
    config.broker_tokens = Some(BrokerTokensConfig {
        hash_key_ref: format!("file:{}", hash.display()),
        ..Default::default()
    });
    config.credential_encryption = Some(CredentialEncryptionConfig {
        active_key: "test".into(),
        keys: vec![CredentialEncryptionKeyConfig {
            id: "test".into(),
            provider: "file".into(),
            env: None,
            path: Some(key.display().to_string()),
        }],
    });
    config.imports = ImportsConfig {
        enabled: true,
        allowed_kinds: vec!["conformance_import".into()],
        allowed_endpoints: vec!["https://synthetic.invalid/mcp".into()],
        disabled_services: vec![],
    };
    let initial = BrokerRuntime::new(config.clone()).unwrap();
    let store = initial.managed_store().unwrap();
    let ring = initial.credential_key_ring().unwrap();
    for principal in ["admin", "alice", "bob", "charlie"] {
        store
            .create_principal(PrincipalWriteRequest {
                role: agent_access_core::PrincipalRole::User,
                self_service_enabled: None,
                principal_id: principal.into(),
                kind: "user".into(),
                display_name: None,
                email: None,
                external_subject: None,
                created_by: "admin".into(),
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
    let draft = store
        .create_imported_service(definition(), "admin", |_| Ok(()))
        .unwrap()
        .catalog;
    let configured = store
        .write_imported_secret(
            ImportedSecretWriteRequest {
                service: "observability".into(),
                purpose: ImportedCredentialPurpose::Execution,
                expected_version: draft.services[0].version,
                expected_catalog_revision: draft.revision,
                token: "import-service-token".into(),
                actor: "admin".into(),
            },
            ring,
            |_, _| Ok(()),
        )
        .unwrap()
        .catalog;
    let mut accept = update(&configured, ImportedServiceStatus::Enabled);
    accept.actions = vec![ImportedActionWrite {
        definition: conformance_import_action(),
        status: ImportedActionStatus::Enabled,
    }];
    store.update_imported_service(accept, |_| Ok(())).unwrap();
    store
        .upsert_user_credential(
            ring,
            CredentialWriteRequest {
                owner_principal_id: "bob".into(),
                service: "observability".into(),
                name: "default".into(),
                profile: "token".into(),
                credential_kind: "bearer_token".into(),
                secret: json!({"token":"import-user-token"}),
                metadata: json!({}),
                actor: "admin".into(),
            },
            agent_access_core::CredentialManagementPurpose::Administrative,
        )
        .unwrap();
    let hasher = BrokerTokenHasher::load(config.broker_tokens.as_ref().unwrap()).unwrap();
    let tokens=["alice","bob","charlie"].into_iter().map(|principal| {
        let issued=store.issue_broker_token(&hasher,BrokerTokenIssueRequest{principal_id:principal.into(),name:"import fixture".into(),token_class:BrokerTokenClass::AgentInvoke,scopes:json!({"allowedServices":["observability"],"allowedExecutionContexts":["default"]}),expires_at:None,created_by:"admin".into()}).unwrap();
        (principal.into(),issued.token)
    }).collect();
    drop(initial);
    // Restart reconstructs descriptors, credential bindings and providers from DB.
    let runtime = BrokerRuntime::new(config.clone()).unwrap();
    for (principal, mode) in [
        ("alice", "service"),
        ("bob", "per_user"),
        ("charlie", "per_user"),
    ] {
        runtime
            .create_managed_policy_grant(grant(principal, mode))
            .unwrap();
    }
    Fixture {
        _directory: directory,
        config,
        runtime,
        tokens,
    }
}
/// Invokes the import through a test broker started, as a restart would, on
/// `runtime`'s configuration and the fixture's state.
async fn invoke(runtime: &BrokerRuntime, token: &str, id: &str) -> (StatusCode, Value) {
    let broker = import_broker(runtime.config()).await;
    let response = authed_json_request(
        broker.app(),
        Method::POST,
        "/v1/invoke/observability/inspect",
        id,
        "Authorization",
        format!("Bearer {token}"),
        Some(r#"{"inputs":{"message":"synthetic input"}}"#),
    )
    .await;
    let outcome = (response.status(), response_json(response).await);
    broker.stop().await;
    outcome
}

/// A test broker on `config` and the fixture's state.
pub(super) async fn import_broker(config: &BrokerConfig) -> TestBroker {
    TestBroker::start_with(
        TestBroker::config_builder(config)
            .reload_timeout(Duration::from_secs(5))
            .shutdown_timeout(Duration::from_secs(5)),
    )
    .await
}

#[tokio::test]
async fn imported_foundation_reconstructs_service_and_per_user_authority_on_restart() {
    let fixture = fixture();
    for (principal, mode) in [("alice", "service"), ("bob", "per_user")] {
        let (status, body) = invoke(
            &fixture.runtime,
            &fixture.tokens[principal],
            &format!("import-{principal}"),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(body["result"]["upstreamMcp"]["credentialMode"], mode);
        assert_eq!(body["result"]["upstreamMcp"]["authority"], mode);
        assert_eq!(body["result"]["upstreamMcp"]["principal"], principal);
    }
    let (status, body) = invoke(
        &fixture.runtime,
        &fixture.tokens["charlie"],
        "import-missing-user",
    )
    .await;
    assert!(
        !status.is_success(),
        "missing user credential must never fall back to service authority: {body}"
    );
    let broker = import_broker(&fixture.config).await;
    let response = authed_json_request(
        broker.app(),
        Method::GET,
        "/v1/spec/catalog",
        "import-catalog",
        "Authorization",
        format!("Bearer {}", fixture.tokens["alice"]),
        None,
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    let catalog = response_json(response).await;
    assert_eq!(catalog["services"][0]["service"], "observability");
    assert_eq!(catalog["services"][0]["actions"][0]["action"], "inspect");
    assert_eq!(catalog["services"][0]["actions"][0]["readOnly"], true);
}

#[tokio::test]
async fn imported_foundation_operator_disable_retains_grants_but_denies_calls() {
    let fixture = fixture();
    let mut disabled = fixture.config.clone();
    disabled.imports.enabled = false;
    let runtime = BrokerRuntime::new(disabled).unwrap();
    assert_eq!(
        runtime.imported_catalog().services[0].actions[0]
            .definition
            .action,
        "inspect"
    );
    assert!(
        runtime
            .managed_store()
            .unwrap()
            .policy_grant("import-alice")
            .is_ok()
    );
    assert!(!runtime.imported_action_available("observability", "inspect"));
    let (status, body) = invoke(
        &runtime,
        &fixture.tokens["alice"],
        "import-operator-disabled",
    )
    .await;
    assert!(!status.is_success(), "{body}");
    assert!(
        runtime
            .create_managed_policy_grant(grant("admin", "service"))
            .is_err()
    );
    let restored = BrokerRuntime::new(fixture.config.clone()).unwrap();
    assert_eq!(
        invoke(
            &restored,
            &fixture.tokens["alice"],
            "import-operator-restored"
        )
        .await
        .0,
        StatusCode::OK
    );
}

#[tokio::test]
async fn imported_foundation_admin_disable_is_durable_and_unrelated_policy_edits_work() {
    let fixture = fixture();
    let store = fixture.runtime.managed_store().unwrap();
    store
        .update_imported_service(
            update(
                fixture.runtime.imported_catalog(),
                ImportedServiceStatus::Disabled,
            ),
            |_| Ok(()),
        )
        .unwrap();
    let disabled = BrokerRuntime::new(fixture.config.clone()).unwrap();
    assert!(!disabled.imported_action_available("observability", "inspect"));
    assert!(
        disabled
            .managed_store()
            .unwrap()
            .policy_grant("import-bob")
            .is_ok()
    );
    disabled
        .patch_managed_policy_grant(agent_access_core::ManagedPolicyGrantPatchRequest {
            grant_id: "import-bob".into(),
            expected_version: 1,
            subjects: None,
            execution_contexts: None,
            service: None,
            actions: None,
            resources: None,
            credential_mode: None,
            priority: None,
            status: None,
            description: Some(Some("Retained while disabled".into())),
            updated_by: "admin".into(),
        })
        .unwrap();
    let (status, body) = invoke(&disabled, &fixture.tokens["alice"], "import-admin-disabled").await;
    assert!(!status.is_success(), "{body}");
    disabled
        .managed_store()
        .unwrap()
        .update_imported_service(
            update(disabled.imported_catalog(), ImportedServiceStatus::Retired),
            |_| Ok(()),
        )
        .unwrap();
    let retired = BrokerRuntime::new(fixture.config.clone()).unwrap();
    assert_eq!(
        retired.imported_catalog().services[0].status,
        ImportedServiceStatus::Retired
    );
    assert!(
        retired
            .managed_store()
            .unwrap()
            .policy_grant("import-bob")
            .is_ok()
    );
    assert!(
        retired
            .managed_store()
            .unwrap()
            .create_imported_service(definition(), "admin", |_| Ok(()))
            .is_err()
    );
}

#[tokio::test]
async fn imported_foundation_cancelled_waiter_does_not_abandon_commit_or_publication() {
    let fixture = fixture();
    let broker = import_broker(&fixture.config).await;
    let state = broker.state();
    let old = state.current();
    let request = update(
        old.runtime.imported_catalog(),
        ImportedServiceStatus::Disabled,
    );
    let (entered_send, entered_receive) = tokio::sync::oneshot::channel();
    let (continue_send, continue_receive) = std::sync::mpsc::channel();
    let caller = {
        let state = state.clone();
        let snapshot = old.clone();
        tokio::spawn(async move {
            state
                .imported_service_mutation(snapshot, move |runtime| {
                    let _ = entered_send.send(());
                    continue_receive.recv().unwrap();
                    let mut candidate = runtime
                        .imported_catalog()
                        .service("observability")
                        .unwrap()
                        .clone();
                    candidate.status = request.status;
                    let prepared = runtime.prepare_imported_service_change(&candidate, None)?;
                    let result = runtime
                        .managed_store()
                        .unwrap()
                        .update_imported_service(request, |catalog| {
                            runtime.with_imported_catalog(catalog.clone(), prepared)
                        })?;
                    Ok((result.value, ()))
                })
                .await
        })
    };
    entered_receive.await.unwrap();
    caller.abort();
    continue_send.send(()).unwrap();
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            if state.current().runtime.import_catalog_revision()
                > old.runtime.import_catalog_revision()
            {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    let current = state.current();
    assert_eq!(
        current.runtime.imported_catalog().services[0].status,
        ImportedServiceStatus::Disabled
    );
    assert_eq!(
        current
            .runtime
            .managed_store()
            .unwrap()
            .imported_catalog()
            .unwrap(),
        *current.runtime.imported_catalog()
    );
    assert!(
        !old.runtime
            .imported_action_available("observability", "inspect")
    );
    let stale = state
        .imported_service_mutation(old, |_| -> Result<(BrokerRuntime, ()), ManagedStoreError> {
            panic!("stale snapshot must fail before invoking the mutation")
        })
        .await;
    assert!(matches!(stale, Err(ManagedStoreError::VersionConflict)));
}

#[tokio::test]
async fn unsupported_personal_binding_keeps_precedence_and_ambiguity_fail_closed() {
    let fixture = fixture();
    let mut shared = grant("bob", "service");
    shared.grant_id = Some("bob-shared".into());
    shared.priority = Some(-1);
    fixture.runtime.create_managed_policy_grant(shared).unwrap();
    let mut change = update(
        fixture.runtime.imported_catalog(),
        ImportedServiceStatus::Enabled,
    );
    let personal = change
        .definition
        .execution_bindings
        .iter_mut()
        .find(|binding| binding.owner_mode == ImportedCredentialMode::PerUser)
        .unwrap();
    personal.mechanism = agent_access_core::imports::ImportedAuthMechanism::Oauth;
    personal.status = agent_access_core::imports::ImportedBindingStatus::Unsupported;
    fixture
        .runtime
        .managed_store()
        .unwrap()
        .update_imported_service(change, |_| Ok(()))
        .unwrap();
    let runtime = BrokerRuntime::new(fixture.config.clone()).unwrap();
    let (status, body) = invoke(
        &runtime,
        &fixture.tokens["bob"],
        "unsupported-personal-precedence",
    )
    .await;
    assert!(!status.is_success(), "{body}");
    assert_eq!(body["reasonCode"], "credential_not_provisioned");
    let mut shared = grant("bob", "service");
    shared.grant_id = Some("bob-shared-same-band".into());
    assert!(
        matches!(runtime.create_managed_policy_grant(shared), Err(ManagedStoreError::PolicyValidationIssues(issues)) if issues.iter().any(|issue| issue.code == "credential_mode_ambiguous"))
    );
}

#[tokio::test]
async fn ordinary_policy_edits_preserve_token_store_snapshot_identity() {
    let fixture = fixture();
    let broker = import_broker(&fixture.config).await;
    let state = broker.state();
    let admitted = state.current();
    state
        .managed_policy_mutation_from_snapshot(admitted.clone(), move |runtime| {
            let mut request = grant("admin", "service");
            request.grant_id = Some("admin-new".into());
            runtime.create_managed_policy_grant(request).map(|_| ())
        })
        .await
        .unwrap();
    assert!(Arc::ptr_eq(&admitted, &state.current()));
    state
        .token_store_call_from_snapshot(admitted, |runtime| {
            runtime
                .managed_store()
                .unwrap()
                .principal("admin")
                .map(|_| ())
        })
        .await
        .unwrap();
}

#[test]
fn unrelated_import_edits_preserve_other_dispatch_and_reject_mismatched_preparations() {
    let fixture = fixture();
    let runtime = &fixture.runtime;
    let store = runtime.managed_store().unwrap();
    let mut other = runtime.imported_catalog().services[0].clone();
    other.definition.service = "other_import".into();
    other.status = ImportedServiceStatus::Draft;
    other.actions.clear();
    other.slot_versions.clear();
    let prepared = runtime
        .prepare_imported_service_change(&other, None)
        .unwrap();
    let draft = store
        .create_imported_service(other.definition, "admin", |catalog| {
            runtime.with_imported_catalog(catalog.clone(), prepared)
        })
        .unwrap();
    runtime.retire_superseded_import_dispatch(&draft.value);
    assert!(runtime.imported_action_available("observability", "inspect"));
    let mut mismatched = draft.catalog.service("observability").unwrap().clone();
    mismatched.definition.display_name = "Uncommitted definition".into();
    let prepared = draft
        .value
        .prepare_imported_service_change(&mismatched, None)
        .unwrap();
    assert!(
        draft
            .value
            .with_imported_catalog(draft.catalog.clone(), prepared)
            .is_err()
    );
    let mut mismatched = draft.catalog.service("observability").unwrap().clone();
    mismatched.actions[0].definition.read_only = !mismatched.actions[0].definition.read_only;
    let prepared = draft
        .value
        .prepare_imported_service_change(&mismatched, None)
        .unwrap();
    assert!(
        draft
            .value
            .with_imported_catalog(draft.catalog.clone(), prepared)
            .is_err(),
        "enabled action definitions must match committed actions"
    );
    let prepared = runtime
        .prepare_imported_service_change(
            runtime.imported_catalog().service("observability").unwrap(),
            None,
        )
        .unwrap();
    assert!(
        draft
            .value
            .with_imported_catalog(draft.catalog, prepared)
            .is_err(),
        "preparation must belong to the admitted catalog"
    );
}

#[test]
fn disabled_grants_can_narrow_retained_references_but_cannot_be_reactivated() {
    let fixture = fixture();
    let mut request = grant("alice", "service");
    request.grant_id = Some("retained-disabled".into());
    request.subjects = vec!["user:alice".into(), "user:bob".into()];
    request.status = Some("disabled".into());
    fixture
        .runtime
        .create_managed_policy_grant(request)
        .unwrap();
    fixture
        .runtime
        .managed_store()
        .unwrap()
        .update_imported_service(
            update(
                fixture.runtime.imported_catalog(),
                ImportedServiceStatus::Disabled,
            ),
            |_| Ok(()),
        )
        .unwrap();
    let runtime = BrokerRuntime::new(fixture.config.clone()).unwrap();
    runtime
        .patch_managed_policy_grant(agent_access_core::ManagedPolicyGrantPatchRequest {
            grant_id: "retained-disabled".into(),
            expected_version: 1,
            subjects: Some(vec!["user:alice".into()]),
            execution_contexts: None,
            service: None,
            actions: None,
            resources: None,
            credential_mode: None,
            priority: None,
            status: None,
            description: None,
            updated_by: "admin".into(),
        })
        .unwrap();
    assert!(
        runtime
            .enable_managed_policy_grant(agent_access_core::ManagedPolicyGrantStatusRequest {
                grant_id: "retained-disabled".into(),
                expected_version: 2,
                updated_by: "admin".into()
            })
            .is_err()
    );
}

#[test]
fn unavailable_import_semantics_do_not_block_restart_or_cleanup() {
    let fixture = fixture();
    let mut action = conformance_import_action();
    action.input_schema["properties"]["message"]["pattern"] = json!("(");
    let connection =
        rusqlite::Connection::open(&fixture.config.managed_store.as_ref().unwrap().path).unwrap();
    connection
        .execute(
            "UPDATE imported_actions SET definition_json=?1 WHERE service='observability'",
            [serde_json::to_string(&action).unwrap()],
        )
        .unwrap();
    drop(connection);
    let runtime = BrokerRuntime::new(fixture.config.clone()).unwrap();
    assert!(!runtime.imported_action_available("observability", "inspect"));
    let request = update(runtime.imported_catalog(), ImportedServiceStatus::Disabled);
    let mut candidate = runtime
        .imported_catalog()
        .service("observability")
        .unwrap()
        .clone();
    candidate.status = ImportedServiceStatus::Disabled;
    let prepared = runtime
        .prepare_imported_service_change(&candidate, None)
        .unwrap();
    runtime
        .managed_store()
        .unwrap()
        .update_imported_service(request, |catalog| {
            runtime.with_imported_catalog(catalog.clone(), prepared)
        })
        .unwrap();
    assert!(BrokerRuntime::new(fixture.config.clone()).is_ok());
}

#[test]
fn retained_unavailable_oauth_binding_does_not_block_other_import_administration() {
    let fixture = fixture();
    let mut definition = definition();
    definition.execution_bindings[1] = agent_access_core::imports::ImportedCredentialBinding {
        owner_mode: ImportedCredentialMode::PerUser,
        mechanism: agent_access_core::imports::ImportedAuthMechanism::Oauth,
        delivery: ImportedCredentialDelivery::Bearer,
        status: agent_access_core::imports::ImportedBindingStatus::Configured,
        adapter_id: Some("mcp_oauth".into()),
        registration_id: Some("removed".into()),
        profile: Some("read".into()),
    };
    assert!(
        fixture
            .runtime
            .require_import_destination(&definition)
            .is_ok()
    );
    assert!(
        fixture
            .runtime
            .require_import_bindings(&definition, None)
            .is_err()
    );
    assert!(
        fixture
            .runtime
            .require_import_bindings(&definition, Some(&definition))
            .is_ok()
    );
    assert!(
        fixture
            .runtime
            .import_binding_available(&definition, &definition.execution_bindings[0])
    );
    assert!(
        !fixture
            .runtime
            .import_binding_available(&definition, &definition.execution_bindings[1])
    );
    let mut changed = definition.clone();
    changed.execution_bindings[1].profile = Some("different".into());
    assert!(
        fixture
            .runtime
            .require_import_bindings(&changed, Some(&definition))
            .is_err()
    );
}

#[test]
fn import_identity_collisions_name_both_owners_on_startup_reload_and_write() {
    // A native kind selected without a provider table still owns its name.
    static OBSERVABILITY_KIND: agent_access_provider::BackendRegistration =
        agent_access_provider::BackendRegistration::new(
            agent_access_provider::module_metadata!(),
            "observability",
            agent_access_provider::parse_backend_config::<agent_access_fake::FakeProviderConfig>,
        );
    let fixture = fixture();
    let mut colliding = fixture.config.clone();
    colliding.providers = ProvidersConfig::new(Arc::new(
        agent_access_core::BackendRegistry::new([&OBSERVABILITY_KIND])
            .unwrap()
            .with_imported_adapters([agent_access_core::imports::imported_adapter_registration(
                agent_access_provider::module_metadata!(),
                &super::conformance_import::CONFORMANCE_IMPORT_ADAPTER,
                None,
            )])
            .unwrap(),
    ));
    assert!(colliding.providers.get_kind("observability").is_none());
    let expected = "retained imported service observability collides with the selected native provider kind observability";
    let rejection = |result: Result<BrokerRuntime, agent_access_core::RuntimeError>| match result {
        Ok(_) => panic!("a colliding composition must not start"),
        Err(error) => error.to_string(),
    };
    let startup = rejection(BrokerRuntime::new(colliding.clone()));
    assert!(startup.contains(expected), "{startup}");
    let reload = rejection(BrokerRuntime::new_for_reload(colliding, &fixture.runtime));
    assert!(reload.contains(expected), "{reload}");
    // The failed candidates leave the published runtime serving the import.
    assert!(
        fixture
            .runtime
            .imported_catalog()
            .service("observability")
            .is_some()
    );

    // Creating an import under a selected, unconfigured native kind.
    let runtime = &fixture.runtime;
    assert!(runtime.config().providers.get_kind("jira").is_none());
    let mut definition = definition();
    definition.service = "jira".into();
    let record = agent_access_core::ImportedServiceRecord {
        definition: definition.clone(),
        status: ImportedServiceStatus::Draft,
        version: 1,
        actions: vec![],
        slot_versions: Default::default(),
        created_at: String::new(),
        created_by: "admin".into(),
        updated_at: String::new(),
        updated_by: "admin".into(),
    };
    let prepared = runtime
        .prepare_imported_service_change(&record, None)
        .unwrap();
    let Err(error) =
        runtime
            .managed_store()
            .unwrap()
            .create_imported_service(definition, "admin", |catalog| {
                runtime.with_imported_catalog(catalog.clone(), prepared)
            })
    else {
        panic!("an import must not take a selected native kind's name");
    };
    assert!(
        matches!(
            &error,
            ManagedStoreError::InputInvalid(message)
                if message == "imported service jira collides with the selected native provider kind jira"
        ),
        "{error:?}"
    );
    assert!(runtime.imported_catalog().service("jira").is_none());
}
