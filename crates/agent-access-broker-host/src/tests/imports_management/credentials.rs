//! Derived forms and publication fencing share the adapter's offline contract.
use super::*;
use agent_access_core::imports::{ImportedCredentialDelivery, ImportedCredentialMode};

fn pending_definition(basic: bool) -> agent_access_core::imports::ImportedServiceDefinition {
    let mut definition = definition();
    definition.service = "pending".into();
    definition.discovery = ImportedDiscoveryCredential::Anonymous;
    if basic {
        for binding in &mut definition.execution_bindings {
            binding.delivery = ImportedCredentialDelivery::Basic;
        }
    }
    definition
}

fn empty_draft_fixture() -> Fixture {
    let fixture = fixture();
    fixture
        .runtime
        .managed_store()
        .unwrap()
        .create_imported_service(pending_definition(false), "admin", |_| Ok(()))
        .unwrap();
    fixture
}

fn token_write() -> CredentialWriteRequest {
    CredentialWriteRequest {
        owner_principal_id: "alice".into(),
        service: "pending".into(),
        name: "default".into(),
        profile: "token".into(),
        credential_kind: "bearer_token".into(),
        secret: json!({"token":"synthetic-personal-token"}),
        metadata: json!({}),
        actor: "admin".into(),
    }
}

fn change_draft_delivery(runtime: BrokerRuntime) -> Result<(BrokerRuntime, ()), ManagedStoreError> {
    let record = runtime.imported_catalog().service("pending").unwrap();
    let mut candidate = record.clone();
    candidate.definition = pending_definition(true);
    let providers = runtime.prepare_imported_service_change(&candidate, None)?;
    let mutation = runtime.managed_store().unwrap().update_imported_service(
        ImportedServiceUpdateRequest {
            discovery_source: agent_access_core::imports::ImportedDiscoverySource::Remote,
            definition: candidate.definition,
            status: record.status,
            actions: vec![],
            expected_version: record.version,
            expected_catalog_revision: runtime.import_catalog_revision(),
            accepted_preview: None,
            actor: "admin".into(),
        },
        |catalog| runtime.with_imported_catalog(catalog.clone(), providers),
    )?;
    Ok((mutation.value, ()))
}

#[tokio::test]
async fn cancelled_first_personal_save_keeps_fence_and_blocks_draft_repurposing() {
    let fixture = empty_draft_fixture();
    let broker = import_broker(&fixture.config).await;
    let state = broker.state();
    let admitted = state.current();
    let contract = admitted
        .runtime
        .prepare_imported_connection_contract("pending")
        .unwrap()
        .unwrap();
    let (entered, entry) = tokio::sync::oneshot::channel();
    let (release, released) = std::sync::mpsc::channel();
    let waiter = {
        let state = state.clone();
        let snapshot = admitted.clone();
        tokio::spawn(async move {
            state
                .token_store_call_from_snapshot(snapshot, move |runtime| {
                    entered.send(()).unwrap();
                    released.recv_timeout(Duration::from_secs(5)).unwrap();
                    runtime
                        .managed_store()
                        .unwrap()
                        .upsert_imported_user_credential(
                            runtime.credential_key_ring().unwrap(),
                            token_write(),
                            CredentialManagementPurpose::Administrative,
                            &contract,
                        )
                })
                .await
        })
    };
    entry.await.unwrap();
    waiter.abort();
    assert!(
        state.policy_mutation_lock.try_lock().is_err(),
        "cancellation must keep the publication fence"
    );
    let mutation = {
        let state = state.clone();
        let snapshot = admitted.clone();
        tokio::spawn(async move {
            state
                .imported_service_mutation(snapshot, change_draft_delivery)
                .await
        })
    };
    release.send(()).unwrap();
    let result = tokio::time::timeout(Duration::from_secs(5), mutation)
        .await
        .unwrap()
        .unwrap();
    assert!(
        matches!(result, Err(ManagedStoreError::InputInvalid(_))),
        "{result:?}"
    );
    assert!(waiter.await.unwrap_err().is_cancelled());
    assert!(Arc::ptr_eq(&admitted, &state.current()));
    let store = state.current().runtime.managed_store().unwrap().clone();
    assert_eq!(
        store
            .credential_by_tuple("alice", "pending", "default")
            .unwrap()
            .profile,
        "token"
    );
    assert_eq!(
        store.imported_catalog().unwrap(),
        *admitted.runtime.imported_catalog()
    );
    drop(store);
    drop(admitted);
    drop(state);
    broker.stop().await;
}

#[tokio::test]
async fn draft_publication_wins_before_first_personal_save_and_rejects_stale_proof() {
    use crate::handlers::management::common::{ManagementAccess, management_context};
    use crate::handlers::management::credentials::tests::put_admitted_connection;
    use axum::http::{HeaderMap, HeaderValue};

    let fixture = empty_draft_fixture();
    let broker = import_broker(&fixture.config).await;
    let state = broker.state();
    let admitted = state.current();
    let app_state = crate::state::AppState {
        reloadable: state.clone(),
    };
    let mut headers = HeaderMap::new();
    headers.insert(
        "Authorization",
        HeaderValue::from_str(&format!("Bearer {}", admin_token(&fixture))).unwrap(),
    );
    headers.insert(
        REQUEST_ID_HEADER,
        HeaderValue::from_static("stale-imported-save"),
    );
    let context = management_context(
        &app_state,
        "127.0.0.1:43210".parse().unwrap(),
        &headers,
        crate::handlers::management::audit_actions::ADMIN_CREDENTIALS_PUT,
        ManagementAccess::AdminWrite,
    )
    .await
    .unwrap();
    assert!(Arc::ptr_eq(&admitted, &context.snapshot));
    let old_contract = admitted
        .runtime
        .prepare_imported_connection_contract("pending")
        .unwrap()
        .unwrap();
    let (entered, entry) = tokio::sync::oneshot::channel();
    let (release, released) = std::sync::mpsc::channel();
    let mutation = {
        let state = state.clone();
        let snapshot = admitted.clone();
        tokio::spawn(async move {
            state
                .imported_service_mutation(snapshot, move |runtime| {
                    entered.send(()).unwrap();
                    released.recv_timeout(Duration::from_secs(5)).unwrap();
                    change_draft_delivery(runtime)
                })
                .await
        })
    };
    entry.await.unwrap();
    let write = {
        let state = state.clone();
        let snapshot = admitted.clone();
        tokio::spawn(async move {
            state
                .token_store_call_from_snapshot(snapshot, |_| -> Result<(), ManagedStoreError> {
                    panic!("a stale admitted connection save must never reach storage")
                })
                .await
        })
    };
    release.send(()).unwrap();
    mutation.await.unwrap().unwrap();
    assert!(matches!(
        write.await.unwrap(),
        Err(ManagedStoreError::VersionConflict)
    ));
    let current = state.current();
    let store = current.runtime.managed_store().unwrap();
    // The independent DB proof check also refuses the old contract if a caller
    // attempts to skip the host's publication fence.
    assert!(matches!(
        store.upsert_imported_user_credential(
            current.runtime.credential_key_ring().unwrap(),
            token_write(),
            CredentialManagementPurpose::Administrative,
            &old_contract,
        ),
        Err(ManagedStoreError::VersionConflict)
    ));
    assert!(matches!(
        store.credential_by_tuple("alice", "pending", "default"),
        Err(ManagedStoreError::CredentialNotFound)
    ));
    let response = put_admitted_connection(
        &app_state,
        context,
        "alice",
        "pending",
        json!({"secret":{"token":"stale-personal-token"}}),
    )
    .await;
    let status = response.status();
    let denied = response_json(response).await;
    assert_eq!(status, StatusCode::CONFLICT, "{denied}");
    assert!(matches!(
        store.credential_by_tuple("alice", "pending", "default"),
        Err(ManagedStoreError::CredentialNotFound)
    ));
    assert_eq!(
        current
            .runtime
            .imported_catalog()
            .service("pending")
            .unwrap()
            .definition,
        pending_definition(true)
    );
    drop(current);
    drop(admitted);
    drop(app_state);
    drop(state);
    broker.stop().await;
}

#[tokio::test]
async fn basic_input_projection_is_derived_nested_and_retirement_is_unavailable() {
    let fixture = fixture();
    let admin = admin_token(&fixture);
    let broker = import_broker(&fixture.config).await;
    let app = broker.app();
    let (status, created) = request(
        &app,
        &admin,
        Method::POST,
        "/v1/admin/imports",
        Some(json!(pending_definition(true))),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{created}");
    let inputs = &created["result"]["service"]["credentialInputs"];
    assert_eq!(inputs.as_object().unwrap().len(), 1);
    assert_eq!(inputs["execution"]["state"], "ready");
    assert_eq!(inputs["execution"]["credentialKind"], "basic_api_token");
    assert_eq!(inputs["execution"]["inputPolicy"], "http_basic");
    assert_eq!(
        inputs["execution"]["fields"][1]["prompt"],
        "Password or API token"
    );
    assert!(created["result"].get("credentialInputs").is_none());
    let runtime = broker.runtime();
    let record = runtime.imported_catalog().service("pending").unwrap();
    assert!(
        serde_json::to_value(record)
            .unwrap()
            .get("credentialInputs")
            .is_none()
    );

    let (status, schema) = request(
        &app,
        &admin,
        Method::GET,
        "/v1/admin/principals/alice/credentials/connections/pending/input-schema",
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{schema}");
    assert_eq!(schema["result"]["inputPolicy"], "http_basic");
    assert_eq!(schema["result"]["fields"], inputs["execution"]["fields"]);
    // Native schemas retain their existing kind-specific fields with no import
    // delivery policy, even when that kind is also used for HTTP Basic imports.
    let native = runtime
        .connection_credential_input_schema("native", "Native", "native-profile", "basic_api_token")
        .unwrap();
    assert!(
        serde_json::to_value(native)
            .unwrap()
            .get("inputPolicy")
            .is_none()
    );

    let (status, put) = request(
        &app,
        &admin,
        Method::PUT,
        "/v1/admin/principals/alice/credentials/connections/pending",
        Some(json!({"secret":{"username":" alice ","token":"  "}})),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{put}");
    assert_eq!(put["result"]["credentialKind"], "basic_api_token");
    for secret in [
        json!({"username":"alice:tenant","token":"secret"}),
        json!({"username":"alice","token":"bad\u{0085}secret"}),
    ] {
        let (status, denied) = request(
            &app,
            &admin,
            Method::PUT,
            "/v1/admin/principals/alice/credentials/connections/pending",
            Some(json!({"secret":secret})),
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{denied}");
    }
    let mut retire = versions(&created["result"]);
    retire["status"] = json!("retired");
    retire["confirm"] = json!(true);
    let (status, retired) = request(
        &app,
        &admin,
        Method::POST,
        "/v1/admin/imports/pending/status",
        Some(retire),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{retired}");
    assert_eq!(
        retired["result"]["service"]["credentialInputs"]["execution"]["state"],
        "unavailable"
    );
    let (status, denied) = request(
        &app,
        &admin,
        Method::PUT,
        "/v1/admin/principals/alice/credentials/connections/pending",
        Some(json!({"secret":{"username":"alice","token":"new"}})),
    )
    .await;
    assert!(!status.is_success(), "{denied}");
    drop(runtime);
    drop(app);
    broker.stop().await;
}

#[tokio::test]
async fn personal_only_binding_does_not_advertise_or_accept_shared_slots() {
    let fixture = fixture();
    let admin = admin_token(&fixture);
    let broker = import_broker(&fixture.config).await;
    let app = broker.app();
    let mut definition = pending_definition(true);
    definition
        .execution_bindings
        .retain(|binding| binding.owner_mode == ImportedCredentialMode::PerUser);
    let (status, created) = request(
        &app,
        &admin,
        Method::POST,
        "/v1/admin/imports",
        Some(json!(definition)),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{created}");
    assert_eq!(created["result"]["service"]["credentialInputs"], json!({}));
    let mut secret = versions(&created["result"]);
    secret["username"] = json!("alice");
    secret["token"] = json!("synthetic");
    let (status, denied) = request(
        &app,
        &admin,
        Method::PUT,
        "/v1/admin/imports/pending/credentials/execution",
        Some(secret),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{denied}");
    drop(app);
    broker.stop().await;
}

#[tokio::test]
async fn unaccepted_command_describes_unavailable_material_without_guessing_token() {
    use crate::tests::imports_command::{CommandFixture, definition as command_definition};
    let fixture = CommandFixture::new("pending", &json!({}));
    let admin = fixture.admin_token();
    let broker = import_broker(&fixture.config).await;
    let app = broker.app();
    let (status, created) = request(
        &app,
        &admin,
        Method::POST,
        "/v1/admin/imports",
        Some(command_definition(
            "pending",
            "pending",
            &["service", "per_user"],
        )),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{created}");
    let input = &created["result"]["service"]["credentialInputs"]["execution"];
    assert_eq!(input["state"], "unavailable");
    assert!(input.get("credentialKind").is_none());
    assert!(input.get("fields").is_none());
    assert!(!input["reason"].as_str().unwrap().is_empty());
    let (status, list) = request(&app, &admin, Method::GET, "/v1/admin/imports", None).await;
    assert_eq!(status, StatusCode::OK, "{list}");
    let row = list["result"]["services"]
        .as_array()
        .unwrap()
        .iter()
        .find(|row| row["definition"]["service"] == "pending")
        .unwrap();
    assert_eq!(row["credentialInputs"]["execution"], *input);
    assert!(row.get("service").is_none());
    assert!(
        fixture.runs().is_empty(),
        "input descriptions must remain offline"
    );
    drop(app);
    broker.stop().await;
}

#[tokio::test]
async fn missing_personal_basic_material_hides_tools_until_provisioned_and_owner_keeps_cleanup() {
    let fixture = fixture();
    let store = fixture.runtime.managed_store().unwrap();
    let draft = store
        .create_imported_service(pending_definition(true), "admin", |_| Ok(()))
        .unwrap()
        .catalog;
    let record = draft.service("pending").unwrap();
    store
        .update_imported_service(
            ImportedServiceUpdateRequest {
                discovery_source: agent_access_core::imports::ImportedDiscoverySource::Remote,
                definition: record.definition.clone(),
                status: ImportedServiceStatus::Enabled,
                actions: vec![ImportedActionWrite {
                    definition: crate::tests::conformance_import::conformance_import_action(),
                    status: ImportedActionStatus::Enabled,
                }],
                expected_version: record.version,
                expected_catalog_revision: draft.revision,
                accepted_preview: None,
                actor: "admin".into(),
            },
            |_| Ok(()),
        )
        .unwrap();
    let broker = import_broker(&fixture.config).await;
    let runtime = broker.runtime();
    runtime
        .create_managed_policy_grant(ManagedPolicyGrantCreateRequest {
            grant_id: Some("pending-personal".into()),
            subjects: vec!["user:alice".into()],
            execution_contexts: vec!["default".into()],
            service: "pending".into(),
            actions: vec!["inspect".into()],
            resources: ResourceSelection::default(),
            credential_mode: "per_user".into(),
            priority: None,
            status: None,
            description: None,
            created_by: "admin".into(),
        })
        .unwrap();
    let token = store.issue_broker_token(
        &BrokerTokenHasher::load(fixture.config.broker_tokens.as_ref().unwrap()).unwrap(),
        BrokerTokenIssueRequest {
            principal_id: "alice".into(), name: "local Basic availability".into(),
            token_class: BrokerTokenClass::AgentInvoke,
            scopes: json!({"allowedServices":["pending"],"allowedExecutionContexts":["default"]}),
            expires_at: None, created_by: "admin".into(),
        }).unwrap().token;
    let app = broker.app();
    let (status, catalog) = request(&app, &token, Method::GET, "/v1/spec/catalog", None).await;
    assert_eq!(status, StatusCode::OK, "{catalog}");
    let unavailable = catalog["services"]
        .as_array()
        .unwrap()
        .iter()
        .find(|service| service["service"] == "pending")
        .unwrap();
    assert_eq!(unavailable["actions"], json!([]));
    assert_eq!(unavailable["availability"]["state"], "unavailable");
    assert!(matches!(
        store.credential_by_tuple("alice", "pending", "default"),
        Err(ManagedStoreError::CredentialNotFound)
    ));
    let (status, denied) = request(
        &app,
        &token,
        Method::POST,
        "/v1/invoke/pending/inspect",
        Some(json!({"inputs":{"message":"no dispatch"}})),
    )
    .await;
    assert!(!status.is_success(), "{denied}");
    assert_ne!(denied["reasonCode"], "upstream_unauthorized");
    // An ordinary administrator save resolves the same contract and enables
    // discovery without probing the synthetic upstream or verifying the secret.
    let admin = admin_token(&fixture);
    let (status, saved) = request(
        &app,
        &admin,
        Method::PUT,
        "/v1/admin/principals/alice/credentials/connections/pending",
        Some(json!({"secret":{"username":"alice","token":" a:Unicode-λ "}})),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{saved}");
    let (status, catalog) = request(&app, &token, Method::GET, "/v1/spec/catalog", None).await;
    assert_eq!(status, StatusCode::OK, "{catalog}");
    assert_eq!(catalog["services"][0]["service"], "pending");
    assert_eq!(catalog["services"][0]["actions"][0]["action"], "inspect");
    assert_eq!(catalog["services"][0]["availability"]["state"], "available");
    let retained = store
        .credential_by_tuple("alice", "pending", "default")
        .unwrap();
    assert!(retained.last_used_at.is_none());
    assert!(retained.last_verified_at.is_none());
    let personal_token = store
        .issue_broker_token(
            &BrokerTokenHasher::load(fixture.config.broker_tokens.as_ref().unwrap()).unwrap(),
            BrokerTokenIssueRequest {
                principal_id: "alice".into(),
                name: "Basic self-service".into(),
                token_class: BrokerTokenClass::UserManage,
                scopes: json!({}),
                expires_at: None,
                created_by: "admin".into(),
            },
        )
        .unwrap()
        .token;
    let (status, personal_schema) = request(
        &app,
        &personal_token,
        Method::GET,
        "/v1/credentials/connections/pending/input-schema",
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{personal_schema}");
    assert_eq!(personal_schema["result"]["inputPolicy"], "http_basic");
    let (status, personal_save) = request(
        &app,
        &personal_token,
        Method::PUT,
        "/v1/credentials/connections/pending",
        Some(json!({"secret":{"username":" alice ","token":" "}})),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{personal_save}");
    assert_eq!(personal_save["result"]["credentialKind"], "basic_api_token");
    runtime
        .delete_managed_policy_grant(ManagedPolicyGrantStatusRequest {
            grant_id: "pending-personal".into(),
            expected_version: store.policy_grant("pending-personal").unwrap().version,
            updated_by: "admin".into(),
        })
        .unwrap();
    let (status, denied) = request(
        &app,
        &personal_token,
        Method::PUT,
        "/v1/credentials/connections/pending",
        Some(json!({"secret":{"username":"alice","token":"changed"}})),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{denied}");
    let (status, cleanup) = request(
        &app,
        &personal_token,
        Method::DELETE,
        "/v1/credentials/connections/pending",
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{cleanup}");
    drop(runtime);
    drop(app);
    broker.stop().await;
}
