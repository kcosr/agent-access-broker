//! Provider preparation precedes locked mutations and preserves unrelated dispatches.
use super::conformance_import::conformance_import_action;
use super::*;
use agent_access_core::imports::{ImportedCredentialDelivery, ImportedCredentialPurpose};
use agent_access_core::{
    BrokerTokenClass, BrokerTokenHasher, BrokerTokenIssueRequest, ImportedActionStatus,
    ImportedActionWrite, ImportedSecretDeleteRequest, ImportedSecretWriteRequest,
    ImportedServiceStatus, ImportedServiceUpdateRequest, ManagedPolicyGrantCreateRequest,
};
use agent_access_provider::test_support::bearer_credential;

async fn invoke(runtime: &BrokerRuntime, token: &str, service: &str) -> (StatusCode, Value) {
    let response = authed_json_request(
        build_router(runtime.clone(), broker_build_status()),
        Method::POST,
        &format!("/v1/invoke/{service}/inspect"),
        &format!("import-publication-{service}"),
        "Authorization",
        format!("Bearer {token}"),
        Some(r#"{"inputs":{"message":"synthetic publication input"}}"#),
    )
    .await;
    (response.status(), response_json(response).await)
}

#[tokio::test]
async fn imported_prepared_transport_rotation_publishes_new_authority_without_store_reentry() {
    let fixture = imports_foundation::fixture();
    let store = fixture.runtime.managed_store().unwrap();
    let ring = fixture.runtime.credential_key_ring().unwrap();
    let mut definition = imports_foundation::definition();
    definition.service = "transported".into();
    definition.transport_auth = true;
    for binding in &mut definition.execution_bindings {
        binding.delivery = ImportedCredentialDelivery::RawHeader {
            name: "X-Execution-Token".into(),
        };
    }
    let mut catalog = store
        .create_imported_service(definition, "admin", |_| Ok(()))
        .unwrap()
        .catalog;
    for (purpose, token) in [
        (ImportedCredentialPurpose::Execution, "import-service-token"),
        (
            ImportedCredentialPurpose::Transport,
            "import-transport-initial",
        ),
    ] {
        catalog = store
            .write_imported_secret(
                ImportedSecretWriteRequest {
                    service: "transported".into(),
                    purpose,
                    expected_version: catalog.service("transported").unwrap().version,
                    expected_catalog_revision: catalog.revision,
                    token: token.into(),
                    actor: "admin".into(),
                },
                ring,
                |_, _| Ok(()),
            )
            .unwrap()
            .catalog;
    }
    let record = catalog.service("transported").unwrap();
    store
        .update_imported_service(
            ImportedServiceUpdateRequest {
                definition: record.definition.clone(),
                status: ImportedServiceStatus::Enabled,
                actions: vec![ImportedActionWrite {
                    definition: conformance_import_action(),
                    status: ImportedActionStatus::Enabled,
                }],
                expected_version: record.version,
                expected_catalog_revision: catalog.revision,
                accepted_preview: None,
                actor: "admin".into(),
            },
            |_| Ok(()),
        )
        .unwrap();
    let runtime = BrokerRuntime::new(fixture.config.clone()).unwrap();
    runtime
        .create_managed_policy_grant(ManagedPolicyGrantCreateRequest {
            grant_id: Some("transported-alice".into()),
            subjects: vec!["user:alice".into()],
            execution_contexts: vec!["default".into()],
            service: "transported".into(),
            actions: vec!["inspect".into()],
            resources: ResourceSelection::default(),
            credential_mode: "service".into(),
            priority: None,
            status: None,
            description: None,
            created_by: "admin".into(),
        })
        .unwrap();
    let hasher = BrokerTokenHasher::load(fixture.config.broker_tokens.as_ref().unwrap()).unwrap();
    let token = store
        .issue_broker_token(
            &hasher,
            BrokerTokenIssueRequest {
                principal_id: "alice".into(),
                name: "transport publication".into(),
                token_class: BrokerTokenClass::AgentInvoke,
                scopes: json!({"allowedServices":["observability","transported"],"allowedExecutionContexts":["default"]}),
                expires_at: None,
                created_by: "admin".into(),
            },
        )
        .unwrap()
        .token;
    let (status, body) = invoke(&runtime, &token, "transported").await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(
        body["result"]["upstreamMcp"]["transportAuthority"],
        "initial"
    );

    // An unchanged configuration reload keeps already admitted services current.
    let reloaded = BrokerRuntime::new_for_reload(fixture.config.clone(), &runtime).unwrap();
    runtime.retire_superseded_import_dispatch(&reloaded);
    assert!(runtime.imported_action_available("observability", "inspect"));
    assert!(runtime.imported_action_available("transported", "inspect"));

    // Stale preparation cannot commit a rotation or deletion, even when the
    // caller forgets the explicit override. The store rolls back both versions
    // and ciphertext, leaving the admitted runtime coherent.
    let record = reloaded.imported_catalog().service("transported").unwrap();
    let rotation = || ImportedSecretWriteRequest {
        service: "transported".into(),
        purpose: ImportedCredentialPurpose::Transport,
        expected_version: record.version,
        expected_catalog_revision: reloaded.import_catalog_revision(),
        token: "import-transport-rotated".into(),
        actor: "admin".into(),
    };
    let stale = reloaded
        .prepare_imported_service_change(record, None)
        .unwrap();
    assert!(
        store
            .write_imported_secret(rotation(), ring, |catalog, _| {
                reloaded.with_imported_catalog(catalog.clone(), stale)
            })
            .is_err()
    );
    assert_eq!(
        store.imported_catalog().unwrap(),
        *reloaded.imported_catalog()
    );
    let stale = reloaded
        .prepare_imported_service_change(record, None)
        .unwrap();
    assert!(
        store
            .delete_imported_secret(
                ImportedSecretDeleteRequest {
                    service: "transported".into(),
                    purpose: ImportedCredentialPurpose::Transport,
                    expected_version: record.version,
                    expected_catalog_revision: reloaded.import_catalog_revision(),
                    actor: "admin".into(),
                },
                |catalog| reloaded.with_imported_catalog(catalog.clone(), stale)
            )
            .is_err()
    );
    assert_eq!(
        store.imported_catalog().unwrap(),
        *reloaded.imported_catalog()
    );
    let wrong_plaintext = reloaded
        .prepare_imported_service_change(
            record,
            Some(Some(bearer_credential("import-transport-initial"))),
        )
        .unwrap();
    assert!(
        store
            .write_imported_secret(rotation(), ring, |catalog, proof| {
                reloaded.with_imported_catalog(
                    catalog.clone(),
                    wrong_plaintext.bind_secret_write(proof)?,
                )
            })
            .is_err()
    );
    assert_eq!(
        store.imported_catalog().unwrap(),
        *reloaded.imported_catalog()
    );

    // Compile with the new plaintext before the write takes the store lock. The
    // transaction callback only assembles the immutable catalog and runtime.
    let record = reloaded.imported_catalog().service("transported").unwrap();
    let providers = reloaded
        .prepare_imported_service_change(
            record,
            Some(Some(bearer_credential("import-transport-rotated"))),
        )
        .unwrap();
    let request = ImportedSecretWriteRequest {
        service: "transported".into(),
        purpose: ImportedCredentialPurpose::Transport,
        expected_version: record.version,
        expected_catalog_revision: reloaded.import_catalog_revision(),
        token: "import-transport-rotated".into(),
        actor: "admin".into(),
    };
    let worker_runtime = reloaded.clone();
    let (send, receive) = std::sync::mpsc::channel();
    let worker = std::thread::spawn(move || {
        let outcome = worker_runtime
            .managed_store()
            .unwrap()
            .write_imported_secret(
                request,
                worker_runtime.credential_key_ring().unwrap(),
                |catalog, proof| {
                    worker_runtime
                        .with_imported_catalog(catalog.clone(), providers.bind_secret_write(proof)?)
                },
            );
        let _ = send.send(outcome);
    });
    let rotated = receive
        .recv_timeout(Duration::from_secs(5))
        .expect("transport publication must not reenter the managed-store mutex")
        .unwrap()
        .value;
    worker.join().unwrap();
    reloaded.retire_superseded_import_dispatch(&rotated);
    assert!(!reloaded.imported_action_available("transported", "inspect"));
    assert!(reloaded.imported_action_available("observability", "inspect"));
    let (status, body) = invoke(&reloaded, &token, "observability").await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let (status, body) = invoke(&reloaded, &token, "transported").await;
    assert!(!status.is_success(), "{body}");
    let (status, body) = invoke(&rotated, &token, "transported").await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(
        body["result"]["upstreamMcp"]["transportAuthority"],
        "rotated"
    );
    assert!(!body.to_string().contains("import-transport-rotated"));

    // Deletion uses an explicit missing override; retained DB material must not
    // accidentally resurrect the previous transport provider during preparation.
    let record = rotated.imported_catalog().service("transported").unwrap();
    let providers = rotated
        .prepare_imported_service_change(record, Some(None))
        .unwrap();
    let deleted = rotated
        .managed_store()
        .unwrap()
        .delete_imported_secret(
            ImportedSecretDeleteRequest {
                service: "transported".into(),
                purpose: ImportedCredentialPurpose::Transport,
                expected_version: record.version,
                expected_catalog_revision: rotated.import_catalog_revision(),
                actor: "admin".into(),
            },
            |catalog| rotated.with_imported_catalog(catalog.clone(), providers),
        )
        .unwrap()
        .value;
    rotated.retire_superseded_import_dispatch(&deleted);
    assert!(!deleted.imported_action_available("transported", "inspect"));
    assert!(deleted.imported_action_available("observability", "inspect"));
    let (status, body) = invoke(&deleted, &token, "transported").await;
    assert!(!status.is_success(), "{body}");
    assert!(
        !BrokerRuntime::new(fixture.config.clone())
            .unwrap()
            .imported_action_available("transported", "inspect")
    );
}
