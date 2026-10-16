//! Personal credentials through credential connections: the principal kind
//! selects the method, and token rows are read as `(connection, default)`.
use super::*;

const PROFILE: &str = "jira-cloud-api-token";

/// Jira on the lookup-trace provider with a per-user connection `connection`
/// and a per-user grant for `agents`.
fn connection_config(connection: &str) -> (BrokerConfig, PathBuf) {
    let mut config = base_fake_config();
    configure_lookup_trace_jira(&mut config);
    let store_path = temp_path("connection-selection.sqlite");
    config.managed_store = Some(ManagedStoreConfig {
        kind: "sqlite".into(),
        path: store_path.display().to_string(),
        require_registered_principal_for_invocation: false,
        auto_migrate: true,
    });
    config.credentials.connections.insert(
        connection.into(),
        crate::ConnectionConfig {
            display_name: None,
            token_profile: Some(PROFILE.into()),
            oauth: None,
        },
    );
    config.credentials.per_user.insert(
        "jira".into(),
        CredentialConfig {
            kind: "connection".into(),
            username_ref: None,
            token_ref: None,
            provider: None,
            path: None,
            read_only: None,
            connection: Some(connection.into()),
        },
    );
    config.policy.grants = vec![lookup_trace_grant("per_user", None, &["project-PROJ"])];
    (config, store_path)
}

fn store_token(runtime: &BrokerRuntime, service: &str, token: &str) {
    let store = runtime.managed_store().unwrap();
    store
        .create_or_update_principal(crate::PrincipalWriteRequest {
            role: crate::PrincipalRole::User,
            self_service_enabled: None,
            principal_id: "agent-one".into(),
            kind: "user".into(),
            display_name: None,
            email: None,
            external_subject: None,
            created_by: "admin".into(),
        })
        .unwrap();
    store
        .upsert_user_credential(
            runtime.credential_key_ring().unwrap(),
            crate::CredentialWriteRequest {
                owner_principal_id: "agent-one".into(),
                service: service.into(),
                name: "default".into(),
                profile: PROFILE.into(),
                credential_kind: "basic_api_token".into(),
                secret: json!({"username": "synthetic-user", "token": token}),
                metadata: json!({}),
                actor: "admin".into(),
            },
            crate::CredentialManagementPurpose::Administrative,
        )
        .unwrap();
}

fn identity(kind: Option<crate::PrincipalKind>) -> IdentityContext {
    IdentityContext {
        principal_kind: kind,
        ..agent_one_identity()
    }
}

async fn invoke_as(runtime: &BrokerRuntime, identity: IdentityContext) -> BrokerResponse<Value> {
    runtime
        .invoke(
            governed(OperationContext {
                agent_request_id: "agent-request".into(),
                broker_request_id: "broker-request".into(),
                identity,
                service: "jira".into(),
                action: "issue.view".into(),
                source: SourceContext::unknown(),
            }),
            InvokeRequest {
                inputs: json!({"project": "PROJ", "message": "hello"}),
                body_parts: vec![],
                ..InvokeRequest::new(json!({}))
            },
        )
        .await
}

#[tokio::test]
async fn a_connection_token_serves_lookups_and_execution_for_every_managed_kind() {
    let provider = Arc::new(LookupTraceProvider::default());
    let observations = provider.observations();
    // The connection's ID, not the consuming service, keys its token rows.
    let (config, _store) = connection_config("tracker");
    let runtime = BrokerRuntime::with_providers(config, vec![provider]).unwrap();
    store_token(&runtime, "tracker", "connection-token");
    store_token(&runtime, "jira", "per-service-token");
    let connection = basic_credential("synthetic-user", "connection-token");

    for kind in [
        crate::PrincipalKind::User,
        crate::PrincipalKind::ServiceAccount,
        crate::PrincipalKind::System,
    ] {
        observations.lock().unwrap().clear();
        let response = invoke_as(&runtime, identity(Some(kind))).await;
        assert_eq!(response.status, 200, "{kind:?}: {:?}", response.envelope);
        assert_eq!(
            observations
                .lock()
                .unwrap()
                .iter()
                .map(|observation| (
                    observation.operation.as_str(),
                    observation.credential.clone()
                ))
                .collect::<Vec<_>>(),
            [
                ("pre_scope", Some(connection.clone())),
                ("execution_lookup", Some(connection.clone())),
                ("execution", Some(connection.clone())),
            ],
            "{kind:?}"
        );
    }

    // A principal without a managed kind selects no method, never the row.
    observations.lock().unwrap().clear();
    let response = invoke_as(&runtime, identity(None)).await;
    assert_eq!(response.status, 403);
    assert_eq!(
        response.envelope.reason_code,
        Some(ReasonCode::CredentialNotProvisioned.into())
    );
    assert_eq!(
        response.envelope.reason.as_deref(),
        Some("the credential connection offers no personal credential method for this principal")
    );
    assert!(observations.lock().unwrap().is_empty());
}

#[test]
fn discovery_distinguishes_an_unselected_method_from_a_missing_token() {
    // A connection with the consumer's ID reads that service's rows unchanged.
    let (config, _store) = connection_config("jira");
    let runtime = BrokerRuntime::new(config).unwrap();
    let discover = |kind| {
        runtime
            .service_capabilities(&identity(kind), &default_execution_context(), "jira")
            .unwrap()
    };

    let missing = discover(Some(crate::PrincipalKind::User));
    assert_eq!(missing.availability.state, AvailabilityState::Unavailable);
    assert_eq!(
        missing.availability.requirements,
        [CredentialRequirement {
            reason: "credential_not_found".into(),
            credential_mode: "per_user".into(),
            resolution: "user".into(),
        }]
    );
    let unselected = discover(None);
    assert_eq!(
        unselected.availability.state,
        AvailabilityState::Unavailable
    );
    assert_eq!(
        unselected.availability.requirements,
        [CredentialRequirement {
            reason: "credential_not_provisioned".into(),
            credential_mode: "per_user".into(),
            resolution: "administrator".into(),
        }]
    );

    store_token(&runtime, "jira", "existing-token");
    for kind in [
        crate::PrincipalKind::User,
        crate::PrincipalKind::ServiceAccount,
        crate::PrincipalKind::System,
    ] {
        let service = discover(Some(kind));
        assert_eq!(
            service.availability.state,
            AvailabilityState::Available,
            "{kind:?}"
        );
        assert_eq!(service.actions.len(), 1);
    }
    assert!(discover(None).actions.is_empty());
}

#[tokio::test]
async fn readiness_checks_connection_configuration_without_principals() {
    let (config, _store) = connection_config("tracker");
    let runtime = BrokerRuntime::new(config).unwrap();
    runtime.readiness().await.unwrap();
    // Management resolves a service's or a connection's token form.
    assert_eq!(runtime.personal_credential_key("jira"), Some("tracker"));
    assert_eq!(
        runtime.personal_token_profile("jira"),
        Some((PROFILE, "basic_api_token"))
    );
    assert_eq!(
        runtime.connection_token_profile("tracker"),
        Some((PROFILE, "basic_api_token"))
    );
    assert_eq!(runtime.connection_token_profile("jira"), None);
    assert_eq!(runtime.personal_credential_key("fake"), None);
}

#[tokio::test]
async fn audit_names_the_connection_only_when_a_personal_credential_is_used() {
    let audit_path = temp_path("connection-audit.jsonl");
    let (mut config, _store) = connection_config("tracker");
    config.audit = Some(jsonl_audit_config(audit_path.display().to_string()));
    configure_lookup_trace_service(&mut config, "synthetic-service-token");
    configure_lookup_trace_lookup(&mut config, "synthetic-lookup-token");
    let runtime = BrokerRuntime::with_providers(
        config.clone(),
        vec![Arc::new(LookupTraceProvider::default())],
    )
    .unwrap();
    store_token(&runtime, "tracker", "connection-token");
    let response = invoke_as(&runtime, identity(Some(crate::PrincipalKind::User))).await;
    assert_eq!(response.status, 200, "{:?}", response.envelope);
    // A principal without a kind fails resolving the personal lookup
    // before policy selects a mode, so nothing names a connection.
    let denied = invoke_as(&runtime, identity(None)).await;
    assert_eq!(denied.status, 403);

    let service_audit_path = temp_path("connection-service-audit.jsonl");
    config.audit = Some(jsonl_audit_config(service_audit_path.display().to_string()));
    config.policy.grants = vec![lookup_trace_grant("service", None, &["project-PROJ"])];
    let service =
        BrokerRuntime::with_providers(config, vec![Arc::new(LookupTraceProvider::default())])
            .unwrap();
    let response = invoke_as(&service, identity(Some(crate::PrincipalKind::User))).await;
    assert_eq!(response.status, 200, "{:?}", response.envelope);

    let personal = audit_records(&audit_path)
        .into_iter()
        .filter(|record| record["service"] == "jira")
        .collect::<Vec<_>>();
    assert_eq!(personal.len(), 2, "{personal:?}");
    assert_eq!(personal[0]["decision"], "allow");
    assert_eq!(personal[0]["credentialMode"], "per_user");
    assert_eq!(personal[0]["credentialConnection"], "tracker");
    assert_eq!(personal[1]["decision"], "deny");
    assert!(personal[1].get("credentialMode").is_none());
    assert!(personal[1].get("credentialConnection").is_none());
    let shared = audit_records(&service_audit_path)
        .into_iter()
        .filter(|record| record["service"] == "jira")
        .collect::<Vec<_>>();
    assert_eq!(shared.len(), 1, "{shared:?}");
    assert_eq!(shared[0]["credentialMode"], "service");
    assert!(
        shared[0].get("credentialConnection").is_none(),
        "{}",
        shared[0]
    );
}
