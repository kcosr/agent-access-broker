//! Personal credentials through credential connections: the principal kind
//! selects the method, and token rows are read as `(connection, default)`.
use super::*;

const PROFILE: &str = "atlassian-api-token";

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
    // Management resolves a connection's token form by its ID.
    assert_eq!(
        runtime.connection_token_profile("tracker"),
        Some((PROFILE, "basic_api_token"))
    );
    assert_eq!(runtime.connection_token_profile("jira"), None);
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

/// `issue.view` for project `project` as a user principal.
async fn invoke_project(runtime: &BrokerRuntime, project: &str) -> BrokerResponse<Value> {
    runtime
        .invoke(
            governed(OperationContext {
                agent_request_id: format!("agent-request-{project}"),
                broker_request_id: format!("broker-request-{project}"),
                identity: identity(Some(crate::PrincipalKind::User)),
                service: "jira".into(),
                action: "issue.view".into(),
                source: SourceContext::unknown(),
            }),
            InvokeRequest {
                inputs: json!({"project": project, "message": "hello"}),
                body_parts: vec![],
                ..InvokeRequest::new(json!({}))
            },
        )
        .await
}

/// A personal lookup before policy reads the caller's connection token, so
/// the denial that follows when no grant covers the resolved project still
/// names that connection, with no credential mode. A shared lookup under a
/// service grant names none.
#[tokio::test]
async fn a_denial_after_a_personal_lookup_names_the_connection_it_used() {
    let audit_path = temp_path("connection-lookup-denial-audit.jsonl");
    let (mut config, _store) = connection_config("tracker");
    config.audit = Some(jsonl_audit_config(audit_path.display().to_string()));
    configure_lookup_trace_service(&mut config, "synthetic-service-token");
    configure_lookup_trace_lookup(&mut config, "synthetic-lookup-token");
    let provider = Arc::new(LookupTraceProvider::default());
    let observations = provider.observations();
    let runtime = BrokerRuntime::with_providers(config.clone(), vec![provider]).unwrap();
    store_token(&runtime, "tracker", "connection-token");
    let denied = invoke_project(&runtime, "OPS").await;
    assert_eq!(denied.status, 403, "{:?}", denied.envelope);
    assert_eq!(
        denied.envelope.reason_code,
        Some(ReasonCode::ScopeUnresolved.into())
    );
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
        [(
            "pre_scope",
            Some(basic_credential("synthetic-user", "connection-token"))
        )]
    );

    let service_audit_path = temp_path("connection-shared-lookup-denial-audit.jsonl");
    config.audit = Some(jsonl_audit_config(service_audit_path.display().to_string()));
    config.policy.grants = vec![lookup_trace_grant("service", None, &["project-PROJ"])];
    let provider = Arc::new(LookupTraceProvider::default());
    let shared_observations = provider.observations();
    let service = BrokerRuntime::with_providers(config, vec![provider]).unwrap();
    let denied = invoke_project(&service, "OPS").await;
    assert_eq!(denied.status, 403, "{:?}", denied.envelope);
    assert_eq!(shared_observations.lock().unwrap().len(), 1);

    let personal = audit_records(&audit_path)
        .into_iter()
        .filter(|record| record["service"] == "jira")
        .collect::<Vec<_>>();
    assert_eq!(personal.len(), 1, "{personal:?}");
    assert_eq!(personal[0]["decision"], "deny");
    assert_eq!(personal[0]["reasonCode"], "scope_unresolved");
    assert_eq!(personal[0]["resourceScopes"], json!({"project": ["OPS"]}));
    assert!(
        personal[0].get("credentialMode").is_none(),
        "{}",
        personal[0]
    );
    assert_eq!(personal[0]["credentialConnection"], "tracker");
    let shared = audit_records(&service_audit_path)
        .into_iter()
        .filter(|record| record["service"] == "jira")
        .collect::<Vec<_>>();
    assert_eq!(shared.len(), 1, "{shared:?}");
    assert_eq!(shared[0]["decision"], "deny");
    assert!(
        shared[0].get("credentialConnection").is_none(),
        "{}",
        shared[0]
    );
}

const RELAY_SECRET: &str = "fixture-connection-relay-credential";

/// A managed-identity broker where `alice` (user), `svc` (service account)
/// and `sys` (system) belong to `agents` and each holds a token for the
/// `tracker` connection Jira consumes. Callers reach it with Broker bearer
/// tokens, Git Basic broker tokens, or a relayed username assertion.
fn managed_matrix() -> (
    BrokerRuntime,
    Arc<Mutex<Vec<CredentialObservation>>>,
    TempDir,
) {
    let directory = TempDir::new().unwrap();
    #[cfg(unix)]
    fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700)).unwrap();
    let store_path = directory.path().join("matrix.sqlite");
    let store_config = ManagedStoreConfig {
        kind: "sqlite".into(),
        path: store_path.display().to_string(),
        require_registered_principal_for_invocation: false,
        auto_migrate: true,
    };
    // Managed policy subjects must exist before the runtime validates them.
    let store = ManagedStore::open(&store_config, ManagedStoreOpenMode::Startup).unwrap();
    store
        .create_group(crate::GroupWriteRequest {
            group_id: "agents".into(),
            display_name: None,
            description: None,
            created_by: "admin".into(),
        })
        .unwrap();
    for (principal, kind) in [
        ("alice", "user"),
        ("svc", "service_account"),
        ("sys", "system"),
    ] {
        store
            .create_principal(crate::PrincipalWriteRequest {
                role: crate::PrincipalRole::User,
                self_service_enabled: None,
                principal_id: principal.into(),
                kind: kind.into(),
                display_name: None,
                email: None,
                external_subject: None,
                created_by: "admin".into(),
            })
            .unwrap();
        store.add_group(principal, "agents", "admin").unwrap();
    }
    store
        .create_username_binding("alice", "linux", "Alice", false, "admin")
        .unwrap();
    drop(store);

    let hash_key = directory.path().join("hash.key");
    fs::write(
        &hash_key,
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode([23_u8; 32]),
    )
    .unwrap();
    let relay = directory.path().join("relay.token");
    fs::write(&relay, RELAY_SECRET).unwrap();
    let (mut config, _) = connection_config("tracker");
    config.managed_store = Some(store_config);
    config.identity = IdentityConfig {
        trusted_callers: BTreeMap::from([(
            "relay".to_string(),
            crate::TrustedCallerConfig {
                credential_ref: format!("file:{}", relay.display()),
                credential_transport: crate::TrustedCallerCredentialTransport::CallerAuthorization,
                username_namespace: Some("linux".into()),
                context_mode: crate::TrustedCallerContextMode::Fixed,
                execution_context: Some("default".into()),
                allowed_execution_contexts: None,
                allow_forwarded_identity: false,
            },
        )]),
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
    config.broker_tokens = Some(BrokerTokensConfig {
        hash_key_ref: format!("file:{}", hash_key.display()),
        ..Default::default()
    });
    let provider = Arc::new(LookupTraceProvider::default());
    let observations = provider.observations();
    let runtime = BrokerRuntime::with_providers(config, vec![provider]).unwrap();
    let store = runtime.managed_store().unwrap();
    for principal in ["alice", "svc", "sys"] {
        store
            .upsert_user_credential(
                runtime.credential_key_ring().unwrap(),
                crate::CredentialWriteRequest {
                    owner_principal_id: principal.into(),
                    service: "tracker".into(),
                    name: "default".into(),
                    profile: PROFILE.into(),
                    credential_kind: "basic_api_token".into(),
                    secret: json!({"username": principal, "token": format!("{principal}-token")}),
                    metadata: json!({}),
                    actor: "admin".into(),
                },
                crate::CredentialManagementPurpose::Administrative,
            )
            .unwrap();
    }
    (runtime, observations, directory)
}

fn agent_token(runtime: &BrokerRuntime, principal: &str) -> String {
    runtime
        .managed_store()
        .unwrap()
        .issue_broker_token(
            runtime.broker_token_hasher().unwrap(),
            crate::BrokerTokenIssueRequest {
                principal_id: principal.into(),
                name: format!("{principal} agent"),
                token_class: BrokerTokenClass::AgentInvoke,
                scopes: json!({"allowedExecutionContexts": ["default"]}),
                expires_at: None,
                created_by: "admin".into(),
            },
        )
        .unwrap()
        .token
}

/// Discovery and execution through `identity`'s connection selection: the
/// principal's own token for a managed kind, nothing without one.
async fn assert_selected(
    runtime: &BrokerRuntime,
    observations: &Arc<Mutex<Vec<CredentialObservation>>>,
    identity: IdentityContext,
    expected: Option<&str>,
    ingress: &str,
) {
    let service = runtime
        .service_capabilities(&identity, &default_execution_context(), "jira")
        .unwrap();
    observations.lock().unwrap().clear();
    let response = invoke_as(runtime, identity).await;
    match expected {
        Some(principal) => {
            assert_eq!(
                service.availability.state,
                AvailabilityState::Available,
                "{ingress} {principal}"
            );
            assert_eq!(response.status, 200, "{ingress} {principal}");
            let token = basic_credential(principal, &format!("{principal}-token"));
            assert!(
                observations
                    .lock()
                    .unwrap()
                    .iter()
                    .all(|observation| observation.credential.as_ref() == Some(&token)),
                "{ingress} {principal}"
            );
        }
        None => {
            assert_eq!(
                service.availability.requirements[0].resolution, "administrator",
                "{ingress}"
            );
            assert_eq!(response.status, 403, "{ingress}");
            assert!(observations.lock().unwrap().is_empty(), "{ingress}");
        }
    }
}

#[tokio::test]
async fn every_ingress_carries_the_principal_kind_that_selects_the_connection() {
    let (runtime, observations, _directory) = managed_matrix();
    runtime.readiness().await.unwrap();
    for (principal, kind) in [
        ("alice", crate::PrincipalKind::User),
        ("svc", crate::PrincipalKind::ServiceAccount),
        ("sys", crate::PrincipalKind::System),
    ] {
        let token = agent_token(&runtime, principal);
        // Broker bearer.
        let mut headers = HeaderMap::new();
        headers.insert("Authorization", format!("Bearer {token}").parse().unwrap());
        let identity = runtime.resolve_identity(&headers).unwrap();
        assert_eq!(identity.principal_kind, Some(kind), "bearer {principal}");
        assert_selected(&runtime, &observations, identity, Some(principal), "bearer").await;
        // Git Basic with the Broker token as the password.
        let identity = runtime.resolve_gateway_basic_broker_token(&token).unwrap();
        assert_eq!(identity.principal_kind, Some(kind), "git basic {principal}");
        assert_selected(
            &runtime,
            &observations,
            identity,
            Some(principal),
            "git basic",
        )
        .await;
    }

    // A trusted caller's username assertion resolves the managed human.
    let mut headers = HeaderMap::new();
    headers.insert(USER_HEADER, "Alice".parse().unwrap());
    headers.insert(
        CALLER_AUTHORIZATION_HEADER,
        format!("Bearer {RELAY_SECRET}").parse().unwrap(),
    );
    let admission = runtime.admit_mcp_ingress(&headers).unwrap();
    let identity = runtime
        .resolve_admitted_identity_with_proof(&headers, &admission)
        .unwrap()
        .identity;
    assert_eq!(identity.principal, "alice");
    assert_eq!(identity.principal_kind, Some(crate::PrincipalKind::User));
    assert_selected(
        &runtime,
        &observations,
        identity,
        Some("alice"),
        "trusted ingress",
    )
    .await;

    // An identity without a managed kind, as a configured static principal
    // has, selects nothing, though alice's row exists.
    let identity = IdentityContext {
        principal: "alice".into(),
        principal_kind: None,
        principal_subject: Some("alice".into()),
        groups: vec!["agents".into()],
        policy_groups: vec!["agents".into()],
        authenticated: true,
        source: None,
        caller_id: None,
    };
    assert_selected(&runtime, &observations, identity, None, "static").await;
}

/// A configured static principal carries the kind of the active managed
/// principal with its ID, read at each resolution, so discovery and
/// execution select its stored token; without an active row it has none.
#[tokio::test]
async fn static_principals_carry_their_managed_rows_kind() {
    let provider = Arc::new(LookupTraceProvider::default());
    let observations = provider.observations();
    let (mut config, store_path) = connection_config("tracker");
    let token_path = write_temp_secret("static-agent-token");
    config.identity = static_identity_config(
        "required",
        &token_path,
        "agent-one",
        vec!["agents".to_string()],
    );
    let runtime = BrokerRuntime::with_providers(config, vec![provider]).unwrap();
    let mut headers = HeaderMap::new();
    headers.insert(
        "X-Agent-Access-Identity-Token",
        "static-agent-token".parse().unwrap(),
    );

    // No managed row: no kind, so no personal method.
    let identity = runtime.resolve_identity(&headers).unwrap();
    assert_eq!(identity.principal_kind, None);
    assert_selected(
        &runtime,
        &observations,
        identity,
        None,
        "static without row",
    )
    .await;

    // A managed user row with a token for the connection.
    store_token(&runtime, "tracker", "static-token");
    let identity = runtime.resolve_identity(&headers).unwrap();
    assert_eq!(identity.principal_kind, Some(crate::PrincipalKind::User));
    let service = runtime
        .service_capabilities(&identity, &default_execution_context(), "jira")
        .unwrap();
    assert_eq!(service.availability.state, AvailabilityState::Available);
    observations.lock().unwrap().clear();
    let response = invoke_as(&runtime, identity).await;
    assert_eq!(response.status, 200, "{:?}", response.envelope);
    let token = basic_credential("synthetic-user", "static-token");
    assert!(
        observations
            .lock()
            .unwrap()
            .iter()
            .all(|observation| observation.credential.as_ref() == Some(&token))
    );

    // A disabled row selects nothing; the static principal still
    // authenticates.
    runtime
        .managed_store()
        .unwrap()
        .patch_principal(crate::PrincipalPatchRequest {
            principal_id: "agent-one".into(),
            display_name: None,
            email: None,
            status: Some("disabled".into()),
        })
        .unwrap();
    let identity = runtime.resolve_identity(&headers).unwrap();
    assert_eq!(identity.principal_kind, None);
    assert_selected(
        &runtime,
        &observations,
        identity,
        None,
        "static disabled row",
    )
    .await;

    // A store that cannot answer fails the resolution closed.
    let conn = rusqlite::Connection::open(&store_path).unwrap();
    conn.execute("ALTER TABLE principals RENAME TO principals_moved", [])
        .unwrap();
    assert_eq!(
        runtime.resolve_identity(&headers).unwrap_err(),
        IdentityFailure::Unavailable
    );
}

/// The kind that selected a static principal's credentials is the kind its
/// command is told: dispatch refuses an identity resolved before its
/// managed row's kind changed.
#[tokio::test]
async fn command_dispatch_refuses_a_static_principal_whose_kind_changed() {
    let (mut config, _store_path) = connection_config("tracker");
    let token_path = write_temp_secret("static-command-token");
    config.identity = static_identity_config(
        "required",
        &token_path,
        "agent-one",
        vec!["agents".to_string()],
    );
    let runtime =
        BrokerRuntime::with_providers(config, vec![Arc::new(LookupTraceProvider::default())])
            .unwrap();
    let store = runtime.managed_store().unwrap();
    let principal = |kind: &str| crate::PrincipalWriteRequest {
        role: crate::PrincipalRole::User,
        self_service_enabled: None,
        principal_id: "agent-one".into(),
        kind: kind.into(),
        display_name: None,
        email: None,
        external_subject: None,
        created_by: "admin".into(),
    };
    store
        .create_or_update_principal(principal("service_account"))
        .unwrap();
    let mut headers = HeaderMap::new();
    headers.insert(
        "X-Agent-Access-Identity-Token",
        "static-command-token".parse().unwrap(),
    );
    let identity = runtime.resolve_identity(&headers).unwrap();
    assert_eq!(
        identity.principal_kind,
        Some(crate::PrincipalKind::ServiceAccount)
    );
    assert_eq!(
        runtime.command_caller(&identity).await.unwrap().kind,
        "service_account"
    );

    store
        .create_or_update_principal(principal("system"))
        .unwrap();
    let stale = runtime.command_caller(&identity).await.unwrap_err();
    assert_eq!(stale.reason_code(), ReasonCode::ServiceActionDenied);
    assert_eq!(
        stale.message,
        "the caller's principal kind changed after admission"
    );
    let current = runtime.resolve_identity(&headers).unwrap();
    assert_eq!(current.principal_kind, Some(crate::PrincipalKind::System));
    assert_eq!(
        runtime.command_caller(&current).await.unwrap().kind,
        "system"
    );
}
