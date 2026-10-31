use super::*;

fn jira_config() -> BrokerConfig {
    let mut config = base_fake_config();
    config.identity = static_identity_config(
        "required",
        &write_temp_secret("synthetic-broker-token"),
        "agent-one",
        vec!["agents".into(), "other".into()],
    );
    configure_lookup_trace_jira(&mut config);
    configure_lookup_trace_service(&mut config, "synthetic-service-token");
    configure_lookup_trace_lookup(&mut config, "synthetic-lookup-token");
    config.policy.grants = vec![lookup_trace_grant(
        "service",
        None,
        &["project-ENG", "project-OPS"],
    )];
    config
}

fn summary(runtime: &BrokerRuntime) -> DiscoveredService {
    runtime
        .service_capabilities(&agent_one_identity(), &default_execution_context(), "jira")
        .unwrap()
}

#[test]
fn discovery_rechecks_shared_files_and_keeps_only_a_service_shell_when_missing() {
    let config = jira_config();
    let path = config.credentials.service["jira"]
        .token_ref
        .as_ref()
        .unwrap()
        .strip_prefix("file:")
        .unwrap()
        .to_owned();
    let runtime = BrokerRuntime::new(config).unwrap();
    assert_eq!(
        summary(&runtime).availability.state,
        AvailabilityState::Available
    );
    fs::remove_file(&path).unwrap();
    let service = summary(&runtime);
    assert_eq!(service.availability.state, AvailabilityState::Unavailable);
    assert_eq!(
        service.availability.requirements[0].credential_mode,
        "service"
    );
    assert_eq!(
        service.availability.requirements[0].resolution,
        "administrator"
    );
    assert!(service.actions.is_empty());
    assert!(service.resource_scopes.is_empty());
    let identity = agent_one_identity();
    let context = default_execution_context();
    let discovery = runtime
        .service_discovery(&identity, &context, "jira")
        .unwrap();
    assert!(
        discovery
            .actions(Some("ENG"), None, None)
            .unwrap()
            .actions
            .is_empty()
    );
    let resources = discovery
        .resource_access(&ResourceAccessQuery::default())
        .unwrap();
    assert!(resources.registered_resources.items.is_empty() && resources.access.is_empty());
    let catalog = runtime.api_services_for_identity(&identity, &context);
    assert_eq!(catalog.len(), 1);
    assert!(catalog[0].actions.is_empty());
    assert!(
        !runtime.policy_visible_services(&identity, &context)[0]
            .actions
            .is_empty()
    );
    for value in ["  ", "restored-synthetic-token"] {
        fs::write(&path, value).unwrap();
        assert_eq!(
            summary(&runtime).actions.is_empty(),
            value.trim().is_empty()
        );
    }
}

#[test]
fn discovery_retains_usable_resource_regions_without_falling_back_from_personal_grants() {
    let mut config = jira_config();
    configure_lookup_trace_missing_per_user(&mut config, "other-users-token");
    let mut personal = lookup_trace_grant("per_user", None, &["project-ENG"]);
    personal.subjects = vec!["user:agent-one".into()];
    config.policy.grants.push(personal);
    let personal_store = config.credentials.per_user["jira"].path.clone().unwrap();
    let runtime = BrokerRuntime::new(config).unwrap();
    let service = summary(&runtime);
    assert_eq!(service.availability.state, AvailabilityState::Partial);
    assert_eq!(service.availability.requirements[0].resolution, "user");
    let identity = agent_one_identity();
    let context = default_execution_context();
    let view = runtime
        .service_discovery(&identity, &context, "jira")
        .unwrap();
    assert!(
        view.actions(Some("ENG"), None, None)
            .unwrap()
            .actions
            .is_empty()
    );
    assert_eq!(
        view.actions(Some("OPS"), None, None).unwrap().actions,
        ["issue.view"]
    );
    let description = view
        .resource_access(&ResourceAccessQuery::default())
        .unwrap();
    assert_eq!(
        description
            .registered_resources
            .items
            .iter()
            .map(|r| r.value.as_str())
            .collect::<Vec<_>>(),
        ["OPS"]
    );
    assert_eq!(
        description.access[0].coverage().unwrap(),
        &[ResourceCoverage {
            selector: ResourceSelector::Exact {
                value: "OPS".into()
            },
            inputs: None,
            restricted: false,
        }]
    );
    let serialized = serde_json::to_string(&description).unwrap();
    assert!(!serialized.contains("\"ENG\"") && !serialized.contains("project-ENG"));
    // Removing personal material must not change the policy-only setup preview.
    assert!(runtime.has_any_per_user_policy_for_service(&identity, "jira"));
    assert!(
        !runtime.visible_services_for_management(&identity)[0]
            .actions
            .is_empty()
    );
    let material = fs::read_to_string(&personal_store)
        .unwrap()
        .replace("other-agent", "agent-one");
    fs::write(personal_store, material).unwrap();
    assert_eq!(
        summary(&runtime).availability.state,
        AvailabilityState::Available
    );
    assert_eq!(
        runtime
            .service_discovery(&identity, &context, "jira")
            .unwrap()
            .actions(Some("ENG"), None, None)
            .unwrap()
            .actions,
        ["issue.view"]
    );
}

#[test]
fn discovery_includes_pre_scope_lookup_dependency_for_personal_regions() {
    let mut config = jira_config();
    configure_lookup_trace_per_user(&mut config, "personal-token");
    let lookup_path = config.credentials.lookup["jira"]
        .token_ref
        .as_ref()
        .unwrap()
        .strip_prefix("file:")
        .unwrap()
        .to_owned();
    let mut personal = lookup_trace_grant("per_user", None, &["project-ENG"]);
    personal.subjects = vec!["user:agent-one".into()];
    config.policy.grants.push(personal);
    let runtime = BrokerRuntime::new(config).unwrap();
    fs::remove_file(lookup_path).unwrap();
    let service = summary(&runtime);
    assert!(service.actions.is_empty());
    assert_eq!(service.availability.requirements.len(), 1);
    assert_eq!(
        service.availability.requirements[0].credential_mode,
        "lookup"
    );
}

#[test]
fn discovery_search_preserves_action_wide_winning_credential_mode() {
    let mut config = jira_config();
    configure_lookup_trace_missing_per_user(&mut config, "other-users-token");
    config.policy.grants[0].actions = vec!["search".into()];
    let mut personal = lookup_trace_grant("per_user", None, &["project-ENG"]);
    personal.actions = vec!["search".into()];
    personal.subjects = vec!["user:agent-one".into()];
    config.policy.grants.push(personal);
    let runtime = BrokerRuntime::new(config).unwrap();
    assert_eq!(
        summary(&runtime).availability.state,
        AvailabilityState::Unavailable
    );
    assert!(
        summary(&runtime).actions.is_empty(),
        "shared OPS grant must not revive a search selecting personal authority"
    );
}

#[test]
fn discovery_filters_broad_coverage_and_invalidates_resource_cursors() {
    let mut config = jira_config();
    configure_lookup_trace_missing_per_user(&mut config, "other-users-token");
    config.policy.grants[0].resources = resource_selection(&["project-all"]);
    let mut personal = lookup_trace_grant("per_user", None, &["project-ENG"]);
    personal.subjects = vec!["user:agent-one".into()];
    config.policy.grants.push(personal);
    let path = config.credentials.service["jira"]
        .token_ref
        .as_ref()
        .unwrap()
        .strip_prefix("file:")
        .unwrap()
        .to_owned();
    let runtime = BrokerRuntime::new(config).unwrap();
    let identity = agent_one_identity();
    let context = default_execution_context();
    let page = runtime
        .service_discovery(&identity, &context, "jira")
        .unwrap()
        .resource_access(&ResourceAccessQuery {
            limit: Some(1),
            ..Default::default()
        })
        .unwrap();
    assert_eq!(page.access[0].coverage().unwrap().len(), 1);
    assert!(page.access[0].coverage().unwrap()[0].restricted);
    assert_eq!(page.availability.state, AvailabilityState::Partial);
    assert_eq!(page.execution_context, context);
    assert_ne!(page.registered_resources.items[0].value, "ENG");
    assert!(page.registered_resources.next_cursor.is_some());
    fs::remove_file(path).unwrap();
    let unavailable = runtime
        .service_discovery(&identity, &context, "jira")
        .unwrap();
    let empty = unavailable
        .resource_access(&ResourceAccessQuery::default())
        .unwrap();
    assert!(empty.registered_resources.items.is_empty() && empty.access.is_empty());
    assert_eq!(empty.availability.state, AvailabilityState::Unavailable);
    assert!(
        unavailable
            .resource_access(&ResourceAccessQuery {
                limit: Some(1),
                cursor: page.registered_resources.next_cursor,
                ..Default::default()
            })
            .is_err()
    );
}

#[test]
fn discovery_cursor_rejects_an_availability_only_change_from_real_local_credentials() {
    let mut config = jira_config();
    configure_lookup_trace_missing_per_user(&mut config, "other-users-token");
    config.policy.grants[0].resources = resource_selection(&["project-all"]);
    let mut personal = lookup_trace_grant("per_user", None, &["project-ENG"]);
    personal.subjects = vec!["user:agent-one".into()];
    config.policy.grants.push(personal);
    let store_path = config.credentials.per_user["jira"].path.clone().unwrap();
    let runtime = BrokerRuntime::new(config).unwrap();
    let identity = agent_one_identity();
    let context = default_execution_context();
    let query = ResourceAccessQuery {
        limit: Some(1),
        ..Default::default()
    };
    let before = runtime
        .service_discovery(&identity, &context, "jira")
        .unwrap()
        .resource_access(&query)
        .unwrap();
    let cursor = before
        .registered_resources
        .next_cursor
        .clone()
        .expect("multiple available registered projects");
    let generation = runtime.policy_generation();
    assert_eq!(
        before.availability.requirements[0].reason,
        "credential_not_provisioned"
    );

    // The same personal grant stays unavailable, but the current local check
    // now reports an invalid store. No policy or catalog publication occurs.
    fs::write(store_path, "invalid credential store JSON").unwrap();
    let discovery = runtime
        .service_discovery(&identity, &context, "jira")
        .unwrap();
    let after = discovery.resource_access(&query).unwrap();
    assert_eq!(
        after.availability.requirements[0].reason,
        "credential_invalid"
    );
    assert_eq!(after.availability.state, before.availability.state);
    assert_eq!(runtime.policy_generation(), generation);
    assert_eq!(after.access, before.access);
    assert_eq!(
        after.registered_resources.items,
        before.registered_resources.items
    );
    assert_eq!(after.live_listings, before.live_listings);
    assert_ne!(
        after.registered_resources.next_cursor,
        before.registered_resources.next_cursor
    );
    assert_eq!(
        discovery
            .resource_access(&ResourceAccessQuery {
                cursor: Some(cursor),
                ..query
            })
            .unwrap_err(),
        "resource cursor is invalid or stale; restart without the cursor"
    );
}

#[test]
fn discovery_does_not_require_dummy_credentials_for_services_without_execution_credentials() {
    let mut config = base_fake_config();
    config.credentials.service.clear();
    let runtime = BrokerRuntime::new(config).unwrap();
    let service = runtime
        .service_capabilities(
            &IdentityContext::anonymous(),
            &default_execution_context(),
            "fake",
        )
        .unwrap();
    assert_eq!(service.availability.state, AvailabilityState::Available);
    assert_eq!(service.actions.len(), 1);
}

#[test]
fn discovery_checks_managed_material_without_recording_use_and_fails_closed_on_store_error() {
    let mut config = jira_config();
    let store_path = temp_path("discovery.sqlite");
    config.managed_store = Some(ManagedStoreConfig {
        kind: "sqlite".into(),
        path: store_path.display().to_string(),
        require_registered_principal_for_invocation: false,
        auto_migrate: true,
    });
    config.credentials.connections.insert(
        "jira".into(),
        crate::ConnectionConfig {
            display_name: None,
            token_profiles: Some(vec!["atlassian-api-token".into()]),
            service_account_token_profiles: None,
            oauth: None,
        },
    );
    config.credentials.per_user.insert(
        "jira".into(),
        CredentialConfig {
            kind: "connection".into(),
            connection: Some("jira".into()),
            profile: None,
            provider: None,
            path: None,
            token_ref: None,
            username_ref: None,
            read_only: None,
        },
    );
    config.policy.grants[0].credential_mode = "per_user".into();
    let runtime = BrokerRuntime::new(config).unwrap();
    // The managed user's kind selects the connection's token.
    let summary = |runtime: &BrokerRuntime| {
        let identity = IdentityContext {
            principal_kind: Some(crate::PrincipalKind::User),
            ..agent_one_identity()
        };
        runtime
            .service_capabilities(&identity, &default_execution_context(), "jira")
            .unwrap()
    };
    let store = runtime.managed_store().unwrap();
    store
        .create_or_update_principal(crate::PrincipalWriteRequest {
            role: crate::PrincipalRole::User,
            self_service_enabled: Some(false),
            principal_id: "agent-one".into(),
            kind: "user".into(),
            display_name: None,
            email: None,
            external_subject: None,
            created_by: "admin".into(),
        })
        .unwrap();
    assert!(summary(&runtime).actions.is_empty());
    let request = crate::CredentialWriteRequest {
        owner_principal_id: "agent-one".into(),
        service: "jira".into(),
        name: "default".into(),
        profile: "atlassian-api-token".into(),
        credential_kind: "basic_api_token".into(),
        secret: json!({"username": "synthetic-user", "token": "synthetic-personal-token"}),
        metadata: json!({}),
        actor: "admin".into(),
    };
    store
        .upsert_user_credential(
            runtime.credential_key_ring().unwrap(),
            request.clone(),
            crate::CredentialManagementPurpose::Administrative,
        )
        .unwrap();
    assert_eq!(
        summary(&runtime).availability.state,
        AvailabilityState::Available
    );
    let conn = rusqlite::Connection::open(store_path).unwrap();
    let last_used: Option<String> = conn
        .query_row("SELECT last_used_at FROM credentials", [], |row| row.get(0))
        .unwrap();
    assert!(last_used.is_none());
    // Execution eligibility does not require self-service, and discovery must not either.
    conn.execute("UPDATE credentials SET status = 'disabled'", [])
        .unwrap();
    assert!(summary(&runtime).actions.is_empty());
    store
        .upsert_user_credential(
            runtime.credential_key_ring().unwrap(),
            crate::CredentialWriteRequest {
                metadata: json!({"expiresAt": "2000-01-01T00:00:00Z"}),
                ..request
            },
            crate::CredentialManagementPurpose::Administrative,
        )
        .unwrap();
    assert!(summary(&runtime).actions.is_empty());
    conn.execute("DROP TABLE credentials", []).unwrap();
    let service = summary(&runtime);
    assert_eq!(service.availability.state, AvailabilityState::Unknown);
    assert!(service.actions.is_empty());
}

/// The message of the input denial `identity` receives for a malformed
/// `jira.issue.view` call, which scope resolution rejects before policy and
/// before any upstream request.
async fn issue_view_denial(runtime: &BrokerRuntime, identity: IdentityContext) -> String {
    let response = runtime
        .invoke(
            governed(OperationContext {
                agent_request_id: "agent-input-denial".into(),
                broker_request_id: "broker-input-denial".into(),
                identity,
                service: "jira".into(),
                action: "issue.view".into(),
                source: SourceContext::unknown(),
            }),
            InvokeRequest::new(json!({"issue": 7})),
        )
        .await;
    assert_eq!(
        response.envelope.reason_code,
        Some(ReasonCode::InputInvalid.into())
    );
    response.envelope.reason.unwrap()
}

/// Scope resolution runs before policy, so a native input denial is
/// explained only when caller discovery lists the action: not under a token
/// whose resources miss every grant, nor once the winning grant's credential
/// is unusable.
#[tokio::test]
async fn native_input_denials_before_policy_follow_caller_discovery() {
    const PROVIDER: &str = "jira.issue.view requires exactly one of issue or url";
    let config = jira_config();
    let token = config.credentials.service["jira"]
        .token_ref
        .as_ref()
        .unwrap()
        .strip_prefix("file:")
        .unwrap()
        .to_owned();
    let runtime = BrokerRuntime::new(config).unwrap();
    let context = default_execution_context();
    let listed = |identity: &IdentityContext| {
        runtime
            .api_services_for_identity(identity, &context)
            .iter()
            .any(|service| {
                service
                    .actions
                    .iter()
                    .any(|action| action.action == "issue.view")
            })
    };

    assert!(listed(&agent_one_identity()));
    assert_eq!(
        issue_view_denial(&runtime, agent_one_identity()).await,
        "jira.issue.view inputs are invalid: inputs.issue must be a string"
    );

    let restricted = shell_token_identity(json!({
        "allowedServices": ["jira"],
        "allowedExecutionContexts": ["default"],
        "serviceRestrictions": {"jira": {
            "actions": ["issue.view"],
            "resources": {"resourceIds": ["project-OTHER"]}
        }}
    }));
    assert!(!listed(&restricted));
    assert_eq!(issue_view_denial(&runtime, restricted).await, PROVIDER);

    fs::remove_file(&token).unwrap();
    assert!(!listed(&agent_one_identity()));
    assert_eq!(
        issue_view_denial(&runtime, agent_one_identity()).await,
        PROVIDER
    );
}
