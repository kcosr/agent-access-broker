//! Read-only identity access paths: one ceiling rule judges each action
//! against the runtime catalog before grants, credentials or providers.
use super::*;

const SERVICE: &str = "path_controls";

static BACKEND: BackendRegistration = BackendRegistration::new(
    agent_access_provider::module_metadata!(),
    SERVICE,
    parse_backend_config::<PathControlConfig>,
)
.development_only();

/// `[providers.path_controls]`, whose descriptor names the actions grants
/// may reference. Tests serve the counting provider in its place.
#[derive(Debug, Clone, Default, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct PathControlConfig {}

impl BackendConfig for PathControlConfig {
    fn kind(&self) -> &'static str {
        SERVICE
    }

    fn validate(&self, _: &ValidationContext<'_>, _: &mut Vec<String>) {}

    fn descriptor(&self) -> ServiceDescriptor {
        path_control_descriptor()
    }

    fn egress_proxies(&self) -> Vec<(String, &EgressProxyConfig)> {
        vec![]
    }

    fn build(&self, _: &BuildContext<'_>) -> Result<Arc<dyn Provider>, ProviderBuildError> {
        Ok(Arc::new(PathControlProvider::default()))
    }
}

/// A read and a write in each resource shape.
fn path_control_descriptor() -> ServiceDescriptor {
    let scoped = json!({
        "type": "object",
        "required": ["project", "message"],
        "properties": {
            "project": { "type": "string" },
            "message": { "type": "string" }
        },
        "additionalProperties": false
    });
    let unscoped = json!({"type": "object", "additionalProperties": false});
    ServiceDescriptor::new(SERVICE, "Path controls fixture")
        .with_resource_scopes(BTreeMap::from([(
            "project".to_string(),
            ResourceScopeCapabilities::new(
                agent_access_fake::FAKE_PROJECT_RESOURCE.id().clone(),
                vec!["exact".to_string(), "all".to_string()],
            ),
        )]))
        .with_actions(vec![
            ActionDescriptor::new("echo", "Read a project", scoped.clone())
                .read_only()
                .scope("project")
                .credential_modes(["service"]),
            ActionDescriptor::new("note.write", "Write a project note", scoped)
                .scope("project")
                .credential_modes(["service"]),
            ActionDescriptor::new("status.view", "Read the service status", unscoped.clone())
                .read_only()
                .credential_modes(["service"]),
            ActionDescriptor::new("status.set", "Set the service status", unscoped)
                .credential_modes(["service"]),
        ])
        .with_credentials(CredentialDescriptor::without_execution_credential())
}

/// The fixture service's provider, counting scope resolutions and dispatches.
#[derive(Default)]
struct PathControlProvider {
    scope_resolutions: AtomicUsize,
    invocations: AtomicUsize,
}

impl agent_access_provider::test_support::DescribedProvider for PathControlProvider {
    fn descriptor(&self) -> ServiceDescriptor {
        path_control_descriptor()
    }
}

#[async_trait]
impl Provider for PathControlProvider {
    async fn resolve_scopes(
        &self,
        request: ScopeRequest<'_>,
    ) -> Result<ScopeResolution, ProviderError> {
        self.scope_resolutions.fetch_add(1, Ordering::SeqCst);
        Ok(
            match request.inputs().get("project").and_then(Value::as_str) {
                Some(project) => ScopeResolution::resources(ResourceScopes::from([(
                    "project".to_owned(),
                    vec![project.to_owned()],
                )])),
                None => ScopeResolution::no_resources(),
            },
        )
    }

    async fn invoke(&self, request: ProviderInvocation) -> Result<ProviderResult, ProviderError> {
        self.invocations.fetch_add(1, Ordering::SeqCst);
        Ok(ProviderResult::new(json!({
            "action": request.action(),
            "credentialMode": request.credential_mode(),
        })))
    }
}

/// Every action of the provider, for a person (`group:agents`) whose grants
/// cover reads and writes alike.
fn path_control_config() -> BrokerConfig {
    let mut config = base_fake_config();
    let registry = crate::BackendRegistry::new([
        &agent_access_jira::JIRA_BACKEND,
        &agent_access_confluence::CONFLUENCE_BACKEND,
        &agent_access_gitlab::GITLAB_BACKEND,
        &agent_access_cloudbees_ci::CLOUDBEES_CI_BACKEND,
        &agent_access_fake::FAKE_BACKEND,
        &agent_access_fake::OAUTH_STUB_BACKEND,
        &BACKEND,
    ])
    .unwrap()
    .with_oauth_dialects([&agent_access_fake::STUB_OAUTH_DIALECT])
    .unwrap();
    config.providers = crate::ProvidersConfig::new(Arc::new(registry))
        .with(agent_access_fake::FakeProviderConfig::default())
        .with(PathControlConfig::default());
    config.policy.grants = vec![
        PolicyGrantConfig {
            subjects: vec!["group:agents".into()],
            service: SERVICE.into(),
            actions: vec!["echo".into(), "note.write".into()],
            resources: resource_selection(&["fake-project-TEST"]),
            execution_contexts: None,
            credential_mode: "service".into(),
            priority: None,
        },
        PolicyGrantConfig {
            subjects: vec!["group:agents".into()],
            service: SERVICE.into(),
            actions: vec!["status.view".into(), "status.set".into()],
            resources: resource_selection(&[]),
            execution_contexts: None,
            credential_mode: "service".into(),
            priority: None,
        },
    ];
    config
}

/// The identity `attested_identity` builds for agent-one: synthetic
/// agent-invoke caveats and the admitted path's read-only setting.
fn attested(read_only: bool) -> IdentityContext {
    attested_with(
        Some(BrokerTokenClass::AgentInvoke),
        Some(json!({"readOnly": false, "allowedExecutionContexts": ["default"]})),
        read_only,
    )
}

fn issued(read_only: bool) -> IdentityContext {
    shell_token_identity(json!({
        "readOnly": read_only,
        "allowedExecutionContexts": ["default"]
    }))
}

fn attested_with(
    token_class: Option<BrokerTokenClass>,
    token_scopes: Option<Value>,
    read_only: bool,
) -> IdentityContext {
    IdentityContext {
        source: Some(IdentitySourceAudit {
            name: "forwarded_identity".into(),
            kind: "forwarded_identity".into(),
            token_header: "x-aw-identity-token-sha256".into(),
            token_scheme: "sha256".into(),
            token_class,
            token_id: None,
            namespace: None,
            binding_id: None,
            read_only_access: Some(read_only),
            token_scopes,
        }),
        ..agent_one_identity()
    }
}

async fn invoke_as(
    runtime: &BrokerRuntime,
    identity: IdentityContext,
    service: &str,
    action: &str,
    inputs: Value,
) -> BrokerResponse<Value> {
    runtime
        .invoke(
            governed(OperationContext {
                agent_request_id: format!("agent-{action}"),
                broker_request_id: format!("broker-{action}"),
                identity,
                service: service.into(),
                action: action.into(),
                source: SourceContext::unknown(),
            }),
            InvokeRequest::new(inputs),
        )
        .await
}

fn project_inputs() -> Value {
    json!({"project": "TEST", "message": "hello"})
}

fn inputs_for(action: &str) -> Value {
    if action.starts_with("status.") {
        json!({})
    } else {
        project_inputs()
    }
}

fn listed_actions(runtime: &BrokerRuntime, identity: &IdentityContext) -> Vec<String> {
    runtime
        .visible_services(identity, &default_execution_context())
        .into_iter()
        .flat_map(|service| {
            let capabilities = service.capabilities;
            capabilities
                .actions
                .into_iter()
                .map(move |action| format!("{}.{}", capabilities.service, action.action))
        })
        .collect()
}

fn assert_read_only_denial(response: &BrokerResponse<Value>, action: &str) {
    assert_eq!(response.status, 403, "{:?}", response.envelope);
    assert_eq!(
        response.envelope.reason_code,
        Some(ReasonCode::ServiceActionDenied.into())
    );
    assert_eq!(
        response.envelope.reason.as_deref(),
        Some("identity access is read-only")
    );
    assert_eq!(response.envelope.action, action);
    assert!(response.envelope.resource_scopes.is_empty());
}

fn assert_token_read_only_denial(response: &BrokerResponse<Value>, action: &str) {
    assert_eq!(response.status, 403, "{:?}", response.envelope);
    assert_eq!(
        response.envelope.reason_code,
        Some(ReasonCode::ServiceActionDenied.into())
    );
    assert_eq!(
        response.envelope.reason.as_deref(),
        Some("broker token is read-only")
    );
    assert_eq!(response.envelope.action, action);
    assert!(response.envelope.resource_scopes.is_empty());
}

#[tokio::test]
async fn read_only_token_blocks_writes_before_provider_work_and_preserves_token_audit() {
    let audit_path = temp_path("token-read-only.audit.jsonl");
    let mut config = path_control_config();
    config.audit = Some(jsonl_audit_config(audit_path.display().to_string()));
    let provider = Arc::new(PathControlProvider::default());
    let runtime = BrokerRuntime::with_providers(config, vec![Arc::clone(&provider)]).unwrap();

    for action in ["note.write", "status.set", "missing"] {
        let response = invoke_as(&runtime, issued(true), SERVICE, action, inputs_for(action)).await;
        assert_token_read_only_denial(&response, action);
    }
    assert_eq!(provider.scope_resolutions.load(Ordering::SeqCst), 0);
    assert_eq!(provider.invocations.load(Ordering::SeqCst), 0);
    for action in ["echo", "status.view"] {
        let response = invoke_as(&runtime, issued(true), SERVICE, action, inputs_for(action)).await;
        assert_eq!(response.status, 200, "{:?}", response.envelope);
    }
    for action in ["note.write", "status.set"] {
        let response =
            invoke_as(&runtime, issued(false), SERVICE, action, inputs_for(action)).await;
        assert_eq!(response.status, 200, "{:?}", response.envelope);
    }
    runtime
        .shutdown_audit(Duration::from_secs(1))
        .await
        .unwrap();
    let records = audit_records(&audit_path);
    let denials = records
        .iter()
        .filter(|record| record["reasonCode"] == "service_action_denied")
        .collect::<Vec<_>>();
    assert_eq!(denials.len(), 3);
    for (denial, action) in denials.iter().zip(["note.write", "status.set", "missing"]) {
        assert_eq!(
            denial["providerAudit"],
            json!({"brokerToken": {
                "tokenId": "tok_shell", "requestedService": SERVICE,
                "requestedAction": action, "readOnly": true
            }})
        );
        assert!(denial["identitySource"].get("readOnlyAccess").is_none());
        assert!(denial.get("matchedGrant").is_none());
        assert!(denial.get("credentialMode").is_none());
    }
}

#[test]
fn read_only_token_discovery_and_resource_access_share_the_action_ceiling() {
    let runtime = BrokerRuntime::with_providers(
        path_control_config(),
        vec![Arc::new(PathControlProvider::default())],
    )
    .unwrap();
    let identity = issued(true);
    let context = default_execution_context();
    assert_eq!(
        listed_actions(&runtime, &identity),
        ["path_controls.echo", "path_controls.status.view"]
    );
    let service = runtime
        .service_capabilities(&identity, &context, SERVICE)
        .unwrap();
    assert_eq!(
        service
            .actions
            .iter()
            .map(|action| action.action.as_str())
            .collect::<BTreeSet<_>>(),
        BTreeSet::from(["echo", "status.view"])
    );
    let catalog = runtime.api_services_for_identity(&identity, &context);
    assert_eq!(catalog.len(), 1);
    assert_eq!(
        catalog[0]
            .actions
            .iter()
            .map(|action| action.action.as_str())
            .collect::<BTreeSet<_>>(),
        BTreeSet::from(["echo", "status.view"])
    );
    let discovery = runtime
        .service_discovery(&identity, &context, SERVICE)
        .unwrap();
    let access = discovery
        .resource_access(&ResourceAccessQuery::default())
        .unwrap();
    assert_eq!(
        access
            .access
            .iter()
            .map(|entry| entry.action())
            .collect::<BTreeSet<_>>(),
        BTreeSet::from(["echo", "status.view"])
    );
    assert_eq!(
        discovery
            .actions(None, None, None)
            .unwrap()
            .actions
            .into_iter()
            .collect::<BTreeSet<_>>(),
        BTreeSet::from(["echo".to_owned(), "status.view".to_owned()])
    );

    // A write-only grant still authorizes an ordinary token; a read-only
    // token has no service or resource disclosure through that grant.
    let mut only_writes = path_control_config();
    only_writes.policy.grants[0].actions = vec!["note.write".into()];
    only_writes.policy.grants[1].actions = vec!["status.set".into()];
    let runtime =
        BrokerRuntime::with_providers(only_writes, vec![Arc::new(PathControlProvider::default())])
            .unwrap();
    assert_eq!(listed_actions(&runtime, &issued(false)).len(), 2);
    assert!(listed_actions(&runtime, &identity).is_empty());
    assert!(
        runtime
            .service_discovery(&identity, &context, SERVICE)
            .is_none()
    );
    assert!(
        runtime
            .api_services_for_identity(&identity, &context)
            .is_empty()
    );
}

#[tokio::test]
async fn inherited_read_only_token_gains_later_reads_but_never_writes() {
    let mut config = path_control_config();
    let all_grants = config.clone();
    config.policy.grants[0].actions = vec!["note.write".into()];
    config.policy.grants[1].actions = vec!["status.set".into()];
    let runtime = BrokerRuntime::with_providers(
        config.clone(),
        vec![Arc::new(PathControlProvider::default())],
    )
    .unwrap();
    let identity = issued(true);
    let caveats = AgentInvokeTokenCaveats::parse_stored(
        identity
            .source
            .as_ref()
            .unwrap()
            .token_scopes
            .as_ref()
            .unwrap(),
    )
    .unwrap();
    assert!(
        runtime
            .preview_agent_token_access(&identity, &caveats)
            .unwrap()
            .access
            .is_empty()
    );
    assert!(listed_actions(&runtime, &identity).is_empty());

    runtime
        .policy_snapshot
        .store(Arc::new(PolicySnapshot::from_config(&all_grants, 1)));
    assert_eq!(
        listed_actions(&runtime, &identity),
        ["path_controls.echo", "path_controls.status.view"]
    );
    assert_eq!(
        runtime
            .preview_agent_token_access(&identity, &caveats)
            .unwrap()
            .access
            .len(),
        2
    );
    for action in ["echo", "status.view"] {
        assert_eq!(
            invoke_as(
                &runtime,
                identity.clone(),
                SERVICE,
                action,
                inputs_for(action)
            )
            .await
            .status,
            200
        );
    }
    for action in ["note.write", "status.set"] {
        assert_token_read_only_denial(
            &invoke_as(
                &runtime,
                identity.clone(),
                SERVICE,
                action,
                inputs_for(action),
            )
            .await,
            action,
        );
    }
    runtime
        .policy_snapshot
        .store(Arc::new(PolicySnapshot::from_config(&config, 2)));
    assert!(listed_actions(&runtime, &identity).is_empty());
    assert_eq!(
        invoke_as(&runtime, identity, SERVICE, "echo", project_inputs())
            .await
            .status,
        403
    );
}

#[test]
fn retained_read_only_token_preview_uses_current_classification_without_rejecting_selections() {
    let mut runtime = BrokerRuntime::with_providers(
        path_control_config(),
        vec![Arc::new(PathControlProvider::default())],
    )
    .unwrap();
    let scopes = json!({"readOnly": true, "allowedExecutionContexts": ["default"], "allowedServices": [SERVICE],
        "serviceRestrictions": { SERVICE: {"actions": ["echo", "status.view"]} }});
    let caveats = AgentInvokeTokenCaveats::parse_stored(&scopes).unwrap();
    let identity = shell_token_identity(scopes);
    assert_eq!(
        runtime
            .preview_agent_token_access(&identity, &caveats)
            .unwrap()
            .access
            .len(),
        2
    );
    let service = Arc::make_mut(&mut runtime.services)
        .get_mut(SERVICE)
        .unwrap();
    Arc::make_mut(service)
        .actions
        .iter_mut()
        .find(|action| action.action == "echo")
        .unwrap()
        .read_only = false;
    let preview = runtime
        .preview_agent_token_access(&identity, &caveats)
        .unwrap();
    assert_eq!(
        preview
            .access
            .iter()
            .map(|entry| entry.action.as_str())
            .collect::<Vec<_>>(),
        ["status.view"]
    );
    let denial = runtime
        .admit_agent_invoke_token_operation(
            &identity,
            SERVICE,
            "echo",
            &default_execution_context(),
            &ResourceScopes::new(),
        )
        .unwrap_err();
    assert_eq!(denial.message, "broker token is read-only");
    assert_eq!(
        listed_actions(&runtime, &identity),
        ["path_controls.status.view"]
    );
}

#[tokio::test]
async fn read_only_identity_lists_and_executes_only_reads_and_does_no_work_for_writes() {
    let audit_path = temp_path("identity-path-controls.audit.jsonl");
    let mut config = path_control_config();
    config.audit = Some(jsonl_audit_config(audit_path.display().to_string()));
    let provider = Arc::new(PathControlProvider::default());
    let runtime = BrokerRuntime::with_providers(config, vec![Arc::clone(&provider)]).unwrap();

    assert_eq!(
        listed_actions(&runtime, &attested(false)),
        [
            "path_controls.echo",
            "path_controls.note.write",
            "path_controls.status.view",
            "path_controls.status.set"
        ]
    );
    assert_eq!(
        listed_actions(&runtime, &attested(true)),
        ["path_controls.echo", "path_controls.status.view"]
    );

    for action in ["note.write", "status.set"] {
        let response = invoke_as(
            &runtime,
            attested(true),
            SERVICE,
            action,
            inputs_for(action),
        )
        .await;
        assert_read_only_denial(&response, action);
    }
    // Refused before descriptor-dependent work, so no scope resolution or dispatch.
    assert_eq!(provider.scope_resolutions.load(Ordering::SeqCst), 0);
    assert_eq!(provider.invocations.load(Ordering::SeqCst), 0);

    for action in ["echo", "status.view"] {
        let response = invoke_as(
            &runtime,
            attested(true),
            SERVICE,
            action,
            inputs_for(action),
        )
        .await;
        assert_eq!(response.status, 200, "{action}: {:?}", response.envelope);
    }
    for action in ["note.write", "status.set"] {
        let response = invoke_as(
            &runtime,
            attested(false),
            SERVICE,
            action,
            inputs_for(action),
        )
        .await;
        assert_eq!(response.status, 200, "{action}: {:?}", response.envelope);
    }
    assert_eq!(provider.invocations.load(Ordering::SeqCst), 4);
    runtime
        .shutdown_audit(Duration::from_secs(1))
        .await
        .unwrap();

    let records = audit_records(&audit_path);
    let denials = records
        .iter()
        .filter(|record| record["reasonCode"] == "service_action_denied")
        .collect::<Vec<_>>();
    assert_eq!(denials.len(), 2);
    for (denial, action) in denials.iter().zip(["note.write", "status.set"]) {
        assert_eq!(
            denial["providerAudit"],
            json!({"identityAccess": {
                "readOnly": true,
                "requestedService": SERVICE,
                "requestedAction": action
            }})
        );
        assert_eq!(denial["identitySource"]["readOnlyAccess"], true);
        assert_eq!(denial["resourceScopes"], json!({}));
        assert!(denial.get("matchedGrant").is_none(), "{denial}");
        assert!(denial.get("credentialMode").is_none(), "{denial}");
    }
    let allowed = records
        .iter()
        .filter(|record| record["decision"] == "allow")
        .map(|record| {
            (
                record["action"].as_str().unwrap().to_owned(),
                record["identitySource"]["readOnlyAccess"].clone(),
            )
        })
        .collect::<Vec<_>>();
    assert_eq!(
        allowed,
        [
            ("echo".to_owned(), json!(true)),
            ("status.view".to_owned(), json!(true)),
            ("note.write".to_owned(), json!(false)),
            ("status.set".to_owned(), json!(false)),
        ]
    );
}

#[tokio::test]
async fn read_only_write_denial_precedes_credential_lookup_scope_resolution_and_dispatch() {
    // jira issue.view has not opted in as a read, so it is a write here. Its
    // lookup before policy reads the caller's personal credential first.
    let provider = Arc::new(LookupTraceProvider::default());
    let observations = provider.observations();
    let mut config = base_fake_config();
    configure_lookup_trace_jira(&mut config);
    configure_lookup_trace_per_user(&mut config, "per-user-token");
    config.policy.grants = vec![lookup_trace_grant("per_user", None, &["project-PROJ"])];
    let runtime = BrokerRuntime::with_providers(config, vec![provider]).unwrap();
    let invoke = |identity| {
        invoke_as(
            &runtime,
            identity,
            "jira",
            "issue.view",
            json!({"project": "PROJ", "message": "hello"}),
        )
    };

    assert_read_only_denial(&invoke(attested(true)).await, "issue.view");
    assert_token_read_only_denial(&invoke(issued(true)).await, "issue.view");
    assert_lookup_observations(&observations, &[]);

    let response = invoke(attested(false)).await;
    assert_eq!(response.status, 200, "{:?}", response.envelope);
    assert_lookup_observations(
        &observations,
        &[
            ("pre_scope", "per-user-token"),
            ("execution_lookup", "per-user-token"),
            ("execution", "per-user-token"),
        ],
    );
}

#[tokio::test]
async fn read_only_ceiling_keeps_the_winning_grant_mode_and_clauses_of_a_read() {
    let audit_path = temp_path("identity-path-precedence.audit.jsonl");
    let mut config = path_control_config();
    config.audit = Some(jsonl_audit_config(audit_path.display().to_string()));
    // The higher grant covers the read and a write; the lower one only the
    // read, everywhere. Removing grants that name writes would let the lower
    // one win.
    config.policy.grants = vec![
        PolicyGrantConfig {
            subjects: vec!["group:agents".into()],
            service: SERVICE.into(),
            actions: vec!["echo".into(), "note.write".into()],
            resources: resource_selection(&["fake-project-TEST"]),
            execution_contexts: None,
            credential_mode: "service".into(),
            priority: Some(20),
        },
        PolicyGrantConfig {
            subjects: vec!["group:agents".into()],
            service: SERVICE.into(),
            actions: vec!["echo".into()],
            resources: resource_selection(&["fake-project-all"]),
            execution_contexts: None,
            credential_mode: "service".into(),
            priority: Some(0),
        },
    ];
    let runtime =
        BrokerRuntime::with_providers(config, vec![Arc::new(PathControlProvider::default())])
            .unwrap();
    let snapshot = runtime.policy_snapshot();
    let context = default_execution_context();
    let clauses = |identity: &IdentityContext| {
        let parsed = parsed_agent_invoke_token_caveats(identity).unwrap();
        runtime.effective_resource_clauses(
            &snapshot,
            identity,
            &context,
            SERVICE,
            "echo",
            parsed.as_ref(),
        )
    };
    assert!(!clauses(&attested(false)).is_empty());
    assert_eq!(clauses(&attested(true)), clauses(&attested(false)));
    assert_eq!(clauses(&issued(true)), clauses(&issued(false)));
    assert_eq!(clauses(&issued(true)), clauses(&attested(false)));

    for identity in [attested(true), attested(false), issued(true), issued(false)] {
        let response = invoke_as(&runtime, identity, SERVICE, "echo", project_inputs()).await;
        assert_eq!(response.status, 200, "{:?}", response.envelope);
    }
    runtime
        .shutdown_audit(Duration::from_secs(1))
        .await
        .unwrap();
    let records = audit_records(&audit_path);
    let selections = records
        .iter()
        .filter(|record| record["action"] == "echo")
        .map(|record| {
            (
                record["matchedGrant"].clone(),
                record["credentialMode"].clone(),
            )
        })
        .collect::<Vec<_>>();
    assert_eq!(selections.len(), 4);
    assert!(
        selections
            .iter()
            .all(|selection| selection == &selections[0])
    );
    assert_eq!(selections[0].0["configIndex"], 0, "{:?}", selections[0]);
    assert_eq!(selections[0].1, "service");
}

#[test]
fn caveat_helper_and_resource_predicate_agree_for_every_catalog_action() {
    let runtime = BrokerRuntime::with_providers(
        path_control_config(),
        vec![Arc::new(PathControlProvider::default())],
    )
    .unwrap();
    let snapshot = runtime.policy_snapshot();
    let context = default_execution_context();
    let other = ExecutionContext::new("other").unwrap();
    let mut actions = runtime
        .services
        .values()
        .flat_map(|service| {
            service
                .actions
                .iter()
                .map(|action| (service.service.clone(), action.action.clone()))
        })
        .collect::<Vec<_>>();
    // A missing descriptor is a write.
    actions.push((SERVICE.into(), "missing".into()));
    for scopes in [
        json!({"readOnly": false, "allowedExecutionContexts": ["default"]}),
        json!({"readOnly": false, "allowedExecutionContexts": ["default"], "allowedServices": [SERVICE],
            "serviceRestrictions": {SERVICE: {"actions": ["echo", "note.write"]}}}),
        json!({"readOnly": false, "allowedExecutionContexts": ["default"], "allowedServices": ["jira"]}),
    ] {
        let full_identity = attested_with(
            Some(BrokerTokenClass::AgentInvoke),
            Some(scopes.clone()),
            false,
        );
        let full = parsed_agent_invoke_token_caveats(&full_identity)
            .unwrap()
            .unwrap();
        let mut read_only_scopes = scopes.clone();
        read_only_scopes["readOnly"] = json!(true);
        for identity in [
            attested_with(
                Some(BrokerTokenClass::AgentInvoke),
                Some(scopes.clone()),
                false,
            ),
            attested_with(
                Some(BrokerTokenClass::AgentInvoke),
                Some(scopes.clone()),
                true,
            ),
            shell_token_identity(scopes.clone()),
            shell_token_identity(read_only_scopes),
        ] {
            let parsed = parsed_agent_invoke_token_caveats(&identity)
                .unwrap()
                .unwrap();
            let read_only = parsed.read_only_access || parsed.caveats.read_only;
            for (service, action) in &actions {
                for execution_context in [&context, &other] {
                    let case =
                        format!("{scopes} {read_only} {service}.{action} {execution_context}");
                    let helper = runtime
                        .enforce_agent_invoke_token_caveats_with(
                            Some(&parsed),
                            service,
                            action,
                            execution_context,
                        )
                        .is_ok();
                    let predicate = runtime.agent_invoke_permits_action(
                        &parsed,
                        execution_context,
                        service,
                        action,
                    );
                    assert_eq!(helper, predicate, "{case}");
                    // Read-only removes exactly the actions that are not reads.
                    let unlimited = runtime.agent_invoke_permits_action(
                        &full,
                        execution_context,
                        service,
                        action,
                    );
                    assert_eq!(
                        predicate,
                        unlimited && (!read_only || runtime.action_is_read_only(service, action)),
                        "{case}"
                    );
                    let clauses = runtime.effective_resource_clauses(
                        &snapshot,
                        &identity,
                        execution_context,
                        service,
                        action,
                        Some(&parsed),
                    );
                    if predicate {
                        // The ceiling never narrows the clauses of an action it permits.
                        assert_eq!(
                            clauses,
                            runtime.effective_resource_clauses(
                                &snapshot,
                                &identity,
                                execution_context,
                                service,
                                action,
                                Some(&full),
                            ),
                            "{case}"
                        );
                    } else {
                        assert!(clauses.is_empty(), "{case}");
                    }
                }
            }
        }
    }
    assert!(runtime.action_is_read_only(SERVICE, "echo"));
    assert!(!runtime.action_is_read_only(SERVICE, "note.write"));
    assert!(!runtime.action_is_read_only(SERVICE, "missing"));
    assert!(!runtime.action_is_read_only("missing", "echo"));
}

#[test]
fn token_preview_and_picker_keep_their_management_boundary() {
    let runtime = BrokerRuntime::with_providers(
        path_control_config(),
        vec![Arc::new(PathControlProvider::default())],
    )
    .unwrap();
    // The proposed token's ceiling is independent of the manager's path.
    for identity in [agent_one_identity(), attested(true)] {
        for read_only in [false, true] {
            let caveats = AgentInvokeTokenCaveats::parse_stored(&json!({
                "readOnly": read_only, "allowedExecutionContexts": ["default"]
            }))
            .unwrap();
            let preview = runtime
                .preview_agent_token_access(&identity, &caveats)
                .unwrap();
            let previewed = preview
                .access
                .iter()
                .map(|entry| entry.action.as_str())
                .collect::<BTreeSet<_>>();
            let expected = if read_only {
                BTreeSet::from(["echo", "status.view"])
            } else {
                BTreeSet::from(["echo", "note.write", "status.set", "status.view"])
            };
            assert_eq!(previewed, expected);
        }
        let options = runtime.agent_token_options_for_identity(&identity);
        let offered = options
            .services
            .iter()
            .flat_map(|service| service.actions.iter().map(|action| action.action.as_str()))
            .collect::<BTreeSet<_>>();
        assert_eq!(
            offered,
            BTreeSet::from(["echo", "note.write", "status.set", "status.view"])
        );
    }
}

#[tokio::test]
async fn attested_identity_with_invalid_synthetic_caveats_lists_nothing_and_is_denied() {
    let provider = Arc::new(PathControlProvider::default());
    let runtime =
        BrokerRuntime::with_providers(path_control_config(), vec![Arc::clone(&provider)]).unwrap();
    for identity in [
        attested_with(Some(BrokerTokenClass::AgentInvoke), None, true),
        attested_with(
            Some(BrokerTokenClass::AgentInvoke),
            Some(json!({"readOnly": false, "allowedExecutionContexts": "default"})),
            true,
        ),
        attested_with(Some(BrokerTokenClass::AgentInvoke), None, false),
        attested_with(
            None,
            Some(json!({"readOnly": false, "allowedExecutionContexts": ["default"]})),
            true,
        ),
        attested_with(
            None,
            Some(json!({"readOnly": false, "allowedExecutionContexts": ["default"]})),
            false,
        ),
    ] {
        assert!(parsed_agent_invoke_token_caveats(&identity).is_err());
        assert!(listed_actions(&runtime, &identity).is_empty());
        assert!(
            runtime
                .service_discovery(&identity, &default_execution_context(), SERVICE)
                .is_none()
        );
        for action in ["echo", "note.write"] {
            let response = invoke_as(
                &runtime,
                identity.clone(),
                SERVICE,
                action,
                project_inputs(),
            )
            .await;
            assert_eq!(response.status, 403);
            assert_eq!(
                response.envelope.reason.as_deref(),
                Some("broker token caveats are invalid")
            );
        }
    }
    assert_eq!(provider.scope_resolutions.load(Ordering::SeqCst), 0);
    assert_eq!(provider.invocations.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn missing_descriptor_is_a_write_on_a_read_only_path() {
    let runtime = BrokerRuntime::with_providers(
        path_control_config(),
        vec![Arc::new(PathControlProvider::default())],
    )
    .unwrap();
    // The ceiling runs before the descriptor lookup, with the same reason code.
    assert_read_only_denial(
        &invoke_as(&runtime, attested(true), SERVICE, "missing", json!({})).await,
        "missing",
    );
    let full = invoke_as(&runtime, attested(false), SERVICE, "missing", json!({})).await;
    assert_eq!(
        full.envelope.reason_code,
        Some(ReasonCode::ServiceActionDenied.into())
    );
    assert_eq!(
        full.envelope.reason.as_deref(),
        Some("service action is not supported")
    );
}

#[test]
fn identity_summary_reports_read_only_access_only_for_attested_identities() {
    let summary = |identity: &IdentityContext| serde_json::to_value(identity.summary()).unwrap();
    assert_eq!(summary(&attested(true))["readOnlyAccess"], true);
    assert_eq!(summary(&attested(false))["readOnlyAccess"], false);
    for identity in [
        agent_one_identity(),
        shell_token_identity(json!({"readOnly": false, "allowedExecutionContexts": ["default"]})),
    ] {
        assert!(summary(&identity).get("readOnlyAccess").is_none());
        let source = serde_json::to_value(&identity.source).unwrap();
        assert!(source.get("readOnlyAccess").is_none(), "{source}");
    }
    let source = serde_json::to_value(&attested(true).source).unwrap();
    assert_eq!(source["readOnlyAccess"], true);
    assert!(source.get("tokenScopes").is_none());
}

#[test]
fn identity_summary_reports_only_strict_issued_agent_token_provenance() {
    for read_only in [false, true] {
        let identity = issued(read_only);
        let summary = serde_json::to_value(identity.summary()).unwrap();
        assert_eq!(summary["brokerToken"], json!({"readOnly": read_only}));
        assert!(summary.get("readOnlyAccess").is_none());
        assert_eq!(identity.has_read_only_agent_access(), read_only);
        let path = attested(read_only);
        assert!(
            serde_json::to_value(path.summary())
                .unwrap()
                .get("brokerToken")
                .is_none()
        );
        assert_eq!(path.has_read_only_agent_access(), read_only);
    }
    for token_class in [BrokerTokenClass::Admin, BrokerTokenClass::UserManage] {
        let mut identity = issued(true);
        identity.source.as_mut().unwrap().token_class = Some(token_class);
        assert!(identity.summary().broker_token.is_none());
        assert!(!identity.has_read_only_agent_access());
    }
    for scopes in [
        json!({"allowedExecutionContexts": ["default"]}),
        json!({"allowedExecutionContexts": ["default"], "readOnly": "true"}),
        json!({"allowedExecutionContexts": ["default"], "readOnly": true, "unknown": true}),
    ] {
        assert!(
            shell_token_identity(scopes)
                .summary()
                .broker_token
                .is_none()
        );
    }
    assert!(agent_one_identity().summary().broker_token.is_none());
    assert!(
        IdentityContext::anonymous()
            .summary()
            .broker_token
            .is_none()
    );
}
