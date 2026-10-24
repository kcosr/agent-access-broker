//! The command authority planner through a published command import whose
//! `project` type the import accepted as `ticketing_project`, registered
//! by runtime publication, so resources and groups of that imported type
//! type, so configured resources and groups exercise every boundary.
use super::*;
use crate::imports::{
    CommandInvocation, CommandVerification, ImportedActionAuthority, ImportedActionResources,
    ImportedAdapter, ImportedCredentialBinding, ImportedCredentialDelivery, ImportedCredentialMode,
    ImportedDiscoveryCredential, ImportedResourceTypeDeclaration, ImportedServiceMetadata,
    imported_adapter_registration,
};
use crate::{
    CommandImportConfig, ImportedActionRecord, ImportedActionStatus, ImportedCatalog,
    ImportedServiceRecord, ImportedServiceStatus, ImportsConfig, PolicyGrantConfig,
};
use agent_access_provider::{
    BuildContext, ExecutionCredential, ProviderBuildError, ProviderCredentialVerification,
    ProviderInvocation, ProviderResult, ScopeRequest, ScopeResolution,
};

const SERVICE: &str = "ticketing";
const PROJECT_TYPE: &str = "ticketing_project";

fn project_type() -> ResourceType {
    ResourceType::new(PROJECT_TYPE).unwrap()
}
const PROBES: [&str; 7] = ["OPS", "ENG", "SEC", "HR", "FIN", "NEWPROJ", "QA"];

/// Reads the declaration the way the command adapter stores it.
fn declared_authority(action: &ImportedActionDefinition) -> ImportedActionAuthority {
    let command = &action.annotations["command"];
    ImportedActionAuthority {
        resources: command
            .get("resources")
            .map(|resources| ImportedActionResources {
                resource_type: resources["type"].as_str().unwrap().to_owned(),
                inputs: resources
                    .get("inputs")
                    .map(|inputs| serde_json::from_value(inputs.clone()).unwrap())
                    .unwrap_or_default(),
            }),
        credential_modes: command
            .get("credentialModes")
            .map(|modes| serde_json::from_value(modes.clone()).unwrap()),
        listing_of: command
            .get("listingOf")
            .and_then(Value::as_str)
            .map(str::to_owned),
    }
}

/// A command adapter double whose provider resolves declared input pointers
/// and admits every dispatched call.
#[derive(Debug)]
struct PlannedCommand;
static PLANNED_COMMAND: PlannedCommand = PlannedCommand;

#[async_trait::async_trait]
impl ImportedAdapter for PlannedCommand {
    fn kind(&self) -> &'static str {
        "command"
    }
    fn development_only(&self) -> bool {
        false
    }
    fn endpoint_form(&self) -> ImportEndpointForm {
        ImportEndpointForm::Command
    }
    fn validate_definition(&self, definition: &ImportedServiceDefinition) -> Result<(), String> {
        definition.validate()
    }
    fn sensitive_output_pointers(&self) -> &'static [&'static str] {
        &["/result/upstreamCommand"]
    }
    fn validate_action(&self, _: &ImportedActionDefinition) -> Result<(), String> {
        Ok(())
    }
    fn action_authority(
        &self,
        action: &ImportedActionDefinition,
    ) -> Result<ImportedActionAuthority, String> {
        if action.annotations["command"] == json!("unreadable") {
            return Err("unreadable declaration".into());
        }
        Ok(declared_authority(action))
    }
    fn scoped_mcp_name(&self, action: &ImportedActionDefinition) -> Result<String, String> {
        Ok(action.action.replace('.', "_"))
    }
    fn build(
        &self,
        _: &ImportedServiceDefinition,
        actions: &[ImportedActionDefinition],
        _: Option<ExecutionCredential>,
        _: &ImportedAdapterContext<'_>,
        _: &BuildContext<'_>,
    ) -> Result<ImportedProvider, ProviderBuildError> {
        Ok(ImportedProvider::Command(Arc::new(PlannedProvider {
            actions: actions
                .iter()
                .map(|action| (action.action.clone(), declared_authority(action)))
                .collect(),
        })))
    }
    async fn discover(
        &self,
        _: &ImportedServiceDefinition,
        _: &crate::imports::ImportedDiscoveryAuthentication,
        _: Option<ExecutionCredential>,
        _: &ImportedAdapterContext<'_>,
        _: &BuildContext<'_>,
    ) -> Result<crate::imports::ImportedDiscovery, crate::imports::AdapterDiscoveryError> {
        unreachable!("planner tests never discover")
    }
}

struct PlannedProvider {
    actions: BTreeMap<String, ImportedActionAuthority>,
}

#[async_trait::async_trait]
impl Provider for PlannedProvider {
    async fn resolve_scopes(
        &self,
        request: ScopeRequest<'_>,
    ) -> Result<ScopeResolution, ProviderError> {
        // Like the adapter, only enabled actions are built.
        let authority = self.actions.get(request.action()).ok_or_else(|| {
            ProviderError::deny(ReasonCode::InputInvalid, "unknown command import action")
        })?;
        Ok(ScopeResolution::resources(
            authority
                .resources
                .iter()
                .filter(|resources| resources.broker_enforced())
                .map(|resources| {
                    (
                        resources.resource_type.clone(),
                        resources
                            .inputs
                            .iter()
                            .flat_map(|pointer| match request.inputs().pointer(pointer) {
                                Some(Value::Array(values)) => values
                                    .iter()
                                    .map(|value| value.as_str().unwrap().to_owned())
                                    .collect(),
                                other => vec![other.unwrap().as_str().unwrap().to_owned()],
                            })
                            .collect(),
                    )
                })
                .collect(),
        ))
    }
    async fn invoke(&self, _: ProviderInvocation) -> Result<ProviderResult, ProviderError> {
        Ok(ProviderResult::new(json!({"dispatched": true})))
    }
}

#[async_trait::async_trait]
impl crate::imports::CommandProvider for PlannedProvider {
    async fn invoke_command(&self, _: CommandInvocation) -> Result<ProviderResult, ProviderError> {
        unreachable!("planner tests dispatch through the provider")
    }
    async fn verify_command(
        &self,
        _: CommandVerification,
    ) -> Result<ProviderCredentialVerification, ProviderError> {
        unreachable!("planner tests never verify")
    }
}

fn registry() -> Arc<crate::BackendRegistry> {
    Arc::new(
        crate::BackendRegistry::new([
            &agent_access_jira::JIRA_BACKEND,
            &agent_access_confluence::CONFLUENCE_BACKEND,
            &agent_access_gitlab::GITLAB_BACKEND,
            &agent_access_cloudbees_ci::CLOUDBEES_CI_BACKEND,
            &agent_access_fake::FAKE_BACKEND,
            &agent_access_fake::OAUTH_STUB_BACKEND,
        ])
        .unwrap()
        .with_oauth_dialects([&agent_access_fake::STUB_OAUTH_DIALECT])
        .unwrap()
        .with_imported_adapters([imported_adapter_registration(
            agent_access_provider::module_metadata!(),
            &PLANNED_COMMAND,
            None,
        )])
        .unwrap(),
    )
}

fn project(
    id: &str,
    selector: ResourceSelector,
    contexts: &[&str],
    enabled: bool,
) -> ResourceDefinition {
    ResourceDefinition {
        id: id.into(),
        display_name: None,
        resource_type: project_type(),
        selector,
        allowed_execution_contexts: contexts.iter().map(|context| (*context).into()).collect(),
        enabled,
    }
}

fn exact(value: &str) -> ResourceSelector {
    ResourceSelector::Exact {
        value: value.into(),
    }
}

/// The base configuration; the imported type's resources join the policy
/// once the import publishes its type.
fn config() -> BrokerConfig {
    let mut config = crate::runtime::tests::base_fake_config();
    config.providers = crate::ProvidersConfig::new(registry())
        .with(agent_access_fake::FakeProviderConfig::default());
    config.execution_context = Some(crate::ExecutionContextConfig {
        allowed_values: vec!["default".into(), "external".into()],
        default_context: None,
    });
    config.policy.resources = Vec::new();
    config.policy.resource_groups = Vec::new();
    config.policy.grants = Vec::new();
    config
}

/// The resources of the imported type: `wide` covers every project except a
/// security project, a disabled one and one eligible only in another
/// execution context.
fn project_resources(config: &mut BrokerConfig) {
    config.policy.resources = vec![
        project("p-ops", exact("OPS"), &["default"], true),
        project("p-eng", exact("ENG"), &["default"], true),
        project("p-sec", exact("SEC"), &["default"], true),
        project("p-hr", exact("HR"), &["default"], false),
        project("p-fin", exact("FIN"), &["external"], true),
        project(
            "p-all",
            ResourceSelector::All,
            &["default", "external"],
            true,
        ),
    ];
    config.policy.resource_groups = vec![crate::ResourceGroupDefinition {
        id: "wide".into(),
        name: "Wide".into(),
        included_resource_ids: vec!["p-all".into()],
        excluded_resource_ids: vec!["p-sec".into(), "p-hr".into(), "p-fin".into()],
    }];
}

fn action(name: &str, command: Value) -> ImportedActionRecord {
    ImportedActionRecord {
        definition: ImportedActionDefinition {
            download: false,
            action: name.into(),
            source: json!({"name": name}),
            label: None,
            description: format!("{name} action."),
            input_schema: json!({"type": "object",
                "properties": {"project": {"type": "string"}, "query": {"type": "string"},
                    "projects": {"type": "array", "items": {"type": "string"}}}}),
            output_schema: None,
            annotations: json!({"command": command}),
            read_only: true,
        },
        status: ImportedActionStatus::Enabled,
        version: 1,
        definition_hash: String::new(),
    }
}

fn actions() -> Vec<ImportedActionRecord> {
    vec![
        action(
            "issue.view",
            json!({"resources": {"type": "project", "inputs": ["/project"]}}),
        ),
        action("issue.search", json!({"resources": {"type": "project"}})),
        action("issue.stats", json!({})),
        action(
            "issue.bulk",
            json!({"resources": {"type": "project", "inputs": ["/projects"]}}),
        ),
        // Actions a refresh narrowed to service mode.
        action(
            "issue.svc_search",
            json!({"resources": {"type": "project"}, "credentialModes": ["service"]}),
        ),
        action(
            "issue.svc_view",
            json!({"resources": {"type": "project", "inputs": ["/project"]},
                "credentialModes": ["service"]}),
        ),
    ]
}

/// A credential-free command import with the given bindings and actions.
fn record(
    modes: &[ImportedCredentialMode],
    actions: Vec<ImportedActionRecord>,
) -> ImportedServiceRecord {
    ImportedServiceRecord {
        definition: ImportedServiceDefinition {
            service: SERVICE.into(),
            display_name: "Ticketing".into(),
            adapter_kind: "command".into(),
            endpoint: format!("command:{SERVICE}"),
            connection_settings: BTreeMap::new(),
            execution_bindings: modes
                .iter()
                .map(|mode| {
                    ImportedCredentialBinding::token(*mode, ImportedCredentialDelivery::Stdin)
                })
                .collect(),
            discovery: ImportedDiscoveryCredential::Anonymous,
            transport_auth: false,
            invocation_limit: None,
        },
        status: ImportedServiceStatus::Enabled,
        version: 1,
        actions,
        slot_versions: BTreeMap::new(),
        accepted_metadata: Some(ImportedServiceMetadata {
            format: "agent-access-command/1".into(),
            version: "1.0.0".into(),
            credential: (!modes.is_empty()).then(|| {
                crate::imports::ImportedCredentialDeclaration {
                    kind: crate::imports::ImportedCredentialKind::Token,
                    modes: modes.to_vec(),
                }
            }),
            verify: false,
            resource_types: vec![ImportedResourceTypeDeclaration {
                id: "project".into(),
                broker_type: PROJECT_TYPE.into(),
                removed: false,
                supports_exclusions: true,
                label: "Project".into(),
                plural_label: "Projects".into(),
                pattern: "[A-Z][A-Z0-9]{1,9}".into(),
                max_length: 10,
                example: "OPS".into(),
                attributes: Vec::new(),
            }],
        }),
        created_at: String::new(),
        created_by: String::new(),
        updated_at: String::new(),
        updated_by: String::new(),
    }
}

/// The registry a generation publishing `record` holds.
fn published_types(record: &ImportedServiceRecord) -> ResourceTypeRegistry {
    EffectiveResourceTypes::composition(&registry())
        .with_imported(
            &ImportedCatalog {
                revision: 1,
                services: vec![record.clone()],
            },
            None,
        )
        .unwrap()
        .registry()
        .clone()
}

#[test]
fn imported_listing_metadata_maps_the_accepted_type_id_and_preserves_unscoped_actions() {
    let mut record = record(
        &[],
        vec![
            action(
                "projects.enumerate",
                json!({"resources": {"type": "project"}, "listingOf": "project"}),
            ),
            action("whoami", json!({})),
        ],
    );
    let broker_type = ResourceType::new("accepted_projects").unwrap();
    record.accepted_metadata.as_mut().unwrap().resource_types[0].broker_type =
        broker_type.as_str().into();
    let types = published_types(&record);
    let descriptor = imports::descriptor(&record, &config(), &types);
    descriptor.validate().unwrap();
    assert!(descriptor.validate_resource_types(&types).is_empty());
    assert_eq!(
        descriptor.actions[0].listing_of.as_ref(),
        Some(&broker_type)
    );
    assert_eq!(
        descriptor
            .action_resource_scope("projects.enumerate")
            .unwrap()
            .1
            .resource_type,
        broker_type
    );
    assert!(descriptor.actions[1].listing_of.is_none());
    assert!(descriptor.actions[1].resource_scope.is_none());
}

fn import_config() -> BrokerConfig {
    let mut config = config();
    project_resources(&mut config);
    config.imports = ImportsConfig {
        enabled: true,
        allowed_kinds: vec!["command".into()],
        ..ImportsConfig::default()
    };
    config.command_imports.insert(
        SERVICE.into(),
        CommandImportConfig {
            max_download_bytes: None,
            path: "/usr/bin/true".into(),
            timeout: "10s".into(),
            max_output_bytes: 1024,
            max_concurrent: 1,
            working_dir: "/".into(),
            network: Default::default(),
            log_stderr: false,
            env: BTreeMap::new(),
        },
    );
    config
}

/// Publishes the import through runtime publication, then installs
/// `grants`. Without `per_user` the import is credential-free: service mode
/// only. With `per_user` it binds both modes and holds a service slot, and
/// the test marks its credentials present without a managed store, as a
/// credential-free import's are, so both modes are available to the planner
/// while each action's modes come from the real mapping.
fn runtime(grants: Vec<PolicyGrantConfig>, per_user: bool) -> BrokerRuntime {
    let base = BrokerRuntime::new(config()).unwrap();
    let mut config = import_config();
    let mut base = base.clone();
    base.config = Arc::new(config.clone());
    let record = if per_user {
        let mut record = record(
            &[
                ImportedCredentialMode::Service,
                ImportedCredentialMode::PerUser,
            ],
            actions(),
        );
        record.slot_versions.insert(
            crate::imports::ImportedCredentialPurpose::Execution,
            "fixture".into(),
        );
        record
    } else {
        record(&[], actions())
    };
    let prepared = base.prepare_imported_service_change(&record, None).unwrap();
    let mut runtime = base
        .with_imported_catalog(
            ImportedCatalog {
                revision: 1,
                services: vec![record],
            },
            prepared,
        )
        .unwrap();
    if per_user {
        credentials_present(&mut runtime);
    }
    config.policy.grants = grants;
    runtime
        .policy_snapshot
        .store(Arc::new(PolicySnapshot::from_config(&config, 2)));
    runtime
}

fn grant(
    subject: &str,
    action: &str,
    mode: &str,
    priority: i32,
    ids: &[&str],
    groups: &[&str],
) -> PolicyGrantConfig {
    PolicyGrantConfig {
        subjects: vec![subject.into()],
        service: SERVICE.into(),
        actions: vec![action.into()],
        resources: ResourceSelection {
            resource_ids: ids.iter().map(|id| (*id).into()).collect(),
            resource_group_ids: groups.iter().map(|id| (*id).into()).collect(),
        },
        execution_contexts: None,
        credential_mode: mode.into(),
        priority: Some(priority),
    }
}

/// A managed user, whose kind selects the import's personal token.
fn identity(token_scopes: Option<Value>) -> IdentityContext {
    IdentityContext {
        caller_id: None,
        principal: "avery".into(),
        principal_kind: Some(crate::PrincipalKind::User),
        principal_subject: Some("avery".into()),
        groups: vec!["engineering".into(), "support".into()],
        policy_groups: vec!["engineering".into(), "support".into()],
        authenticated: true,
        source: token_scopes.map(|scopes| IdentitySourceAudit {
            read_only_access: None,
            namespace: None,
            binding_id: None,
            name: "broker".into(),
            kind: "broker_tokens".into(),
            token_header: "Authorization".into(),
            token_scheme: "Bearer".into(),
            token_class: Some(BrokerTokenClass::AgentInvoke),
            token_id: Some("tok_agent".into()),
            token_scopes: Some(scopes),
        }),
    }
}

fn token(actions: &[&str], resource_ids: &[&str]) -> Value {
    json!({"allowedServices": [SERVICE], "allowedExecutionContexts": ["default"],
        "serviceRestrictions": {SERVICE: {"actions": actions,
            "resources": {"resourceIds": resource_ids}}}})
}

fn context() -> ExecutionContext {
    ExecutionContext::new("default").unwrap()
}

async fn prepare(
    runtime: &BrokerRuntime,
    identity: &IdentityContext,
    action: &str,
    inputs: Value,
) -> Result<PreparedInvocation, ProviderError> {
    runtime
        .prepare_invoke(
            GovernedOperationContext {
                operation: OperationContext {
                    agent_request_id: "agent-request".into(),
                    broker_request_id: "broker-request".into(),
                    identity: identity.clone(),
                    service: SERVICE.into(),
                    action: action.into(),
                    source: SourceContext::unknown(),
                },
                execution_context: context(),
            },
            InvokeRequest::new(inputs),
        )
        .await
        .map_err(|failure| failure.result.unwrap_err())
}

/// The command-enforced grants an admitted call passes.
fn passed(prepared: &PreparedInvocation) -> Vec<(String, CommandSearchScope, Option<i32>)> {
    match prepared.command_authorization().unwrap() {
        CommandAuthorization::Command { grants, .. } => grants
            .iter()
            .map(|grant| {
                (
                    grant.credential_mode.clone(),
                    grant.scope.clone(),
                    grant.grant.priority,
                )
            })
            .collect(),
        other => panic!("expected a command-enforced plan, got {other:?}"),
    }
}

fn finite(values: &[&str]) -> CommandSearchScope {
    CommandSearchScope::Finite {
        values: values.iter().map(|value| (*value).into()).collect(),
    }
}

fn all_except(values: &[&str]) -> CommandSearchScope {
    CommandSearchScope::AllExcept {
        excluded_values: values.iter().map(|value| (*value).into()).collect(),
    }
}

/// The values caller discovery reports for `action`: its catalog presence
/// and, for a typed action, the probes its effective clauses reach.
fn discovered(
    runtime: &BrokerRuntime,
    identity: &IdentityContext,
    action: &str,
) -> Option<BTreeSet<&'static str>> {
    let snapshot = runtime.policy_snapshot();
    let service = runtime
        .available_service_descriptors(identity, &context(), &snapshot, Some(SERVICE))
        .into_iter()
        .next()?;
    service.descriptor.action(action)?;
    let clauses = service.clauses.get(action).cloned().unwrap_or_default();
    Some(
        PROBES
            .into_iter()
            .filter(|probe| clauses.iter().any(|clause| clause.matches(probe)))
            .collect(),
    )
}

/// The probes an admitted plan reaches through any passed grant.
fn reached(prepared: &PreparedInvocation) -> BTreeSet<&'static str> {
    let grants = passed(prepared);
    PROBES
        .into_iter()
        .filter(|probe| {
            grants
                .iter()
                .any(|(_, scope, _)| scope.authority().matches(probe))
        })
        .collect()
}

#[test]
fn descriptors_map_declarations_to_scopes_who_checks_them_and_action_modes() {
    let config = import_config();
    let mut declared = actions();
    declared.push(action(
        "issue.personal",
        json!({"resources": {"type": "project"}, "credentialModes": ["per_user"]}),
    ));
    declared.push(action(
        "issue.orphan",
        json!({"resources": {"type": "retired", "inputs": ["/project"]}}),
    ));
    declared.push(action("issue.corrupt", json!("unreadable")));
    let modes = [
        ImportedCredentialMode::Service,
        ImportedCredentialMode::PerUser,
    ];
    let declaring = record(&modes, declared);
    let descriptor =
        crate::runtime::imports::descriptor(&declaring, &config, &published_types(&declaring));
    descriptor.validate().unwrap();
    for action in &descriptor.actions {
        assert!(!action.reports_universal_reach);
        assert!(matches!(
            action.scoped_mcp_name_source,
            ScopedMcpNameSource::Imported { .. }
        ));
    }
    // Both Broker-enforced and command-enforced import descriptors refuse
    // a forged native opt-in, rather than exposing a disclosure proof.
    for name in ["issue.view", "issue.search"] {
        let mut forged = descriptor.clone();
        let action = forged
            .actions
            .iter_mut()
            .find(|action| action.action == name)
            .unwrap();
        action.read_only = true;
        action.reports_universal_reach = true;
        assert!(
            forged
                .validate()
                .unwrap_err()
                .iter()
                .any(|error| error.contains("universal reach requires"))
        );
    }
    let view = descriptor.action("issue.view").unwrap();
    assert_eq!(view.resource_scope.as_deref(), Some("project"));
    assert!(
        view.native_search.is_none(),
        "inputs mean the Broker checks them"
    );
    assert!(!view.requires_resource_attributes);
    let search = descriptor.action("issue.search").unwrap();
    assert_eq!(search.resource_scope.as_deref(), Some("project"));
    assert!(
        search.native_search.is_none(),
        "command enforcement never enables native search"
    );
    let stats = descriptor.action("issue.stats").unwrap();
    assert!(stats.resource_scope.is_none() && stats.native_search.is_none());
    assert_eq!(stats.credential_modes, ["service", "per_user"]);
    assert_eq!(
        descriptor
            .action("issue.personal")
            .unwrap()
            .credential_modes,
        ["per_user"]
    );
    assert_eq!(
        descriptor.resource_scopes["project"],
        ResourceScopeCapabilities::new(project_type(), vec!["exact".into(), "all".into()])
    );
    // A type the import did not accept, or a declaration that cannot be
    // read, binds the unresolved type and authorizes nothing.
    assert_eq!(
        descriptor.resource_scopes["retired"].resource_type,
        *UNRESOLVED_RESOURCE_TYPE.id()
    );
    let corrupt = descriptor.action("issue.corrupt").unwrap();
    // The unresolved scope is command-enforced, so retained grants mixing
    // modes stay valid; it never reaches a resource.
    assert!(corrupt.native_search.is_none());
    assert_eq!(
        descriptor.resource_scopes[corrupt.resource_scope.as_deref().unwrap()].resource_type,
        *UNRESOLVED_RESOURCE_TYPE.id()
    );
    let imported = ImportedCatalog {
        revision: 1,
        services: vec![declaring],
    };
    let services = BTreeMap::from([(SERVICE.into(), Arc::new(descriptor))]);
    for (name, command_enforced) in [
        ("issue.search", true),
        ("issue.corrupt", true),
        ("issue.view", false),
        ("issue.orphan", false),
    ] {
        assert_eq!(
            command_enforced_action(&config, &imported, &services, SERVICE, name),
            command_enforced,
            "{name}"
        );
    }
    // Without the command adapter the import is unavailable, and every
    // action binds the unresolved type.
    let unlinked_record = record(&modes, actions());
    let unlinked_config = crate::runtime::tests::base_fake_config();
    let unlinked = crate::runtime::imports::descriptor(
        &unlinked_record,
        &unlinked_config,
        &published_types(&unlinked_record),
    );
    let unlinked_imported = ImportedCatalog {
        revision: 1,
        services: vec![unlinked_record],
    };
    let unlinked_services = BTreeMap::from([(SERVICE.into(), Arc::new(unlinked))]);
    let unlinked = &unlinked_services[SERVICE];
    for action in &unlinked.actions {
        assert!(action.native_search.is_none());
        assert!(!action.reports_universal_reach);
        assert_eq!(
            unlinked.resource_scopes[action.resource_scope.as_deref().unwrap()].resource_type,
            *UNRESOLVED_RESOURCE_TYPE.id()
        );
        assert!(
            command_enforced_action(
                &unlinked_config,
                &unlinked_imported,
                &unlinked_services,
                SERVICE,
                &action.action,
            ),
            "{}",
            action.action
        );
    }
    // A credential-free import's actions use service mode.
    let free_record = record(&[], actions());
    let free =
        crate::runtime::imports::descriptor(&free_record, &config, &published_types(&free_record));
    assert_eq!(
        free.action("issue.search").unwrap().credential_modes,
        ["service"]
    );
    assert!(!free.credentials.execution_required);
}

#[tokio::test]
async fn unreadable_command_authority_retains_mixed_mode_grants_without_admitting_resources() {
    let mut declared = actions();
    declared.push(action("issue.corrupt", json!("unreadable")));
    let mut runtime = publish_retained(
        declared,
        ["per_user", "service"]
            .into_iter()
            .map(|mode| {
                grant(
                    "group:engineering",
                    "issue.corrupt",
                    mode,
                    10,
                    &["p-ops"],
                    &[],
                )
            })
            .collect(),
    )
    .expect("an unreadable command declaration must preserve retained mixed-mode grants");
    assert_eq!(
        runtime.resources_checked_by(SERVICE, "issue.corrupt"),
        Some(ResourcesCheckedBy::Command)
    );
    credentials_present(&mut runtime);
    let caller = identity(None);
    assert_eq!(
        prepare(&runtime, &caller, "issue.corrupt", json!({}))
            .await
            .err()
            .unwrap()
            .reason_code(),
        ReasonCode::ServiceActionDenied
    );
    assert_eq!(discovered(&runtime, &caller, "issue.corrupt"), None);
}

#[tokio::test]
async fn command_enforced_calls_pass_the_top_band_with_per_grant_credentials_and_exceptions() {
    let grants = vec![
        grant(
            "group:engineering",
            "issue.search",
            "per_user",
            10,
            &[],
            &["wide"],
        ),
        grant(
            "group:support",
            "issue.search",
            "service",
            10,
            &["p-ops"],
            &[],
        ),
        grant(
            "group:engineering",
            "issue.search",
            "service",
            0,
            &["p-all"],
            &[],
        ),
    ];
    let runtime = runtime(grants, true);
    let caller = identity(None);
    let prepared = prepare(&runtime, &caller, "issue.search", json!({"query": "open"}))
        .await
        .unwrap();
    // Exclusions apply even to disabled and context-ineligible entries, and
    // the lower band's broader grant is never passed.
    assert_eq!(
        passed(&prepared),
        [
            (
                "per_user".into(),
                all_except(&["FIN", "HR", "SEC"]),
                Some(10)
            ),
            ("service".into(), finite(&["OPS"]), Some(10)),
        ]
    );
    let plan = prepared.command_authorization().unwrap();
    assert_eq!(
        plan.credential_modes(),
        BTreeSet::from(["per_user", "service"])
    );
    assert_eq!(plan.credential_mode(), None);
    let CommandAuthorization::Command { resource_type, .. } = plan else {
        unreachable!()
    };
    assert_eq!(
        resource_type.as_ref().unwrap(),
        &CommandResourceType {
            id: "project".into(),
            broker_type: project_type(),
        }
    );
    // Mixed modes report no single audit credential mode, and the provider
    // receives the union boundary with no credential resolved at admission.
    assert_eq!(prepared.finalize_context.credential_mode, None);
    assert_eq!(
        prepared.finalize_context.resource_scopes,
        BTreeMap::from([("project".to_owned(), vec!["*".to_owned()])])
    );
    assert!(prepared.request.execution().is_none());
    assert_eq!(
        prepared.request.authority().search().unwrap().scope,
        all_except(&["FIN", "HR", "SEC"]).authority()
    );
    // Audit records grants, modes and boundaries, never attributes.
    let audit = serde_json::to_value(plan).unwrap();
    assert_eq!(audit["mode"], "command");
    assert_eq!(audit["resourceType"]["id"], "project");
    assert_eq!(audit["grants"][0]["credentialMode"], "per_user");
    assert_eq!(
        audit["grants"][0]["scope"],
        json!({"type": "all_except", "excludedValues": ["FIN", "HR", "SEC"]})
    );
    assert_eq!(audit["grants"][1]["grant"]["subject"], "group:support");
    // Catalog, MCP and resource discovery reach exactly what invocation passes.
    assert_eq!(
        discovered(&runtime, &caller, "issue.search"),
        Some(reached(&prepared))
    );
    let listed = runtime
        .service_discovery(&caller, &context(), SERVICE)
        .unwrap()
        .resource_access(&ResourceAccessQuery::default())
        .unwrap();
    assert_eq!(
        listed
            .registered_resources
            .items
            .iter()
            .map(|resource| resource.value.as_str())
            .collect::<BTreeSet<_>>(),
        BTreeSet::from(["ENG", "OPS"]),
        "excluded, disabled and ineligible entries are not listed"
    );
    let access = listed
        .access
        .iter()
        .find(|access| access.action() == "issue.search")
        .unwrap();
    assert_eq!(
        serde_json::to_value(access).unwrap()["enforcement"],
        "command"
    );
    assert!(matches!(
        access,
        ActionResourceAccess::Resource {
            enforcement: ResourceAccessEnforcement::Command,
            ..
        }
    ));
    let coverage = access.coverage().unwrap();
    assert_eq!(coverage.len(), 2);
    assert!(
        coverage
            .iter()
            .any(|entry| entry.selector == ResourceSelector::All && entry.restricted)
    );
    assert!(
        coverage
            .iter()
            .any(|entry| entry.selector == exact("OPS") && !entry.restricted)
    );
}

#[tokio::test]
async fn unavailable_credentials_are_omitted_without_a_lower_band_fallback() {
    // Personal mode is not configured for this credential-free import.
    let mixed = runtime(
        vec![
            grant(
                "group:engineering",
                "issue.search",
                "per_user",
                10,
                &[],
                &["wide"],
            ),
            grant(
                "group:support",
                "issue.search",
                "service",
                10,
                &["p-ops"],
                &[],
            ),
            grant(
                "group:engineering",
                "issue.search",
                "service",
                0,
                &["p-all"],
                &[],
            ),
        ],
        false,
    );
    let caller = identity(None);
    let prepared = prepare(&mixed, &caller, "issue.search", json!({}))
        .await
        .unwrap();
    assert_eq!(
        passed(&prepared),
        [("service".into(), finite(&["OPS"]), Some(10))]
    );
    assert_eq!(
        prepared.finalize_context.credential_mode.as_deref(),
        Some("service")
    );
    assert_eq!(
        discovered(&mixed, &caller, "issue.search"),
        Some(reached(&prepared))
    );

    let personal_only = runtime(
        vec![
            grant(
                "group:engineering",
                "issue.search",
                "per_user",
                10,
                &[],
                &["wide"],
            ),
            grant(
                "group:engineering",
                "issue.search",
                "service",
                0,
                &["p-all"],
                &[],
            ),
        ],
        false,
    );
    let denied = prepare(&personal_only, &caller, "issue.search", json!({}))
        .await
        .err()
        .unwrap();
    assert_eq!(denied.reason_code(), ReasonCode::CredentialNotProvisioned);
    assert_eq!(discovered(&personal_only, &caller, "issue.search"), None);

    // A selection that resolves to nothing is no candidate, as for native
    // search, so it never hides a lower grant. A token that empties the top
    // band denies the call; the lower band is still never consulted.
    let banded = runtime(
        vec![
            grant(
                "group:engineering",
                "issue.search",
                "service",
                20,
                &["p-hr"],
                &[],
            ),
            grant(
                "group:engineering",
                "issue.search",
                "service",
                10,
                &["p-ops"],
                &[],
            ),
            grant(
                "group:engineering",
                "issue.search",
                "service",
                0,
                &["p-eng"],
                &[],
            ),
        ],
        false,
    );
    let prepared = prepare(&banded, &caller, "issue.search", json!({}))
        .await
        .unwrap();
    assert_eq!(
        passed(&prepared),
        [("service".into(), finite(&["OPS"]), Some(10))]
    );
    let eng_only = identity(Some(token(&["issue.search"], &["p-eng"])));
    let denied = prepare(&banded, &eng_only, "issue.search", json!({}))
        .await
        .err()
        .unwrap();
    assert_eq!(denied.reason_code(), ReasonCode::ServiceActionDenied);
    assert!(denied.audit.is_some(), "the token caused the denial");
    assert_eq!(discovered(&banded, &eng_only, "issue.search"), None);
}

/// The credential modes a scope-free call passes.
fn passed_modes(prepared: &PreparedInvocation) -> BTreeSet<String> {
    passed(prepared)
        .into_iter()
        .map(|(mode, _, _)| mode)
        .collect()
}

#[tokio::test]
async fn a_mixed_band_omits_only_the_mode_whose_credential_is_unavailable() {
    let grants = vec![
        grant(
            "group:engineering",
            "issue.search",
            "per_user",
            10,
            &[],
            &["wide"],
        ),
        grant(
            "group:support",
            "issue.search",
            "service",
            10,
            &["p-ops"],
            &[],
        ),
        grant("group:engineering", "issue.stats", "per_user", 10, &[], &[]),
        grant("group:support", "issue.stats", "service", 10, &[], &[]),
    ];
    let user = identity(None);
    // Without a managed kind the import's connection selects no method.
    let unselected = IdentityContext {
        principal_kind: None,
        ..identity(None)
    };
    let both = runtime(grants.clone(), true);

    // A user selects the connection's token: the whole band passes, for a
    // scoped and a scope-free action.
    let prepared = prepare(&both, &user, "issue.search", json!({}))
        .await
        .unwrap();
    assert_eq!(
        passed(&prepared),
        [
            (
                "per_user".into(),
                all_except(&["FIN", "HR", "SEC"]),
                Some(10)
            ),
            ("service".into(), finite(&["OPS"]), Some(10)),
        ]
    );
    assert_eq!(
        discovered(&both, &user, "issue.search"),
        Some(reached(&prepared))
    );
    let prepared = prepare(&both, &user, "issue.stats", json!({}))
        .await
        .unwrap();
    assert_eq!(
        passed_modes(&prepared),
        BTreeSet::from(["per_user".to_owned(), "service".to_owned()])
    );

    // The unselected personal method omits only the per_user grants; the
    // service grants still pass, and nothing falls back to another method.
    let prepared = prepare(&both, &unselected, "issue.search", json!({}))
        .await
        .unwrap();
    assert_eq!(
        passed(&prepared),
        [("service".into(), finite(&["OPS"]), Some(10))]
    );
    assert_eq!(
        discovered(&both, &unselected, "issue.search"),
        Some(reached(&prepared))
    );
    let prepared = prepare(&both, &unselected, "issue.stats", json!({}))
        .await
        .unwrap();
    assert_eq!(
        passed_modes(&prepared),
        BTreeSet::from(["service".to_owned()])
    );
    assert!(discovered(&both, &unselected, "issue.stats").is_some());

    // With neither credential nothing passes; the planner never falls back
    // to a lower band. (Hosts test the converse, a service slot missing
    // while personal grants pass, against stored credentials.)
    let personal_only = runtime(
        vec![grant(
            "group:engineering",
            "issue.stats",
            "per_user",
            10,
            &[],
            &[],
        )],
        true,
    );
    let denied = prepare(&personal_only, &unselected, "issue.stats", json!({}))
        .await
        .err()
        .unwrap();
    assert_eq!(denied.reason_code(), ReasonCode::CredentialNotProvisioned);
    assert_eq!(discovered(&personal_only, &unselected, "issue.stats"), None);
}

/// Gives the import's connection an OAuth method and, with `token_only`,
/// marks every action token-only. Neither is reachable through an import:
/// imported descriptors never carry the marker and command imports never
/// offer OAuth. They show the planner applies the rule anyway.
fn select_oauth(runtime: &mut BrokerRuntime, token_only: bool) {
    let mut credentials = (*runtime.effective_credentials).clone();
    credentials.connections.get_mut(SERVICE).unwrap().oauth = Some(crate::ConnectionOAuthConfig {
        registration: "stub".into(),
        profile: "read".into(),
    });
    runtime.effective_credentials = Arc::new(credentials);
    let mut services = (*runtime.services).clone();
    let mut descriptor = (*services[SERVICE]).clone();
    for action in &mut descriptor.actions {
        action.token_only = token_only;
    }
    services.insert(SERVICE.into(), Arc::new(descriptor));
    runtime.services = Arc::new(services);
}

/// A token-only command-enforced action drops only the per-user grants
/// whose connection selects OAuth, through the same mode check that drops a
/// mode the action does not support; the band's service grants still pass,
/// and nothing falls back to a lower band.
#[tokio::test]
async fn token_only_command_actions_omit_only_personal_oauth_grants() {
    let grants = vec![
        grant(
            "group:engineering",
            "issue.search",
            "per_user",
            10,
            &[],
            &["wide"],
        ),
        grant(
            "group:support",
            "issue.search",
            "service",
            10,
            &["p-ops"],
            &[],
        ),
        grant(
            "group:engineering",
            "issue.search",
            "service",
            0,
            &["p-all"],
            &[],
        ),
        grant("group:engineering", "issue.stats", "per_user", 10, &[], &[]),
        grant("group:support", "issue.stats", "service", 10, &[], &[]),
    ];
    let user = identity(None);
    let mut oauth = runtime(grants.clone(), true);
    assert!(
        oauth.services[SERVICE]
            .actions
            .iter()
            .all(|action| !action.token_only),
        "imported descriptors never carry the token-only marker"
    );
    // An OAuth selection alone omits nothing.
    select_oauth(&mut oauth, false);
    let prepared = prepare(&oauth, &user, "issue.search", json!({}))
        .await
        .unwrap();
    assert_eq!(
        passed_modes(&prepared),
        BTreeSet::from(["per_user".to_owned(), "service".to_owned()])
    );

    let mut token_only = runtime(grants.clone(), true);
    select_oauth(&mut token_only, true);
    let prepared = prepare(&token_only, &user, "issue.search", json!({}))
        .await
        .unwrap();
    assert_eq!(
        passed(&prepared),
        [("service".into(), finite(&["OPS"]), Some(10))]
    );
    assert_eq!(
        discovered(&token_only, &user, "issue.search"),
        Some(reached(&prepared))
    );
    let prepared = prepare(&token_only, &user, "issue.stats", json!({}))
        .await
        .unwrap();
    assert_eq!(
        passed_modes(&prepared),
        BTreeSet::from(["service".to_owned()])
    );
    assert!(discovered(&token_only, &user, "issue.stats").is_some());

    // A principal whose connection selects the stored token keeps the
    // per-user grants.
    let service_account = IdentityContext {
        principal_kind: Some(crate::PrincipalKind::ServiceAccount),
        ..identity(None)
    };
    let prepared = prepare(&token_only, &service_account, "issue.search", json!({}))
        .await
        .unwrap();
    assert_eq!(
        passed_modes(&prepared),
        BTreeSet::from(["per_user".to_owned(), "service".to_owned()])
    );

    // With only per-user grants in the top band, nothing passes; the lower
    // service grant is never consulted.
    let mut personal_only = runtime(
        vec![
            grant(
                "group:engineering",
                "issue.search",
                "per_user",
                10,
                &[],
                &["wide"],
            ),
            grant(
                "group:engineering",
                "issue.search",
                "service",
                0,
                &["p-all"],
                &[],
            ),
        ],
        true,
    );
    select_oauth(&mut personal_only, true);
    let denied = prepare(&personal_only, &user, "issue.search", json!({}))
        .await
        .err()
        .unwrap();
    assert_eq!(denied.reason_code(), ReasonCode::CredentialNotProvisioned);
    assert_eq!(discovered(&personal_only, &user, "issue.search"), None);
}

#[tokio::test]
async fn agent_token_restrictions_intersect_every_passed_grant() {
    let runtime = runtime(
        vec![
            grant(
                "group:engineering",
                "issue.search",
                "per_user",
                10,
                &[],
                &["wide"],
            ),
            grant(
                "group:support",
                "issue.search",
                "service",
                10,
                &["p-ops"],
                &[],
            ),
        ],
        true,
    );
    let narrowed = identity(Some(token(&["issue.search"], &["p-eng", "p-sec"])));
    let prepared = prepare(&runtime, &narrowed, "issue.search", json!({}))
        .await
        .unwrap();
    // The token's ENG and SEC meet the personal grant's exceptions; the
    // service grant's OPS lies outside the token, so it is not passed.
    assert_eq!(
        passed(&prepared),
        [("per_user".into(), finite(&["ENG"]), Some(10))]
    );
    assert_eq!(
        discovered(&runtime, &narrowed, "issue.search"),
        Some(reached(&prepared))
    );
    let preview = runtime
        .preview_agent_token_access(
            &identity(None),
            &crate::AgentInvokeTokenCaveats::parse_stored(&token(
                &["issue.search"],
                &["p-eng", "p-sec"],
            ))
            .unwrap(),
        )
        .unwrap();
    let entry = preview
        .access
        .iter()
        .find(|entry| entry.action == "issue.search" && entry.execution_context == context())
        .unwrap();
    assert!(entry.clauses.iter().any(|clause| clause.matches("ENG")));
    assert!(
        !entry
            .clauses
            .iter()
            .any(|clause| clause.matches("SEC") || clause.matches("OPS"))
    );

    let outside = identity(Some(token(&["issue.search"], &["p-sec"])));
    let denied = prepare(&runtime, &outside, "issue.search", json!({}))
        .await
        .err()
        .unwrap();
    assert_eq!(denied.reason_code(), ReasonCode::ServiceActionDenied);
    assert_eq!(
        denied.audit.as_deref().unwrap()["brokerToken"]["tokenId"],
        "tok_agent"
    );
    assert_eq!(discovered(&runtime, &outside, "issue.search"), None);
}

#[tokio::test]
async fn untyped_command_actions_pass_action_grants_reaching_any_value() {
    let runtime = runtime(
        vec![
            grant("group:engineering", "issue.stats", "per_user", 0, &[], &[]),
            grant("group:support", "issue.stats", "service", 0, &[], &[]),
        ],
        true,
    );
    let caller = identity(None);
    let prepared = prepare(&runtime, &caller, "issue.stats", json!({}))
        .await
        .unwrap();
    assert_eq!(
        passed(&prepared),
        [
            ("per_user".into(), all_except(&[]), Some(0)),
            ("service".into(), all_except(&[]), Some(0)),
        ]
    );
    let CommandAuthorization::Command { resource_type, .. } =
        prepared.command_authorization().unwrap()
    else {
        unreachable!()
    };
    assert!(resource_type.is_none());
    assert!(prepared.finalize_context.resource_scopes.is_empty());
    assert!(prepared.request.authority().resources().is_none());
    assert!(
        serde_json::to_value(prepared.command_authorization().unwrap())
            .unwrap()
            .get("resourceType")
            .is_none()
    );
    // Both modes are usable, so discovery lists the action with no
    // requirement, as native single-mode selection would refuse.
    let snapshot = runtime.policy_snapshot();
    let available = runtime
        .available_service_descriptors(&caller, &context(), &snapshot, Some(SERVICE))
        .into_iter()
        .next()
        .unwrap();
    assert!(available.descriptor.action("issue.stats").is_some());
    assert_eq!(available.availability.state, AvailabilityState::Available);
    assert!(
        runtime
            .agent_token_options_for_identity(&caller)
            .services
            .iter()
            .any(|service| service
                .actions
                .iter()
                .any(|action| action.action == "issue.stats"))
    );

    // A token resource restriction cannot apply to an untyped action.
    let restricted = identity(Some(token(&["issue.stats"], &["p-ops"])));
    let denied = prepare(&runtime, &restricted, "issue.stats", json!({}))
        .await
        .err()
        .unwrap();
    assert_eq!(denied.reason_code(), ReasonCode::ServiceActionDenied);
    assert_eq!(discovered(&runtime, &restricted, "issue.stats"), None);
}

#[tokio::test]
async fn broker_enforced_calls_select_one_grant_covering_the_named_resources() {
    let runtime = runtime(
        vec![
            grant(
                "group:engineering",
                "issue.view",
                "per_user",
                10,
                &[],
                &["wide"],
            ),
            grant(
                "group:support",
                "issue.view",
                "service",
                10,
                &["p-ops"],
                &[],
            ),
        ],
        true,
    );
    let caller = identity(None);
    let prepared = prepare(&runtime, &caller, "issue.view", json!({"project": "ENG"}))
        .await
        .unwrap();
    let Some(CommandAuthorization::Broker {
        resource_type,
        credential_mode,
        values,
        grant,
    }) = prepared.command_authorization()
    else {
        panic!("expected a Broker-enforced plan")
    };
    assert_eq!(resource_type.id, "project");
    assert_eq!(credential_mode, "per_user");
    assert_eq!(values, &["ENG"]);
    assert_eq!(grant.subject, "group:engineering");
    assert_eq!(
        prepared.request.authority().resources().unwrap()["project"],
        ["ENG"]
    );
    // An uncovered resource is denied before dispatch; a resource two modes
    // cover keeps the native single-credential rule.
    for (project, reason) in [
        ("SEC", ReasonCode::ServiceActionDenied),
        ("OPS", ReasonCode::ServiceActionDenied),
    ] {
        assert_eq!(
            prepare(&runtime, &caller, "issue.view", json!({"project": project}))
                .await
                .err()
                .unwrap()
                .reason_code(),
            reason,
            "{project}"
        );
    }
    let response = runtime
        .invoke(
            GovernedOperationContext {
                operation: OperationContext {
                    agent_request_id: "agent-request".into(),
                    broker_request_id: "broker-request".into(),
                    identity: caller.clone(),
                    service: SERVICE.into(),
                    action: "issue.view".into(),
                    source: SourceContext::unknown(),
                },
                execution_context: context(),
            },
            InvokeRequest::new(json!({"project": "SEC"})),
        )
        .await;
    assert_eq!(response.status, 403);
    assert!(response.envelope.result.is_none(), "nothing was dispatched");
}

#[tokio::test]
async fn a_grant_matched_through_several_subjects_is_passed_once() {
    let mut shared = grant(
        "group:engineering",
        "issue.search",
        "service",
        0,
        &["p-ops"],
        &[],
    );
    shared.subjects.push("group:support".into());
    let runtime = runtime(vec![shared], false);
    let prepared = prepare(&runtime, &identity(None), "issue.search", json!({}))
        .await
        .unwrap();
    assert_eq!(
        passed(&prepared),
        [("service".into(), finite(&["OPS"]), Some(0))]
    );
}

/// The `credential_mode_ambiguous` issues policy validation reports for one
/// subject's two same-priority grants of `action`, in personal and service
/// mode, whose boundaries overlap.
fn ambiguity_issues(
    runtime: &BrokerRuntime,
    service: &str,
    action: &str,
    personal: &ResourceSelection,
    shared: &ResourceSelection,
) -> usize {
    let mut config = (*runtime.config).clone();
    config.credentials = (*runtime.effective_credentials).clone();
    for (id, selector) in [("f-all", ResourceSelector::All), ("f-ops", exact("OPS"))] {
        config.policy.resources.push(ResourceDefinition {
            resource_type: agent_access_fake::FAKE_PROJECT_RESOURCE.id().clone(),
            ..project(id, selector, &["default"], true)
        });
    }
    let actions = [action.to_owned()];
    let grants = [("per_user", personal), ("service", shared)]
        .into_iter()
        .map(|(mode, resources)| crate::NormalizedPolicyGrant {
            label: format!("{mode} grant"),
            service_label: format!("{mode} grant service"),
            actions_label: format!("{mode} grant actions"),
            credential_mode_label: format!("{mode} grant credentialMode"),
            execution_contexts_label: format!("{mode} grant executionContexts"),
            subject_field: "subjects[0]".into(),
            subject: "group:engineering",
            service,
            actions: &actions,
            resources,
            execution_contexts: vec!["default".into()],
            credential_mode: mode,
            priority: Some(10),
        })
        .collect::<Vec<_>>();
    crate::normalized_policy_grant_validation_issues(
        &config,
        &runtime.services,
        &runtime.imported_catalog,
        runtime.resource_types(),
        &grants,
    )
    .into_iter()
    .filter(|issue| issue.code == "credential_mode_ambiguous")
    .count()
}

fn selection(ids: &[&str], groups: &[&str]) -> ResourceSelection {
    ResourceSelection {
        resource_ids: ids.iter().map(|id| (*id).into()).collect(),
        resource_group_ids: groups.iter().map(|id| (*id).into()).collect(),
    }
}

#[tokio::test]
async fn one_subject_may_mix_modes_only_for_command_enforced_actions() {
    let runtime = runtime(
        vec![
            grant(
                "group:engineering",
                "issue.search",
                "per_user",
                10,
                &[],
                &["wide"],
            ),
            grant(
                "group:engineering",
                "issue.search",
                "service",
                10,
                &["p-ops"],
                &[],
            ),
            grant("group:engineering", "issue.stats", "per_user", 10, &[], &[]),
            grant("group:engineering", "issue.stats", "service", 10, &[], &[]),
        ],
        true,
    );
    let (wide, ops, none) = (
        selection(&[], &["wide"]),
        selection(&["p-ops"], &[]),
        ResourceSelection::default(),
    );
    // Overlapping typed boundaries and identical untyped selections are
    // accepted for command-enforced actions.
    assert_eq!(
        ambiguity_issues(&runtime, SERVICE, "issue.search", &wide, &ops),
        0
    );
    assert_eq!(
        ambiguity_issues(&runtime, SERVICE, "issue.stats", &none, &none),
        0
    );
    // A Broker-enforced action and a native action keep the rejection.
    assert_eq!(
        ambiguity_issues(&runtime, SERVICE, "issue.view", &wide, &ops),
        1
    );
    assert_eq!(
        ambiguity_issues(
            &runtime,
            "fake",
            "echo",
            &selection(&["f-all"], &[]),
            &selection(&["f-ops"], &[])
        ),
        1
    );

    // The planner passes both grants, each with its own credential.
    let caller = identity(None);
    let prepared = prepare(&runtime, &caller, "issue.search", json!({}))
        .await
        .unwrap();
    assert_eq!(
        passed(&prepared),
        [
            (
                "per_user".into(),
                all_except(&["FIN", "HR", "SEC"]),
                Some(10)
            ),
            ("service".into(), finite(&["OPS"]), Some(10)),
        ]
    );
    assert_eq!(
        discovered(&runtime, &caller, "issue.search"),
        Some(reached(&prepared))
    );
    let prepared = prepare(&runtime, &caller, "issue.stats", json!({}))
        .await
        .unwrap();
    assert_eq!(
        passed(&prepared),
        [
            ("per_user".into(), all_except(&[]), Some(10)),
            ("service".into(), all_except(&[]), Some(10)),
        ]
    );
}

#[tokio::test]
async fn grants_in_modes_an_action_no_longer_supports_are_never_passed() {
    let runtime = runtime(
        vec![
            grant(
                "group:engineering",
                "issue.svc_search",
                "per_user",
                10,
                &[],
                &["wide"],
            ),
            grant(
                "group:support",
                "issue.svc_search",
                "service",
                10,
                &["p-ops"],
                &[],
            ),
            grant(
                "group:engineering",
                "issue.svc_search",
                "service",
                0,
                &["p-all"],
                &[],
            ),
            grant(
                "group:engineering",
                "issue.svc_view",
                "per_user",
                10,
                &[],
                &["wide"],
            ),
            grant(
                "group:engineering",
                "issue.svc_view",
                "service",
                0,
                &["p-all"],
                &[],
            ),
        ],
        true,
    );
    let caller = identity(None);
    // The planner omits the personal grant as an unavailable credential;
    // the lower band is still never consulted.
    let prepared = prepare(&runtime, &caller, "issue.svc_search", json!({}))
        .await
        .unwrap();
    assert_eq!(
        passed(&prepared),
        [("service".into(), finite(&["OPS"]), Some(10))]
    );
    assert_eq!(
        discovered(&runtime, &caller, "issue.svc_search"),
        Some(reached(&prepared))
    );
    // Native selection denies the unsupported mode instead of using it.
    let denied = prepare(
        &runtime,
        &caller,
        "issue.svc_view",
        json!({"project": "ENG"}),
    )
    .await
    .err()
    .unwrap();
    assert_eq!(denied.reason_code(), ReasonCode::CredentialNotProvisioned);
    let admitted = prepare(
        &runtime,
        &caller,
        "issue.svc_view",
        json!({"project": "SEC"}),
    )
    .await
    .unwrap();
    assert!(matches!(
        admitted.command_authorization(),
        Some(CommandAuthorization::Broker { credential_mode, .. }) if credential_mode == "service"
    ));
    // Discovery agrees: only values the service grant wins are reachable.
    assert_eq!(
        discovered(&runtime, &caller, "issue.svc_view"),
        Some(BTreeSet::from(["SEC", "HR", "FIN"]))
    );
}

#[tokio::test]
async fn broker_enforced_arrays_need_one_grant_covering_every_value() {
    let runtime = runtime(
        vec![
            grant(
                "group:engineering",
                "issue.bulk",
                "per_user",
                10,
                &[],
                &["wide"],
            ),
            grant(
                "group:support",
                "issue.bulk",
                "service",
                10,
                &["p-ops"],
                &[],
            ),
        ],
        true,
    );
    let caller = identity(None);
    for (projects, reason) in [
        // SEC is excluded from the personal grant and outside the service one.
        (json!(["ENG", "SEC"]), ReasonCode::ServiceActionDenied),
        // Both grants cover OPS alone: the native rule finds that ambiguous.
        (json!(["OPS"]), ReasonCode::ServiceActionDenied),
    ] {
        assert_eq!(
            prepare(
                &runtime,
                &caller,
                "issue.bulk",
                json!({"projects": projects})
            )
            .await
            .err()
            .unwrap()
            .reason_code(),
            reason,
            "{projects}"
        );
    }
    let prepared = prepare(
        &runtime,
        &caller,
        "issue.bulk",
        json!({"projects": ["ENG", "OPS"]}),
    )
    .await
    .unwrap();
    let Some(CommandAuthorization::Broker {
        credential_mode,
        values,
        grant,
        ..
    }) = prepared.command_authorization()
    else {
        panic!("expected a Broker-enforced plan")
    };
    assert_eq!(credential_mode, "per_user");
    assert_eq!(values, &["ENG", "OPS"]);
    assert_eq!(grant.subject, "group:engineering");
}

/// Marks the import's credentials present without a managed store, as a
/// credential-free import's are.
fn credentials_present(runtime: &mut BrokerRuntime) {
    let mut services = (*runtime.services).clone();
    let mut descriptor = (*services[SERVICE]).clone();
    descriptor.credentials.execution_required = false;
    services.insert(SERVICE.into(), Arc::new(descriptor));
    runtime.services = Arc::new(services);
}

/// Publishes the import, binding both modes, with `actions` while `grants`
/// are already retained, as an acceptance publishes a refreshed import.
fn publish_retained(
    actions: Vec<ImportedActionRecord>,
    grants: Vec<PolicyGrantConfig>,
) -> Result<BrokerRuntime, ManagedStoreError> {
    let mut base = BrokerRuntime::new(config()).unwrap().clone();
    let mut config = import_config();
    config.policy.grants = grants;
    base.config = Arc::new(config.clone());
    base.policy_snapshot
        .store(Arc::new(PolicySnapshot::from_config(&config, 2)));
    let mut record = record(
        &[
            ImportedCredentialMode::Service,
            ImportedCredentialMode::PerUser,
        ],
        actions,
    );
    record.slot_versions.insert(
        crate::imports::ImportedCredentialPurpose::Execution,
        "fixture".into(),
    );
    let prepared = base.prepare_imported_service_change(&record, None)?;
    base.with_imported_catalog(
        ImportedCatalog {
            revision: 1,
            services: vec![record],
        },
        prepared,
    )
}

/// Every imported-catalog publication resolves the configured connections'
/// implicit types again, from the descriptors it publishes, beside the
/// import's synthesized connection, whose static binding sets
/// `token_profiles` only. A publication under which a configured connection
/// could accept several types is refused.
#[test]
fn imported_catalog_publication_resolves_configured_implicit_types() {
    let publish = |profiles: &[&str]| {
        let mut base = BrokerRuntime::new(config()).unwrap();
        let mut config = import_config();
        config.credentials.connections.insert(
            "tracker_tokens".into(),
            crate::ConnectionConfig {
                display_name: None,
                token_profiles: None,
                service_account_token_profiles: None,
                oauth: None,
            },
        );
        config.credentials.per_user.insert(
            "tracker".into(),
            CredentialConfig {
                kind: "connection".into(),
                username_ref: None,
                token_ref: None,
                provider: None,
                path: None,
                read_only: None,
                connection: Some("tracker_tokens".into()),
                profile: None,
            },
        );
        base.config = Arc::new(config);
        let credentials = profiles
            .iter()
            .fold(CredentialDescriptor::default(), |credentials, profile| {
                credentials.profile(*profile, "bearer_token")
            });
        let mut services = (*base.services).clone();
        services.insert(
            "tracker".into(),
            Arc::new(ServiceDescriptor::new("tracker", "Tracker").with_credentials(credentials)),
        );
        base.services = Arc::new(services);
        let mut record = record(
            &[
                ImportedCredentialMode::Service,
                ImportedCredentialMode::PerUser,
            ],
            actions(),
        );
        record.slot_versions.insert(
            crate::imports::ImportedCredentialPurpose::Execution,
            "fixture".into(),
        );
        let prepared = base.prepare_imported_service_change(&record, None)?;
        base.with_imported_catalog(
            ImportedCatalog {
                revision: 1,
                services: vec![record],
            },
            prepared,
        )
    };

    let published = publish(&["tracker-token"]).unwrap();
    let connections = &published.effective_credentials().connections;
    assert_eq!(
        connections["tracker_tokens"].token_profiles,
        Some(vec!["tracker-token".to_string()])
    );
    assert_eq!(
        published.config.credentials.connections["tracker_tokens"].token_profiles,
        None
    );
    assert_eq!(
        connections[SERVICE],
        crate::ConnectionConfig {
            display_name: Some("Ticketing".into()),
            token_profiles: Some(vec!["token".into()]),
            service_account_token_profiles: None,
            oauth: None,
        }
    );

    let Err(error) = publish(&["tracker-token", "tracker-deploy-token"]) else {
        panic!("a configured connection offering several types needs a list");
    };
    assert!(
        matches!(&error, ManagedStoreError::InputInvalid(message)
            if message == "credentials.connections.tracker_tokens must set token_profiles: its consumers accept several token profiles (tracker-token, tracker-deploy-token)"),
        "{error:?}"
    );
}

#[test]
fn refusals_name_each_retained_grant_once_by_the_reference_clients_resolve() {
    // A two-subject grant whose credential mode the action does not support
    // fails once per subject; it is listed once, as `toml:0`, with the
    // reasons of both subjects. The second invalid grant is `toml:1`, and the
    // valid third grant is not listed.
    let mut both = grant(
        "user:alice",
        "issue.svc_search",
        "per_user",
        0,
        &[],
        &["wide"],
    );
    both.subjects.push("user:bob".into());
    let error = publish_retained(
        actions(),
        vec![
            both,
            grant(
                "group:engineering",
                "issue.stats",
                "service",
                0,
                &["p-ops"],
                &[],
            ),
            grant(
                "group:engineering",
                "issue.search",
                "service",
                0,
                &["p-ops"],
                &[],
            ),
        ],
    )
    .err()
    .unwrap();
    let ManagedStoreError::ImportChangeBlocked(blocked) = error else {
        panic!("expected a blocked import change: {error}");
    };
    assert_eq!(
        blocked
            .affected_grants
            .iter()
            .map(|grant| grant.id.as_str())
            .collect::<Vec<_>>(),
        ["toml:0", "toml:1"],
        "{blocked:?}"
    );
    let first = &blocked.affected_grants[0];
    assert!(
        first.reason.contains("policy.grants[0] subjects[0]")
            && first.reason.contains("policy.grants[0] subjects[1]"),
        "{first:?}"
    );
    assert!(!first.reason_code.is_empty());
    assert!(
        blocked.affected_grants[1]
            .reason
            .starts_with("policy.grants[1] subjects[0]"),
        "{blocked:?}"
    );
}

#[tokio::test]
async fn an_action_naming_a_dropped_type_fails_closed_alone() {
    // A refresh removed `legacy` and quarantined its action; once its
    // resources were deleted an acceptance dropped the type, but the
    // quarantined action and its retained grants remain.
    let mut actions = actions();
    let mut legacy = action(
        "issue.legacy",
        json!({"resources": {"type": "legacy", "inputs": ["/project"]}}),
    );
    legacy.status = ImportedActionStatus::Quarantined;
    actions.push(legacy);
    let mut runtime = publish_retained(
        actions,
        vec![
            grant(
                "group:engineering",
                "issue.legacy",
                "service",
                0,
                &["p-ops"],
                &[],
            ),
            grant(
                "group:engineering",
                "issue.view",
                "service",
                0,
                &["p-ops"],
                &[],
            ),
        ],
    )
    .unwrap();
    credentials_present(&mut runtime);
    let descriptor = &runtime.services[SERVICE];
    assert_eq!(
        descriptor.resource_scopes["legacy"].resource_type,
        *UNRESOLVED_RESOURCE_TYPE.id()
    );
    // The unresolved ID is reserved, so no registered type can answer for
    // such a scope.
    assert!(
        runtime
            .resource_types()
            .get(UNRESOLVED_RESOURCE_TYPE.id())
            .is_none()
    );
    assert_eq!(
        descriptor.resource_scopes["project"].resource_type,
        project_type()
    );
    let caller = identity(None);
    prepare(&runtime, &caller, "issue.view", json!({"project": "OPS"}))
        .await
        .unwrap();
    // The quarantined action is not built, so it is refused before policy.
    assert_eq!(
        prepare(&runtime, &caller, "issue.legacy", json!({"project": "OPS"}))
            .await
            .err()
            .unwrap()
            .reason_code(),
        ReasonCode::InputInvalid
    );
    assert_eq!(discovered(&runtime, &caller, "issue.legacy"), None);
}

#[test]
fn publication_refuses_changes_that_would_invalidate_retained_grants() {
    // One subject's mixed modes on the command-enforced search load; the
    // same pair on the Broker-enforced view, or a mode an action no longer
    // supports, would fail the next start.
    publish_retained(
        actions(),
        vec![
            grant(
                "group:engineering",
                "issue.search",
                "per_user",
                0,
                &[],
                &["wide"],
            ),
            grant(
                "group:engineering",
                "issue.search",
                "service",
                0,
                &["p-ops"],
                &[],
            ),
        ],
    )
    .unwrap();
    for grants in [
        vec![
            grant(
                "group:engineering",
                "issue.view",
                "per_user",
                0,
                &[],
                &["wide"],
            ),
            grant(
                "group:engineering",
                "issue.view",
                "service",
                0,
                &["p-ops"],
                &[],
            ),
        ],
        vec![grant(
            "group:engineering",
            "issue.svc_search",
            "per_user",
            0,
            &[],
            &["wide"],
        )],
        vec![grant(
            "group:engineering",
            "issue.stats",
            "service",
            0,
            &["p-ops"],
            &[],
        )],
    ] {
        let error = publish_retained(actions(), grants).err().unwrap();
        assert!(
            error.to_string().contains("retained grants invalid"),
            "{error}"
        );
        assert!(error.to_string().contains("policy.grants["), "{error}");
    }
}
