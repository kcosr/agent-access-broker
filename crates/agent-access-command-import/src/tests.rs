//! Commands run on Unix only, so most cases and their helpers are Unix-only.
use super::*;
#[cfg(unix)]
use agent_access_core::imports::{CommandRegistry, CommandRequest, ImportedCredentialKind};
use agent_access_core::imports::{
    ImportedCredentialBinding, ImportedCredentialDelivery, ImportedCredentialMode,
};
#[cfg(unix)]
use agent_access_provider::test_support::{InvocationBuilder, TestHost, bearer_credential};
#[cfg(unix)]
use serde_json::json;

#[cfg(unix)]
fn command(fixture: &str) -> CommandImportConfig {
    CommandImportConfig {
        path: format!("{}/tests/fixtures/{fixture}", env!("CARGO_MANIFEST_DIR")),
        timeout: "10s".into(),
        max_output_bytes: 1024 * 1024,
        max_download_bytes: None,
        max_concurrent: 4,
        working_dir: "/".into(),
        network: Default::default(),
        log_stderr: false,
        env: BTreeMap::from([("PATH".into(), "/usr/bin:/bin".into())]),
    }
}

fn definition(modes: &[ImportedCredentialMode]) -> ImportedServiceDefinition {
    ImportedServiceDefinition {
        service: "ticketing".into(),
        display_name: "Ticketing".into(),
        adapter_kind: "command".into(),
        endpoint: "command:ticketing".into(),
        connection_settings: BTreeMap::new(),
        execution_bindings: modes
            .iter()
            .map(|mode| ImportedCredentialBinding::token(*mode, ImportedCredentialDelivery::Stdin))
            .collect(),
        discovery: ImportedDiscoveryCredential::Anonymous,
        transport_auth: false,
        invocation_limit: None,
    }
}

#[cfg(unix)]
async fn discover(
    definition: &ImportedServiceDefinition,
    command: Option<&CommandImportConfig>,
    accepted: Option<&ImportedServiceMetadata>,
) -> Result<ImportedDiscovery, AdapterDiscoveryError> {
    discover_with(definition, command, accepted, &CommandRegistry::new()).await
}

#[cfg(unix)]
async fn discover_with(
    definition: &ImportedServiceDefinition,
    command: Option<&CommandImportConfig>,
    accepted: Option<&ImportedServiceMetadata>,
    registry: &CommandRegistry,
) -> Result<ImportedDiscovery, AdapterDiscoveryError> {
    let host = TestHost::default();
    CommandAdapter
        .discover(
            definition,
            &ImportedDiscoveryAuthentication::Anonymous,
            None,
            &ImportedAdapterContext::new(accepted, command).with_command_registry(registry),
            &host.context(),
        )
        .await
}

#[cfg(unix)]
fn failed_reason(error: AdapterDiscoveryError) -> agent_access_provider::ProviderReason {
    match error {
        AdapterDiscoveryError::Failed(error) => error.reason_code(),
        other => panic!("expected a discovery failure, got {other:?}"),
    }
}

#[test]
fn the_selection_names_the_command_kind_and_its_endpoint_form() {
    let registration = registration();
    assert_eq!(registration.kind(), "command");
    assert_eq!(
        registration.module().crate_name(),
        "agent-access-command-import"
    );
    assert!(!CommandAdapter.development_only());
    assert_eq!(CommandAdapter.endpoint_form(), ImportEndpointForm::Command);
    assert_eq!(
        CommandAdapter.sensitive_output_pointers(),
        ["/result/upstreamCommand"]
    );
}

#[test]
fn live_listing_survives_preview_and_persistence_but_requires_reviewed_read_only() {
    let mut manifest = manifest::tests::sample();
    manifest["actions"][1]["name"] = serde_json::json!("project.list");
    manifest["actions"][1]["listingOf"] = serde_json::json!("project");
    let manifest = manifest::parse(&serde_json::to_vec(&manifest).unwrap()).unwrap();
    let preview = mapping::discovery(
        &definition(&[ImportedCredentialMode::Service]),
        "ticketing",
        &manifest,
        None,
        false,
    )
    .unwrap();
    let tool = &preview.tools[1];
    assert!(tool.unsupported_reason.is_none(), "{tool:?}");
    assert!(
        !tool.definition.read_only,
        "source hints never classify an action"
    );
    assert_eq!(
        tool.definition.annotations["command"]["listingOf"],
        "project"
    );
    assert!(
        CommandAdapter
            .validate_action(&tool.definition)
            .unwrap_err()
            .contains("reviewed read-only")
    );
    let mut accepted: ImportedActionDefinition =
        serde_json::from_value(serde_json::to_value(&tool.definition).unwrap()).unwrap();
    accepted.read_only = true;
    CommandAdapter.validate_action(&accepted).unwrap();
    assert_eq!(
        CommandAdapter
            .action_authority(&accepted)
            .unwrap()
            .listing_of
            .as_deref(),
        Some("project")
    );
    accepted.annotations["command"]["listingOf"] = serde_json::json!("other");
    assert!(CommandAdapter.validate_action(&accepted).is_err());
}

#[test]
fn definitions_use_command_endpoints_anonymous_discovery_and_static_credentials() {
    let both = [
        ImportedCredentialMode::Service,
        ImportedCredentialMode::PerUser,
    ];
    CommandAdapter
        .validate_definition(&definition(&both))
        .unwrap();
    CommandAdapter
        .validate_definition(&definition(&[]))
        .unwrap();
    let mut http = definition(&[]);
    http.endpoint = "https://tools.example/mcp".into();
    assert!(CommandAdapter.validate_definition(&http).is_err());
    let mut slot = definition(&both);
    slot.discovery = ImportedDiscoveryCredential::Execution;
    assert!(CommandAdapter.validate_definition(&slot).is_err());
    let mut oauth = definition(&both);
    oauth.execution_bindings[1].mechanism = ImportedAuthMechanism::Oauth;
    oauth.execution_bindings[1].status = ImportedBindingStatus::Unsupported;
    assert!(CommandAdapter.validate_definition(&oauth).is_err());
}

#[cfg(unix)]
#[tokio::test]
async fn discovery_runs_describe_and_maps_the_manifest() {
    let command = command("ticketing.sh");
    let both = definition(&[
        ImportedCredentialMode::Service,
        ImportedCredentialMode::PerUser,
    ]);
    let discovery = discover(&both, Some(&command), None).await.unwrap();
    assert_eq!(discovery.protocol_version, "agent-access-command/1");
    assert_eq!(discovery.metadata["command"], "ticketing");
    assert_eq!(discovery.metadata["commandVersion"], "1.4.0");
    let names = discovery
        .tools
        .iter()
        .map(|tool| {
            (
                tool.definition.action.as_str(),
                tool.unsupported_reason.is_some(),
            )
        })
        .collect::<Vec<_>>();
    assert_eq!(
        names,
        [
            ("issue.view", false),
            ("issue.search", false),
            ("issue.create", true)
        ]
    );
    assert!(
        discovery.tools[2]
            .unsupported_reason
            .as_ref()
            .unwrap()
            .contains("unsupported field")
    );
    let metadata = discovery.service_metadata.clone().unwrap();
    assert_eq!(
        metadata.credential.as_ref().unwrap().kind,
        ImportedCredentialKind::UsernameToken
    );
    assert_eq!(metadata.resource_types[0].broker_type, "ticketing_project");
    for tool in discovery
        .tools
        .iter()
        .filter(|tool| tool.unsupported_reason.is_none())
    {
        CommandAdapter.validate_action(&tool.definition).unwrap();
        assert_eq!(
            CommandAdapter.scoped_mcp_name(&tool.definition).unwrap(),
            tool.definition.action
        );
    }

    // The import's credential modes must be declared by the command, and an
    // accepted declaration never changes.
    let error = discover(&definition(&[]), Some(&command), None)
        .await
        .unwrap_err();
    assert!(
        matches!(error, AdapterDiscoveryError::Configuration(message) if message.contains("declares a credential"))
    );
    let mut accepted = metadata.clone();
    accepted.credential.as_mut().unwrap().kind = ImportedCredentialKind::Token;
    let error = discover(&both, Some(&command), Some(&accepted))
        .await
        .unwrap_err();
    assert!(
        matches!(error, AdapterDiscoveryError::Configuration(message) if message.contains("create a new import"))
    );
}

#[cfg(unix)]
#[tokio::test]
async fn credential_free_commands_discover_with_an_oauth_notice() {
    let discovery = discover(&definition(&[]), Some(&command("clock.sh")), None)
        .await
        .unwrap();
    assert_eq!(discovery.tools.len(), 1);
    assert!(discovery.tools[0].unsupported_reason.is_none());
    assert_eq!(
        discovery.tools[0].definition.annotations,
        json!({"command": {}})
    );
    assert_eq!(
        discovery.metadata["notices"],
        json!([mapping::OAUTH_NOTICE])
    );
    let metadata = discovery.service_metadata.clone().unwrap();
    assert_eq!(metadata.credential, None);
    assert!(!metadata.verify);
    let error = discover(
        &definition(&[ImportedCredentialMode::Service]),
        Some(&command("clock.sh")),
        None,
    )
    .await
    .unwrap_err();
    assert!(matches!(error, AdapterDiscoveryError::Configuration(_)));
}

#[cfg(unix)]
#[tokio::test]
async fn discovery_failures_never_expose_output_or_paths() {
    let service = definition(&[ImportedCredentialMode::Service]);
    for (fixture, reason) in [
        ("invalid.sh", ReasonCode::UpstreamProtocolFailed),
        ("fail.sh", ReasonCode::OperationFailed),
        ("missing.sh", ReasonCode::OperationFailed),
    ] {
        let error = discover(&service, Some(&command(fixture)), None)
            .await
            .unwrap_err();
        let message = format!("{error:?}");
        assert!(!message.contains("/tests/fixtures"), "{message}");
        assert_eq!(failed_reason(error), reason, "{fixture}");
    }
    let mut slow = command("sleep.sh");
    slow.timeout = "1s".into();
    let started = std::time::Instant::now();
    let error = discover(&service, Some(&slow), None).await.unwrap_err();
    assert_eq!(failed_reason(error), ReasonCode::UpstreamTimeout);
    assert!(started.elapsed() < Duration::from_secs(5));
    // An unapproved command and a credentialed discovery never run.
    assert!(matches!(
        discover(&service, None, None).await.unwrap_err(),
        AdapterDiscoveryError::Configuration(_)
    ));
    let host = TestHost::default();
    let command = command("ticketing.sh");
    let error = CommandAdapter
        .discover(
            &service,
            &ImportedDiscoveryAuthentication::Static(bearer_credential("discovery")),
            None,
            &ImportedAdapterContext::new(None, Some(&command)),
            &host.context(),
        )
        .await
        .unwrap_err();
    assert!(matches!(error, AdapterDiscoveryError::Configuration(_)));
}

#[cfg(unix)]
#[tokio::test]
async fn describe_draws_from_the_command_budget() {
    let service = definition(&[]);
    let mut clock = command("clock.sh");
    clock.timeout = "1s".into();
    clock.max_concurrent = 1;
    let host = TestHost::default();
    let error = CommandAdapter
        .discover(
            &service,
            &ImportedDiscoveryAuthentication::Anonymous,
            None,
            &ImportedAdapterContext::new(None, Some(&clock)),
            &host.context(),
        )
        .await
        .unwrap_err();
    assert!(matches!(error, AdapterDiscoveryError::Configuration(_)));

    // Another run of the command holds the only permit until the deadline.
    let registry = CommandRegistry::new();
    let held = registry
        .acquire(
            "ticketing",
            1,
            tokio::time::Instant::now() + Duration::from_secs(30),
        )
        .await
        .unwrap();
    let started = std::time::Instant::now();
    let error = discover_with(&service, Some(&clock), None, &registry)
        .await
        .unwrap_err();
    assert_eq!(failed_reason(error), ReasonCode::UpstreamTimeout);
    assert!(started.elapsed() >= Duration::from_millis(900));
    assert_eq!(registry.in_use("ticketing"), 1);
    assert_eq!(registry.waiting("ticketing"), 0);

    drop(held);
    discover_with(&service, Some(&clock), None, &registry)
        .await
        .unwrap();
    assert_eq!(registry.in_use("ticketing"), 0);
    assert_eq!(registry.live_processes(), 0);

    assert_eq!(registry.close_and_drain(Duration::ZERO).await, 0);
    let error = discover_with(&service, Some(&clock), None, &registry)
        .await
        .unwrap_err();
    assert_eq!(failed_reason(error), ReasonCode::OperationCancelled);
}

/// The command hook of `command`'s import, built from its accepted
/// discovery, with the first action reviewed as a read and the rest as
/// writes.
#[cfg(unix)]
async fn command_hook(
    command: &CommandImportConfig,
) -> (
    Arc<dyn CommandProvider>,
    Arc<dyn Provider>,
    ImportedServiceMetadata,
    Vec<ImportedActionDefinition>,
) {
    let service = definition(&[ImportedCredentialMode::Service]);
    let discovery = discover(&service, Some(&command_at("ticketing.sh", command)), None)
        .await
        .unwrap();
    let metadata = discovery.service_metadata.clone().unwrap();
    let mut actions = discovery
        .tools
        .into_iter()
        .filter(|tool| tool.unsupported_reason.is_none())
        .map(|tool| tool.definition)
        .collect::<Vec<_>>();
    actions[0].read_only = true;
    let host = TestHost::default();
    let built = CommandAdapter
        .build(
            &service,
            &actions,
            None,
            &ImportedAdapterContext::new(Some(&metadata), Some(command)),
            &host.context(),
        )
        .unwrap();
    let hook = built
        .command()
        .cloned()
        .expect("command imports build a command hook");
    (hook, built.provider(), metadata, actions)
}

/// `command` running the fixture `fixture` instead.
#[cfg(unix)]
fn command_at(fixture: &str, command: &CommandImportConfig) -> CommandImportConfig {
    CommandImportConfig {
        path: format!("{}/tests/fixtures/{fixture}", env!("CARGO_MANIFEST_DIR")),
        ..command.clone()
    }
}

#[cfg(unix)]
fn request() -> CommandRequest {
    CommandRequest::encode(&json!({"format": "agent-access-command/1"})).unwrap()
}

#[cfg(unix)]
async fn permit(registry: &CommandRegistry) -> agent_access_core::imports::CommandPermit {
    registry
        .acquire(
            "ticketing",
            4,
            tokio::time::Instant::now() + Duration::from_secs(5),
        )
        .await
        .unwrap()
}

#[cfg(unix)]
#[tokio::test]
async fn built_providers_need_the_approved_command_and_accepted_metadata() {
    let command = command("ticketing.sh");
    let (_, provider, metadata, actions) = command_hook(&command).await;
    let service = definition(&[ImportedCredentialMode::Service]);
    let host = TestHost::default();
    let build = |context: ImportedAdapterContext<'_>| {
        CommandAdapter.build(&service, &actions, None, &context, &host.context())
    };
    assert!(build(ImportedAdapterContext::new(Some(&metadata), None)).is_err());
    assert!(build(ImportedAdapterContext::new(None, Some(&command))).is_err());

    let mut downloads = actions.clone();
    downloads[0].download = true;
    assert!(
        CommandAdapter
            .build(
                &service,
                &downloads,
                None,
                &ImportedAdapterContext::new(Some(&metadata), Some(&command)),
                &host.context()
            )
            .is_err()
    );
    let mut opted_in = command.clone();
    opted_in.max_download_bytes = Some(1024);
    assert!(
        CommandAdapter
            .build(
                &service,
                &downloads,
                None,
                &ImportedAdapterContext::new(Some(&metadata), Some(&opted_in)),
                &host.context()
            )
            .is_ok()
    );

    let scope = agent_access_provider::test_support::ScopeRequestFixture::new(
        "ticketing",
        "issue.view",
        json!({"project": "OPS", "issue": 42}),
    );
    // A Broker-enforced action names its resources for core to check; the
    // command-enforced search names none; both check their input schema.
    assert_eq!(
        provider
            .resolve_scopes(scope.request())
            .await
            .unwrap()
            .into_scopes(),
        BTreeMap::from([("project".to_owned(), vec!["OPS".to_owned()])])
    );
    let search = agent_access_provider::test_support::ScopeRequestFixture::new(
        "ticketing",
        "issue.search",
        json!({"query": "status = open"}),
    );
    assert!(
        provider
            .resolve_scopes(search.request())
            .await
            .unwrap()
            .scopes()
            .is_empty()
    );
    let invalid = agent_access_provider::test_support::ScopeRequestFixture::new(
        "ticketing",
        "issue.view",
        json!({"project": "OPS"}),
    );
    assert_eq!(
        provider
            .resolve_scopes(invalid.request())
            .await
            .unwrap_err()
            .reason_code(),
        ReasonCode::InputInvalid
    );
    for (action, authority) in actions.iter().map(|action| {
        (
            action.action.as_str(),
            CommandAdapter.action_authority(action).unwrap(),
        )
    }) {
        let resources = authority.resources.unwrap();
        assert_eq!(resources.resource_type, "project");
        // Core's reader of the declared type, which resource type changes
        // use, agrees with the adapter's declaration.
        let named = actions.iter().find(|candidate| candidate.action == action);
        assert_eq!(
            agent_access_core::imports::command_action_resource_type(named.unwrap()),
            Some(resources.resource_type.as_str())
        );
        assert_eq!(resources.broker_enforced(), action == "issue.view");
        assert_eq!(
            authority.credential_modes,
            Some(vec![
                ImportedCredentialMode::Service,
                ImportedCredentialMode::PerUser
            ])
        );
    }
    let mut corrupt = actions[0].clone();
    corrupt.annotations = json!({"command": {"resources": {"type": "project", "inputs": []}}});
    assert!(CommandAdapter.action_authority(&corrupt).is_err());
    corrupt.annotations = json!({"command": {}});
    assert_eq!(
        CommandAdapter.action_authority(&corrupt).unwrap(),
        ImportedActionAuthority::default(),
        "an action without a type or modes is action-only with every bound mode"
    );
    let unknown = agent_access_provider::test_support::ScopeRequestFixture::new(
        "ticketing",
        "other",
        json!({}),
    );
    assert!(provider.resolve_scopes(unknown.request()).await.is_err());

    // Core never calls Provider::invoke on a command import; it fails closed.
    let error = provider
        .invoke(InvocationBuilder::new("ticketing", "issue.search").build())
        .await
        .unwrap_err();
    assert_eq!(error.reason_code(), ReasonCode::OperationFailed);
    assert_eq!(
        error.result.as_deref(),
        Some(&json!({"mutationStatus": "not_applied", "retrySafe": true}))
    );
}

#[cfg(unix)]
#[tokio::test]
async fn the_hook_runs_invoke_and_verify_under_the_permit_it_is_handed() {
    let registry = CommandRegistry::new();
    let deadline = || tokio::time::Instant::now() + Duration::from_secs(10);
    // The fixture answers only `describe`; every other run exits 2.
    let (hook, _, _, _) = command_hook(&command("ticketing.sh")).await;

    let facts = CommandProcessFacts::new();
    let error = hook
        .invoke_command(
            CommandInvocation::new(
                "issue.view".into(),
                true,
                request(),
                deadline(),
                permit(&registry).await,
            )
            .with_facts(facts.clone()),
        )
        .await
        .unwrap_err();
    assert_eq!(error.reason_code(), ReasonCode::OperationFailed);
    assert_eq!(error.message, "The tool failed.");
    assert!(error.result.is_none());
    let recorded = facts.snapshot();
    assert!(recorded.spawned);
    assert_eq!(recorded.exit_code, Some(2));
    assert_eq!(recorded.contract_violation, Some(false));
    assert_eq!(registry.in_use("ticketing"), 0);
    assert_eq!(registry.live_processes(), 0);

    // After the spawn, a write's outcome is unknown.
    let error = hook
        .invoke_command(CommandInvocation::new(
            "issue.search".into(),
            false,
            request(),
            deadline(),
            permit(&registry).await,
        ))
        .await
        .unwrap_err();
    assert_eq!(
        error.result.as_deref(),
        Some(&json!({"mutationStatus": "unknown", "retrySafe": false}))
    );
    let error = hook
        .verify_command(CommandVerification::new(
            request(),
            deadline(),
            permit(&registry).await,
        ))
        .await
        .unwrap_err();
    assert_eq!(error.reason_code(), ReasonCode::OperationFailed);
    assert!(error.result.is_none());

    // A command that answers has its document read: a write it confirms is
    // applied but unverified.
    let (answering, _, _, _) = command_hook(&command("process/echo.sh")).await;
    let facts = CommandProcessFacts::new();
    let result = answering
        .invoke_command(
            CommandInvocation::new(
                "issue.search".into(),
                false,
                request(),
                deadline(),
                permit(&registry).await,
            )
            .with_facts(facts.clone()),
        )
        .await
        .unwrap();
    assert_eq!(
        result.result,
        json!({"upstreamCommand": {"bytes": request().stdin().len()},
            "mutationStatus": "applied_unverified", "retrySafe": false})
    );
    assert_eq!(facts.snapshot().exit_code, Some(0));
    assert_eq!(facts.snapshot().contract_violation, Some(false));
    let verified = answering
        .verify_command(CommandVerification::new(
            request(),
            deadline(),
            permit(&registry).await,
        ))
        .await
        .unwrap();
    assert_eq!(verified.upstream_status, 0);
    assert_eq!(registry.in_use("ticketing"), 0);
}

#[cfg(unix)]
#[tokio::test]
async fn a_missing_binary_fails_before_dispatch_without_applying_anything() {
    let registry = CommandRegistry::new();
    let (hook, _, _, _) = command_hook(&command("missing.sh")).await;
    let facts = CommandProcessFacts::new();
    let error = hook
        .invoke_command(
            CommandInvocation::new(
                "issue.search".into(),
                false,
                request(),
                tokio::time::Instant::now() + Duration::from_secs(10),
                permit(&registry).await,
            )
            .with_facts(facts.clone()),
        )
        .await
        .unwrap_err();

    assert_eq!(error.reason_code(), ReasonCode::OperationFailed);
    assert_eq!(error.message, "The tool could not be started.");
    assert_eq!(
        error.result.as_deref(),
        Some(&json!({"mutationStatus": "not_applied", "retrySafe": true}))
    );
    assert!(!facts.snapshot().spawned);
    assert!(!format!("{error:?}").contains("missing.sh"));
    assert_eq!(registry.in_use("ticketing"), 0);
    assert_eq!(registry.live_processes(), 0);
}

#[cfg(unix)]
#[tokio::test]
async fn clean_exit_before_response_deadline_expiry_keeps_unknown_write_and_null_verdict() {
    let mut command = command("download.sh");
    command.max_download_bytes = Some(1024);
    let (_, _, metadata, mut actions) = command_hook(&command).await;
    let mut definition = actions.remove(1);
    definition.download = true;
    definition.output_schema = None;
    let action = Arc::new(CompiledAction::new(&definition).unwrap());
    let provider = CommandImportProvider {
        service: "ticketing".into(),
        actions: BTreeMap::from([(definition.action, action.clone())]),
        command,
        metadata,
    };
    let registry = CommandRegistry::new();
    let deadline = tokio::time::Instant::now() + Duration::from_secs(30);
    let permit = registry.acquire("ticketing", 1, deadline).await.unwrap();
    let lease = permit.retain_budget();
    let facts = CommandProcessFacts::new();
    let completed = run::execute(run::Run {
        service: &provider.service,
        command: &provider.command,
        operation: CommandOperation::Invoke,
        permit,
        request: Some(request()),
        deadline,
        max_output_bytes: usize::try_from(provider.command.download_output_bytes().unwrap())
            .unwrap(),
        environment: Vec::new(),
        facts: facts.clone(),
    })
    .await
    .unwrap_or_else(|failure| panic!("fixture failed: {failure:?}"));
    assert!(tokio::time::Instant::now() < deadline);
    assert_eq!(facts.snapshot().exit_code, Some(0));
    assert_eq!(facts.snapshot().contract_violation, None);
    assert_eq!(registry.live_processes(), 0);
    assert_eq!(registry.in_use("ticketing"), 1);
    // The process has exited. Move the original clock past its deadline
    // before response processing, without relying on wall-clock sleeps.
    tokio::time::pause();
    tokio::time::advance(Duration::from_secs(31)).await;
    tokio::time::resume();
    let error = provider
        .download_response(
            action,
            false,
            completed,
            &facts,
            CommandSecrets::new(),
            1024,
            deadline,
            lease,
        )
        .await
        .unwrap_err();
    assert_eq!(error.reason_code(), ReasonCode::UpstreamTimeout);
    assert_eq!(error.result.unwrap()["mutationStatus"], "unknown");
    assert_eq!(facts.snapshot().contract_violation, None);
    let next = registry
        .acquire(
            "ticketing",
            1,
            tokio::time::Instant::now() + Duration::from_secs(5),
        )
        .await
        .unwrap();
    drop(next);
    assert_eq!(registry.in_use("ticketing"), 0);
}

#[cfg(unix)]
#[tokio::test]
async fn download_hook_uses_its_own_stdout_cap_and_releases_budget_before_delivery() {
    let mut command = command("download.sh");
    command.max_output_bytes = 1;
    command.max_download_bytes = Some(4);
    let (_, _, metadata, mut actions) = command_hook(&command).await;
    actions[1].download = true;
    actions[1].output_schema = None;
    let host = TestHost::default();
    let service = definition(&[ImportedCredentialMode::Service]);
    let built = CommandAdapter
        .build(
            &service,
            &actions,
            None,
            &ImportedAdapterContext::new(Some(&metadata), Some(&command)),
            &host.context(),
        )
        .unwrap();
    let hook = built.command().unwrap();
    let registry = CommandRegistry::new();
    let facts = CommandProcessFacts::new();
    let result = hook
        .invoke_command(
            CommandInvocation::new(
                actions[1].action.clone(),
                false,
                request(),
                tokio::time::Instant::now() + Duration::from_secs(30),
                permit(&registry).await,
            )
            .with_facts(facts.clone()),
        )
        .await
        .unwrap();
    assert_eq!(result.result["size"], 4);
    assert_eq!(
        result.result["sha256"],
        "054edec1d0211f624fed0cbca9d4f9400b0e491c43742af2c5b0abebf0c990d8"
    );
    assert_eq!(result.result["mutationStatus"], "applied_unverified");
    assert!(result.stream.is_some());
    assert_eq!(facts.snapshot().contract_violation, Some(false));
    assert_eq!(registry.in_use("ticketing"), 0);
    assert_eq!(registry.live_processes(), 0);

    let facts = CommandProcessFacts::new();
    let error = hook
        .invoke_command(
            CommandInvocation::new(
                actions[0].action.clone(),
                true,
                request(),
                tokio::time::Instant::now() + Duration::from_secs(30),
                permit(&registry).await,
            )
            .with_facts(facts.clone()),
        )
        .await
        .unwrap_err();
    assert_eq!(error.reason_code(), ReasonCode::OperationFailed);
    assert_eq!(facts.snapshot().contract_violation, Some(true));
    // Retaining the validated file does not occupy a process/worker slot.
    assert!(result.stream.is_some());
    assert_eq!(registry.in_use("ticketing"), 0);
}

#[cfg(unix)]
#[tokio::test]
async fn a_call_whose_broker_is_shutting_down_never_starts() {
    let registry = CommandRegistry::new();
    let (hook, _, _, _) = command_hook(&command("process/echo.sh")).await;
    let permit = permit(&registry).await;
    assert_eq!(registry.close_and_drain(Duration::ZERO).await, 0);
    let facts = CommandProcessFacts::new();
    let error = hook
        .invoke_command(
            CommandInvocation::new(
                "issue.search".into(),
                false,
                request(),
                tokio::time::Instant::now() + Duration::from_secs(10),
                permit,
            )
            .with_facts(facts.clone()),
        )
        .await
        .unwrap_err();

    assert_eq!(error.reason_code(), ReasonCode::OperationCancelled);
    assert_eq!(
        error.result.as_deref(),
        Some(&json!({"mutationStatus": "not_applied", "retrySafe": true}))
    );
    assert!(!facts.snapshot().spawned);
    assert_eq!(registry.in_use("ticketing"), 0);
}

#[cfg(target_os = "linux")]
#[tokio::test]
async fn invoke_processes_get_the_request_only_on_stdin_and_the_network_variables() {
    let registry = CommandRegistry::new();
    let mut command = command("process/environment.sh");
    command.env.insert("LANG".into(), "C.UTF-8".into());
    let completed = run::execute(run::Run {
        service: "ticketing",
        command: &command,
        operation: CommandOperation::Invoke,
        permit: permit(&registry).await,
        request: Some(
            CommandRequest::encode(
                &json!({"credentials": {"service": {"token": "secret-example"}}}),
            )
            .unwrap(),
        ),
        deadline: tokio::time::Instant::now() + Duration::from_secs(10),
        max_output_bytes: 64 * 1024,
        environment: vec![(
            "HTTPS_PROXY",
            std::ffi::OsString::from("http://proxy.example.net:3128"),
        )],
        facts: CommandProcessFacts::new(),
    })
    .await
    .unwrap_or_else(|failure| panic!("{failure:?}"));

    let mut environment = completed
        .stdout
        .split(|byte| *byte == 0)
        .filter(|entry| !entry.is_empty())
        .map(|entry| String::from_utf8_lossy(entry).into_owned())
        .collect::<Vec<_>>();
    environment.sort();
    assert_eq!(
        environment,
        [
            "HTTPS_PROXY=http://proxy.example.net:3128",
            "LANG=C.UTF-8",
            "PATH=/usr/bin:/bin"
        ]
    );
    assert!(!String::from_utf8_lossy(&completed.stdout).contains("secret-example"));
    assert_eq!(registry.in_use("ticketing"), 0);
}

#[test]
fn basic_delivery_is_rejected_by_command_validation_contract_and_build() {
    let mut service = definition(&[ImportedCredentialMode::Service]);
    service.execution_bindings[0].delivery = ImportedCredentialDelivery::Basic;
    assert!(CommandAdapter.validate_definition(&service).is_err());
    assert!(
        CommandAdapter
            .credential_contract(&service, &ImportedAdapterContext::default())
            .is_err()
    );
    let host = agent_access_provider::test_support::TestHost::default();
    assert!(
        CommandAdapter
            .build(
                &service,
                &[],
                None,
                &ImportedAdapterContext::default(),
                &host.context()
            )
            .is_err()
    );
}
