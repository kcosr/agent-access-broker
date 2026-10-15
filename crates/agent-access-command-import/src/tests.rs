use super::*;
use agent_access_core::imports::{
    CommandRequest, ImportedCredentialBinding, ImportedCredentialDelivery, ImportedCredentialKind,
    ImportedCredentialMode,
};
use agent_access_provider::test_support::{InvocationBuilder, TestHost, bearer_credential};
use serde_json::json;

fn command(fixture: &str) -> CommandImportConfig {
    CommandImportConfig {
        path: format!("{}/tests/fixtures/{fixture}", env!("CARGO_MANIFEST_DIR")),
        timeout: "10s".into(),
        max_output_bytes: 1024 * 1024,
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

async fn discover(
    definition: &ImportedServiceDefinition,
    command: Option<&CommandImportConfig>,
    accepted: Option<&ImportedServiceMetadata>,
) -> Result<ImportedDiscovery, AdapterDiscoveryError> {
    let host = TestHost::default();
    CommandAdapter
        .discover(
            definition,
            &ImportedDiscoveryAuthentication::Anonymous,
            None,
            &ImportedAdapterContext::new(accepted, command),
            &host.context(),
        )
        .await
}

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
    let error = discover(&service, Some(&slow), None).await.unwrap_err();
    assert_eq!(failed_reason(error), ReasonCode::UpstreamTimeout);
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
async fn built_providers_expose_the_command_hook_and_fail_closed() {
    let command = command("ticketing.sh");
    let service = definition(&[ImportedCredentialMode::Service]);
    let discovery = discover(&service, Some(&command), None).await.unwrap();
    let metadata = discovery.service_metadata.clone().unwrap();
    let mut actions = discovery
        .tools
        .into_iter()
        .filter(|tool| tool.unsupported_reason.is_none())
        .map(|tool| tool.definition)
        .collect::<Vec<_>>();
    actions[0].read_only = true;
    let host = TestHost::default();
    let build = |context: ImportedAdapterContext<'_>| {
        CommandAdapter.build(&service, &actions, None, &context, &host.context())
    };
    assert!(build(ImportedAdapterContext::new(Some(&metadata), None)).is_err());
    assert!(build(ImportedAdapterContext::new(None, Some(&command))).is_err());
    let built = build(ImportedAdapterContext::new(Some(&metadata), Some(&command))).unwrap();
    let hook = built
        .command()
        .cloned()
        .expect("command imports build a command hook");
    let provider = built.provider();

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

    // Nothing runs yet: reads fail without a receipt, writes report not_applied.
    let deadline = tokio::time::Instant::now() + Duration::from_secs(1);
    let request = || CommandRequest::encode(&json!({"format": "agent-access-command/1"})).unwrap();
    let error = hook
        .invoke_command(CommandInvocation::new(
            "issue.view".into(),
            true,
            request(),
            deadline,
        ))
        .await
        .unwrap_err();
    assert_eq!(error.reason_code(), ReasonCode::OperationFailed);
    assert!(error.result.is_none());
    let error = hook
        .invoke_command(CommandInvocation::new(
            "issue.search".into(),
            false,
            request(),
            deadline,
        ))
        .await
        .unwrap_err();
    assert_eq!(
        error.result.as_deref(),
        Some(&json!({"mutationStatus": "not_applied", "retrySafe": true}))
    );
    assert!(
        hook.verify_command(CommandVerification::new(request(), deadline))
            .await
            .is_err()
    );
    let error = provider
        .invoke(InvocationBuilder::new("ticketing", "issue.search").build())
        .await
        .unwrap_err();
    assert_eq!(error.reason_code(), ReasonCode::OperationFailed);
}
