//! Companion authority reuses ordinary exact-scope admission without nested reads.
use super::*;
use crate::{BackendRegistry, ProvidersConfig};
use async_trait::async_trait;

const SERVICE: &str = "companion_fixture";
const VIEW: &str = "issue.view";
const LIST: &str = "comment.list";
const BODY: &str = "comment.view";
static PROJECT: ResourceTypeDescriptor = ResourceTypeDescriptor::new(
    ResourceType::from_static("companion_project"),
    "Companion project",
    "Companion projects",
    "ALPHA",
    |value| !value.is_empty() && value.bytes().all(|byte| byte.is_ascii_uppercase()),
    &[],
);
static BACKEND: BackendRegistration = BackendRegistration::new(
    agent_access_provider::module_metadata!(),
    SERVICE,
    parse_backend_config::<FixtureConfig>,
)
.with_resource_types(&[&PROJECT])
.development_only();

#[derive(Debug, Clone, Default, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct FixtureConfig;
impl BackendConfig for FixtureConfig {
    fn kind(&self) -> &'static str {
        SERVICE
    }
    fn validate(&self, _: &ValidationContext<'_>, _: &mut Vec<String>) {}
    fn descriptor(&self) -> ServiceDescriptor {
        let action = |name| {
            ActionDescriptor::new(
                name,
                "Companion read fixture",
                json!({
                    "type":"object", "required":["projects"], "properties":{
                        "projects":{"type":"array","items":{"type":"string"},"minItems":1},
                        "includeContent":{"type":"boolean"}
                    }, "additionalProperties":false
                }),
            )
            .scope("project")
            .credential_modes(["service", "per_user"])
            .read_only()
        };
        ServiceDescriptor::new(SERVICE, "Companion fixture")
            .with_resource_scopes(BTreeMap::from([(
                "project".into(),
                ResourceScopeCapabilities::new(
                    PROJECT.id().clone(),
                    vec!["exact".into(), "all".into()],
                ),
            )]))
            .with_actions(vec![
                action(VIEW).companion_read(LIST).companion_read(BODY),
                action(LIST).companion_read(BODY),
                action(BODY),
                action("plain"),
            ])
            .with_credentials(CredentialDescriptor::without_execution_credential())
    }
    fn egress_proxies(&self) -> Vec<(String, &EgressProxyConfig)> {
        vec![]
    }
    fn build(&self, _: &BuildContext<'_>) -> Result<Arc<dyn Provider>, ProviderBuildError> {
        Ok(Arc::new(Self))
    }
}
#[async_trait]
impl Provider for FixtureConfig {
    async fn resolve_scopes(
        &self,
        request: ScopeRequest<'_>,
    ) -> Result<ScopeResolution, ProviderError> {
        Ok(ScopeResolution::resources(BTreeMap::from([(
            "project".into(),
            request.inputs()["projects"]
                .as_array()
                .unwrap()
                .iter()
                .map(|v| v.as_str().unwrap().into())
                .collect(),
        )])))
    }
    async fn invoke(&self, request: ProviderInvocation) -> Result<ProviderResult, ProviderError> {
        if request.inputs()["includeContent"].as_bool() == Some(true)
            && !request.companion_reads_authorized()
        {
            return Err(ProviderError::deny(
                ReasonCode::ServiceActionDenied,
                "companion read authority required",
            ));
        }
        Ok(ProviderResult::new(json!({
            "companionsAuthorized":request.companion_reads_authorized(),
            "scopes":request.resource_scopes()?, "mode":request.credential_mode(),
        })))
    }
}
fn context() -> ExecutionContext {
    ExecutionContext::new("default").unwrap()
}
fn selection(ids: &[&str], groups: &[&str]) -> ResourceSelection {
    ResourceSelection {
        resource_ids: ids.iter().map(|s| (*s).into()).collect(),
        resource_group_ids: groups.iter().map(|s| (*s).into()).collect(),
    }
}
fn grant(
    actions: &[&str],
    mode: &str,
    priority: i32,
    resources: ResourceSelection,
) -> PolicyGrantConfig {
    PolicyGrantConfig {
        subjects: vec!["group:anonymous".into()],
        service: SERVICE.into(),
        actions: actions.iter().map(|s| (*s).into()).collect(),
        resources,
        execution_contexts: Some(vec!["default".into()]),
        credential_mode: mode.into(),
        priority: Some(priority),
    }
}
fn config() -> BrokerConfig {
    let mut config = tests::base_fake_config();
    config.credentials = Default::default();
    config.providers = ProvidersConfig::new(Arc::new(BackendRegistry::new([&BACKEND]).unwrap()))
        .with(FixtureConfig);
    config.execution_context = Some(crate::ExecutionContextConfig {
        allowed_values: vec!["default".into(), "external".into()],
        default_context: None,
    });
    config.policy.resources = [
        ("all", ResourceSelector::All),
        (
            "alpha",
            ResourceSelector::Exact {
                value: "ALPHA".into(),
            },
        ),
        (
            "beta",
            ResourceSelector::Exact {
                value: "BETA".into(),
            },
        ),
    ]
    .into_iter()
    .map(|(id, selector)| ResourceDefinition {
        id: id.into(),
        display_name: None,
        resource_type: PROJECT.id().clone(),
        selector,
        allowed_execution_contexts: vec!["default".into()],
        enabled: true,
    })
    .collect();
    config.policy.resource_groups = vec![ResourceGroupDefinition {
        id: "except-beta".into(),
        name: "Except beta".into(),
        included_resource_ids: vec!["all".into()],
        excluded_resource_ids: vec!["beta".into()],
    }];
    config.policy.grants = vec![grant(
        &[VIEW, LIST, BODY, "plain"],
        "service",
        0,
        selection(&["all"], &[]),
    )];
    config
}
fn runtime() -> BrokerRuntime {
    let mut runtime = BrokerRuntime::new(config()).unwrap();
    let mut credentials = (*runtime.effective_credentials).clone();
    credentials.per_user.insert(
        SERVICE.into(),
        fake_service_credential("env:UNUSED_COMPANION_TOKEN"),
    );
    runtime.effective_credentials = Arc::new(credentials);
    runtime
}
fn scopes(projects: &[&str]) -> ResourceScopes {
    BTreeMap::from([(
        "project".into(),
        projects.iter().map(|s| (*s).into()).collect(),
    )])
}
fn proof(
    runtime: &BrokerRuntime,
    snapshot: &PolicySnapshot,
    action: &str,
    projects: &[&str],
    mode: &str,
    token: Option<&ParsedAgentInvokeTokenCaveats<'_>>,
) -> bool {
    runtime.admitted_companion_reads(
        snapshot,
        &IdentityContext::anonymous(),
        &context(),
        SERVICE,
        runtime.action_descriptor(SERVICE, action).unwrap(),
        &scopes(projects),
        token,
        mode,
    )
}
fn token() -> ParsedAgentInvokeTokenCaveats<'static> {
    ParsedAgentInvokeTokenCaveats {
        token_id: None,
        read_only_access: false,
        caveats: AgentInvokeTokenCaveats {
            allowed_services: Some(vec![SERVICE.into()]),
            allowed_execution_contexts: Some(vec![context()]),
            service_restrictions: Some(BTreeMap::from([(
                SERVICE.into(),
                crate::AgentTokenServiceRestriction {
                    actions: vec![VIEW.into(), LIST.into(), BODY.into()],
                    resources: None,
                },
            )])),
        },
    }
}
#[test]
fn exact_resources_require_every_companion_without_expanding_source_authority() {
    let runtime = runtime();
    let mut config = config();
    let snapshot = PolicySnapshot::from_config(&config, 1);
    assert!(proof(
        &runtime,
        &snapshot,
        VIEW,
        &["ALPHA", "BETA"],
        "service",
        None
    ));
    assert!(!proof(
        &runtime,
        &snapshot,
        "plain",
        &["ALPHA"],
        "service",
        None
    ));
    assert!(!proof(&runtime, &snapshot, VIEW, &[], "service", None));
    assert!(!proof(
        &runtime,
        &snapshot,
        VIEW,
        &["invalid"],
        "service",
        None
    ));
    for actions in [&[VIEW, LIST][..], &[VIEW, BODY][..]] {
        config.policy.grants[0].actions = actions.iter().map(|s| (*s).into()).collect();
        assert!(!proof(
            &runtime,
            &PolicySnapshot::from_config(&config, 2),
            VIEW,
            &["ALPHA"],
            "service",
            None
        ));
    }
    config.policy.grants = vec![
        grant(&[VIEW, LIST], "service", 0, selection(&["all"], &[])),
        grant(&[BODY], "service", 0, selection(&[], &["except-beta"])),
    ];
    let snapshot = PolicySnapshot::from_config(&config, 3);
    assert!(proof(
        &runtime,
        &snapshot,
        VIEW,
        &["ALPHA"],
        "service",
        None
    ));
    assert!(!proof(
        &runtime,
        &snapshot,
        VIEW,
        &["ALPHA", "BETA"],
        "service",
        None
    ));
    assert!(!proof(
        &runtime,
        &snapshot,
        VIEW,
        &["BETA"],
        "service",
        None
    ));
}
#[test]
fn winning_mode_and_scope_precedence_never_fall_back() {
    let runtime = runtime();
    let mut config = config();
    config
        .policy
        .grants
        .push(grant(&[BODY], "per_user", 10, selection(&["alpha"], &[])));
    let snapshot = PolicySnapshot::from_config(&config, 1);
    assert!(!proof(
        &runtime,
        &snapshot,
        VIEW,
        &["ALPHA"],
        "service",
        None
    ));
    assert!(proof(&runtime, &snapshot, VIEW, &["BETA"], "service", None));
    // A tied winning band with conflicting modes is not resolved by picking
    // the source mode from that band.
    config.policy.grants[1].priority = Some(0);
    assert!(!proof(
        &runtime,
        &PolicySnapshot::from_config(&config, 2),
        VIEW,
        &["ALPHA"],
        "service",
        None
    ));
    // Every companion must agree, even if the supplied source mode matches
    // the last companion's winner.
    config.policy.grants[1].priority = Some(10);
    assert!(!proof(
        &runtime,
        &PolicySnapshot::from_config(&config, 3),
        VIEW,
        &["ALPHA"],
        "per_user",
        None
    ));
}
#[test]
fn caller_ceilings_and_snapshot_apply_to_every_direct_companion() {
    let runtime = runtime();
    let config = config();
    let snapshot = PolicySnapshot::from_config(&config, 1);
    let mut ceiling = token();
    ceiling.read_only_access = true;
    assert!(proof(
        &runtime,
        &snapshot,
        VIEW,
        &["ALPHA"],
        "service",
        Some(&ceiling)
    ));
    for actions in [
        vec![VIEW.into()],
        vec![VIEW.into(), LIST.into()],
        vec![VIEW.into(), BODY.into()],
    ] {
        let mut ceiling = token();
        ceiling
            .caveats
            .service_restrictions
            .as_mut()
            .unwrap()
            .get_mut(SERVICE)
            .unwrap()
            .actions = actions;
        assert!(!proof(
            &runtime,
            &snapshot,
            VIEW,
            &["ALPHA"],
            "service",
            Some(&ceiling)
        ));
    }
    let mut ceiling = token();
    ceiling
        .caveats
        .service_restrictions
        .as_mut()
        .unwrap()
        .get_mut(SERVICE)
        .unwrap()
        .resources = Some(selection(&["alpha"], &[]));
    assert!(proof(
        &runtime,
        &snapshot,
        VIEW,
        &["ALPHA"],
        "service",
        Some(&ceiling)
    ));
    assert!(!proof(
        &runtime,
        &snapshot,
        VIEW,
        &["BETA"],
        "service",
        Some(&ceiling)
    ));
    ceiling.caveats.allowed_execution_contexts =
        Some(vec![ExecutionContext::new("external").unwrap()]);
    assert!(!proof(
        &runtime,
        &snapshot,
        VIEW,
        &["ALPHA"],
        "service",
        Some(&ceiling)
    ));
    let mut narrowed = config;
    narrowed.policy.grants[0].actions = vec![VIEW.into(), LIST.into()];
    assert!(!proof(
        &runtime,
        &PolicySnapshot::from_config(&narrowed, 2),
        VIEW,
        &["ALPHA"],
        "service",
        None
    ));
    assert!(proof(
        &runtime,
        &snapshot,
        VIEW,
        &["ALPHA"],
        "service",
        None
    ));
}
#[test]
fn proofs_follow_only_the_declared_direct_set() {
    let runtime = runtime();
    let mut config = config();
    config.policy.grants[0].actions = vec![VIEW.into(), LIST.into()];
    let snapshot = PolicySnapshot::from_config(&config, 1);
    let mut source = runtime.action_descriptor(SERVICE, VIEW).unwrap().clone();
    source.companion_read_actions = vec![LIST.into()];
    assert!(runtime.admitted_companion_reads(
        &snapshot,
        &IdentityContext::anonymous(),
        &context(),
        SERVICE,
        &source,
        &scopes(&["ALPHA"]),
        None,
        "service"
    ));
    assert!(!proof(
        &runtime,
        &snapshot,
        LIST,
        &["ALPHA"],
        "service",
        None
    ));
}
#[tokio::test]
async fn real_admission_proves_optional_reads_and_preserves_plain_access() {
    for allow_bodies in [false, true] {
        let mut config = config();
        if !allow_bodies {
            config.policy.grants[0]
                .actions
                .retain(|action| action != BODY);
        }
        let runtime = BrokerRuntime::new(config).unwrap();
        for action in [VIEW, LIST] {
            for include in [false, true] {
                let response = runtime
                    .invoke(
                        GovernedOperationContext {
                            admission: None,
                            operation: OperationContext {
                                agent_request_id: "companion-agent".into(),
                                broker_request_id: "companion-broker".into(),
                                identity: IdentityContext::anonymous(),
                                service: SERVICE.into(),
                                action: action.into(),
                                source: SourceContext::unknown(),
                            },
                            execution_context: context(),
                        },
                        InvokeRequest::new(json!({"projects":["ALPHA"],"includeContent":include})),
                    )
                    .await;
                if include && !allow_bodies {
                    assert_eq!(response.status, 403);
                    continue;
                }
                assert_eq!(response.status, 200);
                let envelope = serde_json::to_value(response.envelope).unwrap();
                assert_eq!(envelope["result"]["companionsAuthorized"], allow_bodies);
                assert_eq!(envelope["result"]["scopes"], json!({"project":["ALPHA"]}));
                assert_eq!(envelope["resourceScopes"], json!({"project":["ALPHA"]}));
            }
        }
    }
}
