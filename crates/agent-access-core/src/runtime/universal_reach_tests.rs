//! Universal disclosure reach preserves ordinary per-resource grant selection.
use super::*;
use crate::{BackendRegistry, ProvidersConfig};
use async_trait::async_trait;

const SERVICE: &str = "universal_reach_fixture";
const ACTION: &str = "view";

static PROJECT: ResourceTypeDescriptor = ResourceTypeDescriptor::new(
    ResourceType::from_static("reach_project"),
    "Reach project",
    "Reach projects",
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
                "Exercise universal disclosure reach",
                json!({"type":"object","required":["project"],
                    "properties":{"project":{"type":"string"}},"additionalProperties":false}),
            )
            .scope("project")
            .credential_modes(["service", "per_user"])
            .read_only()
        };
        ServiceDescriptor::new(SERVICE, "Universal reach fixture")
            .with_resource_scopes(BTreeMap::from([(
                "project".into(),
                ResourceScopeCapabilities::new(
                    PROJECT.id().clone(),
                    vec!["exact".into(), "all".into()],
                ),
            )]))
            .with_actions(vec![
                action(ACTION).reports_universal_reach(),
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
            vec![request.inputs()["project"].as_str().unwrap().into()],
        )])))
    }
    async fn invoke(&self, request: ProviderInvocation) -> Result<ProviderResult, ProviderError> {
        assert!(request.search_authorization().is_err());
        Ok(ProviderResult::new(json!({
            "universalReach": request.universal_reach(),
            "scopes": request.resource_scopes()?,
            "mode": request.credential_mode(),
        })))
    }
}

fn context() -> ExecutionContext {
    ExecutionContext::new("default").unwrap()
}

fn selection(ids: &[&str], groups: &[&str]) -> ResourceSelection {
    ResourceSelection {
        resource_ids: ids.iter().map(|value| (*value).into()).collect(),
        resource_group_ids: groups.iter().map(|value| (*value).into()).collect(),
    }
}

fn grant(
    subject: &str,
    priority: i32,
    mode: &str,
    selection: ResourceSelection,
) -> PolicyGrantConfig {
    PolicyGrantConfig {
        subjects: vec![subject.into()],
        service: SERVICE.into(),
        actions: vec![ACTION.into(), "plain".into()],
        resources: selection,
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
        (
            "uncreated",
            ResourceSelector::Exact {
                value: "UNCREATED".into(),
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
    config.policy.resource_groups = ["alpha", "beta", "uncreated"]
        .into_iter()
        .map(|excluded| ResourceGroupDefinition {
            id: format!("except-{excluded}"),
            name: format!("Except {excluded}"),
            included_resource_ids: vec!["all".into()],
            excluded_resource_ids: vec![excluded.into()],
        })
        .collect();
    config.policy.grants = vec![grant(
        "group:anonymous",
        0,
        "service",
        selection(&["all"], &[]),
    )];
    config
}

fn runtime_with_personal_mode(config: BrokerConfig, provisioned: bool) -> BrokerRuntime {
    let mut runtime = BrokerRuntime::new(config).unwrap();
    if provisioned {
        // These policy-only tests never load or acquire this material.
        let mut credentials = (*runtime.effective_credentials).clone();
        credentials.per_user.insert(
            SERVICE.into(),
            fake_service_credential("env:UNUSED_REACH_TOKEN"),
        );
        runtime.effective_credentials = Arc::new(credentials);
    }
    runtime
}

fn reach(
    runtime: &BrokerRuntime,
    snapshot: &PolicySnapshot,
    mode: &str,
    token: Option<&ParsedAgentInvokeTokenCaveats<'_>>,
) -> bool {
    runtime.admitted_universal_reach(
        snapshot,
        &IdentityContext::anonymous(),
        &context(),
        SERVICE,
        runtime.action_descriptor(SERVICE, ACTION).unwrap(),
        token,
        mode,
    )
}

fn token(resources: Option<ResourceSelection>) -> ParsedAgentInvokeTokenCaveats<'static> {
    ParsedAgentInvokeTokenCaveats {
        token_id: None,
        read_only_access: false,
        caveats: AgentInvokeTokenCaveats {
            allowed_services: Some(vec![SERVICE.into()]),
            allowed_execution_contexts: Some(vec![context()]),
            service_restrictions: Some(BTreeMap::from([(
                SERVICE.into(),
                crate::AgentTokenServiceRestriction {
                    actions: vec![ACTION.into()],
                    resources,
                },
            )])),
        },
    }
}

#[test]
fn positive_grants_and_restored_local_exclusions_cover_the_universe() {
    let mut config = config();
    let runtime = runtime_with_personal_mode(config.clone(), true);
    for grants in [
        config.policy.grants.clone(),
        vec![
            grant("group:anonymous", 0, "service", selection(&["all"], &[])),
            grant("user:anonymous", 5, "service", selection(&["alpha"], &[])),
        ],
        vec![
            grant(
                "group:anonymous",
                0,
                "service",
                selection(&[], &["except-beta"]),
            ),
            grant("group:anonymous", 0, "service", selection(&["beta"], &[])),
        ],
        vec![
            grant(
                "group:anonymous",
                0,
                "service",
                selection(&[], &["except-beta"]),
            ),
            grant("user:anonymous", 10, "service", selection(&["beta"], &[])),
        ],
    ] {
        config.policy.grants = grants;
        let snapshot = PolicySnapshot::from_config(&config, 1);
        assert!(reach(&runtime, &snapshot, "service", None));
        assert!(!reach(&runtime, &snapshot, "per_user", None));
    }
}

#[test]
fn other_modes_remain_precedence_competitors_even_when_unavailable() {
    for provisioned in [false, true] {
        let mut config = config();
        let runtime = runtime_with_personal_mode(config.clone(), provisioned);
        for (subject, priority, expected) in [
            ("group:anonymous", -1, true),
            ("group:anonymous", 0, false),
            ("group:anonymous", 1, false),
            ("user:anonymous", -100, false),
        ] {
            config.policy.grants = vec![
                grant("group:anonymous", 0, "service", selection(&["all"], &[])),
                grant(subject, priority, "per_user", selection(&["beta"], &[])),
            ];
            let snapshot = PolicySnapshot::from_config(&config, 2);
            assert_eq!(
                reach(&runtime, &snapshot, "service", None),
                expected,
                "{provisioned} {subject} {priority}"
            );
        }
    }
}

#[test]
fn disabled_context_ineligible_and_unknown_exclusions_remain_real_gaps() {
    let base = config();
    let runtime = runtime_with_personal_mode(base.clone(), false);
    for excluded in ["beta", "uncreated"] {
        for restriction in ["enabled", "disabled", "external"] {
            let mut config = base.clone();
            let entry = config
                .policy
                .resources
                .iter_mut()
                .find(|entry| entry.id == excluded)
                .unwrap();
            match restriction {
                "disabled" => entry.enabled = false,
                "external" => entry.allowed_execution_contexts = vec!["external".into()],
                _ => {}
            }
            config.policy.grants = vec![grant(
                "group:anonymous",
                0,
                "service",
                selection(&[], &[&format!("except-{excluded}")]),
            )];
            assert!(!reach(
                &runtime,
                &PolicySnapshot::from_config(&config, 3),
                "service",
                None
            ));
            // An unavailable positive selection cannot repair that exclusion.
            if restriction != "enabled" {
                config.policy.grants.push(grant(
                    "group:anonymous",
                    0,
                    "service",
                    selection(&[excluded], &[]),
                ));
                assert!(!reach(
                    &runtime,
                    &PolicySnapshot::from_config(&config, 4),
                    "service",
                    None
                ));
            }
        }
    }
    for disabled in [false, true] {
        let mut config = base.clone();
        let all = config
            .policy
            .resources
            .iter_mut()
            .find(|entry| entry.id == "all")
            .unwrap();
        if disabled {
            all.enabled = false;
        } else {
            all.allowed_execution_contexts = vec!["external".into()];
        }
        assert!(!reach(
            &runtime,
            &PolicySnapshot::from_config(&config, 5),
            "service",
            None
        ));
    }
    let mut config = base;
    config.policy.grants[0].execution_contexts = Some(vec!["external".into()]);
    assert!(!reach(
        &runtime,
        &PolicySnapshot::from_config(&config, 6),
        "service",
        None
    ));
}

#[test]
fn caller_ceilings_and_the_admitted_snapshot_are_preserved() {
    let config = config();
    let runtime = runtime_with_personal_mode(config.clone(), false);
    let broad = runtime.policy_snapshot();
    assert!(reach(&runtime, &broad, "service", Some(&token(None))));
    assert!(reach(
        &runtime,
        &broad,
        "service",
        Some(&token(Some(selection(&["all"], &[]))))
    ));
    for resources in [
        selection(&["alpha"], &[]),
        selection(&[], &["except-uncreated"]),
    ] {
        assert!(!reach(
            &runtime,
            &broad,
            "service",
            Some(&token(Some(resources)))
        ));
    }
    for ceiling in ["service", "action", "context"] {
        let mut token = token(None);
        match ceiling {
            "service" => token.caveats.allowed_services = Some(vec!["other".into()]),
            "action" => {
                token
                    .caveats
                    .service_restrictions
                    .as_mut()
                    .unwrap()
                    .get_mut(SERVICE)
                    .unwrap()
                    .actions = vec!["plain".into()]
            }
            "context" => {
                token.caveats.allowed_execution_contexts =
                    Some(vec![ExecutionContext::new("external").unwrap()])
            }
            _ => unreachable!(),
        }
        assert!(
            !reach(&runtime, &broad, "service", Some(&token)),
            "{ceiling}"
        );
    }
    let mut read_only = token(None);
    read_only.read_only_access = true;
    assert!(reach(&runtime, &broad, "service", Some(&read_only)));
    let mut write = runtime.action_descriptor(SERVICE, ACTION).unwrap().clone();
    write.read_only = false;
    assert!(!runtime.admitted_universal_reach(
        &broad,
        &IdentityContext::anonymous(),
        &context(),
        SERVICE,
        &write,
        Some(&read_only),
        "service",
    ));

    let mut narrowed = config;
    narrowed.policy.grants[0].resources = selection(&["alpha"], &[]);
    let narrow = PolicySnapshot::from_config(&narrowed, 42);
    assert!(
        !reach(&runtime, &narrow, "service", None),
        "must use the passed admission snapshot, not runtime's broader current snapshot"
    );
    let narrow_runtime = runtime_with_personal_mode(narrowed, false);
    assert!(reach(&narrow_runtime, &broad, "service", None));
}

#[tokio::test]
async fn real_admission_sets_the_proof_without_expanding_source_authority() {
    for (resources, expected) in [
        (selection(&["all"], &[]), true),
        (selection(&["alpha"], &[]), false),
    ] {
        let mut config = config();
        config.policy.grants[0].resources = resources;
        let runtime = BrokerRuntime::new(config).unwrap();
        for action in [ACTION, "plain"] {
            let response = runtime
                .invoke(
                    GovernedOperationContext {
                        operation: OperationContext {
                            agent_request_id: "universal-reach-agent".into(),
                            broker_request_id: "universal-reach-broker".into(),
                            identity: IdentityContext::anonymous(),
                            service: SERVICE.into(),
                            action: action.into(),
                            source: SourceContext::unknown(),
                        },
                        execution_context: context(),
                    },
                    InvokeRequest::new(json!({"project":"ALPHA"})),
                )
                .await;
            assert_eq!(response.status, 200);
            let envelope = serde_json::to_value(response.envelope).unwrap();
            assert_eq!(
                envelope["result"]["universalReach"],
                expected && action == ACTION
            );
            assert_eq!(envelope["result"]["scopes"], json!({"project":["ALPHA"]}));
            assert_eq!(envelope["resourceScopes"], json!({"project":["ALPHA"]}));
        }
    }
}

#[test]
fn generated_exact_selector_partitions_match_ordinary_policy_selection() {
    let base = config();
    let choices = [
        selection(&["all"], &[]),
        selection(&["alpha"], &[]),
        selection(&["beta"], &[]),
        selection(&["alpha", "beta"], &[]),
        selection(&[], &["except-alpha"]),
        selection(&[], &["except-beta"]),
    ];
    // Every generated selector distinguishes only ALPHA and BETA. FRESH is
    // the entire remaining partition, including every future canonical key.
    // Thus this is exhaustive over selector equivalence classes, not a sample
    // of known projects used to claim universal coverage.
    let representatives = ["ALPHA", "BETA", "FRESH"];
    for provisioned in [false, true] {
        // Each runtime starts from the valid service-only configuration.
        // Generated grants live only in the independently supplied snapshots.
        let runtime = runtime_with_personal_mode(base.clone(), provisioned);
        let mut config = base.clone();
        for left in &choices {
            for right in &choices {
                for (subject, priority) in [
                    ("group:anonymous", -1),
                    ("group:anonymous", 0),
                    ("group:anonymous", 1),
                    ("user:anonymous", -1),
                ] {
                    for other_mode in ["service", "per_user"] {
                        config.policy.grants = vec![
                            grant("group:anonymous", 0, "service", left.clone()),
                            grant(subject, priority, other_mode, right.clone()),
                        ];
                        let snapshot = PolicySnapshot::from_config(&config, 7);
                        for restriction in [
                            None,
                            Some(choices[0].clone()),
                            Some(choices[1].clone()),
                            Some(choices[4].clone()),
                        ] {
                            let token = token(restriction);
                            for mode in ["service", "per_user"] {
                                let expected = representatives.iter().all(|target| {
                                    let scopes = BTreeMap::from([(
                                        "project".into(),
                                        vec![(*target).into()],
                                    )]);
                                    runtime
                                        .enforce_agent_invoke_token_resource_caveats_with(
                                            &snapshot,
                                            &context(),
                                            Some(&token),
                                            SERVICE,
                                            ACTION,
                                            &scopes,
                                        )
                                        .is_ok()
                                        && runtime
                                            .select_policy(
                                                &snapshot,
                                                &IdentityContext::anonymous(),
                                                &context(),
                                                SERVICE,
                                                ACTION,
                                                &scopes,
                                            )
                                            .is_ok_and(|decision| decision.credential_mode == mode)
                                });
                                assert_eq!(
                                    reach(&runtime, &snapshot, mode, Some(&token)),
                                    expected,
                                    "{provisioned} {left:?} {right:?} {subject} {priority} {other_mode} {mode}"
                                );
                            }
                        }
                    }
                }
            }
        }
    }
}
