//! A backend unknown to core exercises discovery's input projection and
//! caller coverage: jobs under configured controllers, like CloudBees CI.
use super::*;
use crate::{BackendRegistry, ProvidersConfig, ResourceCoverage};
use agent_access_provider::{BackendConfig, BackendRegistration};
use async_trait::async_trait;

const SERVICE: &str = "coverage_fixture";

fn is_path(value: &str, segments: std::ops::RangeInclusive<usize>) -> bool {
    let parts = value.split('/').collect::<Vec<_>>();
    segments.contains(&parts.len())
        && parts.iter().all(|part| {
            !part.is_empty()
                && part
                    .bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        })
}

/// `controller/job` for a job; `{controller}` for a namespace below one.
fn job_inputs(selector: &ResourceSelector) -> Option<serde_json::Map<String, Value>> {
    let (value, exact) = match selector {
        ResourceSelector::Exact { value } => (value, true),
        ResourceSelector::Namespace { value } => (value, false),
        _ => return None,
    };
    let (controller, job) = value.split_once('/').unwrap_or((value, ""));
    let mut inputs = serde_json::Map::from_iter([("controller".into(), json!(controller))]);
    if exact {
        inputs.insert("job".into(), json!(job));
    }
    Some(inputs)
}

static JOB: ResourceTypeDescriptor = ResourceTypeDescriptor::new(
    ResourceType::from_static("coverage_job"),
    "Coverage job",
    "Coverage jobs",
    "team-ci/payments/build-api",
    |value| is_path(value, 2..=4),
)
.with_namespace(NamespaceSelectorDescriptor::new(
    |value| is_path(value, 1..=3),
    "Jobs under a namespace",
    "Jobs",
    "team-ci/payments",
))
.with_action_inputs(job_inputs);
static BACKEND: BackendRegistration = BackendRegistration::new(
    agent_access_provider::module_metadata!(),
    SERVICE,
    parse_backend_config::<FixtureConfig>,
)
.with_resource_types(&[&JOB])
.development_only();

#[derive(Debug, Clone, Default, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct FixtureConfig {
    roots: Vec<String>,
}
impl BackendConfig for FixtureConfig {
    fn kind(&self) -> &'static str {
        SERVICE
    }
    fn validate(&self, _: &ValidationContext<'_>, _: &mut Vec<String>) {}
    fn descriptor(&self) -> ServiceDescriptor {
        let schema = json!({"type":"object","properties":{"controller":{"type":"string"},"job":{"type":"string"}},"additionalProperties":false});
        ServiceDescriptor::new(SERVICE, "Coverage fixture")
            .with_resource_scopes(BTreeMap::from([(
                "job".into(),
                ResourceScopeCapabilities::new(
                    JOB.id().clone(),
                    vec!["exact".into(), "namespace".into(), "all".into()],
                ),
            )]))
            .with_actions(
                ["view", "trigger"]
                    .into_iter()
                    .map(|action| {
                        ActionDescriptor::new(action, "Fixture action", schema.clone())
                            .scope("job")
                            .credential_modes(["service", "per_user"])
                    })
                    .collect(),
            )
            .with_credentials(CredentialDescriptor::without_execution_credential())
    }
    fn egress_proxies(&self) -> Vec<(String, &EgressProxyConfig)> {
        vec![]
    }
    fn build(&self, _: &BuildContext<'_>) -> Result<Arc<dyn Provider>, ProviderBuildError> {
        Ok(Arc::new(self.clone()))
    }
}
impl FixtureConfig {
    fn local_scopes(&self, _: &str, inputs: &Value) -> Result<ResourceScopes, ProviderError> {
        let job = format!("{}/{}", inputs["controller"], inputs["job"]);
        Ok(BTreeMap::from([("job".into(), vec![job])]))
    }
}

#[async_trait]
impl Provider for FixtureConfig {
    async fn resolve_scopes(
        &self,
        request: ScopeRequest<'_>,
    ) -> Result<ScopeResolution, ProviderError> {
        self.local_scopes(request.action(), request.inputs())
            .map(ScopeResolution::resources)
    }
    fn resource_roots(&self, resource_type: &ResourceType) -> Vec<String> {
        if resource_type == JOB.id() {
            self.roots.clone()
        } else {
            Vec::new()
        }
    }
    async fn invoke(&self, _: ProviderInvocation) -> Result<ProviderResult, ProviderError> {
        unreachable!("discovery never invokes")
    }
}

fn exact(value: &str) -> ResourceSelector {
    ResourceSelector::Exact {
        value: value.into(),
    }
}
fn namespace(value: &str) -> ResourceSelector {
    ResourceSelector::Namespace {
        value: value.into(),
    }
}
fn resource(id: &str, selector: ResourceSelector) -> ResourceDefinition {
    ResourceDefinition {
        id: id.into(),
        display_name: None,
        resource_type: JOB.id().clone(),
        selector,
        allowed_execution_contexts: vec!["default".into()],
        enabled: true,
    }
}
fn selection(ids: &[&str], groups: &[&str]) -> ResourceSelection {
    ResourceSelection {
        resource_ids: ids.iter().map(|id| (*id).into()).collect(),
        resource_group_ids: groups.iter().map(|id| (*id).into()).collect(),
    }
}
fn grant(actions: &[&str], resources: ResourceSelection) -> PolicyGrantConfig {
    PolicyGrantConfig {
        subjects: vec!["group:anonymous".into()],
        service: SERVICE.into(),
        actions: actions.iter().map(|action| (*action).into()).collect(),
        resources,
        execution_contexts: Some(vec!["default".into()]),
        credential_mode: "service".into(),
        priority: None,
    }
}

/// Catalog: every job (`all`), the two controllers, a team namespace, a
/// registered job, a private job and namespace, and an unconfigured root.
fn config(roots: &[&str]) -> BrokerConfig {
    let mut config = tests::base_fake_config();
    config.credentials = Default::default();
    config.policy.resource_groups.clear();
    config.policy.grants.clear();
    config.execution_context = Some(crate::ExecutionContextConfig {
        allowed_values: vec!["default".into(), "external".into()],
        default_context: None,
    });
    config.policy.resources = vec![
        resource("all-jobs", ResourceSelector::All),
        resource("team-ci", namespace("team-ci")),
        resource("other-ci", namespace("other-ci")),
        resource("other-team", namespace("other-ci/team")),
        resource("payments", namespace("team-ci/payments")),
        resource("build-api", exact("team-ci/payments/build-api")),
        resource("deploy", exact("team-ci/payments/deploy")),
        resource("secret-folder", namespace("team-ci/secret-folder")),
        resource("gone-ci", namespace("gone-ci/payments")),
    ];
    config.providers = ProvidersConfig::new(Arc::new(BackendRegistry::new([&BACKEND]).unwrap()))
        .with(FixtureConfig {
            roots: roots.iter().map(|root| (*root).into()).collect(),
        });
    config
}

fn default_context() -> ExecutionContext {
    ExecutionContext::new("default").unwrap()
}

fn list(
    runtime: &BrokerRuntime,
    identity: &IdentityContext,
    query: ResourceListQuery,
) -> ResourceList {
    runtime
        .service_discovery(identity, &default_context(), SERVICE)
        .unwrap()
        .resources(&query)
        .unwrap()
}

fn coverage(runtime: &BrokerRuntime, identity: &IdentityContext) -> Value {
    serde_json::to_value(list(runtime, identity, ResourceListQuery::default()).coverage).unwrap()
}

fn token(resources: ResourceSelection) -> IdentityContext {
    let mut identity = IdentityContext::anonymous();
    identity.source = Some(IdentitySourceAudit {
        namespace: None,
        binding_id: None,
        name: "test".into(),
        kind: "broker_tokens".into(),
        token_header: "Authorization".into(),
        token_scheme: "Bearer".into(),
        token_class: Some(BrokerTokenClass::AgentInvoke),
        token_id: Some("one".into()),
        token_scopes: Some(
            AgentInvokeTokenCaveats {
                allowed_services: Some(vec![SERVICE.into()]),
                allowed_execution_contexts: Some(vec![default_context()]),
                service_restrictions: Some(BTreeMap::from([(
                    SERVICE.into(),
                    crate::AgentTokenServiceRestriction {
                        actions: vec!["view".into(), "trigger".into()],
                        resources: Some(resources),
                    },
                )])),
            }
            .to_scopes_value(),
        ),
    });
    identity
}

fn entry(selector: ResourceSelector, restricted: bool) -> ResourceCoverage {
    ResourceCoverage {
        resource_type: JOB.id().clone(),
        inputs: job_inputs(&selector),
        selector,
        restricted,
    }
}

#[test]
fn exact_resources_carry_inputs_and_report_no_coverage() {
    let mut config = config(&["team-ci", "other-ci"]);
    config
        .policy
        .grants
        .push(grant(&["view"], selection(&["build-api"], &[])));
    let runtime = BrokerRuntime::new(config).unwrap();
    let page = list(
        &runtime,
        &IdentityContext::anonymous(),
        ResourceListQuery::default(),
    );
    assert_eq!(
        serde_json::to_value(&page).unwrap(),
        json!({
            "service": SERVICE,
            "resources": [{
                "id": "build-api", "type": "coverage_job", "value": "team-ci/payments/build-api",
                "inputs": {"controller": "team-ci", "job": "payments/build-api"}
            }],
            "nextCursor": null
        })
    );
    // Strict clients parse the omitted coverage as empty.
    assert_eq!(
        serde_json::from_value::<ResourceList>(serde_json::to_value(&page).unwrap()).unwrap(),
        page
    );
}

#[test]
fn namespace_and_all_report_reachable_roots_without_contained_entries() {
    let mut config = config(&["team-ci", "other-ci", "Not A Root", "team-ci"]);
    config
        .policy
        .grants
        .push(grant(&["view"], selection(&["payments", "build-api"], &[])));
    let runtime = BrokerRuntime::new(config.clone()).unwrap();
    let page = list(
        &runtime,
        &IdentityContext::anonymous(),
        ResourceListQuery::default(),
    );
    assert_eq!(page.coverage, [entry(namespace("team-ci/payments"), false)]);
    assert_eq!(
        serde_json::to_value(&page.coverage).unwrap(),
        json!([{
            "type": "coverage_job",
            "selector": {"kind": "namespace", "value": "team-ci/payments"},
            "inputs": {"controller": "team-ci"},
            "restricted": false
        }])
    );
    // Registered jobs inside the namespace are still listed as resources.
    assert_eq!(
        page.resources
            .iter()
            .map(|row| row.id.as_str())
            .collect::<Vec<_>>(),
        ["build-api", "deploy"]
    );

    // All is reported per configured, well-formed root; the team namespace
    // and roots outside the provider's configuration are subsumed or dropped.
    config.policy.grants.push(grant(
        &["trigger"],
        selection(&["all-jobs", "gone-ci"], &[]),
    ));
    let runtime = BrokerRuntime::new(config.clone()).unwrap();
    assert_eq!(
        list(
            &runtime,
            &IdentityContext::anonymous(),
            ResourceListQuery::default()
        )
        .coverage,
        [
            entry(namespace("other-ci"), false),
            entry(namespace("team-ci"), false),
        ]
    );

    // Without roots, all is reported as such, without inputs.
    let mut rootless = config.clone();
    rootless.providers = ProvidersConfig::new(Arc::new(BackendRegistry::new([&BACKEND]).unwrap()))
        .with(FixtureConfig::default());
    let runtime = BrokerRuntime::new(rootless).unwrap();
    assert_eq!(
        coverage(&runtime, &IdentityContext::anonymous()),
        json!([{"type": "coverage_job", "selector": {"kind": "all"}, "restricted": false}])
    );
}

#[test]
fn exclusions_restrict_entries_and_hide_unreachable_roots_and_values() {
    let mut config = config(&["team-ci", "other-ci"]);
    config.policy.resource_groups = vec![ResourceGroupDefinition {
        id: "visible".into(),
        name: "Visible jobs".into(),
        included_resource_ids: vec!["all-jobs".into()],
        excluded_resource_ids: vec!["other-ci".into(), "secret-folder".into()],
    }];
    config
        .policy
        .grants
        .push(grant(&["view"], selection(&[], &["visible"])));
    let runtime = BrokerRuntime::new(config.clone()).unwrap();
    let page = list(
        &runtime,
        &IdentityContext::anonymous(),
        ResourceListQuery::default(),
    );
    assert_eq!(page.coverage, [entry(namespace("team-ci"), true)]);
    let rendered = serde_json::to_string(&page).unwrap();
    for hidden in ["other-ci", "secret-folder"] {
        assert!(!rendered.contains(hidden), "{rendered}");
    }

    // A narrower grant inside the excluded root reports only itself, not the
    // root; the all grant's exclusion does not withhold it from this action.
    config
        .policy
        .grants
        .push(grant(&["view"], selection(&["other-team"], &[])));
    let runtime = BrokerRuntime::new(config.clone()).unwrap();
    assert_eq!(
        list(
            &runtime,
            &IdentityContext::anonymous(),
            ResourceListQuery::default()
        )
        .coverage,
        [
            entry(namespace("other-ci/team"), false),
            entry(namespace("team-ci"), true),
        ]
    );

    // Another grant restores the excluded folder for the same action.
    config
        .policy
        .grants
        .push(grant(&["view"], selection(&["secret-folder"], &[])));
    let runtime = BrokerRuntime::new(config.clone()).unwrap();
    assert_eq!(
        list(
            &runtime,
            &IdentityContext::anonymous(),
            ResourceListQuery::default()
        )
        .coverage,
        [
            entry(namespace("other-ci/team"), false),
            entry(namespace("team-ci"), false),
        ]
    );

    // An exclusion on a different action whose grant covers the entry still
    // marks it restricted.
    config
        .policy
        .grants
        .push(grant(&["trigger"], selection(&[], &["visible"])));
    let runtime = BrokerRuntime::new(config).unwrap();
    assert_eq!(
        list(
            &runtime,
            &IdentityContext::anonymous(),
            ResourceListQuery::default()
        )
        .coverage,
        [
            entry(namespace("other-ci/team"), true),
            entry(namespace("team-ci"), true),
        ]
    );
}

#[test]
fn precedence_conditions_withhold_single_targets_until_another_clause_serves_them() {
    let mut config = config(&["team-ci", "other-ci"]);
    config
        .policy
        .grants
        .push(grant(&["view"], selection(&["all-jobs"], &[])));
    let mut unusable = grant(&["view"], selection(&["other-ci"], &[]));
    unusable.credential_mode = "per_user".into();
    unusable.priority = Some(10);
    let mut served = grant(&["view"], selection(&["deploy"], &[]));
    served.priority = Some(10);
    config.policy.grants.extend([unusable, served]);
    // Configuration validation rejects the unconfigured per-user mode;
    // install the policy directly to exercise the runtime precedence guard.
    let mut valid = config.clone();
    valid.policy.grants.truncate(1);
    let runtime = BrokerRuntime::new(valid).unwrap();
    runtime
        .policy_snapshot
        .store(Arc::new(PolicySnapshot::from_config(&config, 1)));
    // The higher, unusable grant withholds every job under other-ci, so that
    // root is unreachable; the higher, usable grant serves its own job.
    assert_eq!(
        list(
            &runtime,
            &IdentityContext::anonymous(),
            ResourceListQuery::default()
        )
        .coverage,
        [entry(namespace("team-ci"), false)]
    );
    assert!(
        runtime
            .service_discovery(&IdentityContext::anonymous(), &default_context(), SERVICE)
            .unwrap()
            .actions(Some("other-ci/x/y"), None, None)
            .unwrap()
            .actions
            .is_empty()
    );
}

#[test]
fn token_restrictions_and_contexts_narrow_coverage() {
    let mut config = config(&["team-ci", "other-ci"]);
    config
        .policy
        .grants
        .push(grant(&["view", "trigger"], selection(&["all-jobs"], &[])));
    config.policy.resource_groups = vec![ResourceGroupDefinition {
        id: "payments-public".into(),
        name: "Public payments jobs".into(),
        included_resource_ids: vec!["payments".into()],
        excluded_resource_ids: vec!["deploy".into()],
    }];
    let runtime = BrokerRuntime::new(config.clone()).unwrap();
    assert_eq!(
        list(
            &runtime,
            &token(selection(&["payments"], &[])),
            ResourceListQuery::default()
        )
        .coverage,
        [entry(namespace("team-ci/payments"), false)]
    );
    let restricted = list(
        &runtime,
        &token(selection(&[], &["payments-public"])),
        ResourceListQuery::default(),
    );
    assert_eq!(
        restricted.coverage,
        [entry(namespace("team-ci/payments"), true)]
    );
    assert!(
        !serde_json::to_string(&restricted)
            .unwrap()
            .contains("deploy")
    );

    // A namespace entry outside the caller's context is not coverage.
    for entry in &mut config.policy.resources {
        if entry.id == "payments" {
            entry.allowed_execution_contexts = vec!["external".into()];
        }
    }
    config.policy.grants = vec![grant(&["view"], selection(&["payments", "build-api"], &[]))];
    let runtime = BrokerRuntime::new(config).unwrap();
    assert_eq!(coverage(&runtime, &IdentityContext::anonymous()), json!([]));
}

#[test]
fn prefix_keeps_entries_matching_or_containing_it_and_pages_omit_coverage() {
    let mut config = config(&["team-ci", "other-ci"]);
    config.policy.grants.push(grant(
        &["view"],
        selection(&["all-jobs", "build-api", "deploy"], &[]),
    ));
    let runtime = BrokerRuntime::new(config).unwrap();
    let anonymous = IdentityContext::anonymous();
    for (prefix, expected) in [
        ("team-ci/payments/b", vec!["team-ci"]),
        ("team-ci", vec!["team-ci"]),
        ("o", vec!["other-ci"]),
        ("team-ci-old", vec![]),
        ("zz", vec![]),
    ] {
        let page = list(
            &runtime,
            &anonymous,
            ResourceListQuery {
                prefix: Some(prefix.into()),
                ..ResourceListQuery::default()
            },
        );
        assert_eq!(
            page.coverage
                .iter()
                .map(|entry| entry.selector.clone())
                .collect::<Vec<_>>(),
            expected.into_iter().map(namespace).collect::<Vec<_>>(),
            "{prefix}"
        );
    }
    let first = list(
        &runtime,
        &anonymous,
        ResourceListQuery {
            limit: Some(1),
            ..ResourceListQuery::default()
        },
    );
    assert_eq!(first.coverage.len(), 2);
    let second = list(
        &runtime,
        &anonymous,
        ResourceListQuery {
            limit: Some(1),
            cursor: first.next_cursor,
            ..ResourceListQuery::default()
        },
    );
    assert_eq!(second.resources[0].value, "team-ci/payments/deploy");
    assert!(second.coverage.is_empty());
    assert!(
        serde_json::to_value(&second)
            .unwrap()
            .get("coverage")
            .is_none()
    );
}

#[test]
fn types_without_projection_or_roots_list_plain_rows_and_all() {
    let mut config = tests::base_fake_config();
    config.policy.grants[0].resources = selection(&["fake-project-all"], &[]);
    let runtime = BrokerRuntime::new(config).unwrap();
    let page = runtime
        .service_discovery(&IdentityContext::anonymous(), &default_context(), "fake")
        .unwrap()
        .resources(&ResourceListQuery::default())
        .unwrap();
    assert!(page.resources.iter().all(|row| row.inputs.is_none()));
    assert_eq!(
        serde_json::to_value(&page.coverage).unwrap(),
        json!([{"type": "fake_project", "selector": {"kind": "all"}, "restricted": false}])
    );
}
