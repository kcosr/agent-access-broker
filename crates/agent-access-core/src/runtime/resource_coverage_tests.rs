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
    &[],
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
                ["view", "trigger", "jobs.list", "enumerate", "status"]
                    .into_iter()
                    .map(|action| {
                        let descriptor =
                            ActionDescriptor::new(action, "Fixture action", schema.clone())
                                .credential_modes(["service", "per_user"]);
                        if action == "status" {
                            return descriptor.read_only();
                        }
                        let descriptor = descriptor.scope("job");
                        if action == "enumerate" {
                            descriptor
                                .read_only()
                                .native_search(
                                    agent_access_provider::NativeSearchEnforcement::ResultFiltered,
                                )
                                .listing_of(JOB.id().clone())
                        } else if action != "trigger" {
                            descriptor.read_only()
                        } else {
                            descriptor
                        }
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
    query: ResourceAccessQuery,
) -> ResourceAccessDescription {
    runtime
        .service_discovery(identity, &default_context(), SERVICE)
        .unwrap()
        .resource_access(&query)
        .unwrap()
}

fn action_coverage<'a>(
    page: &'a ResourceAccessDescription,
    action: &str,
) -> &'a [ResourceCoverage] {
    page.access
        .iter()
        .find(|entry| entry.action() == action)
        .unwrap()
        .coverage()
        .unwrap()
}

fn coverage(runtime: &BrokerRuntime, identity: &IdentityContext) -> Value {
    serde_json::to_value(action_coverage(
        &list(runtime, identity, ResourceAccessQuery::default()),
        "view",
    ))
    .unwrap()
}

fn token(resources: ResourceSelection) -> IdentityContext {
    let mut identity = IdentityContext::anonymous();
    identity.source = Some(IdentitySourceAudit {
        read_only_access: None,
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
        inputs: job_inputs(&selector),
        selector,
        restricted,
    }
}

#[test]
fn exact_access_is_independent_of_registered_references() {
    let mut config = config(&["team-ci", "other-ci"]);
    config
        .policy
        .grants
        .push(grant(&["view"], selection(&["build-api"], &[])));
    let runtime = BrokerRuntime::new(config).unwrap();
    let page = list(
        &runtime,
        &IdentityContext::anonymous(),
        ResourceAccessQuery::default(),
    );
    assert_eq!(
        serde_json::to_value(&page).unwrap(),
        json!({
            "service": SERVICE,
            "executionContext": "default",
            "availability": {
                "state": "available", "requirements": [],
                "message": "Required credentials are locally available; upstream access has not been verified."
            },
            "coverageSemantics": "single_target",
            "access": [{
                "action": "view", "scope": "resource", "resourceType": "coverage_job",
                "enforcement": "request",
                "coverage": [{
                    "selector": {"kind": "exact", "value": "team-ci/payments/build-api"},
                    "inputs": {"controller": "team-ci", "job": "payments/build-api"},
                    "restricted": false
                }]
            }],
            "registeredResources": {
                "source": "broker_configuration",
                "items": [{
                    "id": "build-api", "type": "coverage_job", "value": "team-ci/payments/build-api",
                    "inputs": {"controller": "team-ci", "job": "payments/build-api"}
                }],
                "nextCursor": null
            }
        })
    );
    assert_eq!(
        serde_json::from_value::<ResourceAccessDescription>(serde_json::to_value(&page).unwrap())
            .unwrap(),
        page
    );
    let filtered = list(
        &runtime,
        &IdentityContext::anonymous(),
        ResourceAccessQuery {
            prefix: Some("no-match".into()),
            ..Default::default()
        },
    );
    assert_eq!(filtered.access, page.access);
    assert!(filtered.registered_resources.items.is_empty());
}

#[test]
fn actions_keep_distinct_coverage_and_registered_references_follow_action_filter() {
    let mut config = config(&["team-ci", "other-ci", "Not A Root", "team-ci"]);
    config
        .policy
        .grants
        .push(grant(&["view"], selection(&["all-jobs"], &[])));
    config
        .policy
        .grants
        .push(grant(&["trigger"], selection(&["build-api"], &[])));
    let runtime = BrokerRuntime::new(config).unwrap();
    let identity = IdentityContext::anonymous();
    let page = list(&runtime, &identity, ResourceAccessQuery::default());
    assert_eq!(
        action_coverage(&page, "view"),
        [
            entry(namespace("other-ci"), false),
            entry(namespace("team-ci"), false)
        ]
    );
    assert_eq!(
        action_coverage(&page, "trigger"),
        [entry(exact("team-ci/payments/build-api"), false)]
    );
    assert_eq!(page.registered_resources.items.len(), 2);
    let trigger = list(
        &runtime,
        &identity,
        ResourceAccessQuery {
            action: Some("trigger".into()),
            ..Default::default()
        },
    );
    assert_eq!(trigger.access.len(), 1);
    assert_eq!(
        trigger
            .registered_resources
            .items
            .iter()
            .map(|row| row.id.as_str())
            .collect::<Vec<_>>(),
        ["build-api"]
    );
    let context = default_context();
    let discovery = runtime
        .service_discovery(&identity, &context, SERVICE)
        .unwrap();
    for action in ["hidden", "vie", "enumerate"] {
        assert_eq!(
            discovery
                .resource_access(&ResourceAccessQuery {
                    action: Some(action.into()),
                    resource_type: Some(ResourceType::new("unknown_type").unwrap()),
                    ..Default::default()
                })
                .unwrap_err(),
            "action is not available"
        );
    }
    for action in ["", "bad/name", "has space"] {
        assert_eq!(
            discovery
                .resource_access(&ResourceAccessQuery {
                    action: Some(action.into()),
                    ..Default::default()
                })
                .unwrap_err(),
            "action name is invalid"
        );
    }
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
        ResourceAccessQuery::default(),
    );
    assert_eq!(
        action_coverage(&page, "view"),
        [entry(namespace("team-ci/payments"), false)]
    );
    assert_eq!(
        page.registered_resources
            .items
            .iter()
            .map(|row| row.id.as_str())
            .collect::<Vec<_>>(),
        ["build-api", "deploy"]
    );
    config
        .policy
        .grants
        .push(grant(&["view"], selection(&["all-jobs", "gone-ci"], &[])));
    let runtime = BrokerRuntime::new(config.clone()).unwrap();
    assert_eq!(
        action_coverage(
            &list(
                &runtime,
                &IdentityContext::anonymous(),
                ResourceAccessQuery::default()
            ),
            "view"
        ),
        [
            entry(namespace("other-ci"), false),
            entry(namespace("team-ci"), false)
        ]
    );
    config.providers = ProvidersConfig::new(Arc::new(BackendRegistry::new([&BACKEND]).unwrap()))
        .with(FixtureConfig::default());
    let runtime = BrokerRuntime::new(config).unwrap();
    assert_eq!(
        coverage(&runtime, &IdentityContext::anonymous()),
        json!([{"selector": {"kind": "all"}, "restricted": false}])
    );
}

#[test]
fn exclusions_stay_private_and_independent_grants_restore_only_the_same_action() {
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
        .push(grant(&["view", "trigger"], selection(&[], &["visible"])));
    // Exclusion identity remains effective even when its reference is inactive.
    for resource in &mut config.policy.resources {
        if resource.id == "secret-folder" {
            resource.enabled = false;
        }
        if resource.id == "other-ci" {
            resource.allowed_execution_contexts = vec!["external".into()];
        }
    }
    let runtime = BrokerRuntime::new(config.clone()).unwrap();
    let page = list(
        &runtime,
        &IdentityContext::anonymous(),
        ResourceAccessQuery::default(),
    );
    for action in ["view", "trigger"] {
        assert_eq!(
            action_coverage(&page, action),
            [entry(namespace("team-ci"), true)]
        );
    }
    let rendered = serde_json::to_string(&page).unwrap();
    for hidden in ["other-ci", "secret-folder", "excluded", "visible"] {
        assert!(!rendered.contains(hidden), "{rendered}");
    }
    config
        .policy
        .grants
        .push(grant(&["view"], selection(&["other-team"], &[])));
    for resource in &mut config.policy.resources {
        if resource.id == "secret-folder" {
            resource.enabled = true;
        }
    }
    config
        .policy
        .grants
        .push(grant(&["view"], selection(&["secret-folder"], &[])));
    let runtime = BrokerRuntime::new(config).unwrap();
    let page = list(
        &runtime,
        &IdentityContext::anonymous(),
        ResourceAccessQuery::default(),
    );
    assert_eq!(
        action_coverage(&page, "view"),
        [
            entry(namespace("other-ci/team"), false),
            entry(namespace("team-ci"), false)
        ]
    );
    assert_eq!(
        action_coverage(&page, "trigger"),
        [entry(namespace("team-ci"), true)]
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
    let mut valid = config.clone();
    valid.policy.grants.truncate(1);
    config.policy.grants.extend([unusable, served]);
    let runtime = BrokerRuntime::new(valid).unwrap();
    runtime
        .policy_snapshot
        .store(Arc::new(PolicySnapshot::from_config(&config, 1)));
    assert_eq!(
        action_coverage(
            &list(
                &runtime,
                &IdentityContext::anonymous(),
                ResourceAccessQuery::default()
            ),
            "view"
        ),
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
fn token_restrictions_and_contexts_narrow_each_actions_coverage() {
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
    let broad = list(
        &runtime,
        &token(selection(&["payments"], &[])),
        ResourceAccessQuery::default(),
    );
    let restricted = list(
        &runtime,
        &token(selection(&[], &["payments-public"])),
        ResourceAccessQuery::default(),
    );
    for action in ["view", "trigger"] {
        assert_eq!(
            action_coverage(&broad, action),
            [entry(namespace("team-ci/payments"), false)]
        );
        assert_eq!(
            action_coverage(&restricted, action),
            [entry(namespace("team-ci/payments"), true)]
        );
    }
    assert!(
        !serde_json::to_string(&restricted)
            .unwrap()
            .contains("deploy")
    );
    for resource in &mut config.policy.resources {
        if resource.id == "payments" {
            resource.allowed_execution_contexts = vec!["external".into()];
        }
    }
    config.policy.grants = vec![grant(&["view"], selection(&["payments", "build-api"], &[]))];
    let runtime = BrokerRuntime::new(config).unwrap();
    assert_eq!(
        coverage(&runtime, &IdentityContext::anonymous()),
        serde_json::to_value([entry(exact("team-ci/payments/build-api"), false)]).unwrap()
    );
}

#[test]
fn prefix_and_reference_pages_always_preserve_complete_access_metadata() {
    let mut config = config(&["team-ci", "other-ci"]);
    config.policy.grants.push(grant(
        &["view"],
        selection(&["all-jobs", "build-api", "deploy"], &[]),
    ));
    config
        .policy
        .grants
        .push(grant(&["enumerate"], selection(&["payments"], &[])));
    let runtime = BrokerRuntime::new(config).unwrap();
    let identity = IdentityContext::anonymous();
    let first = list(
        &runtime,
        &identity,
        ResourceAccessQuery {
            limit: Some(1),
            ..Default::default()
        },
    );
    for prefix in ["team-ci/payments/b", "team-ci", "o", "team-ci-old", "zz"] {
        let page = list(
            &runtime,
            &identity,
            ResourceAccessQuery {
                prefix: Some(prefix.into()),
                ..Default::default()
            },
        );
        assert_eq!(page.access, first.access, "{prefix}");
        assert_eq!(page.live_listings, first.live_listings, "{prefix}");
    }
    let second = list(
        &runtime,
        &identity,
        ResourceAccessQuery {
            limit: Some(1),
            cursor: first.registered_resources.next_cursor.clone(),
            ..Default::default()
        },
    );
    assert_eq!(
        second.registered_resources.items[0].value,
        "team-ci/payments/deploy"
    );
    assert_eq!(second.access, first.access);
    assert_eq!(second.live_listings, first.live_listings);
    // Changing only the action selection invalidates the reference cursor,
    // even when both selections have the same registered reference rows.
    assert!(
        runtime
            .service_discovery(&identity, &default_context(), SERVICE)
            .unwrap()
            .resource_access(&ResourceAccessQuery {
                action: Some("view".into()),
                limit: Some(1),
                cursor: first.registered_resources.next_cursor,
                ..Default::default()
            })
            .is_err()
    );
}

#[test]
fn compound_only_authority_is_not_misreported_as_unscoped_or_single_target_access() {
    let mut config = config(&[]);
    config
        .policy
        .grants
        .push(grant(&["view"], selection(&["all-jobs"], &[])));
    let runtime = BrokerRuntime::new(config.clone()).unwrap();
    for id in ["build-api", "deploy"] {
        for mode in ["service", "per_user"] {
            let mut competing = grant(&["view"], selection(&[id], &[]));
            competing.priority = Some(10);
            competing.credential_mode = mode.into();
            config.policy.grants.push(competing);
        }
    }
    // Same-band mode conflicts are normally rejected at publication. Exercise
    // the runtime guard and whole-request precedence with an injected policy.
    runtime
        .policy_snapshot
        .store(Arc::new(PolicySnapshot::from_config(&config, 1)));
    let identity = token(selection(&["build-api", "deploy"], &[]));
    let context = default_context();
    let view = runtime
        .service_discovery(&identity, &context, SERVICE)
        .unwrap();
    let page = view
        .resource_access(&ResourceAccessQuery::default())
        .unwrap();
    assert_eq!(page.access.len(), 1);
    assert!(
        matches!(&page.access[0], ActionResourceAccess::Resource { coverage, .. } if coverage.is_empty())
    );
    assert!(page.registered_resources.items.is_empty());
    let parsed = parsed_agent_invoke_token_caveats(&identity).unwrap();
    let clauses = runtime.effective_resource_clauses(
        &runtime.policy_snapshot(),
        &identity,
        &context,
        SERVICE,
        "view",
        parsed.as_ref(),
    );
    let first = "team-ci/payments/build-api";
    let second = "team-ci/payments/deploy";
    assert!(
        !clauses
            .iter()
            .any(|clause| clause.matches(first) || clause.matches(second))
    );
    assert!(
        clauses
            .iter()
            .any(|clause| clause.matches_request(&[first, second]))
    );
    let rendered = serde_json::to_string(&page).unwrap();
    assert!(!rendered.contains("build-api") && !rendered.contains("deploy"));
}

#[test]
fn unscoped_actions_have_an_exact_shape_and_listing_links_need_independent_permission() {
    let mut config = config(&[]);
    config
        .policy
        .grants
        .push(grant(&["view", "jobs.list"], selection(&["all-jobs"], &[])));
    config
        .policy
        .grants
        .push(grant(&["status"], ResourceSelection::default()));
    let runtime = BrokerRuntime::new(config.clone()).unwrap();
    let identity = IdentityContext::anonymous();
    let page = list(&runtime, &identity, ResourceAccessQuery::default());
    assert!(
        page.live_listings.is_empty(),
        "action names must not imply a listing capability"
    );
    let status = page
        .access
        .iter()
        .find(|entry| entry.action() == "status")
        .unwrap();
    assert_eq!(
        serde_json::to_value(status).unwrap(),
        json!({"scope":"unscoped", "action":"status"})
    );
    assert!(
        serde_json::from_value::<ActionResourceAccess>(
            json!({"scope":"unscoped", "action":"status", "coverage":[]})
        )
        .is_err()
    );
    assert_eq!(
        runtime
            .service_discovery(&identity, &default_context(), SERVICE)
            .unwrap()
            .resource_access(&ResourceAccessQuery {
                action: Some("status".into()),
                resource_type: Some(JOB.id().clone()),
                ..Default::default()
            })
            .unwrap_err(),
        "action does not use this resourceType"
    );
    config
        .policy
        .grants
        .push(grant(&["enumerate"], selection(&["build-api"], &[])));
    let runtime = BrokerRuntime::new(config).unwrap();
    let view = list(
        &runtime,
        &identity,
        ResourceAccessQuery {
            action: Some("view".into()),
            ..Default::default()
        },
    );
    assert_eq!(
        view.live_listings,
        [LiveResourceListing {
            service: SERVICE.into(),
            action: "enumerate".into(),
            resource_type: JOB.id().clone()
        }]
    );
    assert!(
        list(
            &runtime,
            &identity,
            ResourceAccessQuery {
                action: Some("status".into()),
                ..Default::default()
            }
        )
        .live_listings
        .is_empty()
    );
    // Token action restrictions hide enumeration even when the described read remains.
    let token_view = list(
        &runtime,
        &token(selection(&["all-jobs"], &[])),
        ResourceAccessQuery::default(),
    );
    assert!(token_view.live_listings.is_empty());
}

#[test]
fn types_without_projection_or_roots_report_plain_references_and_all_access() {
    let mut config = tests::base_fake_config();
    config.policy.grants[0].resources = selection(&["fake-project-all"], &[]);
    let runtime = BrokerRuntime::new(config).unwrap();
    let page = runtime
        .service_discovery(&IdentityContext::anonymous(), &default_context(), "fake")
        .unwrap()
        .resource_access(&ResourceAccessQuery::default())
        .unwrap();
    assert!(
        page.registered_resources
            .items
            .iter()
            .all(|row| row.inputs.is_none())
    );
    assert_eq!(
        serde_json::to_value(page.access[0].coverage().unwrap()).unwrap(),
        json!([{"selector":{"kind":"all"}, "restricted":false}])
    );
}

#[test]
fn restricted_broad_coverage_keeps_useful_narrow_authority() {
    let mut config = config(&[]);
    config
        .policy
        .resources
        .push(resource("other-job", exact("other-ci/ops/run")));
    config.policy.resource_groups = vec![ResourceGroupDefinition {
        id: "public".into(),
        name: "Public jobs".into(),
        included_resource_ids: vec!["all-jobs".into()],
        excluded_resource_ids: vec!["secret-folder".into()],
    }];
    config.policy.grants = vec![
        grant(&["view"], selection(&[], &["public"])),
        grant(&["view"], selection(&["payments"], &[])),
        grant(&["view"], selection(&["build-api", "other-job"], &[])),
    ];
    let runtime = BrokerRuntime::new(config).unwrap();
    let page = list(
        &runtime,
        &IdentityContext::anonymous(),
        ResourceAccessQuery::default(),
    );
    assert_eq!(
        action_coverage(&page, "view"),
        [
            entry(exact("other-ci/ops/run"), false),
            entry(namespace("team-ci/payments"), false),
            entry(ResourceSelector::All, true),
        ]
    );
    assert!(
        !serde_json::to_string(&page)
            .unwrap()
            .contains("secret-folder")
    );
}

#[test]
fn listing_top_band_and_request_fallback_have_distinct_coverage_and_enforcement() {
    let mut config = config(&[]);
    config
        .policy
        .grants
        .push(grant(&["view", "enumerate"], selection(&["all-jobs"], &[])));
    let mut higher = grant(&["view", "enumerate"], selection(&["build-api"], &[]));
    higher.priority = Some(10);
    config.policy.grants.push(higher);
    let runtime = BrokerRuntime::new(config).unwrap();
    let page = list(
        &runtime,
        &IdentityContext::anonymous(),
        ResourceAccessQuery::default(),
    );
    assert_eq!(
        action_coverage(&page, "view"),
        [entry(ResourceSelector::All, false)]
    );
    assert_eq!(
        action_coverage(&page, "enumerate"),
        [entry(exact("team-ci/payments/build-api"), false)]
    );
    assert!(matches!(
        page.access
            .iter()
            .find(|entry| entry.action() == "view")
            .unwrap(),
        ActionResourceAccess::Resource {
            enforcement: ResourceAccessEnforcement::Request,
            ..
        }
    ));
    assert!(matches!(
        page.access
            .iter()
            .find(|entry| entry.action() == "enumerate")
            .unwrap(),
        ActionResourceAccess::Resource {
            enforcement: ResourceAccessEnforcement::Results,
            ..
        }
    ));
    assert_eq!(page.live_listings.len(), 1);
}

#[test]
fn large_exact_authority_remains_complete_while_references_are_paginated() {
    const COUNT: usize = 256;
    let mut config = config(&[]);
    config.policy.resources = (0..COUNT)
        .map(|index| {
            resource(
                &format!("job-{index:04}"),
                exact(&format!("team-ci/jobs/job-{index:04}")),
            )
        })
        .collect();
    config.policy.grants.push(grant(
        &["view"],
        ResourceSelection {
            resource_ids: config
                .policy
                .resources
                .iter()
                .map(|resource| resource.id.clone())
                .collect(),
            resource_group_ids: Vec::new(),
        },
    ));
    let runtime = BrokerRuntime::new(config).unwrap();
    let identity = IdentityContext::anonymous();
    let first = list(
        &runtime,
        &identity,
        ResourceAccessQuery {
            limit: Some(2),
            ..Default::default()
        },
    );
    let coverage = action_coverage(&first, "view");
    assert_eq!(coverage.len(), COUNT);
    assert!(coverage.iter().all(
        |entry| matches!(entry.selector, ResourceSelector::Exact { .. }) && !entry.restricted
    ));
    assert_eq!(
        coverage.last().unwrap().selector,
        exact("team-ci/jobs/job-0255")
    );
    assert_eq!(first.registered_resources.items.len(), 2);
    let second = list(
        &runtime,
        &identity,
        ResourceAccessQuery {
            limit: Some(2),
            cursor: first.registered_resources.next_cursor.clone(),
            ..Default::default()
        },
    );
    assert_eq!(second.access, first.access);
    assert_eq!(second.registered_resources.items[0].id, "job-0002");
}
