//! Namespace search uses one global grant band across invocation and discovery.
use super::*;
use crate::{BackendRegistry, ProvidersConfig};
use async_trait::async_trait;
use std::sync::atomic::AtomicUsize;

const SERVICE: &str = "namespace_search_fixture";
const ACTION: &str = "search";

static BACKEND: BackendRegistration = BackendRegistration::new(
    agent_access_provider::module_metadata!(),
    SERVICE,
    parse_backend_config::<FixtureConfig>,
)
.development_only();

#[derive(Debug, Clone, Default, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct FixtureConfig {
    #[serde(skip)]
    calls: Arc<AtomicUsize>,
}

impl BackendConfig for FixtureConfig {
    fn kind(&self) -> &'static str {
        SERVICE
    }

    fn validate(&self, _: &ValidationContext<'_>, _: &mut Vec<String>) {}

    fn descriptor(&self) -> ServiceDescriptor {
        ServiceDescriptor::new(SERVICE, "Namespace search fixture")
            .with_resource_scopes(BTreeMap::from([(
                "repository".into(),
                ResourceScopeCapabilities::new(
                    GIT_REPOSITORY_RESOURCE.id().clone(),
                    vec!["exact".into(), "namespace".into(), "all".into()],
                ),
            )]))
            .with_actions(vec![
                ActionDescriptor::new(
                    ACTION,
                    "Exercise namespace search authority",
                    json!({"type": "object", "additionalProperties": false}),
                )
                .scope("repository")
                .credential_modes(["service", "per_user"])
                .native_search(NativeSearchEnforcement::ResultFiltered)
                .read_only(),
            ])
            .with_credentials(CredentialDescriptor::without_execution_credential())
    }

    fn egress_proxies(&self) -> Vec<(String, &EgressProxyConfig)> {
        vec![]
    }

    fn build(&self, _: &BuildContext<'_>) -> Result<Arc<dyn Provider>, ProviderBuildError> {
        Ok(Arc::new(self.clone()))
    }
}

#[async_trait]
impl Provider for FixtureConfig {
    async fn resolve_scopes(&self, _: ScopeRequest<'_>) -> Result<ScopeResolution, ProviderError> {
        panic!("native search must use the planner instead of ordinary scope resolution")
    }

    async fn invoke(&self, request: ProviderInvocation) -> Result<ProviderResult, ProviderError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        let search = request
            .search_authorization()
            .expect("result-filtered search must carry the complete admitted authority");
        Ok(ProviderResult::new(json!({
            "scope": search.scope,
            "scopeType": search.scope_type,
            "credentialMode": request.credential_mode(),
        })))
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

fn context() -> ExecutionContext {
    ExecutionContext::new("default").unwrap()
}

fn resource(id: &str, selector: ResourceSelector) -> ResourceDefinition {
    ResourceDefinition {
        id: id.into(),
        display_name: None,
        resource_type: GIT_REPOSITORY_RESOURCE.id().clone(),
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

fn grant(
    subject: &str,
    priority: i32,
    mode: &str,
    resources: ResourceSelection,
) -> PolicyGrantConfig {
    PolicyGrantConfig {
        subjects: vec![subject.into()],
        service: SERVICE.into(),
        actions: vec![ACTION.into()],
        resources,
        execution_contexts: Some(vec!["default".into()]),
        credential_mode: mode.into(),
        priority: Some(priority),
    }
}

fn group(id: &str, included: &[&str], excluded: &[&str]) -> ResourceGroupDefinition {
    ResourceGroupDefinition {
        id: id.into(),
        name: id.into(),
        included_resource_ids: included.iter().map(|id| (*id).into()).collect(),
        excluded_resource_ids: excluded.iter().map(|id| (*id).into()).collect(),
    }
}

fn config() -> (BrokerConfig, Arc<AtomicUsize>) {
    let mut config = tests::base_fake_config();
    config.credentials = Default::default();
    config.policy.grants.clear();
    config.policy.resource_groups.clear();
    config.execution_context = Some(crate::ExecutionContextConfig {
        allowed_values: vec!["default".into(), "external".into()],
        default_context: None,
    });
    config.policy.resources = vec![
        resource("all", ResourceSelector::All),
        resource("engineering", namespace("engineering")),
        resource("private", namespace("engineering/private")),
        resource("public-tool", exact("engineering/public/tool")),
        resource("private-tool", exact("engineering/private/tool")),
        resource("secret", namespace("engineering/private/secret")),
        resource("secret-copy", exact("engineering/private/secret/tool")),
        resource("labs", namespace("labs")),
        resource("labs-tool", exact("labs/tool")),
        resource("sibling-tool", exact("engineering2/tool")),
    ];
    let calls = Arc::new(AtomicUsize::new(0));
    config.providers = ProvidersConfig::new(Arc::new(BackendRegistry::new([&BACKEND]).unwrap()))
        .with(FixtureConfig {
            calls: Arc::clone(&calls),
        });
    (config, calls)
}

fn operation(identity: IdentityContext) -> GovernedOperationContext {
    GovernedOperationContext {
        operation: OperationContext {
            agent_request_id: "namespace-search-test-agent".into(),
            broker_request_id: "namespace-search-test-broker".into(),
            identity,
            service: SERVICE.into(),
            action: ACTION.into(),
            source: SourceContext::unknown(),
        },
        execution_context: context(),
    }
}

fn caveats(resources: ResourceSelection) -> AgentInvokeTokenCaveats {
    AgentInvokeTokenCaveats {
        allowed_services: Some(vec![SERVICE.into()]),
        allowed_execution_contexts: Some(vec![context()]),
        service_restrictions: Some(BTreeMap::from([(
            SERVICE.into(),
            crate::AgentTokenServiceRestriction {
                actions: vec![ACTION.into()],
                resources: Some(resources),
            },
        )])),
    }
}

fn token(caveats: &AgentInvokeTokenCaveats) -> IdentityContext {
    let mut identity = IdentityContext::anonymous();
    identity.source = Some(IdentitySourceAudit {
        read_only_access: None,
        namespace: None,
        binding_id: None,
        name: "namespace-search-token".into(),
        kind: "broker_tokens".into(),
        token_header: "Authorization".into(),
        token_scheme: "Bearer".into(),
        token_class: Some(BrokerTokenClass::AgentInvoke),
        token_id: Some("namespace-search-token".into()),
        token_scopes: Some(caveats.to_scopes_value()),
    });
    identity
}

fn plan(runtime: &BrokerRuntime) -> Result<SearchAuthorizationPlan, ProviderError> {
    runtime.plan_search_authorization(
        &runtime.policy_snapshot(),
        &IdentityContext::anonymous(),
        &context(),
        SERVICE,
        ACTION,
    )
}

fn effective(
    runtime: &BrokerRuntime,
    token: Option<&AgentInvokeTokenCaveats>,
) -> Vec<EffectiveAccessClause> {
    let token = token.map(|caveats| ParsedAgentInvokeTokenCaveats {
        token_id: None,
        caveats: caveats.clone(),
        read_only_access: false,
    });
    runtime.effective_resource_clauses_for_modes(
        &runtime.policy_snapshot(),
        &IdentityContext::anonymous(),
        &context(),
        SERVICE,
        ACTION,
        token.as_ref(),
        |_| true,
    )
}

fn returned_scope(envelope: &Value) -> SearchAuthorizationScope {
    serde_json::from_value(envelope["result"]["scope"].clone()).unwrap()
}

#[tokio::test]
async fn namespace_search_selects_the_global_subject_rank_then_priority_band() {
    for (winner_subject, winner_priority, loser_priority) in
        [("user:anonymous", 0, 100), ("group:anonymous", 10, 0)]
    {
        let (mut config, calls) = config();
        config.policy.grants = vec![
            grant(
                "group:anonymous",
                loser_priority,
                "service",
                selection(&["labs"], &[]),
            ),
            grant(
                winner_subject,
                winner_priority,
                "service",
                selection(&["engineering"], &[]),
            ),
        ];
        let runtime = BrokerRuntime::new(config).unwrap();
        let selected = plan(&runtime).unwrap();
        assert_eq!(selected.matched_grants.len(), 1);
        assert_eq!(selected.matched_grants[0].subject, winner_subject);
        assert_eq!(selected.matched_grants[0].priority, Some(winner_priority));
        assert!(selected.scope.matches("engineering/new/tool"));
        assert!(!selected.scope.matches("labs/tool"));
        let response = runtime
            .invoke(
                operation(IdentityContext::anonymous()),
                InvokeRequest::new(json!({})),
            )
            .await;
        assert_eq!(response.status, 200);
        let envelope = serde_json::to_value(response.envelope).unwrap();
        assert_eq!(returned_scope(&envelope), selected.scope);
        assert_eq!(envelope["resourceScopes"], json!({"repository": ["*"]}));
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }
}

#[tokio::test]
async fn empty_disabled_and_context_ineligible_candidates_are_removed_before_ranking() {
    for unavailable in ["empty", "disabled", "external"] {
        let (mut config, calls) = config();
        config.policy.grants = vec![grant(
            "group:anonymous",
            0,
            "service",
            selection(&["labs"], &[]),
        )];
        let mut high = grant(
            "user:anonymous",
            100,
            "service",
            selection(&["engineering"], &[]),
        );
        if unavailable == "empty" {
            high.resources = ResourceSelection::default();
        } else {
            let resource = config
                .policy
                .resources
                .iter_mut()
                .find(|resource| resource.id == "engineering")
                .unwrap();
            if unavailable == "disabled" {
                resource.enabled = false;
            } else {
                resource.allowed_execution_contexts = vec!["external".into()];
            }
        }
        let runtime = BrokerRuntime::new(config.clone()).unwrap();
        // An empty authored selection is rejected at configuration admission;
        // inject that case to exercise the runtime's defensive candidate filter.
        config.policy.grants.push(high);
        runtime
            .policy_snapshot
            .store(Arc::new(PolicySnapshot::from_config(&config, 1)));
        let selected = plan(&runtime).unwrap();
        assert!(selected.scope.matches("labs/tool"), "{unavailable}");
        assert!(!selected.scope.matches("engineering/tool"), "{unavailable}");
        assert_eq!(selected.matched_grants.len(), 1);
        assert_eq!(selected.matched_grants[0].subject, "group:anonymous");
        let response = runtime
            .invoke(
                operation(IdentityContext::anonymous()),
                InvokeRequest::new(json!({})),
            )
            .await;
        assert_eq!(response.status, 200, "{unavailable}");
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }
}

#[tokio::test]
async fn mixed_modes_in_disjoint_top_namespace_grants_deny_the_whole_search() {
    let (mut config, calls) = config();
    config.policy.grants = vec![grant(
        "group:anonymous",
        0,
        "service",
        selection(&["all"], &[]),
    )];
    let runtime = BrokerRuntime::new(config.clone()).unwrap();
    // Install the unavailable personal mode after validation to prove mixed-mode
    // denial happens before credentials or a lower band's broad authority.
    config.policy.grants.extend([
        grant(
            "group:anonymous",
            10,
            "service",
            selection(&["engineering"], &[]),
        ),
        grant("group:anonymous", 10, "per_user", selection(&["labs"], &[])),
    ]);
    runtime
        .policy_snapshot
        .store(Arc::new(PolicySnapshot::from_config(&config, 1)));
    assert_eq!(
        plan(&runtime).unwrap_err().reason_code(),
        ReasonCode::ServiceActionDenied
    );
    assert!(effective(&runtime, None).is_empty());
    assert!(
        runtime
            .visible_services(&IdentityContext::anonymous(), &context())
            .is_empty()
    );
    let options = runtime.agent_token_options_for_identity(&IdentityContext::anonymous());
    assert!(
        options.services[0].actions[0].effective_access_by_execution_context[&context()].is_empty()
    );
    let response = runtime
        .invoke(
            operation(IdentityContext::anonymous()),
            InvokeRequest::new(json!({})),
        )
        .await;
    assert_eq!(
        response.envelope.reason_code,
        Some(ReasonCode::ServiceActionDenied.into())
    );
    assert_eq!(calls.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn selected_unsupported_or_unconfigured_mode_never_reveals_a_lower_band() {
    for unsupported in [false, true] {
        let (mut config, calls) = config();
        config.policy.grants = vec![grant(
            "group:anonymous",
            0,
            "service",
            selection(&["all"], &[]),
        )];
        let mut runtime = BrokerRuntime::new(config.clone()).unwrap();
        config.policy.grants.push(grant(
            "user:anonymous",
            10,
            "per_user",
            selection(&["engineering"], &[]),
        ));
        runtime
            .policy_snapshot
            .store(Arc::new(PolicySnapshot::from_config(&config, 1)));
        if unsupported {
            // Simulate descriptor drift at the defensive runtime boundary.
            let mut services = (*runtime.services).clone();
            let mut descriptor = (*services[SERVICE]).clone();
            descriptor.actions[0].credential_modes = vec!["service".into()];
            services.insert(SERVICE.into(), Arc::new(descriptor));
            runtime.services = Arc::new(services);
        }
        assert_eq!(
            plan(&runtime).unwrap_err().reason_code(),
            ReasonCode::CredentialNotProvisioned
        );
        assert!(effective(&runtime, None).is_empty());
        let response = runtime
            .invoke(
                operation(IdentityContext::anonymous()),
                InvokeRequest::new(json!({})),
            )
            .await;
        assert_eq!(
            response.envelope.reason_code,
            Some(ReasonCode::CredentialNotProvisioned.into())
        );
        assert_eq!(calls.load(Ordering::SeqCst), 0);
    }
}

#[test]
fn credential_availability_filters_the_selected_band_without_selecting_a_lower_mode() {
    let (mut config, _) = config();
    config.policy.grants = vec![grant(
        "group:anonymous",
        10,
        "service",
        selection(&["engineering"], &[]),
    )];
    let mut runtime = BrokerRuntime::new(config.clone()).unwrap();
    let lower = grant("group:anonymous", 0, "per_user", selection(&["labs"], &[]));
    config.policy.grants.push(lower.clone());
    runtime
        .policy_snapshot
        .store(Arc::new(PolicySnapshot::from_config(&config, 1)));
    // Planning tests need a configured personal mode, but never obtain a secret.
    let mut credentials = (*runtime.effective_credentials).clone();
    credentials.per_user.insert(
        SERVICE.into(),
        CredentialConfig {
            kind: "connection".into(),
            provider: None,
            connection: Some("fixture-personal".into()),
            profile: None,
            username_ref: None,
            token_ref: None,
            path: None,
            read_only: None,
        },
    );
    runtime.effective_credentials = Arc::new(credentials);
    let filtered = |snapshot: &PolicySnapshot| {
        runtime.effective_resource_clauses_for_modes(
            snapshot,
            &IdentityContext::anonymous(),
            &context(),
            SERVICE,
            ACTION,
            None,
            |mode| mode == "per_user",
        )
    };
    assert!(filtered(&runtime.policy_snapshot()).is_empty());
    assert!(plan(&runtime).unwrap().scope.matches("engineering/tool"));
    // The lower mode really is eligible in isolation, so the denial above is
    // precedence preservation rather than an independently unusable fallback.
    config.policy.grants = vec![lower];
    assert!(
        filtered(&PolicySnapshot::from_config(&config, 2))
            .iter()
            .any(|clause| clause.matches("labs/tool"))
    );
}

#[tokio::test]
async fn token_empties_the_selected_namespace_band_without_falling_back() {
    let (mut config, calls) = config();
    config.policy.grants = vec![
        grant("group:anonymous", 0, "service", selection(&["all"], &[])),
        grant(
            "user:anonymous",
            0,
            "service",
            selection(&["engineering"], &[]),
        ),
    ];
    let runtime = BrokerRuntime::new(config).unwrap();
    let caveats = caveats(selection(&["labs"], &[]));
    let identity = token(&caveats);
    let mut selected = plan(&runtime).unwrap();
    assert!(selected.scope.matches("engineering/tool"));
    assert_eq!(
        runtime
            .intersect_agent_invoke_token_search_authorization(
                &identity,
                SERVICE,
                ACTION,
                &mut selected
            )
            .unwrap_err()
            .reason_code(),
        ReasonCode::ServiceActionDenied
    );
    assert!(effective(&runtime, Some(&caveats)).is_empty());
    assert!(
        runtime
            .preview_agent_token_access(&IdentityContext::anonymous(), &caveats)
            .unwrap()
            .access
            .is_empty()
    );
    assert!(runtime.visible_services(&identity, &context()).is_empty());
    let response = runtime
        .invoke(operation(identity), InvokeRequest::new(json!({})))
        .await;
    assert_eq!(
        response.envelope.reason_code,
        Some(ReasonCode::ServiceActionDenied.into())
    );
    assert_eq!(calls.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn inactive_exclusions_persist_and_an_independent_exact_grant_restores_one_repository() {
    for exclusion_state in ["disabled", "external"] {
        let (mut config, calls) = config();
        let exclusion = config
            .policy
            .resources
            .iter_mut()
            .find(|resource| resource.id == "private")
            .unwrap();
        if exclusion_state == "disabled" {
            exclusion.enabled = false;
        } else {
            exclusion.allowed_execution_contexts = vec!["external".into()];
        }
        config.policy.resource_groups = vec![group("public", &["engineering"], &["private"])];
        config.policy.grants = vec![
            grant("group:anonymous", 0, "service", selection(&[], &["public"])),
            grant(
                "group:anonymous",
                0,
                "service",
                selection(&["private-tool"], &[]),
            ),
        ];
        let runtime = BrokerRuntime::new(config).unwrap();
        let selected = plan(&runtime).unwrap();
        for (path, allowed) in [
            ("engineering/public/tool", true),
            ("engineering/private/tool", true),
            ("engineering/private/secret/tool", false),
            ("engineering/private/tool/child", false),
            ("engineering2/tool", false),
        ] {
            assert_eq!(
                selected.scope.matches(path),
                allowed,
                "{exclusion_state}: {path}"
            );
            assert_eq!(
                effective(&runtime, None)
                    .iter()
                    .any(|clause| clause.matches(path)),
                allowed
            );
        }
        let unrestricted_caveats = caveats(selection(&["engineering"], &[]));
        let response = runtime
            .invoke(
                operation(token(&unrestricted_caveats)),
                InvokeRequest::new(json!({})),
            )
            .await;
        assert_eq!(response.status, 200, "{exclusion_state}");
        assert_eq!(
            returned_scope(&serde_json::to_value(response.envelope).unwrap()),
            selected.scope
        );
        assert_eq!(calls.load(Ordering::SeqCst), 1);

        // Within one token selection its group exclusion also applies to the
        // separately selected exact entry, even when that exclusion is inactive.
        let restricted_caveats = caveats(selection(&["private-tool"], &["public"]));
        let response = runtime
            .invoke(
                operation(token(&restricted_caveats)),
                InvokeRequest::new(json!({})),
            )
            .await;
        assert_eq!(response.status, 200, "{exclusion_state}");
        let narrowed = returned_scope(&serde_json::to_value(response.envelope).unwrap());
        assert!(narrowed.matches("engineering/public/tool"));
        assert!(!narrowed.matches("engineering/private/tool"));
        assert!(
            effective(&runtime, Some(&restricted_caveats))
                .iter()
                .all(|clause| !clause.matches("engineering/private/tool"))
        );
        assert_eq!(calls.load(Ordering::SeqCst), 2);
    }
}

#[tokio::test]
async fn catalog_preview_picker_and_invocation_agree_on_union_coverage_holes() {
    for restore_secret in [false, true] {
        let (mut config, calls) = config();
        config.policy.resource_groups = vec![
            group("public", &["engineering"], &["private"]),
            group("private-except-secret", &["private"], &["secret"]),
            group("unreferenced-secret", &["secret-copy"], &[]),
        ];
        config.policy.grants = vec![
            grant("group:anonymous", 0, "service", selection(&[], &["public"])),
            grant(
                "group:anonymous",
                0,
                "service",
                selection(&[], &["private-except-secret"]),
            ),
        ];
        if restore_secret {
            config.policy.grants.push(grant(
                "group:anonymous",
                0,
                "service",
                selection(&["secret"], &[]),
            ));
        }
        let runtime = BrokerRuntime::new(config).unwrap();
        let identity = IdentityContext::anonymous();
        let selected = plan(&runtime).unwrap();
        assert_eq!(
            selected.scope.covers(&namespace("engineering")),
            restore_secret
        );
        let catalog = runtime
            .service_discovery(&identity, &context(), SERVICE)
            .unwrap()
            .resources(&ResourceListQuery::default())
            .unwrap();
        assert_eq!(catalog.coverage.len(), 1);
        assert_eq!(catalog.coverage[0].selector, namespace("engineering"));
        assert_eq!(catalog.coverage[0].restricted, !restore_secret);
        let visible_ids = catalog
            .resources
            .iter()
            .map(|resource| resource.id.as_str())
            .collect::<BTreeSet<_>>();
        assert!(visible_ids.contains("public-tool"));
        assert!(visible_ids.contains("private-tool"));
        assert_eq!(visible_ids.contains("secret-copy"), restore_secret);
        assert!(!visible_ids.contains("sibling-tool"));
        assert!(!visible_ids.contains("labs-tool"));

        let options = runtime.agent_token_options_for_identity(&identity);
        let picker_clauses =
            &options.services[0].actions[0].effective_access_by_execution_context[&context()];
        assert_eq!(
            options
                .resources
                .iter()
                .any(|resource| resource.id == "secret-copy"),
            restore_secret
        );
        assert_eq!(
            options
                .resource_groups
                .iter()
                .any(|group| group.id == "unreferenced-secret"),
            restore_secret
        );
        // Authored exclusions stay selectable; they are not a claim of access.
        assert!(
            options
                .resources
                .iter()
                .any(|resource| resource.id == "secret")
        );
        let caveats = caveats(selection(&["engineering"], &[]));
        let preview = runtime
            .preview_agent_token_access(&identity, &caveats)
            .unwrap();
        assert_eq!(preview.access.len(), 1);
        let response = runtime
            .invoke(operation(token(&caveats)), InvokeRequest::new(json!({})))
            .await;
        assert_eq!(response.status, 200);
        let invoked = returned_scope(&serde_json::to_value(response.envelope).unwrap());
        for (path, allowed) in [
            ("engineering/public/tool", true),
            ("engineering/private/tool", true),
            ("engineering/private/secret/tool", restore_secret),
            ("engineering2/tool", false),
            ("labs/tool", false),
        ] {
            assert_eq!(selected.scope.matches(path), allowed, "planner: {path}");
            assert_eq!(
                effective(&runtime, Some(&caveats))
                    .iter()
                    .any(|clause| clause.matches(path)),
                allowed,
                "effective: {path}"
            );
            assert_eq!(
                picker_clauses.iter().any(|clause| clause.matches(path)),
                allowed,
                "picker: {path}"
            );
            assert_eq!(
                preview.access[0]
                    .clauses
                    .iter()
                    .any(|clause| clause.matches(path)),
                allowed,
                "preview: {path}"
            );
            assert_eq!(invoked.matches(path), allowed, "invocation: {path}");
        }
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }
}
