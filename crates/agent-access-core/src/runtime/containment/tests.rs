//! A native backend unknown to core proves the policy boundary without relying
//! on Confluence's URL grammar, metadata adapter or network fixtures.
use super::*;
use crate::{BackendRegistry, ProvidersConfig};
use async_trait::async_trait;
use std::sync::atomic::AtomicUsize;

const SERVICE: &str = "location_fixture";
const ORIGIN: &str = "https://docs.example.test";
fn area_type() -> ResourceType {
    ResourceType::from_static("location_area")
}
fn content_type() -> ResourceType {
    ResourceType::from_static("location_content")
}
fn area(value: &str) -> bool {
    !value.is_empty() && value.len() <= 20 && value.bytes().all(|byte| byte.is_ascii_uppercase())
}
fn coordinates(value: &str) -> Result<ResourceSelectorProjection, LocationNormalizationError> {
    let invalid = || LocationNormalizationError::new("selector", "invalid fixture locator");
    let url = Url::parse(value).map_err(|_| invalid())?;
    let parts: Vec<_> = url.path().split('/').collect();
    if parts.len() != 5
        || parts[1] != "s"
        || !area(parts[2])
        || !matches!(parts[3], "document" | "directory" | "journal")
        || parts[4].is_empty()
        || parts[4].starts_with('0')
        || !parts[4].bytes().all(|byte| byte.is_ascii_digit())
        || url.query().is_some()
        || url.fragment().is_some()
        || url.as_str() != value
    {
        return Err(invalid());
    }
    Ok(ResourceSelectorProjection::new(
        url.origin().ascii_serialization(),
        parts[3],
        vec![ResourceContainer::new(area_type(), parts[2])],
    ))
}
fn project(
    selector: &ResourceSelector,
) -> Result<ResourceSelectorProjection, LocationNormalizationError> {
    coordinates(
        selector.value().ok_or_else(|| {
            LocationNormalizationError::new("selector", "missing fixture locator")
        })?,
    )
}
static AREA: ResourceTypeDescriptor = ResourceTypeDescriptor::new(
    ResourceType::from_static("location_area"),
    "Area",
    "Areas",
    "ENG",
    area,
    &[],
);
static CONTENT: ResourceTypeDescriptor = ResourceTypeDescriptor::new(
    ResourceType::from_static("location_content"),
    "Content",
    "Contents",
    "https://docs.example.test/s/ENG/document/1",
    |value| coordinates(value).is_ok(),
    &[],
)
.with_supports_all(false)
.with_exact_validator(|value| {
    coordinates(value)
        .is_ok_and(|projection| matches!(projection.root_kind.as_str(), "document" | "journal"))
})
.with_subtree(SubtreeSelectorDescriptor::new(
    |value| {
        coordinates(value).is_ok_and(|projection| {
            matches!(projection.root_kind.as_str(), "document" | "directory")
        })
    },
    "Subtree",
    "Members",
    "https://docs.example.test/s/ENG/directory/10",
))
.with_selector_projection(project);
static BACKEND: BackendRegistration = BackendRegistration::new(
    agent_access_provider::module_metadata!(),
    SERVICE,
    parse_backend_config::<Fixture>,
)
.with_resource_types(&[&AREA, &CONTENT])
.development_only();

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct Fixture {
    #[serde(skip)]
    state: Arc<Mutex<FixtureState>>,
    #[serde(skip)]
    local_calls: Arc<AtomicUsize>,
    #[serde(skip)]
    scope_calls: Arc<AtomicUsize>,
    #[serde(skip)]
    invoke_calls: Arc<AtomicUsize>,
}
#[derive(Debug, Default)]
struct FixtureState {
    evidence: Option<ContainmentEvidence>,
    candidates: Vec<ContentLocation>,
    invalid_locator: bool,
    omit_state: bool,
    initial_failure: bool,
    final_failure: bool,
    initial_root_failure: bool,
    final_root_failure: bool,
    requested_level: Option<ContainmentEvidenceLevel>,
    roots: usize,
}

fn contract(
    domain: &str,
    target: &str,
    effects: Vec<ContainmentEffect>,
) -> ContainmentScopeCapabilities {
    ContainmentScopeCapabilities::new(
        domain,
        BTreeMap::from([
            (area_type(), vec!["exact".into(), "all".into()]),
            (content_type(), vec!["exact".into(), "subtree".into()]),
        ]),
        vec![area_type()],
        vec![target.into()],
        if target == "journal" {
            Vec::new()
        } else {
            vec!["document".into(), "directory".into()]
        },
        effects,
    )
}
impl BackendConfig for Fixture {
    fn kind(&self) -> &'static str {
        SERVICE
    }
    fn validate(&self, _: &ValidationContext<'_>, _: &mut Vec<String>) {}
    fn descriptor(&self) -> ServiceDescriptor {
        let action = |name: &str, scope: &str| {
            ActionDescriptor::new(
                name,
                "Fixture action",
                json!({"type":"object","properties":{},"additionalProperties":false}),
            )
            .scope(scope)
            .credential_modes(["service", "per_user"])
        };
        ServiceDescriptor::new(SERVICE, "Content location fixture")
            .with_upstream_authority(UpstreamAuthority::from_base_url(ORIGIN).unwrap())
            .with_resource_scopes(BTreeMap::from([
                (
                    "area".into(),
                    ResourceScopeCapabilities::new(area_type(), vec!["exact".into(), "all".into()]),
                ),
                (
                    "document_location".into(),
                    ResourceScopeCapabilities::containment(contract(
                        "document",
                        "document",
                        vec![ContainmentEffect::Content],
                    )),
                ),
                (
                    "journal_location".into(),
                    ResourceScopeCapabilities::containment(contract(
                        "journal",
                        "journal",
                        vec![ContainmentEffect::Content],
                    )),
                ),
                (
                    "document_destination".into(),
                    ResourceScopeCapabilities::containment(contract(
                        "document_destination",
                        "document",
                        vec![ContainmentEffect::ChildPlacement],
                    )),
                ),
                (
                    "document_move".into(),
                    ResourceScopeCapabilities::containment(contract(
                        "document_move",
                        "document",
                        vec![
                            ContainmentEffect::Content,
                            ContainmentEffect::ChildPlacement,
                            ContainmentEffect::SubtreeImpact,
                        ],
                    )),
                ),
            ]))
            .with_actions(vec![
                action("view", "document_location")
                    .read_only()
                    .lookup(LookupRequirement::ScopeResolution),
                action("update", "document_location").lookup(LookupRequirement::ScopeResolution),
                action("create", "document_destination").lookup(LookupRequirement::ScopeResolution),
                action("move", "document_move").lookup(LookupRequirement::ScopeResolution),
                action("handle", "document_location")
                    .read_only()
                    .lookup(LookupRequirement::ScopeResolution)
                    .scope_locator_validation(),
                action("search", "document_location")
                    .read_only()
                    .native_search(NativeSearchEnforcement::ResultFiltered),
                action("journal.search", "journal_location")
                    .read_only()
                    .native_search(NativeSearchEnforcement::ResultFiltered),
                action("universal", "document_location")
                    .read_only()
                    .reports_universal_reach()
                    .lookup(LookupRequirement::ScopeResolution),
                action("with.companion", "document_location")
                    .read_only()
                    .companion_read("view")
                    .lookup(LookupRequirement::ScopeResolution),
            ])
    }
    fn egress_proxies(&self) -> Vec<(String, &EgressProxyConfig)> {
        Vec::new()
    }
    fn build(&self, _: &BuildContext<'_>) -> Result<Arc<dyn Provider>, ProviderBuildError> {
        Ok(Arc::new(self.clone()))
    }
}
#[async_trait]
impl Provider for Fixture {
    fn validate_scope_locator(
        &self,
        _: LocalScopeRequest<'_>,
    ) -> Result<Option<ProviderState>, ProviderError> {
        self.local_calls.fetch_add(1, Ordering::SeqCst);
        if self.state.lock().unwrap().invalid_locator {
            return Err(ProviderError::deny(
                ReasonCode::InvalidDraftHandle,
                "fixture handle is invalid",
            )
            .with_result(json!({"private":"not releasable"}))
            .with_audit(json!({"private":"not auditable"})));
        }
        Ok(Some(ProviderState::new(())))
    }
    async fn resolve_scopes(
        &self,
        request: ScopeRequest<'_>,
    ) -> Result<ScopeResolution, ProviderError> {
        self.scope_calls.fetch_add(1, Ordering::SeqCst);
        let mut state = self.state.lock().unwrap();
        state.requested_level = Some(request.containment_evidence_level());
        state.roots = request.containment_roots().len();
        if state.initial_root_failure {
            return Err(ProviderError::deny(ReasonCode::ScopeUnresolved, "private upstream root failure")
                .with_result(json!({"private":"root-result"}))
                .with_audit(json!({"private":"root-audit", "locationProof": {
                    "finalCheck":"unresolved", "diagnostic":"confluence_move_relation_unresolved", "category":"not_visible_or_absent"
                }})));
        }
        if state.initial_failure {
            return Err(ProviderError::deny(
                ReasonCode::ScopeUnresolved,
                "fixture lookup failed",
            ));
        }
        let evidence = state.evidence.clone().ok_or_else(|| {
            ProviderError::deny(ReasonCode::ScopeUnresolved, "fixture has no target")
        })?;
        let result = ScopeResolution::containment(evidence);
        Ok(if state.omit_state {
            result
        } else {
            result.with_state(ProviderState::new(()))
        })
    }
    async fn invoke(&self, request: ProviderInvocation) -> Result<ProviderResult, ProviderError> {
        self.invoke_calls.fetch_add(1, Ordering::SeqCst);
        let state = self.state.lock().unwrap();
        if state.final_root_failure {
            return Err(ProviderError::deny(ReasonCode::ScopeUnresolved, "relevant root unavailable")
                .with_audit(json!({"locationProof": {
                    "finalCheck":"unresolved", "diagnostic":"confluence_move_relation_unresolved", "category":"not_visible_or_absent"
                }})));
        }
        if state.final_failure {
            return Err(ProviderError::deny(
                ReasonCode::ScopeUnresolved,
                "fixture location changed",
            )
            .with_audit(json!({"locationProof":{"finalCheck":"changed"}})));
        }
        let result = if let Ok(authority) = request.containment_collection_authorization() {
            let admitted = state
                .candidates
                .iter()
                .map(|candidate| authority.matches_candidate(candidate))
                .collect::<Result<Vec<_>, _>>()?;
            json!({"admitted":admitted,"level":authority.evidence_level()})
        } else {
            let authority = request.containment_authorization().unwrap();
            authority.check_same_location(authority.evidence())?;
            json!({"level":authority.evidence_level(),"universal":request.universal_reach(),"companion":request.companion_reads_authorized()})
        };
        Ok(ProviderResult::new(result)
            .with_audit(json!({"locationProof":{"finalCheck":"matched"}})))
    }
}

fn context() -> ExecutionContext {
    ExecutionContext::new("default").unwrap()
}
fn identity() -> IdentityContext {
    let mut identity = IdentityContext::anonymous();
    identity.principal = "person".into();
    identity.authenticated = true;
    identity.policy_groups = vec!["agents".into(), "other".into()];
    identity.groups = identity.policy_groups.clone();
    identity
}
fn locator(kind: &str, id: usize) -> String {
    format!("{ORIGIN}/s/ENG/{kind}/{id}")
}
fn content(kind: &str, id: usize) -> ContainmentIdentity {
    ContainmentIdentity::new(content_type(), kind, locator(kind, id))
}
fn location(kind: &str, id: usize, ancestors: Vec<ContainmentIdentity>) -> ContentLocation {
    ContentLocation::new(
        content(kind, id),
        vec![ResourceContainer::new(area_type(), "ENG")],
        ContainmentEvidenceLevel::CompleteLineage,
    )
    .with_ancestors(ancestors)
}
fn point(id: usize, parent: usize) -> ContainmentEvidence {
    ContainmentEvidence::new(
        "document",
        ORIGIN,
        vec![ContainmentObligation::Content(location(
            "document",
            id,
            vec![content("directory", parent)],
        ))],
    )
}
fn exact(kind: &str, id: usize) -> ResourceSelector {
    ResourceSelector::Exact {
        value: locator(kind, id),
    }
}
fn subtree(kind: &str, id: usize) -> ResourceSelector {
    ResourceSelector::Subtree {
        value: locator(kind, id),
    }
}
fn resource(id: &str, kind: ResourceType, selector: ResourceSelector) -> ResourceDefinition {
    ResourceDefinition {
        id: id.into(),
        display_name: None,
        resource_type: kind,
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
    action: &str,
    mode: &str,
    priority: i32,
    ids: &[&str],
) -> PolicyGrantConfig {
    PolicyGrantConfig {
        subjects: vec![subject.into()],
        service: SERVICE.into(),
        actions: vec![action.into()],
        credential_mode: mode.into(),
        priority: Some(priority),
        resources: selection(ids, &[]),
        execution_contexts: Some(vec![context().to_string()]),
    }
}
fn fixture() -> (BrokerConfig, Fixture) {
    let mut config = super::super::tests::base_fake_config();
    config.credentials = Default::default();
    config.policy.resource_groups.clear();
    config.policy.grants.clear();
    config.execution_context = Some(crate::ExecutionContextConfig {
        allowed_values: vec!["default".into(), "external".into()],
        default_context: None,
    });
    config.policy.resources = vec![
        resource("all", area_type(), ResourceSelector::All),
        resource(
            "eng",
            area_type(),
            ResourceSelector::Exact {
                value: "ENG".into(),
            },
        ),
        resource(
            "other-area",
            area_type(),
            ResourceSelector::Exact {
                value: "OTHER".into(),
            },
        ),
        resource("folder-a", content_type(), subtree("directory", 10)),
        resource("folder-b", content_type(), subtree("directory", 20)),
        resource("document-one", content_type(), exact("document", 1)),
        resource("document-two", content_type(), exact("document", 2)),
        resource("document-subtree", content_type(), subtree("document", 1)),
        resource("journal-one", content_type(), exact("journal", 30)),
    ];
    let dir = super::super::tests::test_temp_dir();
    let token = dir.join("token");
    fs::write(&token, "fixture-token").unwrap();
    config.identity.sources.push(crate::IdentitySourceConfig {
        name: "fixture-identity".into(),
        kind: "static_principals".into(),
        header: "X-Agent-Access-Identity-Token".into(),
        scheme: "raw".into(),
        principals: vec![crate::StaticPrincipalConfig {
            principal: "person".into(),
            token_refs: vec![format!("file:{}", token.display())],
        }],
    });
    let static_credential = |read_only| CredentialConfig {
        kind: "bearer_token".into(),
        username_ref: None,
        token_ref: Some(format!("file:{}", token.display())),
        provider: None,
        path: None,
        read_only,
        connection: None,
        profile: None,
    };
    config
        .credentials
        .service
        .insert(SERVICE.into(), static_credential(None));
    config
        .credentials
        .lookup
        .insert(SERVICE.into(), static_credential(Some(true)));
    let store = dir.join("personal.json");
    fs::write(&store, serde_json::to_vec(&json!({"credentials":[{"principal":"person","type":"bearer_token","token_ref":format!("file:{}",token.display())}]})).unwrap()).unwrap();
    config.credentials.per_user.insert(
        SERVICE.into(),
        CredentialConfig {
            kind: "secret_store".into(),
            username_ref: None,
            token_ref: None,
            provider: Some("local_file".into()),
            path: Some(store.display().to_string()),
            read_only: None,
            connection: None,
            profile: None,
        },
    );
    let fixture = Fixture::default();
    fixture.state.lock().unwrap().evidence = Some(point(1, 10));
    config.providers = ProvidersConfig::new(Arc::new(BackendRegistry::new([&BACKEND]).unwrap()))
        .with(fixture.clone());
    (config, fixture)
}
fn operation(action: &str) -> GovernedOperationContext {
    GovernedOperationContext {
        admission: None,
        execution_context: context(),
        operation: OperationContext {
            agent_request_id: "location-fixture-agent".into(),
            broker_request_id: "location-fixture-broker".into(),
            identity: identity(),
            service: SERVICE.into(),
            action: action.into(),
            source: SourceContext::unknown(),
        },
    }
}
fn token(resources: ResourceSelection, action: &str) -> ParsedAgentInvokeTokenCaveats<'static> {
    ParsedAgentInvokeTokenCaveats {
        token_id: Some("fixture-token"),
        read_only_access: false,
        caveats: AgentInvokeTokenCaveats {
            read_only: false,
            allowed_services: None,
            allowed_execution_contexts: None,
            service_restrictions: Some(BTreeMap::from([(
                SERVICE.into(),
                crate::AgentTokenServiceRestriction {
                    actions: vec![action.into()],
                    resources: Some(resources),
                },
            )])),
        },
    }
}
fn admit(
    runtime: &BrokerRuntime,
    action: &str,
    evidence: ContainmentEvidence,
    token: Option<&ParsedAgentInvokeTokenCaveats<'_>>,
) -> Result<ContainmentAdmission, ProviderError> {
    let snapshot = runtime.policy_snapshot();
    let (level, _) = runtime.containment_lookup_requirements(
        &snapshot,
        &identity(),
        &context(),
        SERVICE,
        action,
        token,
    );
    runtime.admit_containment_evidence(
        &snapshot,
        &identity(),
        &context(),
        SERVICE,
        action,
        token,
        evidence,
        level,
    )
}
fn reason(result: Result<ContainmentAdmission, ProviderError>) -> ReasonCodeId {
    match result {
        Ok(_) => panic!("expected refusal"),
        Err(error) => error.reason_code().into(),
    }
}

#[test]
fn ordinary_selection_uses_complete_operation_rank_and_priority_without_specificity() {
    let (mut config, _) = fixture();
    config.policy.grants = vec![
        grant("group:agents", "update", "per_user", 100, &["folder-a"]),
        grant("user:person", "update", "service", 0, &["eng"]),
    ];
    let runtime = BrokerRuntime::new(config).unwrap();
    let admission =
        admit(&runtime, "update", point(1, 10), None).unwrap_or_else(|error| panic!("{error:?}"));
    assert_eq!(admission.policy.credential_mode, "service");
    assert_eq!(admission.policy.matched_grant.subject, "user:person");
    let InvocationAuthority::Containment(authority) = admission.authority else {
        panic!("typed authority");
    };
    assert_eq!(
        authority.evidence_level(),
        ContainmentEvidenceLevel::CompleteLineage
    );
    assert_eq!(
        admission.scopes,
        BTreeMap::from([("document_location".into(), vec![locator("document", 1)])])
    );
}

#[test]
fn equal_rank_group_modes_are_ambiguous_only_for_matching_complete_requests() {
    let (mut config, _) = fixture();
    config.policy.grants = vec![
        grant("group:agents", "update", "service", 0, &["eng"]),
        grant("group:other", "update", "per_user", 0, &["folder-a"]),
    ];
    let runtime = BrokerRuntime::new(config).unwrap();
    assert_eq!(
        reason(admit(&runtime, "update", point(1, 10), None)),
        ReasonCodeId::from(ReasonCode::ServiceActionDenied)
    );
    assert_eq!(
        admit(&runtime, "update", point(2, 20), None)
            .unwrap_or_else(|error| panic!("{error:?}"))
            .policy
            .credential_mode,
        "service"
    );
}

#[test]
fn publication_rejects_proven_mixed_modes_and_preserves_conditional_and_lookup_universe_rules() {
    for (action, left, right, accepted) in [
        ("update", "eng", "folder-a", false),
        ("update", "folder-a", "folder-b", true),
        ("update", "all", "folder-a", true),
        ("search", "all", "folder-a", false),
        ("search", "document-one", "document-two", true),
    ] {
        let (mut config, _) = fixture();
        config.policy.grants = vec![
            grant("user:person", action, "service", 0, &[left]),
            grant("user:person", action, "per_user", 0, &[right]),
        ];
        let result = BrokerRuntime::new(config);
        assert_eq!(result.is_ok(), accepted, "{action}: {left} / {right}");
        if let Err(error) = result {
            assert!(
                format!("{error:?}").contains("ambiguous credential mode"),
                "{error}"
            );
        }
    }
}

#[test]
fn disabled_exclusions_remain_local_and_tokens_cannot_be_restored_by_another_grant() {
    let (mut config, _) = fixture();
    let excluded = config
        .policy
        .resources
        .iter_mut()
        .find(|resource| resource.id == "folder-a")
        .unwrap();
    excluded.enabled = false;
    excluded.allowed_execution_contexts = vec!["external".into()];
    config.policy.resource_groups.push(ResourceGroupDefinition {
        id: "filtered".into(),
        name: "Filtered".into(),
        included_resource_ids: vec!["eng".into()],
        excluded_resource_ids: vec!["folder-a".into()],
    });
    let mut filtered = grant("group:agents", "view", "service", 0, &["document-one"]);
    filtered
        .resources
        .resource_group_ids
        .push("filtered".into());
    config.policy.grants.push(filtered);
    let denied = BrokerRuntime::new(config.clone()).unwrap();
    assert_eq!(
        reason(admit(&denied, "view", point(1, 10), None)),
        ReasonCodeId::from(ReasonCode::ServiceActionDenied)
    );
    config.policy.grants.push(grant(
        "group:agents",
        "view",
        "service",
        0,
        &["document-one"],
    ));
    let restored = BrokerRuntime::new(config).unwrap();
    assert!(admit(&restored, "view", point(1, 10), None).is_ok());
    let ceiling = token(selection(&["document-one"], &["filtered"]), "view");
    assert_eq!(
        reason(admit(&restored, "view", point(1, 10), Some(&ceiling))),
        ReasonCodeId::from(ReasonCode::ServiceActionDenied)
    );
    let empty = token(ResourceSelection::default(), "view");
    let error = admit(&restored, "view", point(1, 10), Some(&empty))
        .err()
        .unwrap();
    assert!(
        error.audit.is_some(),
        "independent token refusal retains protected token provenance"
    );
}

#[test]
fn exact_parent_does_not_admit_creation_and_separate_grants_do_not_stitch_moves() {
    let (mut config, _) = fixture();
    config.policy.grants.push(grant(
        "group:agents",
        "create",
        "service",
        0,
        &["document-one"],
    ));
    let runtime = BrokerRuntime::new(config.clone()).unwrap();
    let create = ContainmentEvidence::new(
        "document_destination",
        ORIGIN,
        vec![ContainmentObligation::ChildPlacement(location(
            "document",
            1,
            vec![content("directory", 10)],
        ))],
    );
    assert_eq!(
        reason(admit(&runtime, "create", create.clone(), None)),
        ReasonCodeId::from(ReasonCode::ServiceActionDenied)
    );
    config.policy.grants[0].resources = selection(&["document-subtree"], &[]);
    let runtime = BrokerRuntime::new(config.clone()).unwrap();
    assert!(admit(&runtime, "create", create, None).is_ok());
    let current = location("document", 1, vec![content("directory", 10)]);
    let proposed = location("document", 1, vec![content("directory", 20)])
        .with_provenance(ContainmentProvenance::Proposed);
    let moved = ContainmentEvidence::new(
        "document_move",
        ORIGIN,
        vec![
            ContainmentObligation::SubtreeImpact { current, proposed },
            ContainmentObligation::ChildPlacement(location("directory", 20, vec![])),
            ContainmentObligation::Content(location("document", 2, vec![content("directory", 20)])),
        ],
    );
    config.policy.grants = vec![
        grant("group:agents", "move", "service", 0, &["folder-a"]),
        grant("group:other", "move", "service", 0, &["folder-b"]),
    ];
    let runtime = BrokerRuntime::new(config.clone()).unwrap();
    assert_eq!(
        reason(admit(&runtime, "move", moved.clone(), None)),
        ReasonCodeId::from(ReasonCode::ServiceActionDenied)
    );
    config.policy.grants = vec![grant(
        "group:agents",
        "move",
        "service",
        0,
        &["folder-a", "folder-b"],
    )];
    let runtime = BrokerRuntime::new(config).unwrap();
    assert!(admit(&runtime, "move", moved, None).is_ok());
}

#[test]
fn lookup_planning_uses_viable_domains_and_never_a_conditional_universe() {
    for (personal, shared, priority, expected) in [
        (
            "folder-a",
            None,
            0,
            PreScopeLookupPlan::UsePerUserCredential,
        ),
        (
            "folder-a",
            Some("eng"),
            10,
            PreScopeLookupPlan::UseSharedLookupCredential,
        ),
        (
            "all",
            Some("eng"),
            10,
            PreScopeLookupPlan::UsePerUserCredential,
        ),
    ] {
        let (mut config, _) = fixture();
        config.policy.grants = vec![grant(
            "group:agents",
            "view",
            "per_user",
            priority,
            &[personal],
        )];
        if let Some(shared) = shared {
            config
                .policy
                .grants
                .push(grant("group:agents", "view", "service", 0, &[shared]));
        }
        let runtime = BrokerRuntime::new(config).unwrap();
        assert_eq!(
            runtime.plan_pre_scope_lookup(
                &runtime.policy_snapshot(),
                &identity(),
                &context(),
                SERVICE,
                "view"
            ),
            expected
        );
    }
    let (mut config, _) = fixture();
    config.policy.grants = vec![grant(
        "group:agents",
        "view",
        "service",
        0,
        &["journal-one"],
    )];
    let runtime = BrokerRuntime::new(config).unwrap();
    assert_eq!(
        runtime.plan_pre_scope_lookup(
            &runtime.policy_snapshot(),
            &identity(),
            &context(),
            SERVICE,
            "view"
        ),
        PreScopeLookupPlan::NoCandidateGrant
    );
}

#[test]
fn collections_select_global_band_before_token_and_keep_a_complete_protected_plan() {
    let (mut config, fixture) = fixture();
    fixture.state.lock().unwrap().candidates = vec![
        location("document", 1, vec![content("directory", 10)]),
        location("document", 2, vec![content("directory", 20)]),
    ];
    config.policy.grants = vec![
        grant("group:agents", "search", "service", 0, &["eng"]),
        grant("group:agents", "search", "service", 5, &["folder-a"]),
    ];
    let runtime = BrokerRuntime::new(config).unwrap();
    let snapshot = runtime.policy_snapshot();
    let narrowed = token(selection(&["folder-b"], &[]), "search");
    let admitted = runtime
        .admit_containment_collection(
            &snapshot,
            &identity(),
            &context(),
            SERVICE,
            "search",
            Some(&narrowed),
        )
        .unwrap_or_else(|error| panic!("{error:?}"));
    assert_eq!(admitted.policy.matched_grant.priority, Some(5));
    let InvocationAuthority::ContainmentCollection(authority) = admitted.authority else {
        panic!("collection authority");
    };
    assert_eq!(
        authority.evidence_level(),
        ContainmentEvidenceLevel::CompleteLineage
    );
    assert!(
        !authority
            .matches_candidate(&fixture.state.lock().unwrap().candidates[1])
            .unwrap()
    );
    let SearchAuthorizationAudit::Location(audit) = admitted.search_audit.unwrap() else {
        panic!("location audit");
    };
    assert_eq!(audit.grant_boundaries.len(), 1);
    assert_eq!(
        audit.grant_boundaries[0].included[0].selector,
        subtree("directory", 10)
    );
    assert!(audit.token_boundary.is_some());
}

#[tokio::test]
async fn invocation_keeps_admitted_projection_on_final_errors_and_conceals_initial_and_policy_failures()
 {
    let (mut config, fixture) = fixture();
    config
        .policy
        .grants
        .push(grant("group:agents", "view", "service", 0, &["folder-a"]));
    let audit_path = super::super::tests::test_temp_dir().join("audit.jsonl");
    config.audit = Some(crate::AuditConfig::new(
        crate::AuditStoreType::Jsonl,
        audit_path.display().to_string(),
    ));
    let runtime = BrokerRuntime::new(config).unwrap();
    let success = runtime
        .invoke(operation("view"), InvokeRequest::new(json!({})))
        .await;
    assert_eq!(success.envelope.decision, Decision::Allow);
    let admitted = success.envelope.resource_scopes.clone();
    assert_eq!(admitted["document_location"], [locator("document", 1)]);
    fixture.state.lock().unwrap().final_failure = true;
    let final_error = runtime
        .invoke(operation("view"), InvokeRequest::new(json!({})))
        .await;
    assert_eq!(final_error.envelope.resource_scopes, admitted);
    {
        let mut state = fixture.state.lock().unwrap();
        state.final_failure = false;
        state.evidence = Some(point(2, 20));
    }
    let denied = runtime
        .invoke(operation("view"), InvokeRequest::new(json!({})))
        .await;
    assert!(denied.envelope.resource_scopes.is_empty());
    fixture.state.lock().unwrap().initial_failure = true;
    let failed_lookup = runtime
        .invoke(operation("view"), InvokeRequest::new(json!({})))
        .await;
    assert!(failed_lookup.envelope.resource_scopes.is_empty());
    runtime
        .shutdown_own_audit(Duration::from_secs(5))
        .await
        .unwrap();
    let rows: Vec<AuditRecord> = fs::read_to_string(audit_path)
        .unwrap()
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect();
    assert_eq!(rows[1].resource_scopes, admitted);
    assert_eq!(
        rows[1].provider_audit.as_ref().unwrap()["locationAuthorization"]["finalCheck"],
        "changed"
    );
    assert_eq!(
        rows[2].resource_scopes["document_location"],
        [locator("document", 2)]
    );
    assert!(
        rows[2]
            .provider_audit
            .as_ref()
            .is_none_or(|audit| audit.get("locationAuthorization").is_none())
    );
    assert!(rows[3].resource_scopes.is_empty());
}

#[tokio::test]
async fn local_locator_errors_precede_missing_personal_credentials_and_strip_details() {
    let (mut config, fixture) = fixture();
    fixture.state.lock().unwrap().invalid_locator = true;
    config
        .policy
        .grants
        .push(grant("group:agents", "handle", "per_user", 0, &["eng"]));
    config.credentials.lookup.clear();
    fs::write(
        config.credentials.per_user[SERVICE].path.as_ref().unwrap(),
        "{\"credentials\":[]}",
    )
    .unwrap();
    let runtime = BrokerRuntime::new(config).unwrap();
    let denied = runtime
        .invoke(operation("handle"), InvokeRequest::new(json!({})))
        .await;
    assert_eq!(
        denied.envelope.reason_code,
        Some(ReasonCode::InvalidDraftHandle.into())
    );
    assert!(denied.envelope.result.is_none());
    assert_eq!(fixture.scope_calls.load(Ordering::SeqCst), 0);
    assert_eq!(fixture.invoke_calls.load(Ordering::SeqCst), 0);
    assert_eq!(fixture.local_calls.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn missing_state_and_unsigned_provisional_evidence_are_contract_failures() {
    for provisional in [false, true] {
        let (mut config, fixture) = fixture();
        config
            .policy
            .grants
            .push(grant("group:agents", "view", "service", 0, &["eng"]));
        if provisional {
            fixture.state.lock().unwrap().evidence = Some(ContainmentEvidence::new(
                "document",
                ORIGIN,
                vec![ContainmentObligation::Content(
                    location("document", 1, vec![content("directory", 10)])
                        .with_provenance(ContainmentProvenance::SignedLocator),
                )],
            ));
        } else {
            fixture.state.lock().unwrap().omit_state = true;
        }
        let runtime = BrokerRuntime::new(config).unwrap();
        let denied = runtime
            .invoke(operation("view"), InvokeRequest::new(json!({})))
            .await;
        assert_eq!(
            denied.envelope.reason_code,
            Some(ReasonCode::OperationFailed.into())
        );
        assert!(denied.envelope.resource_scopes.is_empty());
        assert_eq!(fixture.invoke_calls.load(Ordering::SeqCst), 0);
    }
}

#[tokio::test]
async fn personal_only_content_lookup_works_without_shared_configuration_and_never_falls_back() {
    let (mut config, fixture) = fixture();
    config
        .policy
        .grants
        .push(grant("group:agents", "view", "per_user", 0, &["folder-a"]));
    config.credentials.lookup.clear();
    let personal_store = config.credentials.per_user[SERVICE].path.clone().unwrap();
    let runtime = BrokerRuntime::new(config).unwrap();
    let success = runtime
        .invoke(operation("view"), InvokeRequest::new(json!({})))
        .await;
    assert_eq!(success.envelope.decision, Decision::Allow);
    assert_eq!(
        fixture.state.lock().unwrap().requested_level,
        Some(ContainmentEvidenceLevel::CompleteLineage)
    );
    let modified = fs::metadata(&personal_store).unwrap().modified().unwrap();
    fs::write(&personal_store, "{\"credentials\":[]}").unwrap();
    filetime::set_file_mtime(
        &personal_store,
        filetime::FileTime::from_system_time(modified + Duration::from_secs(2)),
    )
    .unwrap();
    let denied = runtime
        .invoke(operation("view"), InvokeRequest::new(json!({})))
        .await;
    assert_ne!(denied.envelope.decision, Decision::Allow);
    assert_eq!(fixture.invoke_calls.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn proof_level_comes_from_all_candidates_and_less_evidence_is_a_contract_failure() {
    let (mut config, fixture) = fixture();
    config.policy.grants.push(grant(
        "user:person",
        "view",
        "service",
        10,
        &["document-one"],
    ));
    let container_only = ContentLocation::new(
        content("document", 1),
        vec![ResourceContainer::new(area_type(), "ENG")],
        ContainmentEvidenceLevel::ContainerOnly,
    );
    fixture.state.lock().unwrap().evidence = Some(ContainmentEvidence::new(
        "document",
        ORIGIN,
        vec![ContainmentObligation::Content(container_only)],
    ));
    let runtime = BrokerRuntime::new(config.clone()).unwrap();
    assert_eq!(
        runtime
            .invoke(operation("view"), InvokeRequest::new(json!({})))
            .await
            .envelope
            .decision,
        Decision::Allow
    );
    assert_eq!(
        fixture.state.lock().unwrap().requested_level,
        Some(ContainmentEvidenceLevel::ContainerOnly)
    );
    config
        .policy
        .grants
        .push(grant("group:agents", "view", "service", 0, &["folder-a"]));
    let runtime = BrokerRuntime::new(config).unwrap();
    let denied = runtime
        .invoke(operation("view"), InvokeRequest::new(json!({})))
        .await;
    assert_eq!(
        denied.envelope.reason_code,
        Some(ReasonCode::OperationFailed.into())
    );
    assert!(denied.envelope.resource_scopes.is_empty());
    assert_eq!(
        fixture.state.lock().unwrap().requested_level,
        Some(ContainmentEvidenceLevel::CompleteLineage)
    );
}

#[test]
fn collection_mixed_modes_deny_globally_even_when_their_registered_roots_are_disjoint() {
    let (mut config, _) = fixture();
    config.policy.grants = vec![
        grant("user:person", "search", "service", 0, &["document-one"]),
        grant("user:person", "search", "per_user", 0, &["document-two"]),
    ];
    let runtime = BrokerRuntime::new(config).unwrap();
    let error = runtime
        .admit_containment_collection(
            &runtime.policy_snapshot(),
            &identity(),
            &context(),
            SERVICE,
            "search",
            None,
        )
        .err()
        .unwrap();
    assert_eq!(error.reason_code(), ReasonCode::ServiceActionDenied);
    assert!(!runtime.containment_has_access(
        &runtime.policy_snapshot(),
        &identity(),
        &context(),
        SERVICE,
        "search",
        None,
        |_| true
    ));
}

#[tokio::test]
async fn unavailable_winning_personal_material_does_not_expose_the_shadowed_service_grant() {
    let (mut config, fixture) = fixture();
    config.policy.grants = vec![
        grant("group:agents", "view", "service", 0, &["document-one"]),
        grant("group:agents", "view", "per_user", 5, &["document-subtree"]),
    ];
    fs::write(
        config.credentials.per_user[SERVICE].path.as_ref().unwrap(),
        "{\"credentials\":[]}",
    )
    .unwrap();
    let runtime = BrokerRuntime::new(config).unwrap();
    let response = runtime
        .invoke(operation("view"), InvokeRequest::new(json!({})))
        .await;
    assert_ne!(response.envelope.decision, Decision::Allow);
    assert_eq!(fixture.invoke_calls.load(Ordering::SeqCst), 0);
    let caller = identity();
    let execution_context = context();
    let discovery = runtime
        .service_discovery(&caller, &execution_context, SERVICE)
        .unwrap();
    assert!(
        discovery
            .actions(None, None, None)
            .unwrap()
            .actions
            .is_empty()
    );
    let serialized = serde_json::to_string(
        &discovery
            .resource_access(&ResourceAccessQuery::default())
            .unwrap(),
    )
    .unwrap();
    assert!(!serialized.contains(&locator("document", 1)));
}

#[test]
fn token_intersection_never_rescues_a_lower_collection_band_and_foreign_roots_stay_dormant() {
    let (mut config, _) = fixture();
    config.policy.grants = vec![
        grant("group:agents", "search", "service", 0, &["eng"]),
        grant("group:agents", "search", "service", 5, &["document-one"]),
    ];
    let runtime = BrokerRuntime::new(config.clone()).unwrap();
    let ceiling = token(selection(&["document-two"], &[]), "search");
    assert!(
        runtime
            .admit_containment_collection(
                &runtime.policy_snapshot(),
                &identity(),
                &context(),
                SERVICE,
                "search",
                Some(&ceiling)
            )
            .is_err()
    );
    let mut foreign = resource("foreign", content_type(), subtree("directory", 10));
    foreign.selector = ResourceSelector::Subtree {
        value: "https://other.example.test/s/ENG/directory/10".into(),
    };
    config.policy.resources.push(foreign);
    config.policy.grants = vec![grant("group:agents", "view", "service", 0, &["foreign"])];
    let runtime = BrokerRuntime::new(config).unwrap();
    assert!(
        runtime
            .policy_candidates_for_action(
                &runtime.policy_snapshot(),
                &identity(),
                &context(),
                SERVICE,
                "view"
            )
            .is_empty()
    );
}

#[test]
fn detailed_projections_keep_conditions_while_agent_discovery_withholds_exclusions() {
    let (mut config, _) = fixture();
    config.policy.resource_groups.push(ResourceGroupDefinition {
        id: "filtered".into(),
        name: "Filtered".into(),
        included_resource_ids: vec!["eng".into()],
        excluded_resource_ids: vec!["folder-b".into()],
    });
    let mut wide = grant("group:agents", "view", "service", 0, &[]);
    wide.resources.resource_group_ids.push("filtered".into());
    config.policy.grants = vec![
        wide,
        grant("group:agents", "view", "per_user", 5, &["folder-a"]),
    ];
    let runtime = BrokerRuntime::new(config).unwrap();
    let snapshot = runtime.policy_snapshot();
    let detailed = runtime
        .containment_access_projection(&snapshot, &identity(), &context(), SERVICE, "view", None)
        .unwrap();
    let detailed_json = serde_json::to_string(&detailed).unwrap();
    assert!(detailed_json.contains(&locator("directory", 20)));
    let caller = identity();
    let execution_context = context();
    let view = runtime
        .service_discovery(&caller, &execution_context, SERVICE)
        .unwrap()
        .resource_access(&ResourceAccessQuery::default())
        .unwrap();
    let caller_json = serde_json::to_string(&view).unwrap();
    assert!(!caller_json.contains(&locator("directory", 20)));
    assert!(!caller_json.contains("excludedRequests"));
    assert!(!caller_json.contains("boundaries"));
    assert!(caller_json.contains("\"restricted\":true"));
    assert!(caller_json.contains("\"scope\":\"location\""));
    let options = runtime.agent_token_options_for_identity(&caller);
    let action = options
        .services
        .iter()
        .find(|service| service.service == SERVICE)
        .unwrap()
        .actions
        .iter()
        .find(|action| action.action == "view")
        .unwrap();
    let value = serde_json::to_value(action).unwrap();
    assert_eq!(value["scope"], "location");
    assert!(value.get("resourceType").is_none());
}

#[test]
fn projection_budgets_do_not_change_streaming_availability_or_actual_admission() {
    for (count, complete) in [(512usize, true), (513, false)] {
        let (mut config, _) = fixture();
        config.policy.resources = (1..=count)
            .map(|id| resource(&format!("item-{id}"), content_type(), exact("document", id)))
            .collect();
        config.policy.grants = (1..=count)
            .map(|id| {
                grant(
                    "group:agents",
                    "view",
                    "service",
                    0,
                    &[&format!("item-{id}")],
                )
            })
            .collect();
        let runtime = BrokerRuntime::new(config).unwrap();
        let snapshot = runtime.policy_snapshot();
        let projected = runtime
            .containment_access_projection(
                &snapshot,
                &identity(),
                &context(),
                SERVICE,
                "view",
                None,
            )
            .unwrap();
        assert_eq!(
            matches!(projected.projection, LocationProjection::Complete { .. }),
            complete
        );
        assert!(runtime.containment_has_access(
            &snapshot,
            &identity(),
            &context(),
            SERVICE,
            "view",
            None,
            |_| true
        ));
        assert!(admit(&runtime, "view", point(1, 10), None).is_ok());
        if !complete {
            let json = serde_json::to_value(projected).unwrap();
            assert_eq!(json["reasonCode"], "resource_access_too_complex");
            assert!(json.get("boundaries").is_none() && json.get("clauses").is_none());
            let options = runtime.agent_token_options_for_identity(&identity());
            let action = options
                .services
                .iter()
                .find(|service| service.service == SERVICE)
                .unwrap()
                .actions
                .iter()
                .find(|action| action.action == "view")
                .unwrap();
            let AgentTokenActionScope::Location {
                effective_access_by_execution_context,
                ..
            } = &action.scope
            else {
                panic!("location option")
            };
            assert!(matches!(
                effective_access_by_execution_context[&context()].projection,
                LocationProjection::TooComplex { .. }
            ));
        }
    }
}

#[test]
fn projection_preflights_selector_reference_and_byte_limits() {
    let (mut config, _) = fixture();
    config.policy.resources = (1..=181)
        .map(|id| {
            resource(
                &format!("root-{id}"),
                content_type(),
                subtree("directory", id),
            )
        })
        .collect();
    config.policy.grants = (1..=181)
        .map(|id| {
            grant(
                "group:agents",
                "view",
                "service",
                id,
                &[&format!("root-{id}")],
            )
        })
        .collect();
    let runtime = BrokerRuntime::new(config).unwrap();
    let mut plan = runtime
        .containment_plan(
            &runtime.policy_snapshot(),
            &identity(),
            &context(),
            SERVICE,
            "view",
            None,
        )
        .unwrap();
    assert!(matches!(
        project_location_plan(&plan, |_| true, u64::MAX),
        LocationProjection::TooComplex { .. }
    ));
    plan.candidates.pop();
    assert!(matches!(
        project_location_plan(&plan, |_| true, u64::MAX),
        LocationProjection::Complete { .. }
    ));
    assert!(matches!(
        project_location_plan(&plan, |_| true, 32),
        LocationProjection::TooComplex { .. }
    ));
    let candidate = plan.candidates[0].clone();
    plan.candidates = vec![candidate];
    let typed = |id| {
        runtime
            .resource_types
            .registry()
            .typed_selector(&content_type(), &exact("document", id))
            .unwrap()
    };
    plan.candidates[0].containment = Some(ContainmentBoundary::new(
        (1..=4096).map(typed).collect(),
        Vec::new(),
    ));
    assert!(matches!(
        project_location_plan(&plan, |_| true, u64::MAX),
        LocationProjection::Complete { .. }
    ));
    plan.candidates[0].containment = Some(ContainmentBoundary::new(
        (1..=4097).map(typed).collect(),
        Vec::new(),
    ));
    assert!(matches!(
        project_location_plan(&plan, |_| true, u64::MAX),
        LocationProjection::TooComplex { .. }
    ));
}

#[tokio::test]
async fn optional_containment_hints_use_same_mode_and_complete_evidence() {
    let (mut config, _) = fixture();
    config.policy.grants = ["view", "with.companion", "universal"]
        .into_iter()
        .map(|action| grant("group:agents", action, "service", 0, &["all"]))
        .collect();
    let runtime = BrokerRuntime::new(config.clone()).unwrap();
    let companion = runtime
        .invoke(operation("with.companion"), InvokeRequest::new(json!({})))
        .await;
    assert_eq!(companion.envelope.result.unwrap()["companion"], true);
    let universal = runtime
        .invoke(operation("universal"), InvokeRequest::new(json!({})))
        .await;
    assert_eq!(universal.envelope.result.unwrap()["universal"], true);
    config
        .policy
        .grants
        .push(grant("user:person", "view", "per_user", 0, &["eng"]));
    config.policy.grants.push(grant(
        "user:person",
        "universal",
        "per_user",
        0,
        &["folder-b"],
    ));
    let runtime = BrokerRuntime::new(config).unwrap();
    let companion = runtime
        .invoke(operation("with.companion"), InvokeRequest::new(json!({})))
        .await;
    assert_eq!(companion.envelope.result.unwrap()["companion"], false);
    let universal = runtime
        .invoke(operation("universal"), InvokeRequest::new(json!({})))
        .await;
    assert_eq!(universal.envelope.result.unwrap()["universal"], false);
}

#[tokio::test]
async fn unresolved_move_roots_keep_bounded_provenance_in_protected_audit_and_offline_previews() {
    let (mut config, fixture) = fixture();
    config.policy.resource_groups.push(ResourceGroupDefinition {
        id: "move-boundary".into(),
        name: "Move boundary".into(),
        included_resource_ids: vec!["eng".into()],
        excluded_resource_ids: vec!["document-two".into()],
    });
    let mut selected = grant("group:agents", "move", "service", 0, &[]);
    selected.resources = selection(&[], &["move-boundary"]);
    config.policy.grants.push(selected);
    let audit_path = super::super::tests::test_temp_dir().join("root-audit.jsonl");
    config.audit = Some(crate::AuditConfig::new(
        crate::AuditStoreType::Jsonl,
        audit_path.display().to_string(),
    ));
    let runtime = BrokerRuntime::new(config).unwrap();
    let preview = runtime
        .preview_policy_resources(
            SERVICE,
            &["move".into()],
            &[context()],
            &selection(&[], &["move-boundary"]),
            "service",
        )
        .unwrap();
    let serialized = serde_json::to_value(preview).unwrap();
    assert_eq!(
        serialized["access"][0]["requiresRuntimeRootVisibility"],
        true
    );
    assert_eq!(
        fixture.scope_calls.load(Ordering::SeqCst),
        0,
        "preview stays offline"
    );
    fixture.state.lock().unwrap().initial_root_failure = true;
    let initial = runtime
        .invoke(operation("move"), InvokeRequest::new(json!({})))
        .await;
    assert!(initial.envelope.resource_scopes.is_empty());
    assert!(initial.envelope.result.is_none());
    let initial_wire = serde_json::to_string(&initial.envelope).unwrap();
    assert!(
        !initial_wire.contains("move-boundary")
            && !initial_wire.contains("document-two")
            && !initial_wire.contains("root failure")
    );
    {
        let mut state = fixture.state.lock().unwrap();
        state.initial_root_failure = false;
        state.final_root_failure = true;
        state.evidence = Some(
            ContainmentEvidence::new(
                "document_move",
                ORIGIN,
                vec![
                    ContainmentObligation::SubtreeImpact {
                        current: location("document", 1, vec![content("directory", 10)]),
                        proposed: location("document", 1, vec![content("directory", 20)])
                            .with_provenance(ContainmentProvenance::Proposed),
                    },
                    ContainmentObligation::ChildPlacement(location("directory", 20, vec![])),
                    ContainmentObligation::Content(location(
                        "document",
                        3,
                        vec![content("directory", 20)],
                    )),
                ],
            )
            .with_related_roots(vec![location(
                "document",
                2,
                vec![content("directory", 30)],
            )]),
        );
    }
    let final_error = runtime
        .invoke(operation("move"), InvokeRequest::new(json!({})))
        .await;
    assert!(
        !final_error.envelope.resource_scopes.is_empty(),
        "admitted target projection survives final proof failure"
    );
    assert_eq!(fixture.invoke_calls.load(Ordering::SeqCst), 1);
    fixture.state.lock().unwrap().final_root_failure = false;
    let success = runtime
        .invoke(operation("move"), InvokeRequest::new(json!({})))
        .await;
    assert_eq!(success.envelope.decision, Decision::Allow);
    runtime
        .shutdown_own_audit(Duration::from_secs(5))
        .await
        .unwrap();
    let rows: Vec<AuditRecord> = fs::read_to_string(audit_path)
        .unwrap()
        .lines()
        .map(|row| serde_json::from_str(row).unwrap())
        .collect();
    assert_eq!(rows.len(), 3);
    for row in &rows[..2] {
        let audit = row.provider_audit.as_ref().unwrap();
        let summary = &audit["locationAuthorization"];
        assert_eq!(summary["finalCheck"], "unresolved");
        assert_eq!(
            summary["rootVisibility"]["diagnostic"],
            "confluence_move_relation_unresolved"
        );
        assert_eq!(
            summary["rootVisibility"]["category"],
            "not_visible_or_absent"
        );
        assert_eq!(
            summary["rootVisibility"]["resourceIds"],
            json!(["document-two"])
        );
        assert_eq!(
            summary["rootVisibility"]["resourceGroupIds"],
            json!(["move-boundary"])
        );
        assert!(summary.get("_rootVisibilityProvenance").is_none());
        assert!(audit.get("private").is_none());
    }
    let success_summary = &rows[2].provider_audit.as_ref().unwrap()["locationAuthorization"];
    assert_eq!(success_summary["finalCheck"], "matched");
    assert!(success_summary.get("rootVisibility").is_none());
    assert!(success_summary.get("_rootVisibilityProvenance").is_none());
}

#[test]
fn projection_byte_preflight_borrows_long_selectors_and_matches_the_published_shape() {
    let (mut config, _) = fixture();
    config
        .policy
        .grants
        .push(grant("group:agents", "view", "service", 0, &["eng"]));
    let runtime = BrokerRuntime::new(config).unwrap();
    let mut plan = runtime
        .containment_plan(
            &runtime.policy_snapshot(),
            &identity(),
            &context(),
            SERVICE,
            "view",
            None,
        )
        .unwrap();
    let one = project_location_plan(&plan, |_| true, u64::MAX);
    let LocationProjection::Complete { clauses, .. } = &one else {
        panic!("complete small plan")
    };
    let borrowed_boundaries = [plan.boundary(0)];
    let borrowed = BorrowedLocationProjection {
        projection_status: "complete",
        boundaries: &borrowed_boundaries,
        clauses,
    };
    let owned_bytes = serde_json::to_vec(&one).unwrap();
    assert_eq!(serde_json::to_vec(&borrowed).unwrap(), owned_bytes);
    assert!(serialized_fits_bytes(&borrowed, owned_bytes.len() as u64));
    assert!(!serialized_fits_bytes(
        &borrowed,
        owned_bytes.len() as u64 - 1
    ));
    let complete_access = location_access(
        &plan.scope,
        plan.collection,
        one.clone(),
        plan.requires_runtime_root_visibility(),
    );
    let complete_bytes = serde_json::to_vec(&complete_access).unwrap();
    assert!(location_projection_fits_bytes(
        &plan.scope,
        plan.collection,
        plan.requires_runtime_root_visibility(),
        &borrowed_boundaries,
        clauses,
        complete_bytes.len() as u64
    ));
    assert!(!location_projection_fits_bytes(
        &plan.scope,
        plan.collection,
        plan.requires_runtime_root_visibility(),
        &borrowed_boundaries,
        clauses,
        complete_bytes.len() as u64 - 1
    ));
    let long = "1".repeat(8000);
    let selectors = (1..=2300)
        .map(|id| {
            let selector = ResourceSelector::Exact {
                value: format!("{ORIGIN}/s/ENG/document/{long}{id}"),
            };
            runtime
                .resource_types
                .registry()
                .typed_selector(&content_type(), &selector)
                .unwrap()
        })
        .collect();
    plan.candidates[0].containment = Some(ContainmentBoundary::new(selectors, Vec::new()));
    assert_eq!(
        plan.boundary(0).included().len(),
        2300,
        "selector count is under its independent limit"
    );
    // Only borrowed SDK selectors reach the bounded writer; owned LocationBoundary
    // conversion is below this failed preflight in the production path.
    assert!(!location_projection_fits_bytes(
        &plan.scope,
        plan.collection,
        plan.requires_runtime_root_visibility(),
        &[plan.boundary(0)],
        clauses,
        crate::RESOURCE_ACCESS_MAX_RESPONSE_BYTES as u64
    ));
    assert!(matches!(
        project_location_plan(
            &plan,
            |_| true,
            crate::RESOURCE_ACCESS_MAX_RESPONSE_BYTES as u64
        ),
        LocationProjection::TooComplex { .. }
    ));
}

#[test]
fn move_root_provenance_is_bounded_and_includes_token_exclusions_only_from_selected_groups() {
    let (mut config, _) = fixture();
    let mut selected = grant("group:agents", "move", "service", 0, &[]);
    for index in 0..33 {
        let id = format!("move-group-{index:02}");
        config.policy.resource_groups.push(ResourceGroupDefinition {
            id: id.clone(),
            name: "Move boundary".into(),
            included_resource_ids: vec!["eng".into()],
            excluded_resource_ids: vec!["document-two".into()],
        });
        selected.resources.resource_group_ids.push(id);
    }
    config.policy.grants.push(selected);
    config.policy.resource_groups.extend([
        ResourceGroupDefinition {
            id: "token-boundary".into(),
            name: "Token boundary".into(),
            included_resource_ids: vec!["eng".into()],
            excluded_resource_ids: vec!["folder-b".into()],
        },
        ResourceGroupDefinition {
            id: "unselected".into(),
            name: "Unselected".into(),
            included_resource_ids: vec!["eng".into()],
            excluded_resource_ids: vec!["document-one".into()],
        },
    ]);
    let excluded = config
        .policy
        .resources
        .iter_mut()
        .find(|resource| resource.id == "document-two")
        .unwrap();
    excluded.enabled = false;
    excluded.allowed_execution_contexts = vec!["external".into()];
    let runtime = BrokerRuntime::new(config).unwrap();
    let ceiling = token(selection(&[], &["token-boundary"]), "move");
    let snapshot = runtime.policy_snapshot();
    let (_, roots) = runtime.containment_lookup_requirements(
        &snapshot,
        &identity(),
        &context(),
        SERVICE,
        "move",
        Some(&ceiling),
    );
    assert_eq!(roots.len(), 2);
    let provenance = runtime
        .containment_root_provenance(
            &snapshot,
            &identity(),
            &context(),
            SERVICE,
            "move",
            Some(&ceiling),
            &roots,
        )
        .unwrap();
    assert_eq!(
        provenance["resourceIds"],
        json!(["document-two", "folder-b"])
    );
    assert_eq!(provenance["resourceGroupIds"].as_array().unwrap().len(), 16);
    assert_eq!(provenance["additionalProvenanceCount"], 18);
    assert!(!provenance.to_string().contains("unselected"));
    assert!(root_visibility_diagnostic(Some(&json!({"locationProof":{"finalCheck":"unresolved", "diagnostic":"confluence_move_relation_unresolved", "category":"private-value"}})), Some(&provenance)).is_none());
}

#[test]
fn empty_location_selections_disappear_from_previews_and_token_options() {
    let (mut config, _) = fixture();
    for (id, disabled, external) in [("disabled", true, false), ("external", false, true)] {
        let mut entry = resource(
            id,
            content_type(),
            exact("document", if disabled { 99 } else { 100 }),
        );
        entry.enabled = !disabled;
        if external {
            entry.allowed_execution_contexts = vec!["external".into()];
        }
        config.policy.resources.push(entry);
    }
    config.policy.resources.push(resource(
        "foreign",
        content_type(),
        ResourceSelector::Exact {
            value: locator("document", 80).replace(ORIGIN, "https://foreign.example.test"),
        },
    ));
    config.policy.grants = vec![
        grant("group:agents", "view", "service", 0, &["journal-one"]),
        grant("group:agents", "search", "service", 0, &["document-one"]),
        grant("group:other", "search", "per_user", 0, &["document-two"]),
        grant("group:agents", "update", "service", 0, &["eng"]),
    ];
    let runtime = BrokerRuntime::new(config).unwrap();
    for ids in [
        &[][..],
        &["disabled"],
        &["external"],
        &["foreign"],
        &["journal-one"],
    ] {
        assert!(
            runtime
                .preview_policy_resources(
                    SERVICE,
                    &["view".into()],
                    &[context()],
                    &selection(ids, &[]),
                    "service"
                )
                .unwrap()
                .access
                .is_empty(),
            "{ids:?}"
        );
    }
    let options = runtime.agent_token_options_for_identity(&identity());
    let actions = &options
        .services
        .iter()
        .find(|service| service.service == SERVICE)
        .unwrap()
        .actions;
    assert_eq!(
        actions
            .iter()
            .map(|action| action.action.as_str())
            .collect::<Vec<_>>(),
        ["update"]
    );
}

#[test]
fn token_options_drop_only_empty_location_contexts() {
    let (mut config, _) = fixture();
    config
        .policy
        .resources
        .iter_mut()
        .find(|resource| resource.id == "folder-a")
        .unwrap()
        .allowed_execution_contexts = vec!["external".into()];
    let mut access = grant("group:agents", "view", "service", 0, &["folder-a"]);
    access.execution_contexts = Some(vec!["default".into(), "external".into()]);
    config.policy.grants.push(access);
    let runtime = BrokerRuntime::new(config).unwrap();
    let options = runtime.agent_token_options_for_identity(&identity());
    let action = &options
        .services
        .iter()
        .find(|service| service.service == SERVICE)
        .unwrap()
        .actions[0];
    let external = ExecutionContext::new("external").unwrap();
    assert_eq!(
        action.execution_contexts.as_slice(),
        std::slice::from_ref(&external)
    );
    let AgentTokenActionScope::Location {
        effective_access_by_execution_context,
        ..
    } = &action.scope
    else {
        panic!("location")
    };
    assert_eq!(
        effective_access_by_execution_context
            .keys()
            .collect::<Vec<_>>(),
        [&external]
    );
}

#[test]
fn token_picker_offers_unauthored_location_groups_with_visible_enabled_members() {
    let (mut config, _) = fixture();
    config
        .policy
        .grants
        .push(grant("group:agents", "view", "service", 0, &["eng"]));
    let mut disabled = resource("disabled", content_type(), exact("document", 90));
    disabled.enabled = false;
    let mut external = resource("external", content_type(), exact("document", 91));
    external.allowed_execution_contexts = vec!["external".into()];
    config.policy.resources.extend([
        disabled,
        external,
        resource(
            "outside",
            content_type(),
            ResourceSelector::Exact {
                value: locator("document", 92).replace("/s/ENG/", "/s/OTHER/"),
            },
        ),
    ]);
    for (id, included) in [
        ("subtree-group", "folder-a"),
        ("disabled-group", "disabled"),
        ("external-group", "external"),
        ("outside-group", "outside"),
    ] {
        config.policy.resource_groups.push(ResourceGroupDefinition {
            id: id.into(),
            name: id.into(),
            included_resource_ids: vec![included.into()],
            excluded_resource_ids: vec![],
        });
    }
    let runtime = BrokerRuntime::new(config).unwrap();
    let options = runtime.agent_token_options_for_identity(&identity());
    assert_eq!(
        options
            .resource_groups
            .iter()
            .map(|group| group.id.as_str())
            .collect::<Vec<_>>(),
        ["subtree-group"]
    );
    let preview = runtime
        .preview_agent_token_access(
            &identity(),
            &token(selection(&[], &["subtree-group"]), "view").caveats,
        )
        .unwrap();
    assert_eq!(preview.access.len(), 1);
    assert!(
        matches!(&preview.access[0].scope, EffectiveAccessScope::Location(access) if !access.is_empty())
    );
}

#[test]
fn caller_coverage_includes_its_narrow_token_roots_without_exclusions_or_disjoint_roots() {
    let (mut config, _) = fixture();
    config
        .policy
        .grants
        .push(grant("group:agents", "view", "service", 0, &["eng"]));
    config.policy.resource_groups.push(ResourceGroupDefinition {
        id: "token-folder".into(),
        name: "Token folder".into(),
        included_resource_ids: vec!["folder-a".into(), "other-area".into()],
        excluded_resource_ids: vec!["document-two".into()],
    });
    let runtime = BrokerRuntime::new(config).unwrap();
    let ceiling = token(selection(&[], &["token-folder"]), "view");
    let coverage = runtime.containment_coverage(
        &runtime.policy_snapshot(),
        &identity(),
        &context(),
        SERVICE,
        "view",
        Some(&ceiling),
        |_| true,
    );
    assert!(
        coverage
            .iter()
            .any(|entry| entry.selector == subtree("directory", 10)
                && entry.restricted
                && entry.conditional)
    );
    assert!(coverage.iter().any(|entry| entry.selector
        == ResourceSelector::Exact {
            value: "ENG".into()
        }
        && entry.restricted));
    let serialized = serde_json::to_string(&coverage).unwrap();
    assert!(!serialized.contains(&locator("document", 2)) && !serialized.contains("OTHER"));
    assert!(!serialized.contains("excluded") && !serialized.contains("boundaries"));
}

#[tokio::test]
async fn space_only_child_placement_uses_container_evidence_until_a_subtree_predicate_applies() {
    let (mut config, fixture) = fixture();
    config
        .policy
        .grants
        .push(grant("group:agents", "create", "service", 0, &["eng"]));
    fixture.state.lock().unwrap().evidence = Some(ContainmentEvidence::new(
        "document_destination",
        ORIGIN,
        vec![ContainmentObligation::ChildPlacement(ContentLocation::new(
            content("document", 1),
            vec![ResourceContainer::new(area_type(), "ENG")],
            ContainmentEvidenceLevel::ContainerOnly,
        ))],
    ));
    let runtime = BrokerRuntime::new(config.clone()).unwrap();
    let admitted = runtime
        .invoke(operation("create"), InvokeRequest::new(json!({})))
        .await;
    assert_eq!(admitted.envelope.decision, Decision::Allow);
    assert_eq!(
        fixture.state.lock().unwrap().requested_level,
        Some(ContainmentEvidenceLevel::ContainerOnly)
    );
    let ceiling = token(selection(&["folder-a"], &[]), "create");
    assert_eq!(
        runtime
            .containment_lookup_requirements(
                &runtime.policy_snapshot(),
                &identity(),
                &context(),
                SERVICE,
                "create",
                Some(&ceiling)
            )
            .0,
        ContainmentEvidenceLevel::CompleteLineage
    );
    config
        .policy
        .grants
        .push(grant("group:other", "create", "service", -1, &["folder-a"]));
    let runtime = BrokerRuntime::new(config).unwrap();
    assert_eq!(
        runtime
            .containment_lookup_requirements(
                &runtime.policy_snapshot(),
                &identity(),
                &context(),
                SERVICE,
                "create",
                None
            )
            .0,
        ContainmentEvidenceLevel::CompleteLineage
    );
    assert_eq!(
        runtime
            .containment_lookup_requirements(
                &runtime.policy_snapshot(),
                &identity(),
                &context(),
                SERVICE,
                "move",
                None
            )
            .0,
        ContainmentEvidenceLevel::CompleteLineage
    );
}

#[tokio::test]
async fn move_root_requirements_reach_provider_before_its_relevant_container_limit() {
    let (mut config, fixture) = fixture();
    let excluded_ids: Vec<_> = (1..=65).map(|id| format!("other-root-{id}")).collect();
    config
        .policy
        .resources
        .extend(excluded_ids.iter().enumerate().map(|(index, id)| {
            resource(
                id,
                content_type(),
                ResourceSelector::Exact {
                    value: locator("document", index + 100).replace("/s/ENG/", "/s/OTHER/"),
                },
            )
        }));
    config.policy.resource_groups.push(ResourceGroupDefinition {
        id: "move-boundary".into(),
        name: "Move boundary".into(),
        included_resource_ids: vec!["eng".into()],
        excluded_resource_ids: excluded_ids,
    });
    let mut access = grant("group:agents", "move", "service", 0, &[]);
    access
        .resources
        .resource_group_ids
        .push("move-boundary".into());
    config.policy.grants.push(access);
    fixture.state.lock().unwrap().evidence = Some(ContainmentEvidence::new(
        "document_move",
        ORIGIN,
        vec![
            ContainmentObligation::SubtreeImpact {
                current: location("document", 1, vec![content("directory", 10)]),
                proposed: location("document", 1, vec![content("directory", 20)])
                    .with_provenance(ContainmentProvenance::Proposed),
            },
            ContainmentObligation::ChildPlacement(location("directory", 20, vec![])),
            ContainmentObligation::Content(location("document", 3, vec![content("directory", 20)])),
        ],
    ));
    let runtime = BrokerRuntime::new(config).unwrap();
    let admitted = runtime
        .invoke(operation("move"), InvokeRequest::new(json!({})))
        .await;
    assert_eq!(admitted.envelope.decision, Decision::Allow);
    assert_eq!(fixture.state.lock().unwrap().roots, 65);
    assert_eq!(fixture.scope_calls.load(Ordering::SeqCst), 1);
}

#[test]
fn collection_digest_tracks_canonical_authority_and_survives_unrelated_publications() {
    let (mut config, _) = fixture();
    config.policy.grants = vec![
        grant("group:agents", "search", "service", 0, &["folder-a"]),
        grant("group:agents", "search", "service", 0, &["folder-b"]),
    ];
    let runtime = BrokerRuntime::new(config.clone()).unwrap();
    let snapshot = runtime.policy_snapshot();
    let digest = |snapshot: &PolicySnapshot,
                  ceiling: Option<&ParsedAgentInvokeTokenCaveats<'_>>| {
        let admission = runtime
            .admit_containment_collection(
                snapshot,
                &identity(),
                &context(),
                SERVICE,
                "search",
                ceiling,
            )
            .unwrap();
        let InvocationAuthority::ContainmentCollection(authority) = admission.authority else {
            panic!("collection")
        };
        authority.authority_digest().to_owned()
    };
    let original = digest(&snapshot, None);
    let mut republished = (*snapshot).clone();
    republished.generation += 1;
    republished.grants.reverse();
    republished.grants.push(republished.grants[0].clone());
    assert_eq!(digest(&republished, None), original);
    config
        .policy
        .grants
        .push(grant("group:agents", "view", "service", 0, &["eng"]));
    let unrelated = PolicySnapshot::from_config(&config, snapshot.generation() + 2);
    assert_eq!(digest(&unrelated, None), original);
    let ceiling = token(selection(&["folder-a"], &[]), "search");
    assert_ne!(digest(&republished, Some(&ceiling)), original);
    republished
        .grants
        .retain(|grant| grant.resources.resource_ids != ["folder-a"]);
    assert_ne!(digest(&republished, None), original);
}

#[test]
fn confluence_collection_summary_retains_space_and_existing_content_scope_keys() {
    let (mut config, _) = fixture();
    config.providers = ProvidersConfig::new(crate::tests::test_backend_registry()).with(
        serde_json::from_value::<agent_access_confluence::ConfluenceProviderConfig>(json!({
            "tenant_host":"example.atlassian.net", "allowed_upstream_hosts":["https://example.atlassian.net/wiki/**"]
        })).unwrap());
    config.credentials.lookup.clear();
    config.credentials.per_user.clear();
    let mut credential = config.credentials.service.remove(SERVICE).unwrap();
    credential.kind = "basic_api_token".into();
    credential.username_ref = credential.token_ref.clone();
    config
        .credentials
        .service
        .insert("confluence".into(), credential);
    let space_type = agent_access_confluence::CONFLUENCE_SPACE_RESOURCE
        .id()
        .clone();
    let content_type = agent_access_confluence::CONFLUENCE_CONTENT_RESOURCE
        .id()
        .clone();
    let page = "https://example.atlassian.net/wiki/spaces/OPS/folder/10";
    let blog = "https://example.atlassian.net/wiki/spaces/OPS/blog/30";
    config.policy.resources = vec![
        resource("all", space_type.clone(), ResourceSelector::All),
        resource(
            "eng",
            space_type,
            ResourceSelector::Exact {
                value: "ENG".into(),
            },
        ),
        resource(
            "page",
            content_type.clone(),
            ResourceSelector::Subtree { value: page.into() },
        ),
        resource(
            "blog",
            content_type,
            ResourceSelector::Exact { value: blog.into() },
        ),
    ];
    for (action, ids) in [
        ("search", vec!["eng", "page"]),
        ("blog.search", vec!["eng", "blog"]),
    ] {
        let mut access = grant("group:agents", action, "service", 0, &ids);
        access.service = "confluence".into();
        config.policy.grants.push(access);
    }
    let runtime = BrokerRuntime::new(config.clone()).unwrap();
    let snapshot = runtime.policy_snapshot();
    for (action, key, root) in [
        ("search", "page_location", page),
        ("blog.search", "blog_location", blog),
    ] {
        let admitted = runtime
            .admit_containment_collection(
                &snapshot,
                &identity(),
                &context(),
                "confluence",
                action,
                None,
            )
            .unwrap();
        assert_eq!(
            admitted.scopes,
            BTreeMap::from([
                ("space".into(), vec!["ENG".into()]),
                (key.into(), vec![root.into()])
            ])
        );
        let mut ceiling = token(selection(&["eng"], &[]), action);
        let restrictions = ceiling.caveats.service_restrictions.as_mut().unwrap();
        let restriction = restrictions.remove(SERVICE).unwrap();
        restrictions.insert("confluence".into(), restriction);
        let narrowed = runtime
            .admit_containment_collection(
                &snapshot,
                &identity(),
                &context(),
                "confluence",
                action,
                Some(&ceiling),
            )
            .unwrap();
        assert_eq!(
            narrowed.scopes,
            BTreeMap::from([("space".into(), vec!["ENG".into()])])
        );
    }
    config.policy.grants[0].resources = selection(&["all"], &[]);
    let runtime = BrokerRuntime::new(config).unwrap();
    let admitted = runtime
        .admit_containment_collection(
            &runtime.policy_snapshot(),
            &identity(),
            &context(),
            "confluence",
            "search",
            None,
        )
        .unwrap();
    assert_eq!(
        admitted.scopes,
        BTreeMap::from([("space".into(), vec!["*".into()])])
    );
}
