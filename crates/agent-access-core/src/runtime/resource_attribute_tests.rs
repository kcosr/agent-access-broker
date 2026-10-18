//! A backend unknown to core exercises the complete private-resource contract.
use super::*;
use crate::{BackendRegistry, CreateResourceRequest, PatchResourceRequest, ProvidersConfig};
use agent_access_provider::{BackendConfig, BackendRegistration};
use async_trait::async_trait;
use std::sync::Mutex;

static TYPE: ResourceTypeDescriptor = ResourceTypeDescriptor::new(
    ResourceType::from_static("attribute_fixture"),
    "Fixture destination",
    "Fixture destinations",
    "one",
    |value| !value.is_empty() && value.bytes().all(|b| b.is_ascii_lowercase()),
    &ATTRIBUTES,
);
static ATTRIBUTES: [ResourceAttributeDescriptor; 1] = [ResourceAttributeDescriptor::required(
    "endpoint",
    "Endpoint",
    "Private test endpoint",
    |value| value.starts_with("secret-"),
)];
static BACKEND: BackendRegistration = BackendRegistration::new(
    agent_access_provider::module_metadata!(),
    "attribute_fixture",
    parse_backend_config::<FixtureConfig>,
)
.with_resource_types(&[&TYPE])
.development_only();

#[derive(Debug, Clone, Default, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct FixtureConfig {
    #[serde(skip)]
    observed: Arc<Mutex<Vec<String>>>,
}
impl BackendConfig for FixtureConfig {
    fn kind(&self) -> &'static str {
        "attribute_fixture"
    }
    fn validate(&self, _: &ValidationContext<'_>, _: &mut Vec<String>) {}
    fn validate_resource_attributes(
        &self,
        _: &ResourceType,
        values: &ResourceAttributes,
    ) -> Result<(), String> {
        if values.get("endpoint") == Some("secret-forbidden") {
            Err("fixture endpoint is not allowed".into())
        } else {
            Ok(())
        }
    }
    fn descriptor(&self) -> ServiceDescriptor {
        ServiceDescriptor::new(self.kind(), "Attribute conformance").with_resource_scopes(BTreeMap::from([("destination".into(), ResourceScopeCapabilities::new(TYPE.id().clone(), vec!["exact".into(), "all".into()]))])).with_actions(vec![ActionDescriptor::new("send", "Send to a private fixture", json!({"type":"object","required":["destination"],"properties":{"destination":{"type":"string"}},"additionalProperties":false}))
                .scopes(["destination"]).credential_modes(["service"]).resource_attributes()]).with_credentials(CredentialDescriptor::without_execution_credential())
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
        let target = inputs["destination"]
            .as_str()
            .filter(|target| TYPE.is_canonical_target(target))
            .ok_or_else(|| ProviderError::deny(ReasonCode::BodyMalformed, "invalid destination"))?;
        Ok(BTreeMap::from([(
            "destination".into(),
            vec![target.into()],
        )]))
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
    async fn invoke(&self, request: ProviderInvocation) -> Result<ProviderResult, ProviderError> {
        assert!(request.execution().static_credential().is_none());
        let value = request.resource_attributes().get("endpoint").unwrap();
        assert!(!format!("{request:?}").contains(value));
        assert_invocation_never_serializes();
        self.observed.lock().unwrap().push(value.into());
        Ok(ProviderResult::new(json!({"accepted":true})).with_upstream(Some(202), None))
    }
}

fn fixture() -> (tempfile::TempDir, BrokerRuntime, Arc<Mutex<Vec<String>>>) {
    let directory = tempfile::tempdir().unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700)).unwrap();
    }
    let mut config = tests::base_fake_config();
    config.identity.authority = "managed".into();
    config.identity.groups.clear();
    config.policy.authority = "managed".into();
    config.policy.resources.clear();
    config.policy.resource_groups.clear();
    config.policy.grants.clear();
    config.credentials = Default::default();
    config.managed_store = Some(crate::ManagedStoreConfig {
        kind: "sqlite".into(),
        path: directory.path().join("store.sqlite").display().to_string(),
        auto_migrate: true,
        require_registered_principal_for_invocation: false,
    });
    let keys = &mut config.credential_encryption.as_mut().unwrap().keys;
    let mut second = keys[0].clone();
    second.id = "replacement".into();
    keys.push(second);
    config.execution_context = Some(crate::ExecutionContextConfig {
        allowed_values: vec!["default".into(), "external".into()],
        default_context: None,
    });
    config.audit = Some(crate::AuditConfig::new(
        crate::AuditStoreType::Jsonl,
        directory.path().join("audit.jsonl").display().to_string(),
    ));
    let backend = FixtureConfig::default();
    let observed = backend.observed.clone();
    config.providers =
        ProvidersConfig::new(Arc::new(BackendRegistry::new([&BACKEND]).unwrap())).with(backend);
    (directory, BrokerRuntime::new(config).unwrap(), observed)
}
fn attributes(value: &str) -> ResourceAttributes {
    BTreeMap::from([("endpoint".into(), value.into())]).into()
}
fn create(
    runtime: &BrokerRuntime,
    id: &str,
    selector: ResourceSelector,
    values: ResourceAttributes,
) -> Result<crate::ManagedCatalogMutationResult<crate::ManagedResourceRecord>, ManagedStoreError> {
    runtime.create_managed_resource(CreateResourceRequest {
        id: Some(id.into()),
        display_name: None,
        resource_type: TYPE.id().clone(),
        selector,
        attributes: values,
        allowed_execution_contexts: vec!["default".into()],
        enabled: true,
        created_by: "test".into(),
    })
}
fn exact(value: &str) -> ResourceSelector {
    ResourceSelector::Exact {
        value: value.into(),
    }
}
fn selection(ids: &[&str]) -> ResourceSelection {
    ResourceSelection {
        resource_ids: ids.iter().map(|id| (*id).into()).collect(),
        resource_group_ids: vec![],
    }
}
fn grant(runtime: &BrokerRuntime, resources: ResourceSelection) {
    runtime
        .create_managed_policy_grant(ManagedPolicyGrantCreateRequest {
            grant_id: None,
            subjects: vec!["group:anonymous".into()],
            execution_contexts: vec!["default".into(), "external".into()],
            service: "attribute_fixture".into(),
            actions: vec!["send".into()],
            resources,
            credential_mode: "service".into(),
            priority: None,
            status: None,
            description: None,
            created_by: "test".into(),
        })
        .unwrap();
}
fn context(execution_context: &str) -> GovernedOperationContext {
    GovernedOperationContext {
        operation: OperationContext {
            agent_request_id: "agent-test".into(),
            broker_request_id: uuid::Uuid::new_v4().to_string(),
            identity: IdentityContext::anonymous(),
            service: "attribute_fixture".into(),
            action: "send".into(),
            source: SourceContext::unknown(),
        },
        execution_context: ExecutionContext::new(execution_context).unwrap(),
    }
}
async fn send(runtime: &BrokerRuntime, destination: &str) -> BrokerResponse<Value> {
    runtime
        .invoke(
            context("default"),
            InvokeRequest::new(json!({"destination":destination})),
        )
        .await
}
fn patch(id: &str, version: i64) -> PatchResourceRequest {
    PatchResourceRequest {
        id: id.into(),
        expected_version: version,
        attributes: Default::default(),
        display_name: None,
        resource_type: None,
        selector: None,
        allowed_execution_contexts: None,
        enabled: None,
        updated_by: "test".into(),
    }
}

#[tokio::test]
async fn private_resources_require_configuration_and_do_not_require_dummy_credentials() {
    let (_dir, runtime, observed) = fixture();
    assert!(create(&runtime, "missing", exact("missing"), Default::default()).is_err());
    assert!(
        create(
            &runtime,
            "bad",
            exact("bad"),
            attributes("secret-forbidden")
        )
        .is_err()
    );
    assert!(
        create(
            &runtime,
            "all",
            ResourceSelector::All,
            attributes("secret-one")
        )
        .is_err()
    );
    create(&runtime, "one", exact("one"), attributes("secret-one")).unwrap();
    assert_eq!(send(&runtime, "one").await.status, 403);
    create(&runtime, "all", ResourceSelector::All, Default::default()).unwrap();
    grant(&runtime, selection(&["all"]));
    assert_eq!(send(&runtime, "one").await.status, 200);
    assert_ne!(send(&runtime, "missing").await.status, 200);
    let identity = IdentityContext::anonymous();
    let ctx = ExecutionContext::new("default").unwrap();
    let resources = runtime
        .service_discovery(&identity, &ctx, "attribute_fixture")
        .unwrap()
        .resources(&ResourceListQuery::default())
        .unwrap();
    assert_eq!(resources.resources.len(), 1);
    assert_eq!(resources.resources[0].value, "one");
    assert!(
        !serde_json::to_string(&resources)
            .unwrap()
            .contains("secret-one")
    );
    // A later destination automatically falls under the existing All grant.
    create(&runtime, "two", exact("two"), attributes("secret-two")).unwrap();
    assert_eq!(send(&runtime, "two").await.status, 200);
    let outside = runtime
        .invoke(
            context("external"),
            InvokeRequest::new(json!({"destination":"one"})),
        )
        .await;
    assert_ne!(outside.status, 200);
    let mut change = patch("one", 1);
    change.enabled = Some(false);
    runtime.patch_managed_resource(change).unwrap();
    assert_ne!(send(&runtime, "one").await.status, 200);
    assert_eq!(*observed.lock().unwrap(), vec!["secret-one", "secret-two"]);
    // Invocation audit names the destination but never its private value.
    runtime
        .shutdown_audit(std::time::Duration::from_secs(1))
        .await
        .unwrap();
    let audit = fs::read_to_string(_dir.path().join("audit.jsonl")).unwrap();
    assert!(audit.contains("\"destination\":[\"two\"]"), "{audit}");
    assert!(!audit.contains("secret-"), "{audit}");
}

#[tokio::test]
async fn replacing_disabling_or_reusing_alias_invalidates_prepared_private_resource_calls() {
    for change in ["replace", "disable", "context", "rename", "recreate"] {
        let (_dir, runtime, observed) = fixture();
        create(&runtime, "one", exact("one"), attributes("secret-one")).unwrap();
        create(&runtime, "all", ResourceSelector::All, Default::default()).unwrap();
        grant(&runtime, selection(&["all"]));
        let prepared = runtime
            .begin_invoke(
                context("default"),
                InvokeRequest::new(json!({"destination":"one"})),
            )
            .await
            .unwrap();
        if change == "recreate" {
            runtime
                .delete_managed_resource(crate::DeleteResourceRequest {
                    id: "one".into(),
                    expected_version: 1,
                    updated_by: "test".into(),
                })
                .unwrap();
            create(&runtime, "one", exact("one"), attributes("secret-two")).unwrap();
        } else {
            let mut request = patch("one", 1);
            match change {
                "replace" => request.attributes = attributes("secret-two"),
                "disable" => request.enabled = Some(false),
                "context" => request.allowed_execution_contexts = Some(vec!["external".into()]),
                _ => request.selector = Some(exact("renamed")),
            }
            runtime.patch_managed_resource(request).unwrap();
        }
        let response = runtime.finish_prepared_invoke(prepared, vec![]).await;
        assert_ne!(response.status, 200, "{change}");
        assert!(observed.lock().unwrap().is_empty());
        assert!(
            !serde_json::to_string(&response)
                .unwrap()
                .contains("secret-")
        );
    }
}

#[tokio::test]
async fn rewrap_keeps_prepared_private_resource_binding_valid_and_metadata_patch_preserves_secret()
{
    let (_dir, runtime, observed) = fixture();
    create(&runtime, "one", exact("one"), attributes("secret-one")).unwrap();
    grant(&runtime, selection(&["one"]));
    let prepared = runtime
        .begin_invoke(
            context("default"),
            InvokeRequest::new(json!({"destination":"one"})),
        )
        .await
        .unwrap();
    runtime
        .managed_store()
        .unwrap()
        .rewrap_credentials(
            runtime.credential_key_ring().unwrap(),
            "fixture",
            "replacement",
            "test",
        )
        .unwrap();
    assert_eq!(
        runtime
            .finish_prepared_invoke(prepared, vec![])
            .await
            .status,
        200
    );
    let mut change = patch("one", 1);
    change.display_name = Some(Some("Friendly name".into()));
    let record = runtime.patch_managed_resource(change).unwrap().record;
    assert_eq!(record.configured_attributes, vec!["endpoint"]);
    assert_eq!(send(&runtime, "one").await.status, 200);
    assert_eq!(*observed.lock().unwrap(), vec!["secret-one", "secret-one"]);
}

#[tokio::test]
async fn private_destination_group_exclusions_and_token_narrowing_apply_before_execution() {
    let (_dir, runtime, observed) = fixture();
    for name in ["one", "two", "three"] {
        create(
            &runtime,
            name,
            exact(name),
            attributes(&format!("secret-{name}")),
        )
        .unwrap();
    }
    create(&runtime, "all", ResourceSelector::All, Default::default()).unwrap();
    runtime
        .create_managed_resource_group(crate::CreateResourceGroupRequest {
            id: Some("group".into()),
            name: "All except two".into(),
            included_resource_ids: vec!["all".into()],
            excluded_resource_ids: vec!["two".into()],
            created_by: "test".into(),
        })
        .unwrap();
    grant(
        &runtime,
        ResourceSelection {
            resource_ids: vec![],
            resource_group_ids: vec!["group".into()],
        },
    );
    assert_eq!(send(&runtime, "two").await.status, 403);
    let caveats = AgentInvokeTokenCaveats {
        allowed_services: Some(vec!["attribute_fixture".into()]),
        allowed_execution_contexts: Some(vec![ExecutionContext::new("default").unwrap()]),
        service_restrictions: Some(BTreeMap::from([(
            "attribute_fixture".into(),
            crate::AgentTokenServiceRestriction {
                actions: vec!["send".into()],
                resources: Some(selection(&["one"])),
            },
        )])),
    };
    for (target, expected) in [("one", 200), ("three", 403)] {
        let mut ctx = context("default");
        ctx.operation.identity.source = Some(IdentitySourceAudit {
            namespace: None,
            binding_id: None,
            name: "fixture".into(),
            kind: "broker_tokens".into(),
            token_header: "Authorization".into(),
            token_scheme: "Bearer".into(),
            token_class: Some(BrokerTokenClass::AgentInvoke),
            token_id: Some("test".into()),
            token_scopes: Some(caveats.to_scopes_value()),
        });
        let response = runtime
            .invoke(ctx, InvokeRequest::new(json!({"destination":target})))
            .await;
        assert_eq!(response.status, expected, "{response:?}");
    }
    assert_eq!(*observed.lock().unwrap(), vec!["secret-one"]);
}

#[test]
fn private_attribute_type_metadata_is_generic_and_consumers_must_own_the_type() {
    let (_dir, runtime, _) = fixture();
    let metadata = TYPE.metadata();
    assert_eq!(metadata.attributes[0].name, "endpoint");
    assert!(metadata.attributes[0].secret);
    let mut foreign = runtime.services["attribute_fixture"].as_ref().clone();
    foreign.service = "other".into();
    let mut errors = vec![];
    crate::validate_private_resource_consumers(
        runtime.config(),
        &BTreeMap::from([("other".into(), Arc::new(foreign))]),
        &runtime.resource_types,
        &mut errors,
    );
    assert!(
        errors
            .iter()
            .any(|error| error.contains("defining backend"))
    );
}

/// Private attributes cannot leak through invocation serialization because
/// the invocation does not implement `Serialize`: a serializable invocation
/// makes this item lookup ambiguous and fails to compile.
fn assert_invocation_never_serializes() {
    trait AmbiguousIfSerialize<A> {
        fn item() {}
    }
    impl<T: ?Sized> AmbiguousIfSerialize<()> for T {}
    #[allow(dead_code)]
    struct Serializes;
    impl<T: ?Sized + serde::Serialize> AmbiguousIfSerialize<Serializes> for T {}
    let _ = <ProviderInvocation as AmbiguousIfSerialize<_>>::item;
}
