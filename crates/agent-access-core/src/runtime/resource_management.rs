//! Catalog mutations publish the same immutable policy graph as grant mutations.
use super::*;
use crate::{
    CreateResourceGroupRequest, CreateResourceRequest, DeleteResourceRequest,
    ManagedCatalogMutationResult, ManagedResourceGroupRecord, ManagedResourceRecord,
    PatchResourceGroupRequest, PatchResourceRequest,
};

impl BrokerRuntime {
    pub(super) fn validate_resource_attributes(
        &self,
        resource_type: &ResourceType,
        selector: &ResourceSelector,
        attributes: &ResourceAttributes,
        require_all: bool,
    ) -> Result<(), ManagedStoreError> {
        self.resource_types
            .validate_attributes(
                &self.config.providers,
                resource_type,
                selector,
                attributes,
                require_all,
            )
            .map_err(ManagedStoreError::InputInvalid)
    }

    pub fn create_managed_resource(
        &self,
        request: CreateResourceRequest,
    ) -> Result<ManagedCatalogMutationResult<ManagedResourceRecord>, ManagedStoreError> {
        let _guard = self.managed_policy_mutation_guard()?;
        let store = self.managed_policy_store()?.clone();
        let baseline = store.policy_validation_baseline()?;
        self.resource_types
            .require_new_resources(&request.resource_type)
            .map_err(ManagedStoreError::InputInvalid)?;
        self.validate_resource_attributes(
            &request.resource_type,
            &request.selector,
            &request.attributes,
            true,
        )?;
        let result = store.create_resource(request, |grants, revision, subjects, catalog| {
            self.validate_managed_policy_candidate_for_store(
                grants, revision, subjects, catalog, &baseline,
            )
        })?;
        self.publish_managed_catalog_result(result)
    }

    pub fn patch_managed_resource(
        &self,
        request: PatchResourceRequest,
    ) -> Result<ManagedCatalogMutationResult<ManagedResourceRecord>, ManagedStoreError> {
        let _guard = self.managed_policy_mutation_guard()?;
        let store = self.managed_policy_store()?.clone();
        let baseline = store.policy_validation_baseline()?;
        let existing = store.resource(&request.id)?;
        if existing.version != request.expected_version {
            return Err(ManagedStoreError::VersionConflict);
        }
        // Moving a resource into a removed type adds a resource to it.
        if let Some(resource_type) = request
            .resource_type
            .as_ref()
            .filter(|resource_type| **resource_type != existing.definition.resource_type)
        {
            self.resource_types
                .require_new_resources(resource_type)
                .map_err(ManagedStoreError::InputInvalid)?;
        }
        self.validate_resource_attributes(
            request
                .resource_type
                .as_ref()
                .unwrap_or(&existing.definition.resource_type),
            request
                .selector
                .as_ref()
                .unwrap_or(&existing.definition.selector),
            &request.attributes,
            false,
        )?;
        let result = store.patch_resource(request, |grants, revision, subjects, catalog| {
            self.validate_managed_policy_candidate_for_store(
                grants, revision, subjects, catalog, &baseline,
            )
        })?;
        self.publish_managed_catalog_result(result)
    }

    pub fn delete_managed_resource(
        &self,
        request: DeleteResourceRequest,
    ) -> Result<ManagedCatalogMutationResult<()>, ManagedStoreError> {
        let _guard = self.managed_policy_mutation_guard()?;
        let store = self.managed_policy_store()?.clone();
        let baseline = store.policy_validation_baseline()?;
        let result = store.delete_resource(request, |grants, revision, subjects, catalog| {
            self.validate_managed_policy_candidate_for_store(
                grants, revision, subjects, catalog, &baseline,
            )
        })?;
        self.publish_managed_catalog_result(result)
    }

    pub fn create_managed_resource_group(
        &self,
        request: CreateResourceGroupRequest,
    ) -> Result<ManagedCatalogMutationResult<ManagedResourceGroupRecord>, ManagedStoreError> {
        let _guard = self.managed_policy_mutation_guard()?;
        let store = self.managed_policy_store()?.clone();
        let baseline = store.policy_validation_baseline()?;
        let result =
            store.create_resource_group(request, |grants, revision, subjects, catalog| {
                self.validate_managed_policy_candidate_for_store(
                    grants, revision, subjects, catalog, &baseline,
                )
            })?;
        self.publish_managed_catalog_result(result)
    }

    pub fn patch_managed_resource_group(
        &self,
        request: PatchResourceGroupRequest,
    ) -> Result<ManagedCatalogMutationResult<ManagedResourceGroupRecord>, ManagedStoreError> {
        let _guard = self.managed_policy_mutation_guard()?;
        let store = self.managed_policy_store()?.clone();
        let baseline = store.policy_validation_baseline()?;
        let result =
            store.patch_resource_group(request, |grants, revision, subjects, catalog| {
                self.validate_managed_policy_candidate_for_store(
                    grants, revision, subjects, catalog, &baseline,
                )
            })?;
        self.publish_managed_catalog_result(result)
    }

    pub fn delete_managed_resource_group(
        &self,
        request: DeleteResourceRequest,
    ) -> Result<ManagedCatalogMutationResult<()>, ManagedStoreError> {
        let _guard = self.managed_policy_mutation_guard()?;
        let store = self.managed_policy_store()?.clone();
        let baseline = store.policy_validation_baseline()?;
        let result =
            store.delete_resource_group(request, |grants, revision, subjects, catalog| {
                self.validate_managed_policy_candidate_for_store(
                    grants, revision, subjects, catalog, &baseline,
                )
            })?;
        self.publish_managed_catalog_result(result)
    }

    fn publish_managed_catalog_result<T>(
        &self,
        result: ManagedCatalogMutationResult<T>,
    ) -> Result<ManagedCatalogMutationResult<T>, ManagedStoreError> {
        if self.policy_snapshot.load().generation() > result.revision.generation {
            return Err(ManagedStoreError::VersionConflict);
        }
        let snapshot = PolicySnapshot::from_managed(
            result.revision.generation,
            result.active_grants.clone(),
            result.catalog.clone(),
        );
        self.policy_snapshot.store(Arc::new(snapshot));
        Ok(result)
    }
}

/// Completeness can be validated inside the store transaction without decrypting
/// unrelated values or publishing secrets in a policy snapshot.
pub(super) fn validate_attribute_bindings(
    types: &ResourceTypeRegistry,
    catalog: &ManagedResourceCatalog,
) -> Result<(), ManagedStoreError> {
    for resource in &catalog.resources {
        let Some(descriptor) = types.get(&resource.resource_type) else {
            continue;
        };
        let binding = catalog
            .attribute_bindings
            .iter()
            .find(|binding| binding.resource_id == resource.id);
        if !matches!(resource.selector, ResourceSelector::Exact { .. }) {
            if binding.is_some() {
                return Err(ManagedStoreError::InputInvalid(
                    "private attributes require exact resources".into(),
                ));
            }
            continue;
        }
        if descriptor.attributes().iter().any(|attribute| {
            attribute.is_required()
                && !binding
                    .is_some_and(|binding| binding.material_versions.contains_key(attribute.name()))
        }) {
            return Err(ManagedStoreError::InputInvalid(
                "required resource attributes are missing".into(),
            ));
        }
        if binding.is_some_and(|binding| {
            binding.material_versions.keys().any(|name| {
                !descriptor
                    .attributes()
                    .iter()
                    .any(|attribute| attribute.name() == name)
            })
        }) {
            return Err(ManagedStoreError::InputInvalid(
                "unknown resource attribute".into(),
            ));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use async_trait::async_trait;
    use std::sync::atomic::{AtomicBool, Ordering};
    use tokio::sync::Notify;

    struct HoldingProvider {
        hold_once: AtomicBool,
        entered: Notify,
        resume: Notify,
    }
    impl agent_access_provider::test_support::DescribedProvider for HoldingProvider {
        fn descriptor(&self) -> ServiceDescriptor {
            agent_access_fake::fake_descriptor()
        }
    }

    #[async_trait]
    impl Provider for HoldingProvider {
        async fn resolve_scopes(
            &self,
            request: ScopeRequest<'_>,
        ) -> Result<ScopeResolution, ProviderError> {
            if self.hold_once.swap(false, Ordering::SeqCst) {
                self.entered.notify_one();
                self.resume.notified().await;
            }
            agent_access_fake::FakeProvider
                .echo_scopes(request.action(), request.inputs())
                .map(ScopeResolution::resources)
        }
        async fn invoke(
            &self,
            request: ProviderInvocation,
        ) -> Result<ProviderResult, ProviderError> {
            agent_access_fake::FakeProvider.invoke(request).await
        }
    }

    fn managed_config(path: &Path) -> BrokerConfig {
        let mut config = super::super::tests::base_fake_config();
        config.identity.authority = "managed".into();
        config.identity.groups.clear();
        config.policy.authority = "managed".into();
        config.policy.resources.clear();
        config.policy.resource_groups.clear();
        config.policy.grants.clear();
        config.managed_store = Some(crate::ManagedStoreConfig {
            kind: "sqlite".into(),
            path: path.display().to_string(),
            require_registered_principal_for_invocation: false,
            auto_migrate: true,
        });
        config
    }

    fn create_project(runtime: &BrokerRuntime, id: &str, key: &str) {
        runtime
            .create_managed_resource(CreateResourceRequest {
                attributes: Default::default(),
                id: Some(id.into()),
                display_name: None,
                resource_type: agent_access_fake::FAKE_PROJECT_RESOURCE.id().clone(),
                selector: ResourceSelector::Exact { value: key.into() },
                allowed_execution_contexts: vec!["default".into()],
                enabled: true,
                created_by: "test-admin".into(),
            })
            .unwrap();
    }

    fn create_grant(runtime: &BrokerRuntime, resources: ResourceSelection) {
        runtime
            .create_managed_policy_grant(ManagedPolicyGrantCreateRequest {
                grant_id: None,
                subjects: vec!["group:anonymous".into()],
                execution_contexts: vec!["default".into()],
                service: "fake".into(),
                actions: vec!["echo".into()],
                resources,
                credential_mode: "service".into(),
                priority: None,
                status: None,
                description: None,
                created_by: "test-admin".into(),
            })
            .unwrap();
    }

    fn token_identity(selection: Option<ResourceSelection>) -> IdentityContext {
        let mut identity = IdentityContext::anonymous();
        let caveats = AgentInvokeTokenCaveats {
            allowed_services: Some(vec!["fake".into()]),
            allowed_execution_contexts: Some(vec![ExecutionContext::new("default").unwrap()]),
            service_restrictions: Some(BTreeMap::from([(
                "fake".into(),
                crate::AgentTokenServiceRestriction {
                    actions: vec!["echo".into()],
                    resources: selection,
                },
            )])),
        };
        identity.source = Some(IdentitySourceAudit {
            read_only_access: None,
            namespace: None,
            binding_id: None,
            name: "test-agent".into(),
            kind: "broker_tokens".into(),
            token_header: "Authorization".into(),
            token_scheme: "Bearer".into(),
            token_class: Some(BrokerTokenClass::AgentInvoke),
            token_id: Some("test-token".into()),
            token_scopes: Some(caveats.to_scopes_value()),
        });
        identity
    }

    async fn invoke_project(
        runtime: &BrokerRuntime,
        identity: IdentityContext,
        project: &str,
    ) -> BrokerResponse<Value> {
        runtime
            .invoke(
                GovernedOperationContext {
                    operation: OperationContext {
                        agent_request_id: format!("agent-{project}"),
                        broker_request_id: format!("broker-{project}"),
                        identity,
                        service: "fake".into(),
                        action: "echo".into(),
                        source: SourceContext::unknown(),
                    },
                    execution_context: ExecutionContext::new("default").unwrap(),
                },
                InvokeRequest::new(json!({"project": project, "message": "test"})),
            )
            .await
    }

    #[tokio::test]
    async fn live_group_updates_preserve_inflight_snapshot_and_restrict_existing_tokens() {
        let directory = tempfile::tempdir().unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700)).unwrap();
        }
        let provider = Arc::new(HoldingProvider {
            hold_once: AtomicBool::new(true),
            entered: Notify::new(),
            resume: Notify::new(),
        });
        let mut config = managed_config(&directory.path().join("policy.sqlite3"));
        config.execution_context = Some(crate::ExecutionContextConfig {
            allowed_values: vec!["default".into(), "external".into()],
            default_context: None,
        });
        let runtime = BrokerRuntime::with_providers(config, vec![provider.clone()]).unwrap();
        create_project(&runtime, "first", "FIRST");
        create_project(&runtime, "second", "SECOND");
        runtime
            .create_managed_resource_group(CreateResourceGroupRequest {
                id: Some("selected".into()),
                name: "Selected projects".into(),
                included_resource_ids: vec!["first".into()],
                excluded_resource_ids: vec![],
                created_by: "test-admin".into(),
            })
            .unwrap();
        let selection = ResourceSelection {
            resource_ids: vec![],
            resource_group_ids: vec!["selected".into()],
        };
        create_grant(&runtime, selection.clone());
        let identity = token_identity(Some(selection));
        let old_generation = runtime.policy_generation();
        let task_runtime = runtime.clone();
        let task_identity = identity.clone();
        let pending =
            tokio::spawn(
                async move { invoke_project(&task_runtime, task_identity, "FIRST").await },
            );
        timeout(Duration::from_secs(5), provider.entered.notified())
            .await
            .unwrap();
        runtime
            .patch_managed_resource_group(PatchResourceGroupRequest {
                id: "selected".into(),
                expected_version: 1,
                name: None,
                included_resource_ids: Some(vec!["second".into()]),
                excluded_resource_ids: None,
                updated_by: "test-admin".into(),
            })
            .unwrap();
        assert!(runtime.policy_generation() > old_generation);
        provider.resume.notify_one();
        let old_response = pending.await.unwrap();
        assert_eq!(
            old_response.envelope.decision,
            Decision::Allow,
            "in-flight authorization must retain the entire old graph"
        );
        assert_eq!(
            invoke_project(&runtime, identity.clone(), "FIRST")
                .await
                .envelope
                .decision,
            Decision::Deny
        );
        assert_eq!(
            invoke_project(&runtime, identity.clone(), "SECOND")
                .await
                .envelope
                .decision,
            Decision::Allow,
            "same token follows live group membership"
        );
        runtime
            .patch_managed_resource(PatchResourceRequest {
                attributes: Default::default(),
                id: "second".into(),
                expected_version: 1,
                display_name: None,
                resource_type: None,
                selector: None,
                allowed_execution_contexts: Some(vec!["external".into()]),
                enabled: None,
                updated_by: "test-admin".into(),
            })
            .unwrap();
        assert_eq!(
            invoke_project(&runtime, identity.clone(), "SECOND")
                .await
                .envelope
                .decision,
            Decision::Deny,
            "resource context edits immediately narrow the existing token"
        );
        runtime
            .patch_managed_resource(PatchResourceRequest {
                attributes: Default::default(),
                id: "second".into(),
                expected_version: 2,
                display_name: None,
                resource_type: None,
                selector: None,
                allowed_execution_contexts: Some(vec!["default".into()]),
                enabled: Some(false),
                updated_by: "test-admin".into(),
            })
            .unwrap();
        assert_eq!(
            invoke_project(&runtime, identity.clone(), "SECOND")
                .await
                .envelope
                .decision,
            Decision::Deny,
            "disabled positive entry provides no permission"
        );
        runtime
            .patch_managed_resource(PatchResourceRequest {
                attributes: Default::default(),
                id: "second".into(),
                expected_version: 3,
                display_name: None,
                resource_type: None,
                selector: None,
                allowed_execution_contexts: None,
                enabled: Some(true),
                updated_by: "test-admin".into(),
            })
            .unwrap();
        runtime
            .patch_managed_resource_group(PatchResourceGroupRequest {
                id: "selected".into(),
                expected_version: 2,
                name: None,
                included_resource_ids: Some(vec![]),
                excluded_resource_ids: None,
                updated_by: "test-admin".into(),
            })
            .unwrap();
        assert_eq!(
            invoke_project(&runtime, identity.clone(), "SECOND")
                .await
                .envelope
                .decision,
            Decision::Deny,
            "empty restricted group cannot become unrestricted"
        );
        let caveats = parsed_agent_invoke_token_caveats(&identity)
            .unwrap()
            .unwrap()
            .caveats;
        let preview = runtime
            .preview_agent_token_access(&identity, &caveats)
            .unwrap();
        assert!(preview.access.is_empty());
        assert_eq!(preview.policy_generation, runtime.policy_generation());
        let delegated_catalog =
            runtime.policy_resource_catalog_for_scope(&PolicyReadScope::Services {
                services: BTreeSet::from(["fake".into()]),
            });
        assert!(
            delegated_catalog
                .resource_groups
                .iter()
                .any(|group| group.id == "selected"),
            "delegated manager must retain an authored empty group reference"
        );
        let options = runtime.agent_token_options_for_identity(&identity);
        assert!(
            options
                .resource_groups
                .iter()
                .any(|group| group.id == "selected"),
            "authored empty group must remain selectable"
        );
        let action = &options
            .services
            .iter()
            .find(|service| service.service == "fake")
            .unwrap()
            .actions[0];
        assert!(
            action.effective_access_by_execution_context
                [&ExecutionContext::new("default").unwrap()]
                .is_empty()
        );
    }

    #[tokio::test]
    async fn group_exclusions_survive_resource_disabling_and_context_ineligibility() {
        let directory = tempfile::tempdir().unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700)).unwrap();
        }
        let mut config = managed_config(&directory.path().join("policy.sqlite3"));
        config.execution_context = Some(crate::ExecutionContextConfig {
            allowed_values: vec!["default".into(), "external".into()],
            default_context: None,
        });
        let runtime = BrokerRuntime::new(config).unwrap();
        runtime
            .create_managed_resource(CreateResourceRequest {
                attributes: Default::default(),
                id: Some("all".into()),
                display_name: None,
                resource_type: agent_access_fake::FAKE_PROJECT_RESOURCE.id().clone(),
                selector: ResourceSelector::All,
                allowed_execution_contexts: vec!["default".into()],
                enabled: true,
                created_by: "test-admin".into(),
            })
            .unwrap();
        runtime
            .create_managed_resource(CreateResourceRequest {
                attributes: Default::default(),
                id: Some("private".into()),
                display_name: None,
                resource_type: agent_access_fake::FAKE_PROJECT_RESOURCE.id().clone(),
                selector: ResourceSelector::Exact {
                    value: "PRIVATE".into(),
                },
                allowed_execution_contexts: vec!["external".into()],
                enabled: false,
                created_by: "test-admin".into(),
            })
            .unwrap();
        runtime
            .create_managed_resource_group(CreateResourceGroupRequest {
                id: Some("broad".into()),
                name: "Broad except private".into(),
                included_resource_ids: vec!["all".into()],
                excluded_resource_ids: vec!["private".into()],
                created_by: "test-admin".into(),
            })
            .unwrap();
        runtime
            .create_managed_resource_group(CreateResourceGroupRequest {
                id: Some("overlap".into()),
                name: "Overlapping include".into(),
                included_resource_ids: vec!["all".into()],
                excluded_resource_ids: vec![],
                created_by: "test-admin".into(),
            })
            .unwrap();
        let selection = ResourceSelection {
            resource_ids: vec![],
            resource_group_ids: vec!["broad".into(), "overlap".into()],
        };
        create_grant(&runtime, selection.clone());
        let identity = token_identity(None);
        assert_eq!(
            invoke_project(&runtime, identity.clone(), "NEWPROJECT")
                .await
                .envelope
                .decision,
            Decision::Allow
        );
        assert_eq!(
            invoke_project(&runtime, identity.clone(), "PRIVATE")
                .await
                .envelope
                .decision,
            Decision::Deny
        );
        let preview = runtime
            .preview_policy_resources(
                "fake",
                &["echo".into()],
                &[ExecutionContext::new("default").unwrap()],
                &selection,
            )
            .unwrap();
        assert_eq!(preview.access.len(), 1);
        assert!(!preview.access[0].clauses[0].matches("PRIVATE"));
        assert!(
            runtime
                .policy_resource_catalog_for_scope(&PolicyReadScope::Services {
                    services: BTreeSet::from(["fake".into()])
                })
                .resources
                .len()
                == 2
        );
    }
    #[test]
    fn discovery_managed_label_edit_advances_policy_revision_and_invalidates_cursor() {
        let directory = tempfile::tempdir().unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700)).unwrap();
        }
        let runtime =
            BrokerRuntime::new(managed_config(&directory.path().join("policy.sqlite3"))).unwrap();
        create_project(&runtime, "first", "FIRST");
        create_project(&runtime, "second", "SECOND");
        create_grant(
            &runtime,
            ResourceSelection {
                resource_ids: vec!["first".into(), "second".into()],
                resource_group_ids: vec![],
            },
        );
        let identity = IdentityContext::anonymous();
        let context = ExecutionContext::new("default").unwrap();
        let first = runtime
            .service_discovery(&identity, &context, "fake")
            .unwrap()
            .resources(&ResourceListQuery {
                limit: Some(1),
                ..Default::default()
            })
            .unwrap();
        let generation = runtime.policy_generation();
        runtime
            .patch_managed_resource(PatchResourceRequest {
                attributes: Default::default(),
                id: "second".into(),
                expected_version: 1,
                display_name: Some(Some("Second project".into())),
                resource_type: None,
                selector: None,
                allowed_execution_contexts: None,
                enabled: None,
                updated_by: "test-admin".into(),
            })
            .unwrap();
        assert!(runtime.policy_generation() > generation);
        let view = runtime
            .service_discovery(&identity, &context, "fake")
            .unwrap();
        assert!(
            view.resources(&ResourceListQuery {
                limit: Some(1),
                cursor: first.next_cursor,
                ..Default::default()
            })
            .is_err()
        );
        assert_eq!(
            view.resources(&ResourceListQuery::default())
                .unwrap()
                .resources[1]
                .display_name
                .as_deref(),
            Some("Second project")
        );
    }
}
