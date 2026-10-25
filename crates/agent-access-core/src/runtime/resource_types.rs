//! The effective resource type registry of one runtime generation.
//!
//! A generation understands the composition's static types (the host's own
//! `git_repository` and every selected native's types) and the types its
//! imports accepted. The registry is built with the generation and published
//! with it in one swap, so the registry, the imported catalog, the service
//! descriptors and the policy snapshot a request reads always agree. Each
//! type has one owner, which decides how the private attribute values of its
//! resources are validated.
use crate::imports::{ImportedResourceTypeDeclaration, imported_type_descriptor};
use crate::{BackendRegistry, ImportedCatalog, ProvidersConfig};
use agent_access_provider::{
    ResourceAttributes, ResourceSelector, ResourceType, ResourceTypeDescriptor,
    ResourceTypeRegistry,
};
use std::collections::BTreeMap;
use std::sync::Arc;

/// What defines a resource type in one generation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum ResourceTypeOwner {
    /// The broker itself, independently of any backend.
    Host,
    /// A selected native backend, by kind. A native service is named after
    /// its kind.
    Backend(&'static str),
    /// An imported service, whose accepted metadata declares the type and
    /// alone validates its attributes. A type the service's source no longer
    /// declares is `removed`: it stays registered for its stored resources
    /// and accepts no new ones.
    Imported { service: String, removed: bool },
}

impl std::fmt::Display for ResourceTypeOwner {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Host => f.write_str("the broker"),
            Self::Backend(kind) => write!(f, "the {kind} backend"),
            Self::Imported { service, .. } => write!(f, "imported service {service}"),
        }
    }
}

/// Whether the broker reserves `id` without registering it: the runtime's
/// placeholder type for a scope whose type cannot be resolved.
fn reserved(id: &ResourceType) -> bool {
    id == super::UNRESOLVED_RESOURCE_TYPE.id()
}

/// A generation's resource types and their owners.
#[derive(Debug, Clone)]
pub(crate) struct EffectiveResourceTypes {
    registry: ResourceTypeRegistry,
    owners: BTreeMap<ResourceType, ResourceTypeOwner>,
    /// Each import's accepted declarations and the descriptors built from
    /// them, which the next generation reuses while they are unchanged.
    imported: BTreeMap<String, ImportedTypes>,
}

#[derive(Debug, Clone)]
struct ImportedTypes {
    declarations: Vec<ImportedResourceTypeDeclaration>,
    descriptors: Vec<Arc<ResourceTypeDescriptor>>,
}

impl EffectiveResourceTypes {
    /// The composition's types: what offline configuration validation sees,
    /// and the base of every generation's registry.
    pub(crate) fn composition(backends: &BackendRegistry) -> Self {
        let registry = backends.resource_types().clone();
        let owners = registry
            .ids()
            .map(|id| {
                let owner = backends
                    .resource_owner(id)
                    .map_or(ResourceTypeOwner::Host, ResourceTypeOwner::Backend);
                (id.clone(), owner)
            })
            .collect();
        Self {
            registry,
            owners,
            imported: BTreeMap::new(),
        }
    }

    /// These composition types followed by every type the imports in
    /// `catalog` accepted, whatever the import's status, so stored resources
    /// stay valid while an import is disabled or retired. Descriptors of an
    /// import whose declarations `previous` already holds are reused. An
    /// imported type ID that another owner registers fails the build.
    pub(crate) fn with_imported(
        &self,
        catalog: &ImportedCatalog,
        previous: Option<&Self>,
    ) -> Result<Self, String> {
        let mut descriptors = self.registry.descriptors().cloned().collect::<Vec<_>>();
        let mut owners = self.owners.clone();
        let mut imported = BTreeMap::new();
        for record in &catalog.services {
            let Some(metadata) = &record.accepted_metadata else {
                continue;
            };
            if metadata.resource_types.is_empty() {
                continue;
            }
            let service = &record.definition.service;
            let types = match previous
                .and_then(|previous| previous.imported.get(service))
                .filter(|types| types.declarations == metadata.resource_types)
            {
                Some(types) => types.clone(),
                None => ImportedTypes {
                    declarations: metadata.resource_types.clone(),
                    descriptors: metadata
                        .resource_types
                        .iter()
                        .map(|declared| {
                            imported_type_descriptor(declared).map(Arc::new).map_err(|error| {
                                format!(
                                    "imported service {service} resource type {} is invalid: {error}",
                                    declared.broker_type
                                )
                            })
                        })
                        .collect::<Result<_, _>>()?,
                },
            };
            for (declared, descriptor) in types.declarations.iter().zip(&types.descriptors) {
                if reserved(descriptor.id()) {
                    return Err(format!(
                        "imported service {service} resource type {} collides with a type of {}",
                        descriptor.id(),
                        ResourceTypeOwner::Host
                    ));
                }
                if let Some(owner) = owners.get(descriptor.id()) {
                    return Err(format!(
                        "imported service {service} resource type {} collides with a type of {owner}",
                        descriptor.id()
                    ));
                }
                owners.insert(
                    descriptor.id().clone(),
                    ResourceTypeOwner::Imported {
                        service: service.clone(),
                        removed: declared.removed,
                    },
                );
                descriptors.push(Arc::clone(descriptor));
            }
            imported.insert(service.clone(), types);
        }
        let registry =
            ResourceTypeRegistry::from_shared(descriptors).map_err(|errors| errors.join("; "))?;
        Ok(Self {
            registry,
            owners,
            imported,
        })
    }

    pub(crate) fn registry(&self) -> &ResourceTypeRegistry {
        &self.registry
    }

    /// The registry's client-facing metadata, marking imported types with
    /// their service and removed types as accepting no new resources.
    pub(crate) fn metadata(&self) -> Vec<agent_access_provider::ResourceTypeMetadata> {
        self.registry
            .metadata()
            .into_iter()
            .map(|mut metadata| {
                if let Some(ResourceTypeOwner::Imported { service, removed }) =
                    self.owner(&metadata.id)
                {
                    metadata.removed = *removed;
                    metadata.imported_service = Some(service.clone());
                }
                metadata
            })
            .collect()
    }

    pub(crate) fn get(&self, id: &ResourceType) -> Option<&Arc<ResourceTypeDescriptor>> {
        self.registry.get(id)
    }

    pub(crate) fn owner(&self, id: &ResourceType) -> Option<&ResourceTypeOwner> {
        self.owners.get(id)
    }

    /// The service that defines `id`, which alone may consume the private
    /// attributes of its resources.
    pub(crate) fn defining_service(&self, id: &ResourceType) -> Option<&str> {
        match self.owner(id)? {
            ResourceTypeOwner::Backend(kind) => Some(kind),
            ResourceTypeOwner::Imported { service, .. } => Some(service),
            ResourceTypeOwner::Host => None,
        }
    }

    /// Whether `id` is reserved or registered by an owner other than
    /// imported service `service`, so a new imported type may not take it.
    pub(crate) fn registered_outside(&self, id: &str, service: &str) -> bool {
        ResourceType::new(id).is_ok_and(|id| {
            reserved(&id)
                || self.owner(&id).is_some_and(|owner| {
                !matches!(owner, ResourceTypeOwner::Imported { service: owner, .. } if owner == service)
            })
        })
    }

    /// Rejects a new resource of a type its imported service removed: the
    /// type stays registered only for its stored resources.
    pub(crate) fn require_new_resources(&self, id: &ResourceType) -> Result<(), String> {
        match self.owner(id) {
            Some(ResourceTypeOwner::Imported {
                service,
                removed: true,
            }) => Err(format!(
                "resource type {id} was removed from imported service {service} and accepts no new resources"
            )),
            _ => Ok(()),
        }
    }

    /// Validates a resource's private attribute values against its type's
    /// declaration and, for a native type, against the owning backend's
    /// configured checks; an imported type's declaration is its only check,
    /// so it needs no configured backend. `require_all` requires every
    /// required attribute, as a creation does; a patch supplies only the
    /// values it changes.
    pub(crate) fn validate_attributes(
        &self,
        providers: &ProvidersConfig,
        resource_type: &ResourceType,
        selector: &ResourceSelector,
        attributes: &ResourceAttributes,
        require_all: bool,
    ) -> Result<(), String> {
        let Some(descriptor) = self.get(resource_type) else {
            // Leave metadata-only requests to the catalog's ordinary selector
            // validation so it retains the resource ID in its diagnostics.
            return if attributes.is_empty() {
                Ok(())
            } else {
                Err("unknown resource type".into())
            };
        };
        descriptor.validate_attributes(selector, attributes, require_all)?;
        if attributes.is_empty() {
            return Ok(());
        }
        match self.owner(resource_type) {
            Some(ResourceTypeOwner::Backend(kind)) => providers
                .get_kind(kind)
                .ok_or_else(|| "resource backend must be configured".to_string())?
                .validate_resource_attributes(resource_type, attributes),
            Some(ResourceTypeOwner::Imported { .. }) => Ok(()),
            Some(ResourceTypeOwner::Host) | None => {
                Err("resource backend must be configured".into())
            }
        }
    }
}

impl super::BrokerRuntime {
    /// The registry a generation with `catalog` publishes: the composition's
    /// types and every accepted imported type, reusing this generation's
    /// descriptors for unchanged imports.
    pub(super) fn imported_resource_types(
        &self,
        catalog: &ImportedCatalog,
    ) -> Result<EffectiveResourceTypes, crate::ManagedStoreError> {
        EffectiveResourceTypes::composition(self.config.providers.registry())
            .with_imported(catalog, Some(&self.resource_types))
            .map_err(crate::ManagedStoreError::InputInvalid)
    }

    /// Whether a new type of imported service `service` may not take
    /// `broker_type` because the composition or another import registers it.
    pub fn imported_resource_type_taken(&self, service: &str, broker_type: &str) -> bool {
        self.resource_types.registered_outside(broker_type, service)
    }

    /// Commits an imported-service update and builds the generation that
    /// publishes it, holding the managed policy mutation lock, which resource
    /// writes also take. An acceptance applies its resource type changes in
    /// the same transaction, and when it changes the types every stored
    /// resource is checked against the new registry before commit. When the
    /// changes delete attribute values or drop a type the generation also
    /// publishes the resulting managed policy, so its registry, imported
    /// catalog, resource catalog and attribute bindings change together.
    /// Every update, in the same transaction and under the same lock, also
    /// refuses to leave the service's retained grants invalid for the next
    /// start, checked against the policy it publishes.
    pub fn commit_imported_service_update(
        &self,
        request: crate::ImportedServiceUpdateRequest,
        prepared: super::imports::PreparedImportedProviders,
    ) -> Result<
        (
            crate::ImportedMutationResult<super::BrokerRuntime>,
            crate::ImportedTypeEffects,
        ),
        crate::ManagedStoreError,
    > {
        let _guard = self.managed_policy_mutation_guard()?;
        let store = self.managed_store.as_ref().ok_or_else(|| {
            crate::ManagedStoreError::InputInvalid(
                "imported services require managed storage".into(),
            )
        })?;
        let service = request.definition.service.clone();
        store.update_imported_service_with_policy(request, |catalog, transaction| {
            let next = self.with_imported_catalog(catalog.clone(), prepared)?;
            let Some(transaction) = transaction else {
                return Ok(next);
            };
            next.check_stored_resources(transaction.catalog)?;
            match transaction.policy {
                Some(policy) => {
                    // The retained grants are rechecked against the policy
                    // this acceptance publishes.
                    let next = next.with_managed_policy_state(policy)?;
                    next.check_retained_import_grants(&service)?;
                    Ok(next)
                }
                None => Ok(next),
            }
        })
    }

    /// Checks a managed resource catalog against this generation's registry:
    /// every resource's type and selector, group exclusions, and attribute bindings.
    fn check_stored_resources(
        &self,
        catalog: &crate::ManagedResourceCatalog,
    ) -> Result<(), crate::ManagedStoreError> {
        if self.config.policy.authority != "managed" {
            return Ok(());
        }
        let errors = crate::validate_resource_catalog_types(
            self.resource_types.registry(),
            &catalog.resources,
            &catalog.resource_groups,
        );
        if !errors.is_empty() {
            return Err(crate::ManagedStoreError::InputInvalid(errors.join("; ")));
        }
        super::resource_management::validate_attribute_bindings(
            self.resource_types.registry(),
            catalog,
        )
    }

    /// Publishes `state`, committed in the same transaction as the catalog
    /// this generation carries and already checked against its registry, as
    /// its managed policy snapshot.
    fn with_managed_policy_state(
        mut self,
        state: &crate::ManagedPolicyState,
    ) -> Result<Self, crate::ManagedStoreError> {
        if self.config.policy.authority != "managed" {
            return Ok(self);
        }
        if self.policy_snapshot.load().generation() > state.revision.generation {
            return Err(crate::ManagedStoreError::VersionConflict);
        }
        self.policy_snapshot = Arc::new(arc_swap::ArcSwap::from_pointee(
            super::PolicySnapshot::from_managed(
                state.revision.generation,
                state.active_grants.clone(),
                state.catalog.clone(),
            ),
        ));
        Ok(self)
    }
}

#[cfg(any(test, feature = "test-support"))]
impl super::BrokerRuntime {
    /// The private attribute bindings this generation's policy snapshot
    /// publishes, for tests that compare them with the store.
    pub fn published_attribute_bindings(&self) -> Vec<crate::ResourceAttributeBinding> {
        self.policy_snapshot
            .load()
            .resource_catalog
            .attribute_bindings
            .clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::imports::{
        ImportedDiscoveryCredential, ImportedResourceAttributeDeclaration,
        ImportedServiceDefinition, ImportedServiceMetadata,
    };
    use crate::{ImportedServiceRecord, ImportedServiceStatus};
    use agent_access_provider::GIT_REPOSITORY_RESOURCE;

    fn declaration(broker_type: &str, removed: bool) -> ImportedResourceTypeDeclaration {
        ImportedResourceTypeDeclaration {
            id: "project".into(),
            broker_type: broker_type.into(),
            removed,
            label: "Project".into(),
            plural_label: "Projects".into(),
            pattern: "[A-Z][A-Z0-9]{1,9}".into(),
            max_length: 256,
            example: "OPS".into(),
            supports_exclusions: true,
            attributes: vec![ImportedResourceAttributeDeclaration {
                name: "region".into(),
                label: "Region".into(),
                description: "Hosting region.".into(),
                required: true,
                pattern: Some("[a-z0-9-]{1,32}".into()),
            }],
        }
    }

    fn record(
        service: &str,
        status: ImportedServiceStatus,
        types: Vec<ImportedResourceTypeDeclaration>,
    ) -> ImportedServiceRecord {
        ImportedServiceRecord {
            document: None,
            definition: ImportedServiceDefinition {
                service: service.into(),
                display_name: service.into(),
                adapter_kind: "command".into(),
                endpoint: format!("command:{service}"),
                connection_settings: BTreeMap::new(),
                execution_bindings: Vec::new(),
                discovery: ImportedDiscoveryCredential::Anonymous,
                transport_auth: false,
                invocation_limit: None,
            },
            status,
            version: 1,
            actions: Vec::new(),
            slot_versions: BTreeMap::new(),
            accepted_metadata: Some(ImportedServiceMetadata {
                format: "agent-access-command/1".into(),
                version: "1.0.0".into(),
                credential: None,
                verify: false,
                resource_types: types,
            }),
            created_at: String::new(),
            created_by: String::new(),
            updated_at: String::new(),
            updated_by: String::new(),
        }
    }

    fn catalog(records: Vec<ImportedServiceRecord>) -> ImportedCatalog {
        ImportedCatalog {
            revision: 1,
            services: records,
        }
    }

    #[test]
    fn imported_resource_types_join_the_registry_whatever_their_import_status() {
        let backends = crate::tests::test_backend_registry();
        let composition = EffectiveResourceTypes::composition(&backends);
        let catalog = catalog(vec![
            record(
                "tickets",
                ImportedServiceStatus::Retired,
                vec![declaration("tickets_project", false)],
            ),
            record(
                "boards",
                ImportedServiceStatus::Disabled,
                vec![declaration("boards_project", true)],
            ),
        ]);
        let types = composition.with_imported(&catalog, None).unwrap();
        let tickets = ResourceType::new("tickets_project").unwrap();
        let boards = ResourceType::new("boards_project").unwrap();
        // Composition types come first, then imported types in catalog order.
        let ids = types.registry().ids().cloned().collect::<Vec<_>>();
        assert_eq!(
            &ids[..composition.registry().ids().count()],
            composition.registry().ids().cloned().collect::<Vec<_>>()
        );
        assert_eq!(&ids[ids.len() - 2..], [tickets.clone(), boards.clone()]);
        assert_eq!(
            types.owner(&tickets),
            Some(&ResourceTypeOwner::Imported {
                service: "tickets".into(),
                removed: false
            })
        );
        assert_eq!(types.defining_service(&tickets), Some("tickets"));
        let metadata = types.metadata();
        let listed = |id: &ResourceType| {
            metadata
                .iter()
                .find(|metadata| &metadata.id == id)
                .unwrap()
                .clone()
        };
        assert_eq!(
            (listed(&tickets).removed, listed(&tickets).imported_service),
            (false, Some("tickets".to_owned()))
        );
        assert_eq!(
            (listed(&boards).removed, listed(&boards).imported_service),
            (true, Some("boards".to_owned()))
        );
        let git = listed(GIT_REPOSITORY_RESOURCE.id());
        assert_eq!((git.removed, git.imported_service), (false, None));
        assert_eq!(types.get(&tickets).unwrap().label(), "Project");
        // A removed type stays registered for its resources and accepts no
        // new ones.
        assert!(types.require_new_resources(&tickets).is_ok());
        assert!(
            types
                .require_new_resources(&boards)
                .unwrap_err()
                .contains("accepts no new resources")
        );
        assert!(
            types
                .require_new_resources(GIT_REPOSITORY_RESOURCE.id())
                .is_ok()
        );
        // Types an owner registers cannot be taken by another import.
        assert!(types.registered_outside("git_repository", "tickets"));
        // The runtime's placeholder for unresolved scopes is reserved.
        assert!(types.registered_outside("unresolved_resource_type", "tickets"));
        assert!(types.registered_outside("boards_project", "tickets"));
        assert!(!types.registered_outside("tickets_project", "tickets"));
        assert!(!types.registered_outside("unregistered_type", "tickets"));

        // Imported attributes validate from the declaration alone, without a
        // configured backend.
        let providers = ProvidersConfig::default();
        let exact = ResourceSelector::Exact {
            value: "OPS".into(),
        };
        let attributes = |values: &[(&str, &str)]| {
            ResourceAttributes::from(
                values
                    .iter()
                    .map(|(name, value)| ((*name).to_owned(), (*value).to_owned()))
                    .collect::<BTreeMap<_, _>>(),
            )
        };
        assert!(
            types
                .validate_attributes(
                    &providers,
                    &tickets,
                    &exact,
                    &attributes(&[("region", "eu-1")]),
                    true
                )
                .is_ok()
        );
        for (values, require_all, message) in [
            (
                vec![("region", "EU 1")],
                true,
                "resource attribute region is invalid",
            ),
            (
                vec![("owner", "avery")],
                false,
                "unknown resource attribute",
            ),
            (vec![], true, "required resource attributes are missing"),
        ] {
            assert_eq!(
                types
                    .validate_attributes(
                        &providers,
                        &tickets,
                        &exact,
                        &attributes(&values),
                        require_all
                    )
                    .unwrap_err(),
                message
            );
        }
    }

    #[test]
    fn imported_resource_types_reuse_unchanged_descriptors_and_reject_collisions() {
        let backends = crate::tests::test_backend_registry();
        let composition = EffectiveResourceTypes::composition(&backends);
        let first = composition
            .with_imported(
                &catalog(vec![
                    record(
                        "tickets",
                        ImportedServiceStatus::Enabled,
                        vec![declaration("tickets_project", false)],
                    ),
                    record(
                        "boards",
                        ImportedServiceStatus::Enabled,
                        vec![declaration("boards_project", false)],
                    ),
                ]),
                None,
            )
            .unwrap();
        let mut changed = declaration("boards_project", false);
        changed.label = "Board".into();
        let next = composition
            .with_imported(
                &catalog(vec![
                    record(
                        "tickets",
                        ImportedServiceStatus::Disabled,
                        vec![declaration("tickets_project", false)],
                    ),
                    record("boards", ImportedServiceStatus::Enabled, vec![changed]),
                ]),
                Some(&first),
            )
            .unwrap();
        let tickets = ResourceType::new("tickets_project").unwrap();
        let boards = ResourceType::new("boards_project").unwrap();
        assert!(Arc::ptr_eq(
            next.get(&tickets).unwrap(),
            first.get(&tickets).unwrap()
        ));
        assert!(!Arc::ptr_eq(
            next.get(&boards).unwrap(),
            first.get(&boards).unwrap()
        ));
        assert_eq!(next.get(&boards).unwrap().label(), "Board");

        for (types, owner) in [
            (vec![declaration("git_repository", false)], "the broker"),
            (
                vec![declaration("unresolved_resource_type", false)],
                "the broker",
            ),
            (vec![declaration("jira_project", false)], "the jira backend"),
            (
                vec![declaration("tickets_project", false)],
                "imported service tickets",
            ),
        ] {
            let error = composition
                .with_imported(
                    &catalog(vec![
                        record(
                            "tickets",
                            ImportedServiceStatus::Enabled,
                            vec![declaration("tickets_project", false)],
                        ),
                        record("boards", ImportedServiceStatus::Enabled, types),
                    ]),
                    None,
                )
                .unwrap_err();
            assert!(
                error.contains("collides") && error.contains(owner),
                "{error}"
            );
        }
        let mut invalid = declaration("boards_project", false);
        invalid.pattern = "(unclosed".into();
        assert!(
            composition
                .with_imported(
                    &catalog(vec![record(
                        "boards",
                        ImportedServiceStatus::Enabled,
                        vec![invalid]
                    )]),
                    None,
                )
                .unwrap_err()
                .contains("is invalid")
        );
    }

    #[test]
    fn composition_resource_types_have_host_and_backend_owners() {
        let backends = crate::tests::test_backend_registry();
        let types = EffectiveResourceTypes::composition(&backends);
        assert_eq!(
            types.registry().ids().collect::<Vec<_>>(),
            backends.resource_types().ids().collect::<Vec<_>>()
        );
        assert_eq!(
            types.owner(GIT_REPOSITORY_RESOURCE.id()),
            Some(&ResourceTypeOwner::Host)
        );
        assert_eq!(types.defining_service(GIT_REPOSITORY_RESOURCE.id()), None);
        let jira = ResourceType::new("jira_project").unwrap();
        assert_eq!(
            types.owner(&jira),
            Some(&ResourceTypeOwner::Backend("jira"))
        );
        assert_eq!(types.defining_service(&jira), Some("jira"));
        assert!(Arc::ptr_eq(
            types.get(&jira).unwrap(),
            backends.resource_types().get(&jira).unwrap()
        ));
        let unknown = ResourceType::new("unknown_type").unwrap();
        assert!(types.get(&unknown).is_none());
        assert!(types.owner(&unknown).is_none());
    }

    #[test]
    fn resource_attributes_of_unowned_types_are_rejected() {
        let backends = crate::tests::test_backend_registry();
        let types = EffectiveResourceTypes::composition(&backends);
        let providers = ProvidersConfig::default();
        let exact = ResourceSelector::Exact {
            value: "engineering/payments".into(),
        };
        let none = ResourceAttributes::default();
        let some = ResourceAttributes::from(BTreeMap::from([("x".into(), "y".into())]));
        assert!(
            types
                .validate_attributes(
                    &providers,
                    GIT_REPOSITORY_RESOURCE.id(),
                    &exact,
                    &none,
                    true
                )
                .is_ok()
        );
        assert_eq!(
            types
                .validate_attributes(
                    &providers,
                    GIT_REPOSITORY_RESOURCE.id(),
                    &exact,
                    &some,
                    true
                )
                .unwrap_err(),
            "unknown resource attribute"
        );
        let unknown = ResourceType::new("unknown_type").unwrap();
        assert!(
            types
                .validate_attributes(&providers, &unknown, &exact, &none, true)
                .is_ok()
        );
        assert_eq!(
            types
                .validate_attributes(&providers, &unknown, &exact, &some, true)
                .unwrap_err(),
            "unknown resource type"
        );
    }
}
