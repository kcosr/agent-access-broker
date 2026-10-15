//! The effective resource type registry of one runtime generation.
//!
//! A generation understands the composition's static types (the host's own
//! `git_repository` and every selected native's types). The registry is built
//! with the generation and published with it in one swap, so the registry,
//! the service descriptors and the policy snapshot a request reads always
//! agree. Each type has one owner, which decides how the private attribute
//! values of its resources are validated.
use crate::{BackendRegistry, ProvidersConfig};
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
}

/// A generation's resource types and their owners.
#[derive(Debug, Clone)]
pub(crate) struct EffectiveResourceTypes {
    registry: ResourceTypeRegistry,
    owners: BTreeMap<ResourceType, ResourceTypeOwner>,
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
        Self { registry, owners }
    }

    pub(crate) fn registry(&self) -> &ResourceTypeRegistry {
        &self.registry
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
            ResourceTypeOwner::Host => None,
        }
    }

    /// Validates a resource's private attribute values against its type's
    /// declaration and, for a native type, against the owning backend's
    /// configured checks. `require_all` requires every required attribute,
    /// as a creation does; a patch supplies only the values it changes.
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
            Some(ResourceTypeOwner::Host) | None => {
                Err("resource backend must be configured".into())
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use agent_access_provider::GIT_REPOSITORY_RESOURCE;

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
