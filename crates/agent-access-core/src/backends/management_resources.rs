//! Exact Broker targets use the same grammar as their management operations.
use agent_access_provider::{ResourceSelector, ResourceType, ResourceTypeDescriptor};

fn principal(value: &str) -> bool {
    crate::managed_store::validate_principal_id(value).is_ok()
}
fn group(value: &str) -> bool {
    crate::managed_store::validate_group_name(value).is_ok()
}
fn grant(value: &str) -> bool {
    crate::managed_store::validate_policy_grant_id(value).is_ok()
}
fn connection(value: &str) -> bool {
    agent_access_provider::is_service_name(value) && !super::is_reserved_service_name(value)
}

fn inputs(
    selector: &ResourceSelector,
    key: &str,
) -> Option<serde_json::Map<String, serde_json::Value>> {
    match selector {
        ResourceSelector::Exact { value } => Some(serde_json::Map::from_iter([(
            key.to_owned(),
            serde_json::Value::String(value.clone()),
        )])),
        _ => None,
    }
}

pub(crate) static PRINCIPAL: ResourceTypeDescriptor = ResourceTypeDescriptor::new(
    ResourceType::from_static("broker_principal"),
    "Broker principal",
    "Broker principals",
    "review-worker",
    principal,
    &[],
)
.exact_only()
.with_action_inputs(|selector| inputs(selector, "principalId"));

pub(crate) static GROUP: ResourceTypeDescriptor = ResourceTypeDescriptor::new(
    ResourceType::from_static("broker_group"),
    "Broker identity group",
    "Broker identity groups",
    "review-automation",
    group,
    &[],
)
.exact_only()
.with_action_inputs(|selector| inputs(selector, "groupId"));

pub(crate) static GRANT: ResourceTypeDescriptor = ResourceTypeDescriptor::new(
    ResourceType::from_static("broker_grant"),
    "Broker grant",
    "Broker grants",
    "gitlab-review",
    grant,
    &[],
)
.exact_only()
.with_action_inputs(|selector| inputs(selector, "grantId"));

pub(crate) static CONNECTION: ResourceTypeDescriptor = ResourceTypeDescriptor::new(
    ResourceType::from_static("broker_connection"),
    "Broker credential connection",
    "Broker credential connections",
    "gitlab-main",
    connection,
    &[],
)
.exact_only()
.with_action_inputs(|selector| inputs(selector, "connectionId"));

pub(crate) const TYPES: &[&ResourceTypeDescriptor] = &[&PRINCIPAL, &GROUP, &GRANT, &CONNECTION];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn broker_targets_are_exact_only_and_use_object_grammars() {
        for descriptor in TYPES {
            assert_eq!(descriptor.selector_kinds(), ["exact"]);
            assert!(!descriptor.accepts(&ResourceSelector::All));
        }
        assert!(PRINCIPAL.is_canonical_target("review.worker+bot@example.com"));
        assert!(!PRINCIPAL.is_canonical_target("review/worker"));
        assert!(!PRINCIPAL.is_canonical_target("anonymous"));
        assert!(!GRANT.is_canonical_target("export"));
        assert!(!GRANT.is_canonical_target("VALIDATE"));
        assert!(!CONNECTION.is_canonical_target("broker_management"));
        assert!(!CONNECTION.is_canonical_target("access_management"));
    }
}
