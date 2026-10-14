use agent_access_core::{ResourceDefinition, ResourceSelection};
use agent_access_provider::{ResourceSelector, ResourceType};

pub fn resource_selection(ids: &[&str]) -> ResourceSelection {
    ResourceSelection {
        resource_ids: ids.iter().map(|id| (*id).to_string()).collect(),
        resource_group_ids: vec![],
    }
}

pub fn resource_catalog(
    entries: &[(&str, ResourceType, ResourceSelector)],
) -> Vec<ResourceDefinition> {
    entries
        .iter()
        .map(|(id, resource_type, selector)| ResourceDefinition {
            id: (*id).to_string(),
            display_name: None,
            resource_type: resource_type.clone(),
            selector: selector.clone(),
            allowed_execution_contexts: vec!["default".to_string()],
            enabled: true,
        })
        .collect()
}
