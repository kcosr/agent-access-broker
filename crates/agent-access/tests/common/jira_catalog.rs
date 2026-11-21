//! Current native Jira contracts for synthetic Broker transport fixtures.
pub fn catalog() -> serde_json::Value {
    let config: agent_access_jira::JiraProviderConfig =
        serde_json::from_value(serde_json::json!({"tenant_host":"example.atlassian.net"})).unwrap();
    let mut catalog = agent_access_core::empty_catalog(serde_json::json!({}));
    catalog.services = vec![
        agent_access_core::api_service_spec(&agent_access_jira::jira_descriptor(&config), true)
            .unwrap(),
    ];
    serde_json::to_value(catalog).unwrap()
}
