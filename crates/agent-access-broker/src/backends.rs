//! The backends this broker binary links.
use agent_access_cloudbees_ci::CLOUDBEES_CI_BACKEND;
use agent_access_confluence::CONFLUENCE_BACKEND;
use agent_access_core::BackendRegistry;
use agent_access_fake::FAKE_BACKEND;
use agent_access_gitlab::GITLAB_BACKEND;
use agent_access_gmail::{GMAIL_BACKEND, GOOGLE_OAUTH_DIALECT};
use agent_access_jira::JIRA_BACKEND;
use agent_access_teams::TEAMS_BACKEND;

/// Every backend the broker can configure through `[providers.<kind>]`,
/// in resource-type listing order.
pub fn backend_registry() -> BackendRegistry {
    let registry = BackendRegistry::new([
        &JIRA_BACKEND,
        &CONFLUENCE_BACKEND,
        &GITLAB_BACKEND,
        &CLOUDBEES_CI_BACKEND,
        &FAKE_BACKEND,
        &GMAIL_BACKEND,
        &TEAMS_BACKEND,
    ])
    .expect("linked backends register consistently")
    .with_oauth_dialects([
        &GOOGLE_OAUTH_DIALECT,
        &agent_access_mcp_upstream::MCP_OAUTH_DIALECT,
    ])
    .expect("linked OAuth dialects register consistently")
    .with_imported_adapters([
        &agent_access_mcp_upstream::McpAdapter as &dyn agent_access_core::ImportedAdapter,
        &agent_access_openapi_upstream::OpenApiAdapter as &dyn agent_access_core::ImportedAdapter,
    ])
    .expect("linked imported adapters register consistently");
    #[cfg(test)]
    let registry = registry
        .with_imported_adapters([&agent_access_conformance::CONFORMANCE_IMPORT_ADAPTER
            as &dyn agent_access_core::ImportedAdapter])
        .expect("test import adapter registers consistently");
    registry
}

#[cfg(test)]
mod tests {
    use super::*;
    use agent_access_core::mcp::{
        McpView, ProjectionMode, ToolRegistry, action_eligible, evaluate_scoped_mcp_readiness,
    };
    use std::{collections::BTreeSet, sync::Arc};

    #[test]
    fn every_compiled_builtin_has_readable_aggregate_and_ready_scoped_mcp_names() {
        // Exercise the actual registered configuration parsers and descriptors.
        // Parsing and projection do not resolve credentials or contact providers.
        let raw = format!(
            "{}\n[providers.gmail]\n[providers.teams]\nallowed_upstream_hosts = []\n[providers.cloudbees_ci]\ncontrollers = {{}}\n[providers.fake]\n",
            include_str!("../../../agent-access-broker.sample.toml")
                .replace("[deployment]", "[deployment]\nenable_fake_service = true")
        );
        let config = agent_access_core::parse_broker_config_raw(
            "builtin-scoped-mcp-fixture.toml",
            &raw,
            &Arc::new(backend_registry()),
        )
        .unwrap();
        let mut tested = BTreeSet::new();
        let mut combined = agent_access_core::empty_catalog(serde_json::json!({}));
        for backend in config.providers.iter() {
            let descriptor = backend.descriptor();
            descriptor.validate_builtin_mcp_names().unwrap();
            let readiness =
                evaluate_scoped_mcp_readiness(&descriptor, config.mcp.max_catalog_bytes);
            assert!(readiness.ready, "{}: {readiness:?}", descriptor.service);
            let mut catalog = agent_access_core::empty_catalog(serde_json::json!({}));
            let service = agent_access_core::api_service_spec(&descriptor, true).unwrap();
            assert!(service.actions.iter().all(|action| action.scoped_mcp_name.as_deref() == Some(action.action.as_str())));
            catalog.services.push(service);
            for mode in [ProjectionMode::Http, ProjectionMode::Stdio] {
                ToolRegistry::build(
                    &catalog,
                    &McpView::Service(descriptor.service.clone()),
                    mode,
                    config.mcp.max_catalog_bytes,
                )
                .unwrap();
            }
            combined.services.extend(catalog.services);
            tested.insert(descriptor.service);
        }
        for mode in [ProjectionMode::Http, ProjectionMode::Stdio] {
            let registry = ToolRegistry::build(
                &combined,
                &McpView::Aggregate,
                mode,
                config.mcp.max_catalog_bytes,
            )
            .unwrap();
            let expected = combined
                .services
                .iter()
                .flat_map(|service| &service.actions)
                .filter(|action| action_eligible(action, mode))
                .count();
            let definitions = registry.definitions();
            assert_eq!(definitions.len(), expected + 5, "{mode:?}");
            assert!(
                definitions
                    .iter()
                    .all(|tool| tool["name"].as_str().unwrap().len() <= 64)
            );
            assert!(
                definitions
                    .iter()
                    .any(|tool| tool["name"] == "cloudbees_ci_build_log_read")
            );
            assert!(
                definitions
                    .iter()
                    .any(|tool| tool["name"] == "jira_issue_view")
            );
        }
        assert_eq!(
            tested,
            [
                "jira",
                "confluence",
                "gitlab",
                "cloudbees_ci",
                "fake",
                "gmail",
                "teams"
            ]
            .into_iter()
            .map(str::to_owned)
            .collect()
        );
    }
}
