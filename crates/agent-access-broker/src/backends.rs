//! The modules this broker distribution links.
use agent_access_broker_host::{BrokerComposition, CompositionError};
use agent_access_cloudbees_ci::CLOUDBEES_CI_BACKEND;
use agent_access_confluence::CONFLUENCE_BACKEND;
use agent_access_core::BackendRegistry;
use agent_access_fake::FAKE_BACKEND;
use agent_access_gitlab::GITLAB_BACKEND;
use agent_access_gmail::{GMAIL_BACKEND, GOOGLE_OAUTH_DIALECT};
use agent_access_jira::JIRA_BACKEND;
use agent_access_mcp_upstream::{MCP_OAUTH_DIALECT, McpAdapter};
use agent_access_openapi_upstream::OpenApiAdapter;
use agent_access_provider::{BackendRegistration, ImportedAdapter, OAuthDialectRegistration};
use agent_access_teams::TEAMS_BACKEND;

/// Native providers, in resource-type listing order.
static NATIVES: [&BackendRegistration; 7] = [
    &JIRA_BACKEND,
    &CONFLUENCE_BACKEND,
    &GITLAB_BACKEND,
    &CLOUDBEES_CI_BACKEND,
    &FAKE_BACKEND,
    &GMAIL_BACKEND,
    &TEAMS_BACKEND,
];
static OAUTH_DIALECTS: [&OAuthDialectRegistration; 2] = [&GOOGLE_OAUTH_DIALECT, &MCP_OAUTH_DIALECT];
static IMPORT_ADAPTERS: [&dyn ImportedAdapter; 2] = [&McpAdapter, &OpenApiAdapter];

/// Every module this broker can configure.
pub fn composition() -> Result<BrokerComposition, CompositionError> {
    let mut builder = BrokerComposition::builder();
    for native in NATIVES {
        builder = builder.native(native);
    }
    for dialect in OAUTH_DIALECTS {
        builder = builder.oauth(dialect);
    }
    for adapter in IMPORT_ADAPTERS {
        builder = builder.import_adapter(adapter);
    }
    builder.build()
}

/// The same selection as a raw core registry, for the CLI smokes that still
/// construct host state directly. It goes away with the host's raw router and
/// state exports.
pub fn backend_registry() -> BackendRegistry {
    BackendRegistry::new(NATIVES)
        .expect("linked backends register consistently")
        .with_oauth_dialects(OAUTH_DIALECTS)
        .expect("linked OAuth dialects register consistently")
        .with_imported_adapters(IMPORT_ADAPTERS)
        .expect("linked imported adapters register consistently")
}

#[cfg(test)]
mod tests {
    use super::*;
    use agent_access_core::McpConfig;
    use agent_access_core::mcp::{
        McpView, ProjectionMode, ToolRegistry, action_eligible, evaluate_scoped_mcp_readiness,
    };
    use std::collections::BTreeSet;

    #[test]
    fn the_composition_selects_every_linked_module() {
        let composition = composition().unwrap();
        assert_eq!(
            composition.native_kinds().collect::<Vec<_>>(),
            [
                "jira",
                "confluence",
                "gitlab",
                "cloudbees_ci",
                "fake",
                "gmail",
                "teams"
            ]
        );
        assert!(composition.oauth_dialect_ids().any(|id| id == "google"));
        assert!(composition.oauth_dialect_ids().any(|id| id == "mcp_oauth"));
    }

    #[test]
    fn every_compiled_builtin_has_readable_aggregate_and_ready_scoped_mcp_names() {
        // Exercise the actual registered configuration parsers and descriptors.
        // Parsing and projection do not resolve credentials or contact providers.
        let raw = format!(
            "{}\n[providers.gmail]\n[providers.teams]\nallowed_upstream_hosts = []\n[providers.cloudbees_ci]\ncontrollers = {{}}\n[providers.fake]\n",
            include_str!("../../../agent-access-broker.sample.toml")
                .replace("[deployment]", "[deployment]\nenable_fake_service = true")
        );
        let descriptors = composition()
            .unwrap()
            .configured_service_descriptors(&raw)
            .unwrap();
        // The sample keeps the default MCP catalog budget.
        let max_catalog_bytes = McpConfig::default().max_catalog_bytes;
        let mut tested = BTreeSet::new();
        let mut combined = agent_access_core::empty_catalog(serde_json::json!({}));
        for descriptor in descriptors {
            descriptor.validate_builtin_mcp_names().unwrap();
            let readiness = evaluate_scoped_mcp_readiness(&descriptor, max_catalog_bytes);
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
                    max_catalog_bytes,
                )
                .unwrap();
            }
            combined.services.extend(catalog.services);
            tested.insert(descriptor.service);
        }
        for mode in [ProjectionMode::Http, ProjectionMode::Stdio] {
            let registry =
                ToolRegistry::build(&combined, &McpView::Aggregate, mode, max_catalog_bytes)
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
