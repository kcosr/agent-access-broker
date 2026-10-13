//! What the upstream assembly supplies to the host, for host tests: a backend
//! registry mirroring its selection and a build status standing in for its
//! build stamp. Integration tests include this file by path, so it names host
//! types through its parent module.
use super::{BrokerBuildStatus, BuildProvenance};
use agent_access_cloudbees_ci::CLOUDBEES_CI_BACKEND;
use agent_access_confluence::CONFLUENCE_BACKEND;
use agent_access_core::{API_CATALOG_VERSION, BackendRegistry, SEND_SCHEMA_VERSION};
use agent_access_fake::{FAKE_BACKEND, OAUTH_STUB_BACKEND, STUB_OAUTH_DIALECT};
use agent_access_gitlab::GITLAB_BACKEND;
use agent_access_gmail::{GMAIL_BACKEND, GOOGLE_OAUTH_DIALECT};
use agent_access_jira::JIRA_BACKEND;
use agent_access_teams::TEAMS_BACKEND;

pub(crate) fn backend_registry() -> BackendRegistry {
    BackendRegistry::new([
        &JIRA_BACKEND,
        &CONFLUENCE_BACKEND,
        &GITLAB_BACKEND,
        &CLOUDBEES_CI_BACKEND,
        &FAKE_BACKEND,
        &GMAIL_BACKEND,
        &TEAMS_BACKEND,
        // Last, so its resource type keeps the bundled listing order.
        &OAUTH_STUB_BACKEND,
    ])
    .expect("linked backends register consistently")
    .with_oauth_dialects([
        &GOOGLE_OAUTH_DIALECT,
        &agent_access_mcp_upstream::MCP_OAUTH_DIALECT,
        &STUB_OAUTH_DIALECT,
    ])
    .expect("linked OAuth dialects register consistently")
    .with_imported_adapters([
        &agent_access_mcp_upstream::McpAdapter as &dyn agent_access_provider::ImportedAdapter,
        &agent_access_openapi_upstream::OpenApiAdapter
            as &dyn agent_access_provider::ImportedAdapter,
    ])
    .expect("linked imported adapters register consistently")
}

/// The status of an unstamped development build of the assembly.
pub(crate) fn broker_build_status() -> BrokerBuildStatus {
    BrokerBuildStatus {
        broker_version: env!("CARGO_PKG_VERSION"),
        build_commit: None,
        build_provenance: BuildProvenance::Unavailable,
        catalog_version: API_CATALOG_VERSION,
        send_schema_version: SEND_SCHEMA_VERSION,
    }
}
