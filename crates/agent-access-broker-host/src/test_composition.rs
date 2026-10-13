//! What an assembly supplies to the host, for host tests: a backend registry
//! and a composition mirroring the upstream selection, and the build status
//! of an unstamped test assembly. Integration tests include this file
//! by path, so it names host types through its parent module.
use super::{AssemblyIdentity, BrokerApplication, BrokerBuildStatus, BrokerComposition};
use agent_access_cloudbees_ci::CLOUDBEES_CI_BACKEND;
use agent_access_confluence::CONFLUENCE_BACKEND;
use agent_access_core::BackendRegistry;
use agent_access_core::imports::ImportedAdapterRegistration;
use agent_access_fake::{FAKE_BACKEND, OAUTH_STUB_BACKEND, STUB_OAUTH_DIALECT};
use agent_access_gitlab::GITLAB_BACKEND;
use agent_access_gmail::{GMAIL_BACKEND, GOOGLE_OAUTH_DIALECT};
use agent_access_jira::JIRA_BACKEND;
use agent_access_provider::{BackendRegistration, OAuthDialectRegistration};
use agent_access_teams::TEAMS_BACKEND;

static NATIVES: [&BackendRegistration; 8] = [
    &JIRA_BACKEND,
    &CONFLUENCE_BACKEND,
    &GITLAB_BACKEND,
    &CLOUDBEES_CI_BACKEND,
    &FAKE_BACKEND,
    &GMAIL_BACKEND,
    &TEAMS_BACKEND,
    // Last, so its resource type keeps the bundled listing order.
    &OAUTH_STUB_BACKEND,
];
static OAUTH_DIALECTS: [&OAuthDialectRegistration; 2] =
    [&GOOGLE_OAUTH_DIALECT, &STUB_OAUTH_DIALECT];

/// The MCP selection contributes its mcp_oauth companion dialect.
fn import_adapters() -> [ImportedAdapterRegistration; 2] {
    [
        agent_access_mcp_upstream::registration(),
        agent_access_openapi_upstream::registration(),
    ]
}

pub(crate) fn backend_registry() -> BackendRegistry {
    BackendRegistry::new(NATIVES)
        .expect("linked backends register consistently")
        .with_oauth_dialects(OAUTH_DIALECTS)
        .expect("linked OAuth dialects register consistently")
        .with_imported_adapters(import_adapters())
        .expect("linked imported adapters register consistently")
}

pub(crate) fn composition() -> BrokerComposition {
    let mut builder = BrokerComposition::builder();
    for native in NATIVES {
        builder = builder.native(native);
    }
    for dialect in OAUTH_DIALECTS {
        builder = builder.oauth(dialect);
    }
    for adapter in import_adapters() {
        builder = builder.import_adapter(adapter);
    }
    builder
        .build()
        .expect("linked modules compose consistently")
}

/// The name and version of the assembly host tests stand in for, distinct
/// from the host package's own.
pub(crate) const TEST_ASSEMBLY: (&str, &str) = ("example-assembly", "9.8.7");

/// The status of an unstamped build of that assembly.
pub(crate) fn broker_build_status() -> BrokerBuildStatus {
    BrokerApplication::new(
        composition(),
        AssemblyIdentity::new(TEST_ASSEMBLY.0, TEST_ASSEMBLY.1),
    )
    .expect("the test assembly identity is valid")
    .status()
    .clone()
}
