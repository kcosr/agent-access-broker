//! What an assembly supplies to the host, for host tests: a backend registry
//! and a composition mirroring the upstream selection, and the build status
//! of an unstamped test assembly.
use super::{AssemblyIdentity, BrokerApplication, BrokerBuildStatus, BrokerComposition};
use agent_access_atlassian::ATLASSIAN_OAUTH_DIALECT;
use agent_access_cloudbees_ci::CLOUDBEES_CI_BACKEND;
use agent_access_confluence::CONFLUENCE_BACKEND;
use agent_access_core::BackendRegistry;
use agent_access_core::imports::ImportedAdapterRegistration;
use agent_access_fake::{FAKE_BACKEND, OAUTH_STUB_BACKEND, STUB_OAUTH_DIALECT};
use agent_access_gitlab::{GITLAB_BACKEND, GITLAB_OAUTH_DIALECT};
use agent_access_gmail::{GMAIL_BACKEND, GOOGLE_OAUTH_DIALECT};
use agent_access_jira::JIRA_BACKEND;
use agent_access_provider::{BackendRegistration, OAuthDialectRegistration};
use agent_access_teams::TEAMS_BACKEND;

/// The natives the assembly selects, in its listing order.
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
static OAUTH_DIALECTS: [&OAuthDialectRegistration; 4] = [
    &GOOGLE_OAUTH_DIALECT,
    &GITLAB_OAUTH_DIALECT,
    &ATLASSIAN_OAUTH_DIALECT,
    &STUB_OAUTH_DIALECT,
];

/// The MCP selection contributes its mcp_oauth companion dialect.
fn import_adapters() -> [ImportedAdapterRegistration; 3] {
    [
        agent_access_mcp_upstream::registration(),
        agent_access_openapi_upstream::registration(),
        agent_access_command_import::registration(),
    ]
}

pub(crate) fn backend_registry() -> BackendRegistry {
    registry_of(NATIVES, OAUTH_DIALECTS)
}

/// The assembly's selection with `replacement` in place of the native of the
/// same kind, for tests serving a test-local backend under a linked kind.
pub(crate) fn backend_registry_replacing(
    replacement: &'static BackendRegistration,
) -> BackendRegistry {
    registry_of(replacing_native(replacement), OAUTH_DIALECTS)
}

/// The assembly's selection with `dialect` in place of the OAuth dialect of
/// the same ID, for tests whose linked backends consume a dialect fixture
/// that reaches a stub server.
pub(crate) fn backend_registry_with_dialect(
    dialect: &'static OAuthDialectRegistration,
) -> BackendRegistry {
    registry_of(NATIVES, replacing_dialect(dialect))
}

/// [`backend_registry_replacing`] with `dialect` in place of the OAuth
/// dialect of the same ID, for tests whose test-local backend consumes a
/// dialect fixture that reaches a stub server.
pub(crate) fn backend_registry_replacing_with_dialect(
    replacement: &'static BackendRegistration,
    dialect: &'static OAuthDialectRegistration,
) -> BackendRegistry {
    registry_of(replacing_native(replacement), replacing_dialect(dialect))
}

fn replacing_dialect(
    dialect: &'static OAuthDialectRegistration,
) -> [&'static OAuthDialectRegistration; 4] {
    OAUTH_DIALECTS.map(|linked| {
        if linked.id() == dialect.id() {
            dialect
        } else {
            linked
        }
    })
}

fn replacing_native(
    replacement: &'static BackendRegistration,
) -> [&'static BackendRegistration; 8] {
    NATIVES.map(|native| {
        if native.kind() == replacement.kind() {
            replacement
        } else {
            native
        }
    })
}

fn registry_of(
    natives: [&'static BackendRegistration; 8],
    dialects: [&'static OAuthDialectRegistration; 4],
) -> BackendRegistry {
    BackendRegistry::new(natives)
        .expect("linked backends register consistently")
        .with_oauth_dialects(dialects)
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
