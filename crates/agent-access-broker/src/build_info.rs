use agent_access_broker_host::{AssemblyIdentity, ModuleProvenance, SourceRevision};

const VERSION: &str = env!("CARGO_PKG_VERSION");
/// The commit a release build recorded; empty without release provenance.
const RELEASE_COMMIT: &str = env!("AGENT_ACCESS_EMBEDDED_BUILD_COMMIT");
const RELEASE_SOURCE: SourceRevision = SourceRevision::evidence(RELEASE_COMMIT);

/// The module packages this assembly registers, all members of this
/// workspace and so built from its one commit.
const fn workspace_modules(source: SourceRevision) -> [ModuleProvenance; 11] {
    [
        ModuleProvenance::new("agent-access-atlassian", VERSION, source),
        ModuleProvenance::new("agent-access-cloudbees-ci", VERSION, source),
        ModuleProvenance::new("agent-access-command-import", VERSION, source),
        ModuleProvenance::new("agent-access-confluence", VERSION, source),
        ModuleProvenance::new("agent-access-fake", VERSION, source),
        ModuleProvenance::new("agent-access-gitlab", VERSION, source),
        ModuleProvenance::new("agent-access-gmail", VERSION, source),
        ModuleProvenance::new("agent-access-jira", VERSION, source),
        ModuleProvenance::new("agent-access-mcp-upstream", VERSION, source),
        ModuleProvenance::new("agent-access-openapi-upstream", VERSION, source),
        ModuleProvenance::new("agent-access-teams", VERSION, source),
    ]
}

static RELEASE_MODULES: [ModuleProvenance; 11] = workspace_modules(RELEASE_SOURCE);

/// This executable's identity, stamped by `build.rs`. A release build was
/// made from a verified clean checkout of one commit, which is the source of
/// the assembly, the host, the SDK and every registered module; it is
/// evidence-backed. An unstamped build reports every revision unavailable.
/// The assembly declares no qualification label.
pub fn build_identity() -> AssemblyIdentity {
    let identity = AssemblyIdentity::new("agent-access-broker", VERSION)
        .with_about("Agent Access Broker service");
    match (
        env!("AGENT_ACCESS_EMBEDDED_BUILD_PROVENANCE"),
        RELEASE_COMMIT,
    ) {
        ("release", commit) if !commit.is_empty() => identity
            .with_source(RELEASE_SOURCE)
            .with_host_source(RELEASE_SOURCE)
            .with_sdk_source(RELEASE_SOURCE)
            .with_module_provenance(&RELEASE_MODULES),
        ("unavailable", "") => identity,
        _ => unreachable!("build.rs emits a closed build provenance"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use agent_access_broker_host::BrokerApplication;
    use serde_json::json;

    #[test]
    fn a_release_stamp_covers_every_registered_package_with_one_commit() {
        const COMMIT: &str = "0123456789abcdef0123456789abcdef01234567";
        const SOURCE: SourceRevision = SourceRevision::evidence(COMMIT);
        static MODULES: [ModuleProvenance; 11] = workspace_modules(SOURCE);
        let identity = AssemblyIdentity::new("agent-access-broker", VERSION)
            .with_source(SOURCE)
            .with_host_source(SOURCE)
            .with_sdk_source(SOURCE)
            .with_module_provenance(&MODULES);
        let application = BrokerApplication::new(crate::composition().unwrap(), identity).unwrap();
        let status = serde_json::to_value(application.status()).unwrap();
        let evidence = json!({"revision": COMMIT, "provenance": "evidence"});
        assert_eq!(status["assembly"]["source"], evidence);
        assert_eq!(status["assembly"]["qualification"], "unqualified");
        assert_eq!(status["host"]["source"], evidence);
        assert_eq!(status["sdk"]["source"], evidence);
        let modules = status["modules"].as_array().unwrap();
        assert_eq!(modules.len(), MODULES.len());
        assert!(modules.iter().all(|module| module["source"] == evidence));
    }

    #[test]
    fn an_unstamped_build_reports_every_revision_unavailable() {
        let application =
            BrokerApplication::new(crate::composition().unwrap(), build_identity()).unwrap();
        let status = serde_json::to_value(application.status()).unwrap();
        if env!("AGENT_ACCESS_EMBEDDED_BUILD_PROVENANCE") != "unavailable" {
            return;
        }
        let unavailable = json!({"revision": null, "provenance": "unavailable"});
        assert_eq!(status["assembly"]["name"], "agent-access-broker");
        assert_eq!(status["assembly"]["version"], VERSION);
        assert_eq!(status["assembly"]["source"], unavailable);
        assert_eq!(status["host"]["source"], unavailable);
        assert_eq!(status["sdk"]["source"], unavailable);
        assert!(
            status["modules"]
                .as_array()
                .unwrap()
                .iter()
                .all(|module| module["source"] == unavailable)
        );
    }
}
