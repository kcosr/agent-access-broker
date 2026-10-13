use agent_access_broker_host::{AssemblyIdentity, BrokerBuildStatus};

/// This executable's identity, stamped by `build.rs`.
pub fn build_identity() -> AssemblyIdentity {
    let identity = AssemblyIdentity::new("agent-access-broker", env!("CARGO_PKG_VERSION"))
        .with_about("Agent Access Broker service");
    match (
        env!("AGENT_ACCESS_EMBEDDED_BUILD_PROVENANCE"),
        env!("AGENT_ACCESS_EMBEDDED_BUILD_COMMIT"),
    ) {
        ("release", commit) if !commit.is_empty() => identity.with_release_commit(commit),
        ("unavailable", "") => identity,
        _ => unreachable!("build.rs emits a closed build provenance"),
    }
}

/// This executable's build status, for tests that construct host state
/// directly.
pub fn broker_build_status() -> BrokerBuildStatus {
    build_identity().build_status()
}
