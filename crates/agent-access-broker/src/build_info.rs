use agent_access_broker_host::{BrokerBuildStatus, BuildProvenance};
use agent_access_core::{API_CATALOG_VERSION, SEND_SCHEMA_VERSION};

/// This executable's build status, stamped by `build.rs`.
pub fn broker_build_status() -> BrokerBuildStatus {
    let build_provenance = match env!("AGENT_ACCESS_EMBEDDED_BUILD_PROVENANCE") {
        "release" => BuildProvenance::Release,
        "unavailable" => BuildProvenance::Unavailable,
        _ => unreachable!("build.rs emits a closed build provenance"),
    };
    let build_commit = env!("AGENT_ACCESS_EMBEDDED_BUILD_COMMIT");
    BrokerBuildStatus {
        broker_version: env!("CARGO_PKG_VERSION"),
        build_commit: (!build_commit.is_empty()).then_some(build_commit),
        build_provenance,
        catalog_version: API_CATALOG_VERSION,
        send_schema_version: SEND_SCHEMA_VERSION,
    }
}
