use agent_access_core::{API_CATALOG_VERSION, SEND_SCHEMA_VERSION};
use serde::Serialize;

#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum BuildProvenance {
    Release,
    Unavailable,
}

#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct BrokerBuildStatus {
    pub broker_version: &'static str,
    pub build_commit: Option<&'static str>,
    pub build_provenance: BuildProvenance,
    pub catalog_version: &'static str,
    pub send_schema_version: &'static str,
}

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

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn unavailable_status_has_exact_public_shape() {
        let value = serde_json::to_value(BrokerBuildStatus {
            broker_version: "0.1.0",
            build_commit: None,
            build_provenance: BuildProvenance::Unavailable,
            catalog_version: "agent-access.catalog.v2",
            send_schema_version: "agent-access.send.v1",
        })
        .unwrap();
        assert_eq!(
            value,
            json!({
                "brokerVersion": "0.1.0",
                "buildCommit": null,
                "buildProvenance": "unavailable",
                "catalogVersion": "agent-access.catalog.v2",
                "sendSchemaVersion": "agent-access.send.v1"
            })
        );
    }

    #[test]
    fn release_status_has_exact_public_shape() {
        const COMMIT: &str = "0123456789abcdef0123456789abcdef01234567";
        let value = serde_json::to_value(BrokerBuildStatus {
            broker_version: "0.1.0",
            build_commit: Some(COMMIT),
            build_provenance: BuildProvenance::Release,
            catalog_version: "agent-access.catalog.v2",
            send_schema_version: "agent-access.send.v1",
        })
        .unwrap();
        assert_eq!(value["buildCommit"], COMMIT);
        assert_eq!(value["buildProvenance"], "release");
    }
}
