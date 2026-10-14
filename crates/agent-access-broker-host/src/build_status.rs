//! Build status served at `/v1/broker/status` and summarized in the
//! `broker_starting` event. The linking assembly supplies its identity and
//! module provenance; the host adds its own and the SDK's package identity
//! and the compiled module inventory. It never describes the host as the
//! executable, and it lists what is compiled in, not what is configured.
use agent_access_core::StateLockHolder;
use serde::Serialize;
use sha2::{Digest, Sha256};

/// Where a reported source revision comes from.
#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub(crate) enum Provenance {
    /// The assembler declared the revision without build evidence.
    Declared,
    /// The assembler's recorded build evidence backs the revision.
    Evidence,
    /// No revision was supplied; none is inferred.
    Unavailable,
}

impl Provenance {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::Declared => "declared",
            Self::Evidence => "evidence",
            Self::Unavailable => "unavailable",
        }
    }
}

/// A source revision as reported: `revision` is present exactly when
/// `provenance` is not `unavailable`.
#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq)]
pub(crate) struct SourceStatus {
    pub(crate) revision: Option<&'static str>,
    pub(crate) provenance: Provenance,
}

impl SourceStatus {
    pub(crate) const UNAVAILABLE: Self = Self {
        revision: None,
        provenance: Provenance::Unavailable,
    };
}

/// What a module package registers.
#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub(crate) enum ModuleRoleKind {
    Native,
    Oauth,
    Import,
}

impl ModuleRoleKind {
    fn as_str(self) -> &'static str {
        match self {
            Self::Native => "native",
            Self::Oauth => "oauth",
            Self::Import => "import",
        }
    }
}

/// One registration of a module package: a native kind, an OAuth dialect ID
/// or an import kind.
#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct ModuleRole {
    role: ModuleRoleKind,
    id: &'static str,
}

impl ModuleRole {
    pub(crate) fn new(role: ModuleRoleKind, id: &'static str) -> Self {
        Self { role, id }
    }
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub(crate) struct AssemblyStatus {
    pub(crate) name: &'static str,
    pub(crate) version: &'static str,
    pub(crate) qualification: &'static str,
    pub(crate) source: SourceStatus,
}

/// The host or SDK package.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub(crate) struct PackageStatus {
    #[serde(rename = "crate")]
    pub(crate) crate_name: &'static str,
    pub(crate) version: &'static str,
    pub(crate) source: SourceStatus,
}

/// A compiled module package and every role it registers.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub(crate) struct ModuleStatus {
    #[serde(rename = "crate")]
    pub(crate) crate_name: &'static str,
    pub(crate) version: &'static str,
    pub(crate) roles: Vec<ModuleRole>,
    pub(crate) source: SourceStatus,
}

/// The executable's immutable identity: the assembly, the host and SDK it
/// links, its compiled module inventory in canonical order, a fingerprint of
/// that inventory, and the runtime contract versions. It holds no secret
/// reference, local path or credential.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct BrokerBuildStatus {
    pub(crate) assembly: AssemblyStatus,
    pub(crate) host: PackageStatus,
    pub(crate) sdk: PackageStatus,
    pub(crate) modules: Vec<ModuleStatus>,
    pub(crate) inventory_fingerprint: String,
    pub(crate) catalog_version: &'static str,
    pub(crate) send_schema_version: &'static str,
}

impl BrokerBuildStatus {
    /// Builds the status; `modules` must already be in canonical order.
    pub(crate) fn new(
        assembly: AssemblyStatus,
        host: PackageStatus,
        sdk: PackageStatus,
        modules: Vec<ModuleStatus>,
    ) -> Self {
        let inventory_fingerprint = inventory_fingerprint(&host, &sdk, &modules);
        Self {
            assembly,
            host,
            sdk,
            modules,
            inventory_fingerprint,
            catalog_version: agent_access_core::API_CATALOG_VERSION,
            send_schema_version: agent_access_core::SEND_SCHEMA_VERSION,
        }
    }

    /// The assembly's name, which serves as the program in state lock
    /// metadata and the aggregate MCP server name.
    pub(crate) fn assembly_name(&self) -> &'static str {
        self.assembly.name
    }

    pub(crate) fn assembly_version(&self) -> &'static str {
        self.assembly.version
    }

    /// The holder that this executable's state locks record.
    pub(crate) fn lock_holder<'a>(&self, node_id: &'a str) -> StateLockHolder<'a> {
        StateLockHolder::new(self.assembly.name, self.assembly.version, node_id)
    }
}

const FINGERPRINT_DOMAIN: &str = "agent-access.broker.inventory.v1";

/// SHA-256 over a length-delimited encoding of the host and SDK identities
/// and the canonical module inventory, each with its revision and
/// provenance.
fn inventory_fingerprint(
    host: &PackageStatus,
    sdk: &PackageStatus,
    modules: &[ModuleStatus],
) -> String {
    let mut encoder = Encoder::default();
    encoder.string(FINGERPRINT_DOMAIN);
    for (label, package) in [("host", host), ("sdk", sdk)] {
        encoder.string(label);
        encoder.string(package.crate_name);
        encoder.string(package.version);
        encoder.source(package.source);
    }
    encoder.count(modules.len());
    for module in modules {
        encoder.string(module.crate_name);
        encoder.string(module.version);
        encoder.count(module.roles.len());
        for role in &module.roles {
            encoder.string(role.role.as_str());
            encoder.string(role.id);
        }
        encoder.source(module.source);
    }
    let digest = encoder.0.finalize();
    let mut fingerprint = String::with_capacity(7 + digest.len() * 2);
    fingerprint.push_str("sha256:");
    for byte in digest {
        fingerprint.push_str(&format!("{byte:02x}"));
    }
    fingerprint
}

#[derive(Default)]
struct Encoder(Sha256);

impl Encoder {
    fn count(&mut self, value: usize) {
        self.0.update((value as u64).to_be_bytes());
    }

    fn string(&mut self, value: &str) {
        self.count(value.len());
        self.0.update(value.as_bytes());
    }

    fn source(&mut self, source: SourceStatus) {
        self.string(source.provenance.as_str());
        self.string(source.revision.unwrap_or_default());
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    const COMMIT: &str = "0123456789abcdef0123456789abcdef01234567";

    fn evidence() -> SourceStatus {
        SourceStatus {
            revision: Some(COMMIT),
            provenance: Provenance::Evidence,
        }
    }

    fn status(module_source: SourceStatus) -> BrokerBuildStatus {
        BrokerBuildStatus::new(
            AssemblyStatus {
                name: "example-broker",
                version: "1.2.3",
                qualification: "unqualified",
                source: evidence(),
            },
            PackageStatus {
                crate_name: "agent-access-broker-host",
                version: "0.1.0",
                source: SourceStatus::UNAVAILABLE,
            },
            PackageStatus {
                crate_name: "agent-access-provider",
                version: "0.1.0",
                source: SourceStatus::UNAVAILABLE,
            },
            vec![ModuleStatus {
                crate_name: "agent-access-fake",
                version: "0.1.0",
                roles: vec![
                    ModuleRole::new(ModuleRoleKind::Native, "fake"),
                    ModuleRole::new(ModuleRoleKind::Oauth, "stub"),
                ],
                source: module_source,
            }],
        )
    }

    #[test]
    fn status_has_the_documented_public_shape() {
        let value = serde_json::to_value(status(evidence())).unwrap();
        let fingerprint = value["inventoryFingerprint"].as_str().unwrap().to_owned();
        assert!(fingerprint.starts_with("sha256:"));
        assert_eq!(fingerprint.len(), 7 + 64);
        assert_eq!(
            value,
            json!({
                "assembly": {
                    "name": "example-broker",
                    "version": "1.2.3",
                    "qualification": "unqualified",
                    "source": {"revision": COMMIT, "provenance": "evidence"}
                },
                "host": {
                    "crate": "agent-access-broker-host",
                    "version": "0.1.0",
                    "source": {"revision": null, "provenance": "unavailable"}
                },
                "sdk": {
                    "crate": "agent-access-provider",
                    "version": "0.1.0",
                    "source": {"revision": null, "provenance": "unavailable"}
                },
                "modules": [{
                    "crate": "agent-access-fake",
                    "version": "0.1.0",
                    "roles": [
                        {"role": "native", "id": "fake"},
                        {"role": "oauth", "id": "stub"}
                    ],
                    "source": {"revision": COMMIT, "provenance": "evidence"}
                }],
                "inventoryFingerprint": fingerprint,
                "catalogVersion": "agent-access.catalog.v2",
                "sendSchemaVersion": "agent-access.send.v1"
            })
        );
    }

    #[test]
    fn the_fingerprint_covers_module_revisions_and_their_provenance() {
        let evidence = status(evidence()).inventory_fingerprint;
        assert_eq!(evidence, status(self::evidence()).inventory_fingerprint);
        let declared = status(SourceStatus {
            revision: Some(COMMIT),
            provenance: Provenance::Declared,
        })
        .inventory_fingerprint;
        let unavailable = status(SourceStatus::UNAVAILABLE).inventory_fingerprint;
        assert_ne!(evidence, declared);
        assert_ne!(evidence, unavailable);
        assert_ne!(declared, unavailable);
    }

    #[test]
    fn the_fingerprint_excludes_the_assembly_label_but_covers_the_host_and_sdk() {
        let base = status(evidence());
        let mut relabeled = base.clone();
        relabeled.assembly.name = "renamed-broker";
        relabeled.assembly.qualification = "staging";
        assert_eq!(
            BrokerBuildStatus::new(
                relabeled.assembly,
                relabeled.host.clone(),
                relabeled.sdk.clone(),
                relabeled.modules.clone()
            )
            .inventory_fingerprint,
            base.inventory_fingerprint
        );
        let mut host = base.host.clone();
        host.source = evidence();
        assert_ne!(
            BrokerBuildStatus::new(
                base.assembly.clone(),
                host,
                base.sdk.clone(),
                base.modules.clone()
            )
            .inventory_fingerprint,
            base.inventory_fingerprint
        );
        let mut sdk = base.sdk.clone();
        sdk.version = "0.1.1";
        assert_ne!(
            BrokerBuildStatus::new(base.assembly.clone(), base.host.clone(), sdk, base.modules)
                .inventory_fingerprint,
            base.inventory_fingerprint
        );
    }
}
