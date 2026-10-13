//! The identity a linking assembly supplies: its name, version, source
//! revisions with their provenance, qualification label, and the source
//! provenance of the module packages it registers. The host checks it
//! against the composition and derives the build status from both.
use crate::build_status::{
    AssemblyStatus, BrokerBuildStatus, ModuleStatus, PackageStatus, Provenance, SourceStatus,
};
use crate::composition::{BrokerComposition, CompositionError};
use agent_access_provider::SDK_PACKAGE;
use std::collections::BTreeMap;
use std::collections::btree_map::Entry;

/// The qualification label of an assembly that declares none.
const UNQUALIFIED: &str = "unqualified";
const MAX_LABEL_BYTES: usize = 64;
const MAX_SHOWN_BYTES: usize = 80;

/// A full source revision, a lowercase 40- or 64-hex Git object ID, that the
/// assembler supplies at build time, and whether it is the assembler's
/// declaration or backed by its recorded build evidence. Revisions are
/// labels from the assembler, not attestation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SourceRevision {
    revision: &'static str,
    evidence: bool,
}

impl SourceRevision {
    /// A revision the assembler declares without build evidence.
    pub const fn declared(revision: &'static str) -> Self {
        Self {
            revision,
            evidence: false,
        }
    }

    /// A revision the assembler's recorded build evidence backs, such as the
    /// verified clean checkout a release build ran from, or a locked Git
    /// source in the resolved dependency graph.
    pub const fn evidence(revision: &'static str) -> Self {
        Self {
            revision,
            evidence: true,
        }
    }

    fn status(self) -> SourceStatus {
        SourceStatus {
            revision: Some(self.revision),
            provenance: if self.evidence {
                Provenance::Evidence
            } else {
                Provenance::Declared
            },
        }
    }
}

/// The source revision of one registered module package, keyed by its crate
/// name and version. Every role the package registers shares it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ModuleProvenance {
    crate_name: &'static str,
    crate_version: &'static str,
    source: SourceRevision,
}

impl ModuleProvenance {
    pub const fn new(
        crate_name: &'static str,
        crate_version: &'static str,
        source: SourceRevision,
    ) -> Self {
        Self {
            crate_name,
            crate_version,
            source,
        }
    }
}

/// The executable that links the host: its command name and description,
/// its version, the source revisions its assembler supplies for itself, the
/// host and the SDK, its qualification label, and its module provenance map.
///
/// The identity labels the command line, build status, startup event, MCP
/// server information and state lock metadata. The configuration path,
/// state, keys and lock file names never depend on it.
///
/// [`crate::BrokerApplication::new`] checks the identity against the
/// composition: the name and qualification label are 1 to 64 ASCII letters,
/// digits, `.`, `_` or `-`, starting with a letter or digit; the version is
/// 1 to 64 ASCII letters, digits, `.`, `+` or `-`; every revision is a full
/// object ID; and the module provenance map names only registered module
/// packages, each at most once. A revision that is not supplied is reported
/// as unavailable.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AssemblyIdentity {
    name: &'static str,
    about: Option<&'static str>,
    version: &'static str,
    source: Option<SourceRevision>,
    host_source: Option<SourceRevision>,
    sdk_source: Option<SourceRevision>,
    qualification: &'static str,
    modules: &'static [ModuleProvenance],
}

impl AssemblyIdentity {
    pub const fn new(name: &'static str, version: &'static str) -> Self {
        Self {
            name,
            about: None,
            version,
            source: None,
            host_source: None,
            sdk_source: None,
            qualification: UNQUALIFIED,
            modules: &[],
        }
    }

    /// The description shown in command-line help.
    pub const fn with_about(mut self, about: &'static str) -> Self {
        self.about = Some(about);
        self
    }

    /// The assembly's own source revision.
    pub const fn with_source(mut self, source: SourceRevision) -> Self {
        self.source = Some(source);
        self
    }

    /// The source revision of the linked host package.
    pub const fn with_host_source(mut self, source: SourceRevision) -> Self {
        self.host_source = Some(source);
        self
    }

    /// The source revision of the linked SDK package.
    pub const fn with_sdk_source(mut self, source: SourceRevision) -> Self {
        self.sdk_source = Some(source);
        self
    }

    /// The qualification scope the assembler declares for these exact
    /// assembled sources, such as the label of its own release process.
    /// Without one the assembly is `unqualified`; linking qualified upstream
    /// code never confers its label.
    pub const fn with_qualification(mut self, label: &'static str) -> Self {
        self.qualification = label;
        self
    }

    /// The source revisions of registered module packages, replacing any
    /// earlier map. Packages the map omits report an unavailable revision.
    pub const fn with_module_provenance(mut self, modules: &'static [ModuleProvenance]) -> Self {
        self.modules = modules;
        self
    }

    pub(crate) fn name(&self) -> &'static str {
        self.name
    }

    pub(crate) fn about(&self) -> Option<&'static str> {
        self.about
    }

    /// Checks the identity against `composition` and derives the build
    /// status. Problems name only packages, versions and identity fields;
    /// supplied values are shown escaped and truncated.
    pub(crate) fn build_status(
        &self,
        composition: &BrokerComposition,
    ) -> Result<BrokerBuildStatus, CompositionError> {
        let mut problems = Vec::new();
        if !is_label(self.name) {
            problems.push(format!(
                "assembly name {} must be 1 to {MAX_LABEL_BYTES} ASCII letters, digits, '.', '_' or '-', starting with a letter or digit",
                shown(self.name)
            ));
        }
        if !is_version(self.version) {
            problems.push(format!(
                "assembly version {} must be 1 to {MAX_LABEL_BYTES} ASCII letters, digits, '.', '+' or '-'",
                shown(self.version)
            ));
        }
        if !is_label(self.qualification) {
            problems.push(format!(
                "qualification label {} must be 1 to {MAX_LABEL_BYTES} ASCII letters, digits, '.', '_' or '-', starting with a letter or digit",
                shown(self.qualification)
            ));
        }
        for (subject, source) in [
            ("assembly", self.source),
            ("host", self.host_source),
            ("SDK", self.sdk_source),
        ] {
            if source.is_some_and(|source| !is_full_object_id(source.revision)) {
                problems.push(format!(
                    "{subject} source revision must be a full lowercase 40- or 64-hex object ID"
                ));
            }
        }

        let packages = composition.module_packages();
        let mut supplied = BTreeMap::new();
        for entry in self.modules {
            let key = (entry.crate_name, entry.crate_version);
            let package = format!("{} {}", shown(entry.crate_name), shown(entry.crate_version));
            if !packages.contains_key(&key) {
                problems.push(format!(
                    "module provenance names {package}, which is not a registered module package"
                ));
                continue;
            }
            if !is_full_object_id(entry.source.revision) {
                problems.push(format!(
                    "module provenance for {package} must be a full lowercase 40- or 64-hex object ID"
                ));
            }
            match supplied.entry(key) {
                Entry::Vacant(vacant) => {
                    vacant.insert(entry.source);
                }
                Entry::Occupied(occupied) if *occupied.get() == entry.source => {
                    problems.push(format!("module provenance lists {package} more than once"))
                }
                Entry::Occupied(_) => problems.push(format!(
                    "module provenance gives {package} conflicting revisions"
                )),
            }
        }
        if !problems.is_empty() {
            return Err(CompositionError::assembly_identity(problems));
        }

        let status_of = |source: Option<SourceRevision>| {
            source.map_or(SourceStatus::UNAVAILABLE, SourceRevision::status)
        };
        let modules = packages
            .into_iter()
            .map(|((crate_name, version), roles)| ModuleStatus {
                crate_name,
                version,
                roles,
                source: status_of(supplied.get(&(crate_name, version)).copied()),
            })
            .collect();
        Ok(BrokerBuildStatus::new(
            AssemblyStatus {
                name: self.name,
                version: self.version,
                qualification: self.qualification,
                source: status_of(self.source),
            },
            PackageStatus {
                crate_name: env!("CARGO_PKG_NAME"),
                version: env!("CARGO_PKG_VERSION"),
                source: status_of(self.host_source),
            },
            PackageStatus {
                crate_name: SDK_PACKAGE.crate_name(),
                version: SDK_PACKAGE.crate_version(),
                source: status_of(self.sdk_source),
            },
            modules,
        ))
    }
}

fn is_label(value: &str) -> bool {
    (1..=MAX_LABEL_BYTES).contains(&value.len())
        && value.as_bytes()[0].is_ascii_alphanumeric()
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
}

fn is_version(value: &str) -> bool {
    (1..=MAX_LABEL_BYTES).contains(&value.len())
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'+' | b'-'))
}

fn is_full_object_id(value: &str) -> bool {
    matches!(value.len(), 40 | 64)
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

/// A supplied value for a diagnostic: escaped, and truncated on a character
/// boundary.
fn shown(value: &str) -> String {
    let mut end = value.len().min(MAX_SHOWN_BYTES);
    while !value.is_char_boundary(end) {
        end -= 1;
    }
    if end < value.len() {
        format!("{:?}...", &value[..end])
    } else {
        format!("{value:?}")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::backend_registry;
    use serde_json::{Value, json};

    const SHA1: &str = "0123456789abcdef0123456789abcdef01234567";
    const SHA256: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    const VERSION: &str = env!("CARGO_PKG_VERSION");
    const IDENTITY: AssemblyIdentity = AssemblyIdentity::new("example-broker", "1.2.3");

    fn composition() -> BrokerComposition {
        BrokerComposition::from_registry(backend_registry())
    }

    fn status(identity: AssemblyIdentity) -> Value {
        serde_json::to_value(identity.build_status(&composition()).unwrap()).unwrap()
    }

    fn problems(identity: AssemblyIdentity) -> Vec<String> {
        let error = identity.build_status(&composition()).unwrap_err();
        assert_eq!(error.to_string(), "broker assembly identity is invalid");
        error.problems().to_vec()
    }

    fn module<'a>(status: &'a Value, name: &str) -> &'a Value {
        status["modules"]
            .as_array()
            .unwrap()
            .iter()
            .find(|module| module["crate"] == name)
            .unwrap()
    }

    #[test]
    fn an_unstamped_identity_reports_every_revision_unavailable() {
        let status = status(IDENTITY);
        let unavailable = json!({"revision": null, "provenance": "unavailable"});
        assert_eq!(
            status["assembly"],
            json!({
                "name": "example-broker",
                "version": "1.2.3",
                "qualification": "unqualified",
                "source": unavailable
            })
        );
        assert_eq!(
            status["host"],
            json!({"crate": "agent-access-broker-host", "version": VERSION, "source": unavailable})
        );
        assert_eq!(
            status["sdk"],
            json!({"crate": "agent-access-provider", "version": VERSION, "source": unavailable})
        );
        let modules = status["modules"].as_array().unwrap();
        assert!(modules.iter().all(|module| module["source"] == unavailable));
    }

    #[test]
    fn the_inventory_lists_compiled_modules_canonically_with_every_role() {
        let status = status(IDENTITY);
        let names = status["modules"]
            .as_array()
            .unwrap()
            .iter()
            .map(|module| module["crate"].as_str().unwrap())
            .collect::<Vec<_>>();
        assert_eq!(
            names,
            [
                "agent-access-cloudbees-ci",
                "agent-access-confluence",
                "agent-access-fake",
                "agent-access-gitlab",
                "agent-access-gmail",
                "agent-access-jira",
                "agent-access-mcp-upstream",
                "agent-access-openapi-upstream",
                "agent-access-teams",
            ]
        );
        assert_eq!(
            module(&status, "agent-access-fake")["roles"],
            json!([
                {"role": "native", "id": "fake"},
                {"role": "native", "id": "oauth_stub"},
                {"role": "oauth", "id": "stub"}
            ])
        );
        assert_eq!(
            module(&status, "agent-access-mcp-upstream")["roles"],
            json!([
                {"role": "oauth", "id": "mcp_oauth"},
                {"role": "import", "id": "mcp_http"}
            ])
        );
        assert_eq!(
            module(&status, "agent-access-gmail")["roles"],
            json!([
                {"role": "native", "id": "gmail"},
                {"role": "oauth", "id": "google"}
            ])
        );
    }

    #[test]
    fn supplied_revisions_report_their_provenance() {
        static MODULES: [ModuleProvenance; 2] = [
            ModuleProvenance::new(
                "agent-access-jira",
                env!("CARGO_PKG_VERSION"),
                SourceRevision::evidence(SHA1),
            ),
            ModuleProvenance::new(
                "agent-access-fake",
                env!("CARGO_PKG_VERSION"),
                SourceRevision::declared(SHA256),
            ),
        ];
        let status = status(
            IDENTITY
                .with_source(SourceRevision::declared(SHA1))
                .with_host_source(SourceRevision::evidence(SHA256))
                .with_sdk_source(SourceRevision::declared(SHA256))
                .with_qualification("example-release")
                .with_module_provenance(&MODULES),
        );
        assert_eq!(
            status["assembly"]["source"],
            json!({"revision": SHA1, "provenance": "declared"})
        );
        assert_eq!(status["assembly"]["qualification"], "example-release");
        assert_eq!(
            status["host"]["source"],
            json!({"revision": SHA256, "provenance": "evidence"})
        );
        assert_eq!(
            status["sdk"]["source"],
            json!({"revision": SHA256, "provenance": "declared"})
        );
        assert_eq!(
            module(&status, "agent-access-jira")["source"],
            json!({"revision": SHA1, "provenance": "evidence"})
        );
        assert_eq!(
            module(&status, "agent-access-fake")["source"],
            json!({"revision": SHA256, "provenance": "declared"})
        );
        assert_eq!(
            module(&status, "agent-access-gitlab")["source"],
            json!({"revision": null, "provenance": "unavailable"})
        );
    }

    #[test]
    fn the_fingerprint_follows_the_inventory_not_the_assembly_label() {
        static JIRA: [ModuleProvenance; 1] = [ModuleProvenance::new(
            "agent-access-jira",
            env!("CARGO_PKG_VERSION"),
            SourceRevision::evidence(SHA1),
        )];
        static JIRA_DECLARED: [ModuleProvenance; 1] = [ModuleProvenance::new(
            "agent-access-jira",
            env!("CARGO_PKG_VERSION"),
            SourceRevision::declared(SHA1),
        )];
        let fingerprint = |identity: AssemblyIdentity| {
            identity
                .build_status(&composition())
                .unwrap()
                .inventory_fingerprint
        };
        let base = fingerprint(IDENTITY.with_module_provenance(&JIRA));
        assert_eq!(
            base,
            fingerprint(
                AssemblyIdentity::new("renamed", "9.9.9")
                    .with_qualification("staging")
                    .with_source(SourceRevision::evidence(SHA256))
                    .with_module_provenance(&JIRA)
            )
        );
        assert_ne!(base, fingerprint(IDENTITY));
        assert_ne!(
            base,
            fingerprint(IDENTITY.with_module_provenance(&JIRA_DECLARED))
        );
        assert_ne!(
            base,
            fingerprint(
                IDENTITY
                    .with_module_provenance(&JIRA)
                    .with_host_source(SourceRevision::evidence(SHA1))
            )
        );
        let smaller = BrokerComposition::builder()
            .native(&agent_access_jira::JIRA_BACKEND)
            .build()
            .unwrap();
        assert_ne!(
            base,
            IDENTITY
                .with_module_provenance(&JIRA)
                .build_status(&smaller)
                .unwrap()
                .inventory_fingerprint
        );
    }

    #[test]
    fn unknown_duplicate_conflicting_and_malformed_module_entries_are_rejected() {
        static MODULES: [ModuleProvenance; 7] = [
            // The host and SDK have their own fields.
            ModuleProvenance::new(
                "agent-access-broker-host",
                env!("CARGO_PKG_VERSION"),
                SourceRevision::evidence(SHA1),
            ),
            ModuleProvenance::new(
                "agent-access-jira",
                "0.0.0-other",
                SourceRevision::evidence(SHA1),
            ),
            ModuleProvenance::new(
                "agent-access-gitlab",
                env!("CARGO_PKG_VERSION"),
                SourceRevision::evidence(SHA1),
            ),
            ModuleProvenance::new(
                "agent-access-gitlab",
                env!("CARGO_PKG_VERSION"),
                SourceRevision::evidence(SHA1),
            ),
            ModuleProvenance::new(
                "agent-access-teams",
                env!("CARGO_PKG_VERSION"),
                SourceRevision::evidence(SHA1),
            ),
            ModuleProvenance::new(
                "agent-access-teams",
                env!("CARGO_PKG_VERSION"),
                SourceRevision::declared(SHA1),
            ),
            ModuleProvenance::new(
                "agent-access-fake",
                env!("CARGO_PKG_VERSION"),
                SourceRevision::evidence("0123456"),
            ),
        ];
        let version = env!("CARGO_PKG_VERSION");
        assert_eq!(
            problems(IDENTITY.with_module_provenance(&MODULES)),
            [
                format!(
                    "module provenance names \"agent-access-broker-host\" \"{version}\", which is not a registered module package"
                ),
                "module provenance names \"agent-access-jira\" \"0.0.0-other\", which is not a registered module package".to_string(),
                format!(
                    "module provenance lists \"agent-access-gitlab\" \"{version}\" more than once"
                ),
                format!(
                    "module provenance gives \"agent-access-teams\" \"{version}\" conflicting revisions"
                ),
                format!(
                    "module provenance for \"agent-access-fake\" \"{version}\" must be a full lowercase 40- or 64-hex object ID"
                ),
            ]
        );
    }

    #[test]
    fn malformed_identity_fields_are_rejected_without_echoing_them_raw() {
        let uppercase = "0123456789ABCDEF0123456789ABCDEF01234567";
        let found = problems(
            AssemblyIdentity::new("bad name\n", "")
                .with_qualification("-unqualified")
                .with_source(SourceRevision::evidence(uppercase))
                .with_host_source(SourceRevision::declared(""))
                .with_sdk_source(SourceRevision::declared("HEAD")),
        );
        assert_eq!(
            found,
            [
                "assembly name \"bad name\\n\" must be 1 to 64 ASCII letters, digits, '.', '_' or '-', starting with a letter or digit",
                "assembly version \"\" must be 1 to 64 ASCII letters, digits, '.', '+' or '-'",
                "qualification label \"-unqualified\" must be 1 to 64 ASCII letters, digits, '.', '_' or '-', starting with a letter or digit",
                "assembly source revision must be a full lowercase 40- or 64-hex object ID",
                "host source revision must be a full lowercase 40- or 64-hex object ID",
                "SDK source revision must be a full lowercase 40- or 64-hex object ID",
            ]
        );
        let long = "x".repeat(200);
        let long: &'static str = Box::leak(long.into_boxed_str());
        let found = problems(AssemblyIdentity::new("broker", "1").with_qualification(long));
        assert!(
            found[0].contains(&format!("{:?}...", &long[..80])),
            "{found:?}"
        );
        assert!(!found[0].contains(&long[..81]));
    }

    #[test]
    fn labels_and_versions_are_bounded() {
        assert!(is_label("a"));
        assert!(is_label("Acme_Broker.v2-rc"));
        assert!(is_label(&"a".repeat(64)));
        assert!(!is_label(&"a".repeat(65)));
        assert!(!is_label(""));
        assert!(!is_label(".hidden"));
        assert!(!is_label("has space"));
        assert!(!is_label("caf\u{e9}"));
        assert!(is_version("1.2.3-rc.1+build.5"));
        assert!(!is_version("1.2.3 beta"));
        assert!(!is_version(&"1".repeat(65)));
    }
}
