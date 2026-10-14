//! Emits the locked versions and full commits of the upstream and provider
//! repositories from this assembly's own `Cargo.lock`, for its module
//! provenance.
use std::env;
use std::fs;
use std::path::Path;

/// One package from each pinned repository; every package of a repository
/// shares its locked commit.
const REPOSITORIES: [(&str, &str); 2] = [
    ("UPSTREAM", "agent-access-broker-host"),
    ("PROVIDER", "agent-access-conformance"),
];

fn main() {
    let lock = Path::new(&env::var("CARGO_MANIFEST_DIR").expect("Cargo sets CARGO_MANIFEST_DIR"))
        .join("Cargo.lock");
    println!("cargo:rerun-if-changed={}", lock.display());
    let lock = fs::read_to_string(&lock).expect("the assembly builds from its own Cargo.lock");
    for (prefix, package) in REPOSITORIES {
        let (version, revision) = locked_git_package(&lock, package);
        println!("cargo:rustc-env=DOWNSTREAM_BROKER_{prefix}_VERSION={version}");
        println!("cargo:rustc-env=DOWNSTREAM_BROKER_{prefix}_REVISION={revision}");
    }
}

/// The version and locked full commit of the single Git package `name`.
fn locked_git_package(lock: &str, name: &str) -> (String, String) {
    let mut found = None;
    for block in lock.split("[[package]]").skip(1) {
        let field = |key: &str| {
            let prefix = format!("{key} = \"");
            block.lines().find_map(|line| {
                line.strip_prefix(&prefix)
                    .and_then(|rest| rest.strip_suffix('"'))
                    .map(str::to_owned)
            })
        };
        if field("name").as_deref() != Some(name) {
            continue;
        }
        let revision = field("source")
            .and_then(|source| {
                source
                    .strip_prefix("git+")
                    .and_then(|source| source.rsplit_once('#'))
                    .map(|(_, revision)| revision.to_owned())
            })
            .filter(|revision| {
                matches!(revision.len(), 40 | 64)
                    && revision
                        .bytes()
                        .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
            })
            .unwrap_or_else(|| panic!("{name} must be locked to a full Git commit"));
        let version = field("version").unwrap_or_else(|| panic!("{name} has no locked version"));
        assert!(
            found.replace((version, revision)).is_none(),
            "{name} is locked more than once"
        );
    }
    found.unwrap_or_else(|| panic!("{name} is not in Cargo.lock"))
}
