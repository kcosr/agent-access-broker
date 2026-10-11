mod build_support;

use build_support::parse_build_provenance;
use std::env::{self, VarError};

const COMMIT_ENV: &str = "AGENT_ACCESS_BUILD_COMMIT";
const PROVENANCE_ENV: &str = "AGENT_ACCESS_BUILD_PROVENANCE";
const REQUIRE_ENV: &str = "AGENT_ACCESS_REQUIRE_BUILD_PROVENANCE";

fn main() {
    for name in [COMMIT_ENV, PROVENANCE_ENV, REQUIRE_ENV] {
        println!("cargo:rerun-if-env-changed={name}");
    }

    let commit = read_env(COMMIT_ENV);
    let provenance = read_env(PROVENANCE_ENV);
    let require = read_env(REQUIRE_ENV);
    let parsed =
        parse_build_provenance(commit.as_deref(), provenance.as_deref(), require.as_deref())
            .unwrap_or_else(|error| {
                panic!("invalid Agent Access Broker build provenance: {error}")
            });

    println!(
        "cargo:rustc-env=AGENT_ACCESS_EMBEDDED_BUILD_PROVENANCE={}",
        parsed.provenance.as_str()
    );
    println!(
        "cargo:rustc-env=AGENT_ACCESS_EMBEDDED_BUILD_COMMIT={}",
        parsed.commit.as_deref().unwrap_or("")
    );
}

fn read_env(name: &str) -> Option<String> {
    match env::var(name) {
        Ok(value) => Some(value),
        Err(VarError::NotPresent) => None,
        Err(VarError::NotUnicode(_)) => {
            panic!("invalid Agent Access Broker build provenance: {name} is not valid Unicode")
        }
    }
}
