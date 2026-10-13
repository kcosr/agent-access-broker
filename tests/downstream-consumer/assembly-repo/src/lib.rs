//! A downstream broker distribution: production CloudBees CI from upstream
//! and the conformance provider from a separately owned provider repository,
//! run by the upstream host application under this assembly's own identity.
use agent_access_broker_host::{AssemblyIdentity, BrokerComposition, CompositionError};
use agent_access_cloudbees_ci::CLOUDBEES_CI_BACKEND;
use agent_access_conformance::CONFORMANCE_BACKEND;

/// The modules this distribution links. Conformance is a development
/// provider: it can be configured only when the deployment enables
/// development fixtures.
pub fn composition() -> Result<BrokerComposition, CompositionError> {
    BrokerComposition::builder()
        .native(&CLOUDBEES_CI_BACKEND)
        .native(&CONFORMANCE_BACKEND)
        .build()
}

/// This executable's identity. It names the distribution, not the host
/// crate it links.
pub fn identity() -> AssemblyIdentity {
    AssemblyIdentity::new(env!("CARGO_PKG_NAME"), env!("CARGO_PKG_VERSION"))
        .with_about("Downstream broker distribution fixture")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_composition_selects_the_linked_modules_in_order() {
        let composition = composition().unwrap();
        assert_eq!(
            composition.native_kinds().collect::<Vec<_>>(),
            ["cloudbees_ci", "conformance"]
        );
    }

    #[test]
    fn a_duplicate_selection_is_rejected() {
        let error = BrokerComposition::builder()
            .native(&CLOUDBEES_CI_BACKEND)
            .native(&CLOUDBEES_CI_BACKEND)
            .build()
            .unwrap_err();
        assert!(!error.problems().is_empty());
    }

    #[test]
    fn the_status_reports_this_assembly_version() {
        let status = identity().build_status();
        assert_eq!(status.broker_version, env!("CARGO_PKG_VERSION"));
        assert_eq!(status.build_commit, None);
    }
}
