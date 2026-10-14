//! A downstream broker distribution: production CloudBees CI from upstream
//! and the conformance provider from a separately owned provider repository,
//! run by the upstream host application under this assembly's own identity.
use agent_access_broker_host::{
    AssemblyIdentity, BrokerComposition, CompositionError, ModuleProvenance, SourceRevision,
};
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

/// The locked upstream commit: the host, the SDK and CloudBees CI.
const UPSTREAM: SourceRevision =
    SourceRevision::evidence(env!("DOWNSTREAM_BROKER_UPSTREAM_REVISION"));

/// The locked commit of the provider repository.
const PROVIDER: SourceRevision =
    SourceRevision::evidence(env!("DOWNSTREAM_BROKER_PROVIDER_REVISION"));

/// One entry per registered module package, keyed by its crate name and
/// version. Upstream packages share one release version.
static MODULES: [ModuleProvenance; 2] = [
    ModuleProvenance::new(
        "agent-access-cloudbees-ci",
        env!("DOWNSTREAM_BROKER_UPSTREAM_VERSION"),
        UPSTREAM,
    ),
    ModuleProvenance::new(
        "agent-access-conformance",
        env!("DOWNSTREAM_BROKER_PROVIDER_VERSION"),
        PROVIDER,
    ),
];

/// This executable's identity. Its own revision and qualification label are
/// set only by the process that builds and qualifies a verified clean checkout
/// of this repository.
pub fn build_identity() -> AssemblyIdentity {
    let identity = AssemblyIdentity::new(env!("CARGO_PKG_NAME"), env!("CARGO_PKG_VERSION"))
        .with_about("Downstream broker distribution fixture")
        .with_host_source(UPSTREAM)
        .with_sdk_source(UPSTREAM)
        .with_module_provenance(&MODULES);
    let identity = match option_env!("DOWNSTREAM_BROKER_REVISION") {
        Some(revision) => identity.with_source(SourceRevision::evidence(revision)),
        None => identity,
    };
    match option_env!("DOWNSTREAM_BROKER_QUALIFICATION") {
        Some(label) => identity.with_qualification(label),
        None => identity,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use agent_access_broker_host::BrokerApplication;
    use agent_access_broker_host::test_support::IsolatedBroker;
    use serde_json::{Value, json};

    const TOKEN: &str = "downstream-status-token";

    fn status() -> Value {
        let application = BrokerApplication::new(composition().unwrap(), build_identity()).unwrap();
        serde_json::to_value(application.status()).unwrap()
    }

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
    fn the_identity_reports_the_locked_sources_of_every_module() {
        let status = status();
        let upstream = json!({
            "revision": env!("DOWNSTREAM_BROKER_UPSTREAM_REVISION"),
            "provenance": "evidence"
        });
        let provider = json!({
            "revision": env!("DOWNSTREAM_BROKER_PROVIDER_REVISION"),
            "provenance": "evidence"
        });
        assert_eq!(status["assembly"]["name"], env!("CARGO_PKG_NAME"));
        assert_eq!(status["assembly"]["version"], env!("CARGO_PKG_VERSION"));
        assert_eq!(
            status["assembly"]["qualification"],
            option_env!("DOWNSTREAM_BROKER_QUALIFICATION").unwrap_or("unqualified")
        );
        assert_eq!(status["host"]["source"], upstream);
        assert_eq!(status["sdk"]["source"], upstream);
        assert_eq!(
            status["modules"],
            json!([
                {
                    "crate": "agent-access-cloudbees-ci",
                    "version": env!("DOWNSTREAM_BROKER_UPSTREAM_VERSION"),
                    "roles": [{"role": "native", "id": "cloudbees_ci"}],
                    "source": upstream
                },
                {
                    "crate": "agent-access-conformance",
                    "version": env!("DOWNSTREAM_BROKER_PROVIDER_VERSION"),
                    "roles": [{"role": "native", "id": "conformance"}],
                    "source": provider
                }
            ])
        );
    }

    #[test]
    fn provenance_for_an_unregistered_package_is_rejected() {
        static UNREGISTERED: [ModuleProvenance; 1] = [ModuleProvenance::new(
            "agent-access-jira",
            env!("DOWNSTREAM_BROKER_UPSTREAM_VERSION"),
            UPSTREAM,
        )];
        let identity = build_identity().with_module_provenance(&UNREGISTERED);
        assert!(BrokerApplication::new(composition().unwrap(), identity).is_err());
    }

    #[tokio::test]
    async fn the_isolated_application_serves_this_identity() {
        let application = IsolatedBroker::new(composition().unwrap(), build_identity()).unwrap();
        let token = application
            .directory()
            .secret_file("identity.token", TOKEN)
            .unwrap();
        let spool = application.directory().join("spool");
        let document = format!(
            r#"
[deployment]
environment = "development"

[identity]
mode = "required"
authority = "toml"

[[identity.sources]]
name = "local"
type = "static_principals"
header = "Authorization"
scheme = "Bearer"

[[identity.sources.principals]]
principal = "status-user"
token_refs = ["file:{}"]

[policy]
authority = "toml"

[limits]
upload_spool_dir = "{}"
"#,
            token.display(),
            spool.display()
        );
        let broker = application.config_document(document).start().await.unwrap();
        let response = reqwest::Client::builder()
            .no_proxy()
            .build()
            .unwrap()
            .get(format!("{}/v1/broker/status", broker.public_url()))
            .header("X-Agent-Access-Request-Id", "downstream-status")
            .header("Authorization", format!("Bearer {TOKEN}"))
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), 200);
        assert_eq!(response.json::<Value>().await.unwrap(), status());
        broker.shutdown();
        assert!(broker.join().await.unwrap().is_clean());
    }
}
