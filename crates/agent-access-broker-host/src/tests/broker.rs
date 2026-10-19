//! Isolated brokers for host tests. Every test broker starts from a real
//! configuration document through [`crate::test_support::IsolatedBroker`],
//! the production startup and `serve` lifecycle; requests then go through
//! the routers the listeners serve, in process, so tests keep control of the
//! connection's source address.
use super::config_render::render_config;
use crate::state::ReloadableState;
use crate::test_support::{
    IsolatedBroker, ProviderFixture, ReloadOutcome, RunningBroker, ShutdownReport,
};
use crate::{AssemblyIdentity, BrokerComposition};
use agent_access_core::{BackendRegistry, BrokerConfig, BrokerRuntime, parse_broker_config_raw};
use agent_access_provider::ServiceProvider;
use agent_access_provider::test_support::DescribedProvider;
use axum::Router;
use std::sync::Arc;

/// The assembly host tests stand in for, unstamped; its build status is
/// [`crate::broker_build_status`].
fn test_identity() -> AssemblyIdentity {
    let (name, version) = crate::test_composition::TEST_ASSEMBLY;
    AssemblyIdentity::new(name, version)
}

/// The document of a broker configuration a test builds in Rust.
#[derive(Clone, Debug)]
pub(crate) struct ConfigDoc(toml::Table);

impl ConfigDoc {
    /// The document of a configuration a test builds in Rust. Panics unless
    /// the document parses back, with the configuration's own backends, to
    /// exactly `config`.
    pub(crate) fn from_config(config: &BrokerConfig) -> Self {
        let document = Self(render_config(config));
        let parsed = parse_broker_config_raw(
            "test-broker.toml",
            &document.render(),
            config.providers.registry(),
        )
        .unwrap_or_else(|error| {
            panic!(
                "rendered test configuration does not parse: {error}\n{}",
                document.render()
            )
        });
        assert_eq!(
            format!("{parsed:#?}"),
            format!("{config:#?}"),
            "the rendered test configuration differs from the test's"
        );
        document
    }

    /// The document's TOML text.
    pub(crate) fn render(&self) -> String {
        toml::to_string(&self.0).expect("configuration documents render")
    }
}

/// A test broker started from a configuration document with the upstream
/// composition and identity. Keep it alive while requests are made through
/// its routers: dropping it shuts the broker down.
pub(crate) struct TestBroker {
    running: RunningBroker,
}

impl TestBroker {
    /// The reload budget of test brokers whose tests check what a reload
    /// publishes, not how long it takes. Candidate admission does real
    /// filesystem and worker-thread work, which a contended host slows far
    /// beyond its usual fraction of a second; this is the most
    /// `--reload-timeout-ms` accepts.
    pub(crate) const RELOAD_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(300);

    /// An isolated broker application serving the configuration file at
    /// `path`, which the test owns.
    pub(crate) fn builder_at(path: impl Into<std::path::PathBuf>) -> IsolatedBroker {
        IsolatedBroker::new(crate::test_composition::composition(), test_identity())
            .expect("fixture directory")
            .config_path(path)
    }

    /// An isolated broker application serving the document of a
    /// configuration built in Rust, composed of that configuration's
    /// backends.
    pub(crate) fn config_builder(config: &BrokerConfig) -> IsolatedBroker {
        // Every broker locks its upload spool, so concurrent tests need their
        // own (see `test_limits`) rather than one under the working directory.
        assert!(
            std::path::Path::new(&config.limits.upload_spool_dir).starts_with(std::env::temp_dir()),
            "give the test broker a private limits.upload_spool_dir"
        );
        let registry: Arc<BackendRegistry> = Arc::clone(config.providers.registry());
        IsolatedBroker::new(BrokerComposition::from_registry(registry), test_identity())
            .expect("fixture directory")
            .config_document(ConfigDoc::from_config(config).render())
    }

    /// Starts on the document of a configuration built in Rust.
    pub(crate) async fn start_config(config: &BrokerConfig) -> Self {
        Self::start_with(Self::config_builder(config)).await
    }

    /// Starts on the document of `config` with each provider serving, through
    /// the fixture control, the configured service its descriptor names.
    pub(crate) async fn start_with_providers(
        config: &BrokerConfig,
        providers: impl IntoIterator<Item = impl TestProvider>,
    ) -> Self {
        Self::start_with(with_provider_instances(
            Self::config_builder(config),
            providers,
        ))
        .await
    }

    pub(crate) async fn start_with(application: IsolatedBroker) -> Self {
        Self::try_start_with(application)
            .await
            .unwrap_or_else(|error| panic!("test broker failed to start: {error:#}"))
    }

    /// Starts `application`, or reports the startup failure.
    pub(crate) async fn try_start_with(application: IsolatedBroker) -> anyhow::Result<Self> {
        Ok(Self {
            running: application.start().await?,
        })
    }

    /// The router the public listener serves.
    pub(crate) fn app(&self) -> Router {
        self.running.public_app()
    }

    /// The router the gateway listener serves.
    pub(crate) fn gateway_app(&self) -> Router {
        self.running.gateway_app()
    }

    pub(crate) fn state(&self) -> Arc<ReloadableState> {
        self.running.reloadable_state()
    }

    /// The active generation's runtime.
    pub(crate) fn runtime(&self) -> BrokerRuntime {
        self.state().current().runtime.clone()
    }

    pub(crate) fn running(&self) -> &RunningBroker {
        &self.running
    }

    /// Rewrites the configuration file with the document of `config` and
    /// reloads it, as SIGUSR2 does; panics unless the reload succeeds.
    pub(crate) async fn reload_config(&self, config: &BrokerConfig) -> ReloadOutcome {
        self.running
            .rewrite_config(ConfigDoc::from_config(config).render())
            .expect("configuration file is writable");
        let outcome = self.running.reload().await.expect("the broker reloads");
        assert!(outcome.is_success(), "{outcome:?}");
        outcome
    }

    /// Shuts down and waits for the drain and the state locks' release. Drop
    /// router and state clones first: they hold the broker state.
    pub(crate) async fn stop(self) -> ShutdownReport {
        self.running.shutdown();
        self.running
            .join()
            .await
            .unwrap_or_else(|error| panic!("test broker failed to stop: {error:#}"))
    }
}

/// A provider instance a host test serves through the fixture control. Each
/// generation takes its descriptor afresh, so a test provider that describes
/// itself from mutable state is described as it is at each reload.
pub(crate) trait TestProvider: Send + Sync + 'static {
    fn service_provider(&self) -> ServiceProvider;
}

impl<P: DescribedProvider> TestProvider for Arc<P> {
    fn service_provider(&self) -> ServiceProvider {
        ServiceProvider::from(Arc::clone(self))
    }
}

impl TestProvider for ServiceProvider {
    fn service_provider(&self) -> ServiceProvider {
        self.clone()
    }
}

/// `application` serving each provider, through the fixture control, for the
/// configured service its descriptor names, in every generation.
pub(crate) fn with_provider_instances(
    application: IsolatedBroker,
    providers: impl IntoIterator<Item = impl TestProvider>,
) -> IsolatedBroker {
    providers
        .into_iter()
        .fold(application, |application, provider| {
            let kind = provider.service_provider().descriptor.service;
            application.provider_fixture(
                kind,
                ProviderFixture::factory(move |_| provider.service_provider()),
            )
        })
}
