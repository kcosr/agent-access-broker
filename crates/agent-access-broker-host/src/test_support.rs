//! Isolated broker applications for acceptance tests, behind the
//! `test-support` feature. Release builds must not enable it.
//!
//! An [`IsolatedBroker`] starts the same way the broker process serves: it
//! reads a real configuration file, validates and locks its state, checks
//! readiness, binds loopback listeners on ephemeral ports, and publishes
//! reloads and drains operations exactly as `serve` does. It never installs a
//! process signal handler or a global log subscriber:
//! [`RunningBroker::reload`] and [`RunningBroker::shutdown`] stand in for
//! SIGUSR2 and SIGTERM, and events reach whatever dispatcher the starting
//! task has.
//!
//! [`ProviderFixture`] is a fixture control, not an embedding API. It
//! replaces the provider that a selected and configured native registration
//! would build, in every generation, while configuration validation, state
//! locks, admission and generation ownership still apply. Nothing outside
//! this module can install one.
use crate::composition::BrokerComposition;
use crate::identity::AssemblyIdentity;
use crate::lifecycle::{
    self, DrainReport, LoggingMode, PreboundListeners, ReloadRequest, ServeControl, ServeOptions,
    SignalSource, StartupHooks,
};
use crate::reload::ConfigOperationResponse;
use crate::state::ReloadableState;
use agent_access_core::test_support::ProviderFixtures;
use agent_access_core::{
    AuditStoreType, ImportedCatalog, ManagedPolicyGrantRecord, ManagedStore, ManagedStoreError,
    StateLockSet, parse_broker_config_raw,
};
use agent_access_provider::ServiceProvider;
use anyhow::{Context, anyhow, bail};
use serde_json::Value;
use std::fmt;
use std::io;
use std::net::{Ipv4Addr, SocketAddr};
use std::path::{Component, Path, PathBuf};
use std::sync::{Arc, Mutex, Weak};
use std::time::{Duration, Instant};
use tokio::sync::{mpsc, oneshot};
use tracing::instrument::WithSubscriber;

pub use agent_access_core::test_support::ProviderFixtureContext;

const CONFIG_FILE: &str = "broker.toml";
const DEFAULT_TIMEOUT: Duration = Duration::from_secs(30);
/// How long [`RunningBroker::join`] waits, beyond the shutdown timeout, for
/// the last holders of the state locks to finish.
const LOCK_RELEASE_GRACE: Duration = Duration::from_secs(5);

/// A private temporary directory for a fixture's configuration, secrets and
/// state: the directory is `0700` and secret files are `0600` on Unix.
/// Clones share the directory, which is removed when the last clone drops,
/// so a restarted broker can reuse its predecessor's state.
#[derive(Clone)]
pub struct FixtureDir {
    inner: Arc<tempfile::TempDir>,
}

impl FixtureDir {
    pub fn new() -> io::Result<Self> {
        let dir = tempfile::Builder::new()
            .prefix("agent-access-broker-fixture-")
            .tempdir()?;
        set_private_mode(dir.path(), PRIVATE_DIR_MODE)?;
        Ok(Self {
            inner: Arc::new(dir),
        })
    }

    pub fn path(&self) -> &Path {
        self.inner.path()
    }

    /// The path of `relative` inside the directory, without creating it.
    /// Panics if `relative` is absolute or leaves the directory.
    pub fn join(&self, relative: impl AsRef<Path>) -> PathBuf {
        let relative = relative.as_ref();
        assert!(
            is_contained(relative),
            "fixture path {} must stay inside the fixture directory",
            relative.display()
        );
        self.path().join(relative)
    }

    /// Creates the private directory `relative`, and any missing parents.
    pub fn private_dir(&self, relative: impl AsRef<Path>) -> io::Result<PathBuf> {
        let path = self.contained(relative.as_ref())?;
        self.create_private_dirs(&path)?;
        Ok(path)
    }

    /// Writes the private file `relative`, replacing its contents, and
    /// creates any missing parent directories privately.
    pub fn secret_file(
        &self,
        relative: impl AsRef<Path>,
        contents: impl AsRef<[u8]>,
    ) -> io::Result<PathBuf> {
        let path = self.contained(relative.as_ref())?;
        if let Some(parent) = path.parent() {
            self.create_private_dirs(parent)?;
        }
        write_private_file(&path, contents.as_ref())?;
        Ok(path)
    }

    fn contained(&self, relative: &Path) -> io::Result<PathBuf> {
        if is_contained(relative) {
            Ok(self.path().join(relative))
        } else {
            Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!(
                    "fixture path {} must stay inside the fixture directory",
                    relative.display()
                ),
            ))
        }
    }

    fn create_private_dirs(&self, path: &Path) -> io::Result<()> {
        let relative = path.strip_prefix(self.path()).unwrap_or(path);
        let mut current = self.path().to_path_buf();
        for component in relative.components() {
            current.push(component);
            match std::fs::create_dir(&current) {
                Ok(()) => set_private_mode(&current, PRIVATE_DIR_MODE)?,
                Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
                Err(error) => return Err(error),
            }
        }
        Ok(())
    }
}

impl fmt::Debug for FixtureDir {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_tuple("FixtureDir")
            .field(&self.path())
            .finish()
    }
}

fn is_contained(relative: &Path) -> bool {
    relative
        .components()
        .all(|component| matches!(component, Component::Normal(_)))
        && relative.components().next().is_some()
}

const PRIVATE_DIR_MODE: u32 = 0o700;
const PRIVATE_FILE_MODE: u32 = 0o600;

fn set_private_mode(path: &Path, mode: u32) -> io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode))
    }
    #[cfg(not(unix))]
    {
        let _ = (path, mode);
        Ok(())
    }
}

fn write_private_file(path: &Path, contents: &[u8]) -> io::Result<()> {
    use std::io::Write;
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(PRIVATE_FILE_MODE);
    }
    let mut file = options.open(path)?;
    // An existing file keeps its mode through `open`; make it private too.
    set_private_mode(path, PRIVATE_FILE_MODE)?;
    file.write_all(contents)?;
    file.sync_all()
}

/// The provider an isolated broker serves for one configured native kind, in
/// place of the one its registration would build. See the module notes: it
/// is a fixture control, not an embedding API.
#[derive(Clone)]
pub struct ProviderFixture {
    factory: Arc<dyn Fn(&ProviderFixtureContext<'_>) -> ServiceProvider + Send + Sync>,
}

impl ProviderFixture {
    /// Serves `provider`, the same instance in every generation.
    pub fn instance(provider: impl Into<ServiceProvider>) -> Self {
        let provider = provider.into();
        Self::factory(move |_| provider.clone())
    }

    /// Builds the provider each time a generation that configures the kind
    /// is constructed, at startup and for every reload candidate.
    pub fn factory(
        factory: impl Fn(&ProviderFixtureContext<'_>) -> ServiceProvider + Send + Sync + 'static,
    ) -> Self {
        Self {
            factory: Arc::new(factory),
        }
    }
}

impl fmt::Debug for ProviderFixture {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ProviderFixture")
            .finish_non_exhaustive()
    }
}

enum ConfigSource {
    Document(String),
    Path(PathBuf),
}

/// Starts an isolated broker application: an assembly's composition and
/// identity, one real configuration file, and loopback listeners on
/// ephemeral ports. The listeners are bound when the application is created,
/// so a configuration can name their addresses, such as `mcp.public_url`.
#[must_use]
pub struct IsolatedBroker {
    composition: BrokerComposition,
    identity: AssemblyIdentity,
    directory: FixtureDir,
    config: Option<ConfigSource>,
    public: std::net::TcpListener,
    gateway: Option<std::net::TcpListener>,
    body_hard_cap: Option<u64>,
    reload_timeout: Duration,
    shutdown_timeout: Duration,
    fixtures: Vec<(String, ProviderFixture)>,
    /// Host tests' replacements for startup internals.
    #[cfg(test)]
    test_hooks: StartupHooks,
}

impl IsolatedBroker {
    /// An application in a new private [`FixtureDir`] with a bound public
    /// listener, the production default reload and shutdown timeouts and no
    /// gateway listener.
    pub fn new(composition: BrokerComposition, identity: AssemblyIdentity) -> io::Result<Self> {
        Ok(Self {
            composition,
            identity,
            directory: FixtureDir::new()?,
            config: None,
            public: loopback_listener()?,
            gateway: None,
            body_hard_cap: None,
            reload_timeout: DEFAULT_TIMEOUT,
            shutdown_timeout: DEFAULT_TIMEOUT,
            fixtures: Vec::new(),
            #[cfg(test)]
            test_hooks: StartupHooks::default(),
        })
    }

    /// The fixture directory, for the secrets and paths the configuration
    /// names.
    pub fn directory(&self) -> &FixtureDir {
        &self.directory
    }

    /// The public listener's loopback address.
    pub fn public_addr(&self) -> SocketAddr {
        self.public
            .local_addr()
            .expect("a bound listener has an address")
    }

    /// `http://` and the public listener's address.
    pub fn public_url(&self) -> String {
        format!("http://{}", self.public_addr())
    }

    /// The gateway listener's loopback address, once
    /// [`Self::gateway_listener`] binds it.
    pub fn gateway_addr(&self) -> Option<SocketAddr> {
        self.gateway.as_ref().map(|listener| {
            listener
                .local_addr()
                .expect("a bound listener has an address")
        })
    }

    /// Uses `directory` instead, such as a stopped broker's, to restart on
    /// its state.
    pub fn in_directory(mut self, directory: FixtureDir) -> Self {
        self.directory = directory;
        self
    }

    /// Serves the TOML `document`, written privately to `broker.toml` in the
    /// fixture directory when the application starts.
    pub fn config_document(mut self, document: impl Into<String>) -> Self {
        self.config = Some(ConfigSource::Document(document.into()));
        self
    }

    /// Serves the configuration file at `path`, which the test owns.
    pub fn config_path(mut self, path: impl Into<PathBuf>) -> Self {
        self.config = Some(ConfigSource::Path(path.into()));
        self
    }

    /// Also binds the Git gateway listener.
    pub fn gateway_listener(mut self) -> io::Result<Self> {
        self.gateway = Some(loopback_listener()?);
        Ok(self)
    }

    /// `--max-http-body-hard-cap-bytes`.
    pub fn body_hard_cap(mut self, bytes: u64) -> Self {
        self.body_hard_cap = Some(bytes);
        self
    }

    /// `--reload-timeout-ms`.
    pub fn reload_timeout(mut self, timeout: Duration) -> Self {
        self.reload_timeout = timeout;
        self
    }

    /// `--shutdown-timeout-ms`.
    pub fn shutdown_timeout(mut self, timeout: Duration) -> Self {
        self.shutdown_timeout = timeout;
        self
    }

    /// Serves `fixture` for the native kind `kind`, which must be selected by
    /// the composition and configured at startup. Generations that do not
    /// configure `kind` build no provider for it.
    pub fn provider_fixture(mut self, kind: impl Into<String>, fixture: ProviderFixture) -> Self {
        self.fixtures.push((kind.into(), fixture));
        self
    }

    /// Host tests' Microsoft OIDC transport and clock for the startup
    /// generation.
    #[cfg(test)]
    pub(crate) fn microsoft_oidc_components(
        mut self,
        transport: Arc<dyn crate::state::MicrosoftOidcTransport>,
        clock: Arc<dyn agent_access_core::microsoft_oidc::MicrosoftOidcClock>,
    ) -> Self {
        self.test_hooks.microsoft_oidc = Some((transport, clock));
        self
    }

    /// Host tests' invocation limiter, such as one with a manual clock.
    #[cfg(test)]
    pub(crate) fn invocation_limiter(
        mut self,
        limiter: crate::ingress::invocation_limits::InvocationLimiter,
    ) -> Self {
        self.test_hooks.invocation_limiter = Some(limiter);
        self
    }

    /// Starts serving on the caller's Tokio runtime. Fails as the broker
    /// process would at startup, for example on an invalid configuration or
    /// a held state lock.
    pub async fn start(self) -> anyhow::Result<RunningBroker> {
        let Self {
            composition,
            identity,
            directory,
            config,
            public,
            gateway,
            body_hard_cap,
            reload_timeout,
            shutdown_timeout,
            fixtures,
            #[cfg(test)]
            test_hooks,
        } = self;
        let public_addr = public.local_addr()?;
        let gateway_addr = gateway
            .as_ref()
            .map(|gateway| gateway.local_addr())
            .transpose()?;
        let config_path = match config {
            Some(ConfigSource::Document(document)) => {
                let path = directory.join(CONFIG_FILE);
                write_private_file(&path, document.as_bytes())
                    .with_context(|| format!("failed to write {}", path.display()))?;
                path
            }
            Some(ConfigSource::Path(path)) => path,
            None => bail!("an isolated broker needs a configuration document or path"),
        };
        let provider_fixtures = provider_fixtures(fixtures)?;
        let (shutdown, shutdown_requests) = oneshot::channel();
        let (reload, reload_requests) = mpsc::unbounded_channel();
        let (listening, started) = oneshot::channel();
        let control = ServeControl {
            signals: SignalSource::controlled(shutdown_requests, reload_requests),
            logging: LoggingMode::Ambient,
            startup: StartupHooks {
                listeners: Some(PreboundListeners { public, gateway }),
                listening: Some(listening),
                provider_fixtures,
                #[cfg(test)]
                microsoft_oidc: test_hooks.microsoft_oidc,
                #[cfg(test)]
                invocation_limiter: test_hooks.invocation_limiter,
            },
        };
        let options = ServeOptions {
            config_path: config_path.clone(),
            listen: public_addr,
            gateway_listen: gateway_addr,
            body_hard_cap,
            reload_timeout,
            shutdown_timeout,
        };
        let mut task = tokio::spawn(
            lifecycle::serve(composition, identity, options, control).with_current_subscriber(),
        );
        let listening = match started.await {
            Ok(listening) => listening,
            Err(_) => {
                return Err(match (&mut task).await {
                    Ok(Err(error)) => error,
                    Ok(Ok(_)) => anyhow!("the broker stopped before it was listening"),
                    Err(error) => anyhow!("the broker task failed: {error}"),
                });
            }
        };
        Ok(RunningBroker {
            public_addr,
            gateway_addr,
            config_path,
            directory,
            shutdown_timeout,
            shutdown: Mutex::new(Some(shutdown)),
            reload,
            state: Some(listening.state),
            mcp: Some(listening.mcp),
            task: Some(task),
            #[cfg(test)]
            public_app: listening.public_app,
            #[cfg(test)]
            gateway_app: listening.gateway_app,
        })
    }
}

/// A non-blocking listener on an ephemeral loopback port.
fn loopback_listener() -> io::Result<std::net::TcpListener> {
    let listener = std::net::TcpListener::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)))?;
    listener.set_nonblocking(true)?;
    Ok(listener)
}

fn provider_fixtures(
    fixtures: Vec<(String, ProviderFixture)>,
) -> anyhow::Result<Option<ProviderFixtures>> {
    if fixtures.is_empty() {
        return Ok(None);
    }
    let mut set = ProviderFixtures::new();
    for (kind, fixture) in fixtures {
        let factory = fixture.factory;
        if !set.insert(kind.clone(), move |context| factory(context)) {
            bail!("provider fixture {kind} is supplied more than once");
        }
    }
    Ok(Some(set))
}

/// A started isolated broker. Dropping it requests shutdown without waiting;
/// [`Self::join`] waits for the drain and the release of every state lock.
pub struct RunningBroker {
    public_addr: SocketAddr,
    gateway_addr: Option<SocketAddr>,
    config_path: PathBuf,
    directory: FixtureDir,
    shutdown_timeout: Duration,
    shutdown: Mutex<Option<oneshot::Sender<()>>>,
    reload: mpsc::UnboundedSender<ReloadRequest>,
    state: Option<Arc<ReloadableState>>,
    mcp: Option<crate::mcp::Endpoint>,
    task: Option<tokio::task::JoinHandle<anyhow::Result<DrainReport>>>,
    #[cfg(test)]
    public_app: axum::Router,
    #[cfg(test)]
    gateway_app: Option<axum::Router>,
}

impl RunningBroker {
    /// The public listener's address on the loopback interface.
    pub fn public_addr(&self) -> SocketAddr {
        self.public_addr
    }

    /// `http://` and the public listener's address.
    pub fn public_url(&self) -> String {
        format!("http://{}", self.public_addr)
    }

    /// The Git gateway listener's address, when the application binds one.
    pub fn gateway_addr(&self) -> Option<SocketAddr> {
        self.gateway_addr
    }

    /// The configuration file the broker reads at startup and on reload.
    pub fn config_path(&self) -> &Path {
        &self.config_path
    }

    pub fn directory(&self) -> &FixtureDir {
        &self.directory
    }

    /// Replaces the configuration file's contents privately, for a following
    /// [`Self::reload`].
    pub fn rewrite_config(&self, document: impl AsRef<str>) -> io::Result<()> {
        write_private_file(&self.config_path, document.as_ref().as_bytes())
    }

    /// The active configuration generation; startup is generation 1.
    pub fn config_generation(&self) -> u64 {
        self.state().current().generation
    }

    /// Reloads the configuration as SIGUSR2 does, audited as the system,
    /// and returns the outcome. Fails once shutdown has begun.
    pub async fn reload(&self) -> anyhow::Result<ReloadOutcome> {
        let (outcome, received) = oneshot::channel();
        self.reload
            .send(ReloadRequest {
                outcome: Some(outcome),
            })
            .map_err(|_| anyhow!("the broker is no longer serving"))?;
        let response = received
            .await
            .map_err(|_| anyhow!("the broker shut down before reloading"))?;
        Ok(ReloadOutcome::from(response))
    }

    /// Requests shutdown, as SIGTERM does. Idempotent.
    pub fn shutdown(&self) {
        if let Some(shutdown) = self.shutdown.lock().unwrap().take() {
            let _ = shutdown.send(());
        }
    }

    /// Waits for a requested shutdown to drain listeners, operations and
    /// audit, then for every state lock the application acquired to be
    /// released, so another broker may start on the same state. Fails with
    /// the serve error, or when a lock stays held past the shutdown timeout
    /// plus a short grace period. HTTP MCP sessions still open after the
    /// drain are closed, as process exit would end them.
    pub async fn join(mut self) -> anyhow::Result<ShutdownReport> {
        let task = self.task.take().expect("a running broker has a task");
        let drained = task
            .await
            .map_err(|error| anyhow!("the broker task failed: {error}"))??;
        let state = self.state.take().expect("a running broker has state");
        let locks = state_lock_sets(&state);
        drop(state);
        // Shutdown leaves HTTP MCP sessions open, each holding the broker
        // state, until process exit ends them; end them here instead.
        if let Some(mcp) = self.mcp.take() {
            mcp.close_sessions().await;
        }
        #[cfg(test)]
        {
            self.public_app = axum::Router::new();
            self.gateway_app = None;
        }
        wait_for_release(locks, self.shutdown_timeout + LOCK_RELEASE_GRACE).await?;
        Ok(ShutdownReport::from(drained))
    }

    /// The active generation's audit store, or `None` when audit is
    /// disabled. The view stays usable after shutdown.
    pub fn audit(&self) -> Option<AuditStoreView> {
        let snapshot = self.state().current();
        snapshot
            .runtime
            .config()
            .audit
            .as_ref()
            .map(|audit| AuditStoreView {
                kind: audit.kind,
                path: PathBuf::from(&audit.path),
            })
    }

    /// The active generation's managed store, read-only, or `None` without
    /// one.
    pub fn managed_store(&self) -> Option<ManagedStoreView> {
        self.state()
            .current()
            .runtime
            .managed_store()
            .cloned()
            .map(|store| ManagedStoreView { store })
    }

    fn state(&self) -> &Arc<ReloadableState> {
        self.state.as_ref().expect("a running broker has state")
    }

    /// The running state, for host tests.
    #[cfg(test)]
    pub(crate) fn reloadable_state(&self) -> Arc<ReloadableState> {
        Arc::clone(self.state())
    }

    /// The router the public listener serves, for in-process host tests.
    #[cfg(test)]
    pub(crate) fn public_app(&self) -> axum::Router {
        self.public_app.clone()
    }

    /// The router the gateway listener serves, for in-process host tests.
    #[cfg(test)]
    pub(crate) fn gateway_app(&self) -> axum::Router {
        self.gateway_app
            .clone()
            .expect("the isolated broker binds a gateway listener")
    }
}

impl Drop for RunningBroker {
    fn drop(&mut self) {
        self.shutdown();
    }
}

impl fmt::Debug for RunningBroker {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RunningBroker")
            .field("public_addr", &self.public_addr)
            .field("gateway_addr", &self.gateway_addr)
            .field("config_path", &self.config_path)
            .finish_non_exhaustive()
    }
}

/// Every state lock set the application has published, including reload
/// generations' sets still alive.
fn state_lock_sets(state: &ReloadableState) -> Vec<Weak<StateLockSet>> {
    state
        .live_state_lock_sets()
        .iter()
        .map(Arc::downgrade)
        .collect()
}

async fn wait_for_release(locks: Vec<Weak<StateLockSet>>, budget: Duration) -> anyhow::Result<()> {
    let deadline = Instant::now() + budget;
    loop {
        let held = locks
            .iter()
            .filter_map(Weak::upgrade)
            .flat_map(|set| set.infos())
            .map(|info| info.lock_file.display().to_string())
            .collect::<Vec<_>>();
        if held.is_empty() {
            return Ok(());
        }
        if Instant::now() >= deadline {
            bail!(
                "state locks are still held after shutdown: {}",
                held.join(", ")
            );
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
}

/// The outcome of [`RunningBroker::reload`], as the reload's audit and
/// `config.status` record it.
#[derive(Debug, Clone)]
pub struct ReloadOutcome {
    status: u16,
    decision: &'static str,
    reason_code: Option<String>,
    message: Option<String>,
    result: Value,
}

impl ReloadOutcome {
    /// Whether the candidate was published.
    pub fn is_success(&self) -> bool {
        self.status == 200
    }

    /// The HTTP status an administrative reload would have returned.
    pub fn status(&self) -> u16 {
        self.status
    }

    /// `allow`, `deny` or `error`.
    pub fn decision(&self) -> &str {
        self.decision
    }

    pub fn reason_code(&self) -> Option<&str> {
        self.reason_code.as_deref()
    }

    pub fn message(&self) -> Option<&str> {
        self.message.as_deref()
    }

    /// The `config.reload` result of a published reload, such as
    /// `generation` and `configHash`; `null` otherwise.
    pub fn result(&self) -> &Value {
        &self.result
    }
}

impl From<ConfigOperationResponse> for ReloadOutcome {
    fn from(response: ConfigOperationResponse) -> Self {
        Self {
            status: response.status.as_u16(),
            decision: response.decision(),
            reason_code: response.reason_code().map(str::to_owned),
            message: response.message().map(str::to_owned),
            result: response.result,
        }
    }
}

/// How [`RunningBroker::join`]'s shutdown drained.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ShutdownReport {
    unfinished_operations: usize,
    forced: bool,
    audit_error: Option<String>,
}

impl ShutdownReport {
    /// Operations still unfinalized when the operation drain ended.
    pub fn unfinished_operations(&self) -> usize {
        self.unfinished_operations
    }

    /// Whether listeners or lifecycle tasks were cut off at the shutdown
    /// deadline.
    pub fn was_forced(&self) -> bool {
        self.forced
    }

    /// Why the audit store failed to drain, if it did.
    pub fn audit_error(&self) -> Option<&str> {
        self.audit_error.as_deref()
    }

    /// Every operation finished, nothing was cut off and audit drained.
    pub fn is_clean(&self) -> bool {
        self.unfinished_operations == 0 && !self.forced && self.audit_error.is_none()
    }
}

impl From<DrainReport> for ShutdownReport {
    fn from(report: DrainReport) -> Self {
        Self {
            unfinished_operations: report.unfinished_operations,
            forced: report.forced,
            audit_error: report.audit_error,
        }
    }
}

/// Read-only access to an isolated broker's audit store.
#[derive(Debug, Clone)]
pub struct AuditStoreView {
    kind: AuditStoreType,
    path: PathBuf,
}

impl AuditStoreView {
    /// `jsonl` or `sqlite`.
    pub fn kind(&self) -> &'static str {
        self.kind.as_str()
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Every stored record in write order: the live JSONL file without
    /// rotated files, or the SQLite records. Panics if the store is
    /// unreadable.
    pub fn records(&self) -> Vec<Value> {
        agent_access_core::test_support::read_audit_records(self.kind, &self.path)
    }

    /// The stored records as JSONL text, one record per line, whichever the
    /// backend. Panics if the store is unreadable.
    pub fn text(&self) -> String {
        agent_access_core::test_support::read_audit_text(self.kind, &self.path)
    }
}

/// Read-only access to an isolated broker's managed store.
#[derive(Clone)]
pub struct ManagedStoreView {
    store: ManagedStore,
}

impl ManagedStoreView {
    /// Every managed policy grant.
    pub fn policy_grants(&self) -> Result<Vec<ManagedPolicyGrantRecord>, ManagedStoreError> {
        self.store.policy_grants()
    }

    /// The retained imported services and their accepted actions.
    pub fn imported_catalog(&self) -> Result<ImportedCatalog, ManagedStoreError> {
        self.store.imported_catalog()
    }
}

impl fmt::Debug for ManagedStoreView {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ManagedStoreView")
            .finish_non_exhaustive()
    }
}

/// The grant catalog that management reports for the configured native
/// `service` of `config`, as the portal's conformance fixture records it.
/// It parses `config` with `composition`'s selected parsers without
/// validating it or reading any file it references.
pub fn portal_service_catalog(
    composition: &BrokerComposition,
    config: &str,
    service: &str,
) -> anyhow::Result<Value> {
    let config = parse_broker_config_raw("broker configuration", config, composition.registry())?;
    let descriptor = config
        .providers
        .iter()
        .map(|provider| provider.descriptor())
        .find(|descriptor| descriptor.service == service)
        .ok_or_else(|| anyhow!("the configuration configures no native service {service}"))?;
    let catalog = crate::handlers::management::policy::service_catalog(
        &config.credentials,
        descriptor.capabilities(),
        Some(&descriptor.credentials),
    );
    Ok(serde_json::to_value(catalog)?)
}

#[cfg(test)]
mod tests;
