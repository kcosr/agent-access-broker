//! The `serve` lifecycle: logging, runtime state, listeners, reload requests,
//! and bounded shutdown with operation drain.
use crate::BrokerBuildStatus;
use crate::composition::BrokerComposition;
use crate::identity::AssemblyIdentity;
use crate::reload::{build_reloadable_state, validate_shutdown_timeout};
use crate::router::{build_gateway_router, build_public_router};
use crate::state::ReloadableState;
use anyhow::{Context, Result};
use futures_util::future::BoxFuture;
use futures_util::stream::BoxStream;
use futures_util::{FutureExt, StreamExt};
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::sync::watch;
use tokio::task::{JoinHandle, JoinSet};
use tracing_subscriber::EnvFilter;
use tracing_subscriber::prelude::*;

pub(crate) const DEFAULT_LOG_FILTER: &str = "agent_access_broker=info,agent_access_broker_host=info,agent_access_core=info,agent_access_provider=info,axum=warn,tower=warn";

/// Settings of one `serve` run.
#[derive(Debug, Clone)]
pub(crate) struct ServeOptions {
    pub(crate) config_path: PathBuf,
    pub(crate) listen: SocketAddr,
    pub(crate) gateway_listen: Option<SocketAddr>,
    pub(crate) body_hard_cap: Option<u64>,
    pub(crate) reload_timeout: Duration,
    pub(crate) shutdown_timeout: Duration,
}

/// How a `serve` run reports its events.
pub(crate) enum LoggingMode {
    /// Installs the process-global JSON subscriber on stderr, filtered by
    /// `RUST_LOG` or else [`DEFAULT_LOG_FILTER`].
    Process,
}

impl LoggingMode {
    fn install(self) -> Result<()> {
        match self {
            Self::Process => {
                if let Some(error) = init_process_tracing()? {
                    tracing::warn!(
                        event = "logging_filter_invalid",
                        envVar = "RUST_LOG",
                        error = %error,
                        fallback = DEFAULT_LOG_FILTER,
                    );
                }
                Ok(())
            }
        }
    }
}

/// Where shutdown and reload requests come from.
pub(crate) struct SignalSource {
    /// Resolves with the cause once shutdown is requested.
    shutdown: BoxFuture<'static, ShutdownCause>,
    /// Yields once per reload request and ends when no more can arrive.
    reload: BoxStream<'static, ()>,
}

impl SignalSource {
    /// The process's signals: SIGTERM or SIGINT shuts down and, on Unix,
    /// SIGUSR2 reloads. Each handler is installed when the lifecycle first
    /// waits for it; without a SIGUSR2 handler, signals never reload.
    pub(crate) fn process() -> Self {
        Self {
            shutdown: wait_for_shutdown_signal().boxed(),
            reload: process_reload_requests(),
        }
    }
}

/// Serves until a shutdown request, a listener failure, or a startup error,
/// then drains within the shutdown timeout. Runs on the caller's runtime.
pub(crate) async fn serve(
    composition: BrokerComposition,
    identity: AssemblyIdentity,
    options: ServeOptions,
    signals: SignalSource,
    logging: LoggingMode,
) -> Result<()> {
    logging.install()?;
    let result = match identity.build_status(&composition) {
        Ok(build) => {
            emit_broker_starting(&build, &options);
            run_service(&composition, build, options, signals).await
        }
        Err(error) => Err(error.into()),
    };
    if let Err(error) = &result {
        tracing::error!(event = "broker_start_failed", error = %error);
    }
    result
}

fn init_process_tracing() -> Result<Option<String>> {
    let (filter, invalid_filter) = env_filter_for_serve();
    let fmt_layer = tracing_subscriber::fmt::layer()
        .json()
        .with_writer(std::io::stderr)
        .with_ansi(false)
        .with_current_span(true)
        .with_span_list(true)
        .flatten_event(true);
    tracing_subscriber::registry()
        .with(filter)
        // The protocol SDK logs raw JSON at trace, including caller secrets.
        // A hard filter cannot be overridden by more-specific RUST_LOG rules.
        .with(tracing_subscriber::filter::filter_fn(|metadata| {
            metadata.target() != "rmcp" && !metadata.target().starts_with("rmcp::")
        }))
        .with(fmt_layer)
        .try_init()
        .map_err(|error| anyhow::anyhow!("failed to initialize tracing subscriber: {error}"))?;
    Ok(invalid_filter)
}

fn env_filter_for_serve() -> (EnvFilter, Option<String>) {
    env_filter_for_serve_value(std::env::var("RUST_LOG").ok().as_deref())
}

fn env_filter_for_serve_value(value: Option<&str>) -> (EnvFilter, Option<String>) {
    match value {
        Some(value) => match EnvFilter::try_new(value) {
            Ok(filter) => (filter, None),
            Err(error) => (EnvFilter::new(DEFAULT_LOG_FILTER), Some(error.to_string())),
        },
        None => (EnvFilter::new(DEFAULT_LOG_FILTER), None),
    }
}

/// Logs the assembly identity, its source revision and provenance when
/// available, and the inventory fingerprint, which no reload changes.
fn emit_broker_starting(build: &BrokerBuildStatus, options: &ServeOptions) {
    let assembly = &build.assembly;
    tracing::info!(
        event = "broker_starting",
        assemblyName = assembly.name,
        assemblyVersion = assembly.version,
        assemblyRevision = assembly.source.revision,
        assemblyProvenance = assembly.source.provenance.as_str(),
        qualification = assembly.qualification,
        inventoryFingerprint = build.inventory_fingerprint.as_str(),
        configPath = %options.config_path.display(),
        publicListen = %options.listen,
        gatewayListen = options
            .gateway_listen
            .map(|addr| addr.to_string())
            .unwrap_or_default(),
        reloadTimeoutMs = duration_millis(options.reload_timeout),
        shutdownTimeoutMs = duration_millis(options.shutdown_timeout),
        bodyHardCapBytes = options.body_hard_cap,
    );
}

fn duration_millis(duration: Duration) -> u64 {
    u64::try_from(duration.as_millis()).unwrap_or(u64::MAX)
}

async fn run_service(
    composition: &BrokerComposition,
    build: BrokerBuildStatus,
    options: ServeOptions,
    signals: SignalSource,
) -> Result<()> {
    let ServeOptions {
        config_path,
        listen,
        gateway_listen,
        body_hard_cap,
        reload_timeout,
        shutdown_timeout,
    } = options;
    validate_shutdown_timeout(shutdown_timeout)?;
    let state = build_reloadable_state(
        config_path,
        Arc::clone(composition.registry()),
        build,
        body_hard_cap,
        reload_timeout,
        shutdown_timeout,
    )
    .await?;
    let public_listener = tokio::net::TcpListener::bind(listen).await?;
    let gateway_listener = match gateway_listen {
        Some(gateway_listen) => Some((
            gateway_listen,
            tokio::net::TcpListener::bind(gateway_listen).await?,
        )),
        None => None,
    };

    let coordinator = ShutdownCoordinator::new();
    let SignalSource { shutdown, reload } = signals;
    let reload_tasks = Arc::new(tokio::sync::Mutex::new(Vec::new()));
    let reload_signal_task = tokio::spawn(run_reload_signal_loop(
        reload,
        state.clone(),
        coordinator.clone(),
        Arc::clone(&reload_tasks),
    ));
    let shutdown_signal_task = tokio::spawn(shutdown_signal_task(shutdown, coordinator.clone()));
    let mut servers = JoinSet::new();

    let node_id = state.node_id();
    tracing::info!(
        event = "broker_listening",
        nodeId = node_id.as_str(),
        listener = "public",
        address = %listen,
    );
    let public_app = build_public_router(state.clone());
    spawn_public_server(
        &mut servers,
        public_listener,
        public_app,
        coordinator.clone(),
    );
    if let Some((gateway_listen, gateway_listener)) = gateway_listener {
        tracing::info!(
            event = "broker_listening",
            nodeId = node_id.as_str(),
            listener = "gateway",
            address = %gateway_listen,
        );
        let gateway_app = build_gateway_router(state.clone());
        spawn_gateway_server(
            &mut servers,
            gateway_listener,
            gateway_app,
            coordinator.clone(),
        );
    }

    drain_lifecycle(
        state,
        coordinator,
        servers,
        reload_signal_task,
        shutdown_signal_task,
        reload_tasks,
        shutdown_timeout,
    )
    .await
}

fn spawn_public_server(
    servers: &mut JoinSet<Result<()>>,
    listener: tokio::net::TcpListener,
    app: axum::Router,
    coordinator: ShutdownCoordinator,
) {
    servers.spawn(async move {
        axum::serve(
            listener,
            app.into_make_service_with_connect_info::<SocketAddr>(),
        )
        .with_graceful_shutdown(async move {
            let _ = coordinator.wait().await;
        })
        .await
        .context("public listener failed")
    });
}

fn spawn_gateway_server(
    servers: &mut JoinSet<Result<()>>,
    listener: tokio::net::TcpListener,
    app: axum::Router,
    coordinator: ShutdownCoordinator,
) {
    servers.spawn(async move {
        axum::serve(
            listener,
            app.into_make_service_with_connect_info::<SocketAddr>(),
        )
        .with_graceful_shutdown(async move {
            let _ = coordinator.wait().await;
        })
        .await
        .context("gateway listener failed")
    });
}

async fn drain_lifecycle(
    state: Arc<ReloadableState>,
    coordinator: ShutdownCoordinator,
    mut servers: JoinSet<Result<()>>,
    reload_signal_task: JoinHandle<()>,
    shutdown_signal_task: JoinHandle<()>,
    reload_tasks: Arc<tokio::sync::Mutex<Vec<JoinHandle<()>>>>,
    shutdown_timeout: Duration,
) -> Result<()> {
    let mut listener_error = None;
    loop {
        tokio::select! {
            result = servers.join_next(), if !servers.is_empty() => {
                match result {
                    Some(Ok(Ok(()))) => {
                        if servers.is_empty() && !coordinator.is_shutdown() {
                            coordinator.trigger(ShutdownCause::ListenerFinished);
                        }
                        if servers.is_empty() {
                            break;
                        }
                    }
                    Some(Ok(Err(error))) => {
                        let message = error.to_string();
                        coordinator.trigger(ShutdownCause::ListenerError(message));
                        listener_error = Some(error);
                        break;
                    }
                    Some(Err(error)) => {
                        let error = anyhow::anyhow!("server task failed: {error}");
                        coordinator.trigger(ShutdownCause::ListenerError(error.to_string()));
                        listener_error = Some(error);
                        break;
                    }
                    None => break,
                }
            }
            cause = coordinator.wait(), if !coordinator.is_shutdown() => {
                let _ = cause;
                break;
            }
            cause = coordinator.wait(), if coordinator.is_shutdown() => {
                let _ = cause;
                break;
            }
        }
    }

    let operation_state = state.clone();
    let operation_budget =
        remaining_shutdown_time(&coordinator, shutdown_timeout).unwrap_or_default();
    let operation_deadline = tokio::time::Instant::now() + operation_budget;
    let (listeners_drained, listener_drain) = tokio::sync::oneshot::channel();
    let operation_drain = tokio::spawn(async move {
        // Accepted requests may still be reading their bodies. Keep the owner
        // registry open while those listeners drain, then close admission and
        // drain detached owners. The hard deadline reserves a bounded final phase
        // even when a slow request never finishes intake.
        let reserve = (operation_budget / 4).min(Duration::from_secs(1));
        tokio::select! {
            _ = listener_drain => {}
            _ = tokio::time::sleep_until(operation_deadline - reserve) => {}
        }
        operation_state
            .shutdown_operations(
                operation_deadline.saturating_duration_since(tokio::time::Instant::now()),
            )
            .await
    });
    let timed_out =
        drain_servers_until_deadline(&mut servers, &coordinator, shutdown_timeout).await;
    let _ = listeners_drained.send(());
    if timed_out {
        let canceled = state.cancel_terminal_audits();
        tracing::warn!(
            event = "broker_shutdown_forced",
            terminalStreamsCanceled = canceled,
        );
        servers.abort_all();
        while servers.join_next().await.is_some() {}
    }

    let lifecycle_timed_out = drain_reload_tasks_until_deadline(
        reload_signal_task,
        shutdown_signal_task,
        reload_tasks,
        &coordinator,
        shutdown_timeout,
    )
    .await;
    if lifecycle_timed_out {
        let canceled = state.cancel_terminal_audits();
        tracing::warn!(
            event = "broker_shutdown_lifecycle_forced",
            terminalStreamsCanceled = canceled,
        );
    }

    if let Err(error) = operation_drain.await {
        tracing::error!(event = "operation_shutdown_failed", error = %error);
    }
    let remaining = remaining_shutdown_time(&coordinator, shutdown_timeout)
        .unwrap_or_else(|| Duration::from_millis(100));
    if let Err(error) = state.shutdown_audit(remaining).await {
        tracing::error!(event = "audit_shutdown_failed", error = %error);
    }

    if let Some(error) = listener_error {
        return Err(error);
    }
    Ok(())
}

async fn drain_servers_until_deadline(
    servers: &mut JoinSet<Result<()>>,
    coordinator: &ShutdownCoordinator,
    shutdown_timeout: Duration,
) -> bool {
    while !servers.is_empty() {
        let Some(remaining) = remaining_shutdown_time(coordinator, shutdown_timeout) else {
            return true;
        };
        match tokio::time::timeout(remaining, servers.join_next()).await {
            Ok(Some(Ok(Ok(())))) => {}
            Ok(Some(Ok(Err(error)))) => {
                tracing::error!(event = "listener_drain_failed", error = %error);
            }
            Ok(Some(Err(error))) => {
                tracing::error!(event = "listener_task_failed", error = %error);
            }
            Ok(None) => break,
            Err(_) => return true,
        }
    }
    false
}

async fn drain_reload_tasks_until_deadline(
    reload_signal_task: JoinHandle<()>,
    shutdown_signal_task: JoinHandle<()>,
    reload_tasks: Arc<tokio::sync::Mutex<Vec<JoinHandle<()>>>>,
    coordinator: &ShutdownCoordinator,
    shutdown_timeout: Duration,
) -> bool {
    let mut timed_out = false;
    timed_out |= drain_lifecycle_handle(reload_signal_task, coordinator, shutdown_timeout).await;

    let handles = reload_tasks.lock().await.drain(..).collect::<Vec<_>>();
    for handle in handles {
        timed_out |= drain_lifecycle_handle(handle, coordinator, shutdown_timeout).await;
    }

    timed_out |= drain_lifecycle_handle(shutdown_signal_task, coordinator, shutdown_timeout).await;
    timed_out
}

async fn drain_lifecycle_handle(
    mut handle: JoinHandle<()>,
    coordinator: &ShutdownCoordinator,
    shutdown_timeout: Duration,
) -> bool {
    let Some(remaining) = remaining_shutdown_time(coordinator, shutdown_timeout) else {
        handle.abort();
        return true;
    };
    match tokio::time::timeout(remaining, &mut handle).await {
        Ok(Ok(())) => false,
        Ok(Err(error)) => {
            tracing::error!(event = "lifecycle_task_failed", error = %error);
            false
        }
        Err(_) => {
            handle.abort();
            true
        }
    }
}

fn remaining_shutdown_time(
    coordinator: &ShutdownCoordinator,
    shutdown_timeout: Duration,
) -> Option<Duration> {
    shutdown_timeout.checked_sub(coordinator.elapsed_since_shutdown()?)
}

#[derive(Debug, Clone)]
enum ShutdownCause {
    Signal(&'static str),
    ListenerError(String),
    ListenerFinished,
}

#[derive(Clone)]
struct ShutdownCoordinator {
    inner: Arc<ShutdownCoordinatorInner>,
}

struct ShutdownCoordinatorInner {
    cause: Mutex<Option<ShutdownCause>>,
    started: Mutex<Option<Instant>>,
    admission: Mutex<()>,
    signal: watch::Sender<Option<ShutdownCause>>,
}

impl ShutdownCoordinator {
    fn new() -> Self {
        let (signal, _) = watch::channel(None);
        Self {
            inner: Arc::new(ShutdownCoordinatorInner {
                cause: Mutex::new(None),
                started: Mutex::new(None),
                admission: Mutex::new(()),
                signal,
            }),
        }
    }

    fn trigger(&self, cause: ShutdownCause) -> bool {
        let _admission = self.inner.admission.lock().unwrap();
        let mut current = self.inner.cause.lock().unwrap();
        if current.is_some() {
            return false;
        }
        log_shutdown_started(&cause);
        *current = Some(cause.clone());
        *self.inner.started.lock().unwrap() = Some(Instant::now());
        self.inner.signal.send_replace(Some(cause));
        true
    }

    fn is_shutdown(&self) -> bool {
        self.inner.cause.lock().unwrap().is_some()
    }

    async fn wait(&self) -> ShutdownCause {
        let mut receiver = self.inner.signal.subscribe();
        loop {
            if let Some(cause) = receiver.borrow().clone() {
                return cause;
            }
            if receiver.changed().await.is_err()
                && let Some(cause) = self.inner.cause.lock().unwrap().clone()
            {
                return cause;
            }
        }
    }

    fn elapsed_since_shutdown(&self) -> Option<Duration> {
        self.inner
            .started
            .lock()
            .unwrap()
            .map(|started| started.elapsed())
    }

    fn before_shutdown<T>(&self, action: impl FnOnce() -> T) -> Option<T> {
        let _admission = self.inner.admission.lock().unwrap();
        if self.inner.cause.lock().unwrap().is_some() {
            return None;
        }
        Some(action())
    }
}

fn log_shutdown_started(cause: &ShutdownCause) {
    let (kind, detail) = match cause {
        ShutdownCause::Signal(signal) => ("signal", Some(*signal)),
        ShutdownCause::ListenerError(error) => ("listener_error", Some(error.as_str())),
        ShutdownCause::ListenerFinished => ("listener_finished", None),
    };
    tracing::info!(
        event = "broker_shutdown",
        reason = kind,
        detail = detail.unwrap_or(""),
    );
}

async fn shutdown_signal_task(
    shutdown: BoxFuture<'static, ShutdownCause>,
    coordinator: ShutdownCoordinator,
) {
    tokio::select! {
        cause = shutdown => {
            coordinator.trigger(cause);
        }
        _ = coordinator.wait() => {}
    }
}

#[cfg(unix)]
async fn wait_for_shutdown_signal() -> ShutdownCause {
    let (sigterm, sigint) = shutdown_signal_receivers();
    wait_for_shutdown_signal_from(sigterm, sigint).await
}

#[cfg(unix)]
fn shutdown_signal_receivers() -> (tokio::signal::unix::Signal, tokio::signal::unix::Signal) {
    let sigterm = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
        .expect("SIGTERM handler installs");
    let sigint = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::interrupt())
        .expect("SIGINT handler installs");
    (sigterm, sigint)
}

#[cfg(unix)]
async fn wait_for_shutdown_signal_from(
    mut sigterm: tokio::signal::unix::Signal,
    mut sigint: tokio::signal::unix::Signal,
) -> ShutdownCause {
    tokio::select! {
        _ = sigterm.recv() => ShutdownCause::Signal("SIGTERM"),
        _ = sigint.recv() => ShutdownCause::Signal("SIGINT"),
    }
}

#[cfg(not(unix))]
async fn wait_for_shutdown_signal() -> ShutdownCause {
    let _ = tokio::signal::ctrl_c().await;
    ShutdownCause::Signal("SIGINT")
}

#[cfg(unix)]
fn process_reload_requests() -> BoxStream<'static, ()> {
    futures_util::stream::once(async { reload_signal_receiver().ok() })
        .filter_map(futures_util::future::ready)
        .flat_map(unix_reload_requests)
        .boxed()
}

#[cfg(unix)]
fn reload_signal_receiver() -> std::io::Result<tokio::signal::unix::Signal> {
    tokio::signal::unix::signal(tokio::signal::unix::SignalKind::user_defined2())
}

/// One item per signal delivered to an installed handler.
#[cfg(unix)]
fn unix_reload_requests(signal: tokio::signal::unix::Signal) -> BoxStream<'static, ()> {
    futures_util::stream::unfold(signal, |mut signal| async move {
        signal.recv().await.map(|()| ((), signal))
    })
    .boxed()
}

#[cfg(not(unix))]
fn process_reload_requests() -> BoxStream<'static, ()> {
    futures_util::stream::pending().boxed()
}

async fn run_reload_signal_loop(
    mut requests: BoxStream<'static, ()>,
    state: Arc<ReloadableState>,
    coordinator: ShutdownCoordinator,
    reload_tasks: Arc<tokio::sync::Mutex<Vec<JoinHandle<()>>>>,
) {
    loop {
        tokio::select! {
            _ = coordinator.wait() => break,
            received = requests.next() => {
                if received.is_none() || coordinator.is_shutdown() {
                    break;
                }
                let mut reload_tasks = reload_tasks.lock().await;
                let state = state.clone();
                if coordinator.before_shutdown(|| {
                    let handle = tokio::spawn(async move {
                        state.reload_from_signal().await;
                    });
                    track_reload_task(&mut reload_tasks, handle);
                }).is_none() {
                    break;
                }
            }
        }
    }
}

fn track_reload_task(reload_tasks: &mut Vec<JoinHandle<()>>, handle: JoinHandle<()>) {
    reload_tasks.retain(|handle| !handle.is_finished());
    reload_tasks.push(handle);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{backend_registry, broker_build_status};
    use axum::Router;
    use axum::routing::get;
    use std::future;
    use tokio::sync::Notify;

    // Default tests do not send SIGTERM/SIGINT/SIGUSR2 to this in-process test
    // binary: Tokio's signal handlers are process-global and cargo runs tests
    // concurrently. The ignored smoke harness below sends real signals only in
    // isolated child test processes; default deterministic tests cover the
    // coordinator, listener drain, and reload-task tracking without signaling
    // unrelated tests in the same process.

    #[cfg(unix)]
    const SIGNAL_SMOKE_CHILD_ENV: &str = "AGENT_ACCESS_BROKER_SIGNAL_SMOKE_CHILD";
    #[cfg(unix)]
    const SIGNAL_SMOKE_CHILD_TEST: &str = "lifecycle::tests::unix_signal_smoke_child_harness";

    #[test]
    fn serve_tracing_filter_uses_default_valid_override_and_invalid_fallback() {
        let default_directives = [
            "agent_access_broker=info",
            "agent_access_broker_host=info",
            "agent_access_core=info",
            "agent_access_provider=info",
            "axum=warn",
            "tower=warn",
        ];
        let (default_filter, default_error) = env_filter_for_serve_value(None);
        assert_filter_contains(&default_filter, &default_directives);
        assert!(default_error.is_none());

        let (override_filter, override_error) = env_filter_for_serve_value(Some(
            "agent_access_broker_host=debug,agent_access_core=warn",
        ));
        assert_filter_contains(
            &override_filter,
            &["agent_access_broker_host=debug", "agent_access_core=warn"],
        );
        assert!(override_error.is_none());

        let (fallback_filter, fallback_error) =
            env_filter_for_serve_value(Some("agent_access_broker_host=notalevel"));
        assert_filter_contains(&fallback_filter, &default_directives);
        assert!(fallback_error.is_some());
    }

    fn assert_filter_contains(filter: &EnvFilter, directives: &[&str]) {
        let rendered = filter.to_string();
        for directive in directives {
            assert!(
                rendered.contains(directive),
                "filter {rendered:?} missing directive {directive:?}"
            );
        }
    }

    #[cfg(unix)]
    #[test]
    #[ignore = "sends real Unix signals in isolated child test processes"]
    fn unix_signal_smoke_in_isolated_child_processes() {
        for case in ["shutdown-sigterm", "shutdown-sigint", "sigusr2-reload"] {
            let output = std::process::Command::new(std::env::current_exe().unwrap())
                .arg("--exact")
                .arg(SIGNAL_SMOKE_CHILD_TEST)
                .arg("--ignored")
                .arg("--nocapture")
                .arg("--color=never")
                .env(SIGNAL_SMOKE_CHILD_ENV, case)
                .output()
                .unwrap();
            assert!(
                signal_smoke_child_passed(&output, case),
                "signal smoke child case {case} did not prove one passing executed case; status {:?}\nstdout:\n{}\nstderr:\n{}",
                output.status.code(),
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            );
        }
    }

    #[cfg(unix)]
    fn signal_smoke_child_passed(output: &std::process::Output, case: &str) -> bool {
        let stdout = String::from_utf8_lossy(&output.stdout);
        let marker = format!("signal smoke case passed: {case}");
        let mut summaries = stdout
            .lines()
            .filter(|line| line.starts_with("test result: "));
        output.status.success()
            && stdout
                .lines()
                .filter(|line| *line == marker.as_str())
                .count()
                == 1
            && summaries.next().is_some_and(|summary| {
                summary.starts_with("test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; ")
            })
            && summaries.next().is_none()
    }

    #[cfg(unix)]
    #[test]
    fn signal_smoke_child_rejects_zero_matches_and_unexecuted_cases() {
        for test_name in [
            "lifecycle::tests::__nonexistent_unix_signal_smoke_child_harness__",
            SIGNAL_SMOKE_CHILD_TEST,
        ] {
            let output = std::process::Command::new(std::env::current_exe().unwrap())
                .arg("--exact")
                .arg(test_name)
                .arg("--ignored")
                .arg("--nocapture")
                .arg("--color=never")
                .env_remove(SIGNAL_SMOKE_CHILD_ENV)
                .output()
                .unwrap();
            assert!(output.status.success(), "fixture must exit successfully");
            assert!(
                !signal_smoke_child_passed(&output, "shutdown-sigterm"),
                "successful exit without an executed signal case must be rejected: {test_name}"
            );
        }
    }

    #[cfg(unix)]
    #[test]
    #[ignore = "child process entrypoint for unix_signal_smoke_in_isolated_child_processes"]
    fn unix_signal_smoke_child_harness() {
        let Ok(case) = std::env::var(SIGNAL_SMOKE_CHILD_ENV) else {
            return;
        };
        match case.as_str() {
            "shutdown-sigterm" => run_shutdown_signal_smoke_child(libc::SIGTERM, "SIGTERM"),
            "shutdown-sigint" => run_shutdown_signal_smoke_child(libc::SIGINT, "SIGINT"),
            "sigusr2-reload" => run_sigusr2_reload_smoke_child(),
            other => panic!("unknown signal smoke child case: {other}"),
        }
        println!("\nsignal smoke case passed: {case}");
    }

    #[cfg(unix)]
    fn run_shutdown_signal_smoke_child(signal: libc::c_int, expected: &'static str) {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        runtime.block_on(async move {
            let (sigterm, sigint) = shutdown_signal_receivers();
            send_unix_signal_to_self(signal);
            let cause = tokio::time::timeout(
                Duration::from_secs(2),
                wait_for_shutdown_signal_from(sigterm, sigint),
            )
            .await
            .expect("shutdown signal smoke child must observe signal");
            assert!(matches!(cause, ShutdownCause::Signal(signal) if signal == expected));
        });
    }

    #[cfg(unix)]
    fn run_sigusr2_reload_smoke_child() {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        runtime.block_on(async {
            let signal = reload_signal_receiver().expect("SIGUSR2 handler installs");
            let state = test_reloadable_state().await;
            let coordinator = ShutdownCoordinator::new();
            let reload_tasks = Arc::new(tokio::sync::Mutex::new(Vec::new()));
            let reload_signal_task = tokio::spawn(run_reload_signal_loop(
                unix_reload_requests(signal),
                state,
                coordinator.clone(),
                Arc::clone(&reload_tasks),
            ));

            send_unix_signal_to_self(libc::SIGUSR2);
            tokio::time::timeout(Duration::from_secs(2), async {
                loop {
                    if !reload_tasks.lock().await.is_empty() {
                        break;
                    }
                    tokio::time::sleep(Duration::from_millis(10)).await;
                }
            })
            .await
            .expect("SIGUSR2 before shutdown must start a reload task");
            let reload_count_before_shutdown = reload_tasks.lock().await.len();
            assert!(reload_count_before_shutdown >= 1);

            coordinator.trigger(ShutdownCause::Signal("SIGTERM"));
            tokio::time::timeout(Duration::from_secs(2), reload_signal_task)
                .await
                .expect("reload signal task must exit after shutdown")
                .expect("reload signal task must not panic");

            send_unix_signal_to_self(libc::SIGUSR2);
            tokio::time::sleep(Duration::from_millis(50)).await;
            assert_eq!(
                reload_tasks.lock().await.len(),
                reload_count_before_shutdown
            );

            let reload_handles = reload_tasks.lock().await.drain(..).collect::<Vec<_>>();
            for handle in reload_handles {
                tokio::time::timeout(Duration::from_secs(2), handle)
                    .await
                    .expect("signal-triggered reload task must finish")
                    .expect("signal-triggered reload task must not panic");
            }
        });
    }

    #[cfg(unix)]
    fn send_unix_signal_to_self(signal: libc::c_int) {
        let result = unsafe { libc::kill(libc::getpid(), signal) };
        assert_eq!(
            result,
            0,
            "failed to send Unix signal {signal}: {}",
            std::io::Error::last_os_error()
        );
    }

    #[tokio::test]
    async fn shutdown_wait_observes_signal_triggered_before_subscription() {
        let coordinator = ShutdownCoordinator::new();
        assert!(coordinator.trigger(ShutdownCause::Signal("SIGTERM")));

        let cause = tokio::time::timeout(Duration::from_millis(25), coordinator.wait())
            .await
            .expect("late shutdown waiter must observe retained cause");
        assert!(matches!(cause, ShutdownCause::Signal("SIGTERM")));
    }

    #[tokio::test]
    async fn a_shutdown_request_from_the_signal_source_triggers_shutdown() {
        let coordinator = ShutdownCoordinator::new();
        let (request, requested) = tokio::sync::oneshot::channel();
        let task = tokio::spawn(shutdown_signal_task(
            async move {
                requested.await.unwrap();
                ShutdownCause::Signal("SIGINT")
            }
            .boxed(),
            coordinator.clone(),
        ));
        request.send(()).unwrap();
        let cause = tokio::time::timeout(Duration::from_secs(1), coordinator.wait())
            .await
            .unwrap();
        assert!(matches!(cause, ShutdownCause::Signal("SIGINT")));
        task.await.unwrap();
    }

    #[tokio::test]
    async fn public_server_stops_on_shutdown_trigger() {
        let coordinator = ShutdownCoordinator::new();
        let mut servers = JoinSet::new();
        let public_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let public_addr = public_listener.local_addr().unwrap();
        let app = Router::new().route("/", get(|| async { "ok" }));

        spawn_public_server(&mut servers, public_listener, app, coordinator.clone());

        coordinator.trigger(ShutdownCause::Signal("SIGTERM"));
        assert!(
            !drain_servers_until_deadline(&mut servers, &coordinator, Duration::from_secs(1)).await
        );
        assert!(servers.is_empty());
        assert!(tokio::net::TcpStream::connect(public_addr).await.is_err());
    }

    #[tokio::test]
    async fn admitted_request_delays_shutdown_until_it_finishes() {
        let coordinator = ShutdownCoordinator::new();
        let mut servers = JoinSet::new();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let release = Arc::new(Notify::new());
        let (entered_tx, entered_rx) = tokio::sync::oneshot::channel();
        let entered_tx = Arc::new(Mutex::new(Some(entered_tx)));
        let app = Router::new().route(
            "/",
            get({
                let release = Arc::clone(&release);
                let entered_tx = Arc::clone(&entered_tx);
                move || {
                    let release = Arc::clone(&release);
                    let entered_tx = Arc::clone(&entered_tx);
                    async move {
                        if let Some(tx) = entered_tx.lock().unwrap().take() {
                            let _ = tx.send(());
                        }
                        release.notified().await;
                        "done"
                    }
                }
            }),
        );
        spawn_public_server(&mut servers, listener, app, coordinator.clone());
        let client = tokio::spawn(raw_http_get(addr));
        entered_rx.await.unwrap();

        coordinator.trigger(ShutdownCause::Signal("SIGTERM"));
        let mut drain = Box::pin(drain_servers_until_deadline(
            &mut servers,
            &coordinator,
            Duration::from_secs(1),
        ));
        assert!(
            tokio::time::timeout(Duration::from_millis(25), &mut drain)
                .await
                .is_err()
        );
        release.notify_waiters();
        assert!(!drain.await);
        client.await.unwrap();
    }

    #[tokio::test]
    async fn graceful_shutdown_allows_an_accepted_json_body_to_finish_before_dispatch() {
        use axum::body::Body;
        use axum::http::{Request, StatusCode};
        use tower::ServiceExt;
        let directory = tempfile::tempdir().unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700))
                .unwrap();
        }
        let config_path = directory.path().join("broker.toml");
        let token_path = directory.path().join("token");
        std::fs::write(&token_path, "synthetic-shutdown-provider-token").unwrap();
        std::fs::write(
            &config_path,
            format!(
                r#"
[deployment]
environment="development"
enable_fake_service=true

[providers.fake]
[identity]
mode="anonymous"
authority="toml"
[credentials.service.fake]
type="bearer_token"
token_ref="file:{}"
[policy]
authority="toml"
default_decision="deny"
[[policy.resources]]
id="test"
resource_type="fake_project"
selector={{kind="exact",value="TEST"}}
allowed_execution_contexts=["default"]
[[policy.grants]]
subjects=["group:anonymous"]
service="fake"
actions=["echo"]
resources={{resource_ids=["test"]}}
credential_mode="service"
[limits]
upload_spool_dir="{}"
[audit]
type="jsonl"
path="{}"
"#,
                token_path.display(),
                directory.path().join("spool").display(),
                directory.path().join("audit.jsonl").display()
            ),
        )
        .unwrap();
        let state = build_reloadable_state(
            config_path,
            Arc::new(backend_registry()),
            broker_build_status(),
            None,
            Duration::from_secs(1),
            Duration::from_secs(2),
        )
        .await
        .unwrap();
        let app = build_public_router(state.clone());
        let (reading_body, body_started) = tokio::sync::oneshot::channel();
        let (release_body, resume_body) = tokio::sync::oneshot::channel();
        let body = Body::from_stream(futures_util::stream::once(async move {
            reading_body.send(()).unwrap();
            resume_body.await.unwrap();
            Ok::<_, std::io::Error>(bytes::Bytes::from_static(
                br#"{"inputs":{"project":"TEST","message":"drain"}}"#,
            ))
        }));
        let (completed, response) = tokio::sync::oneshot::channel();
        let mut servers = JoinSet::new();
        servers.spawn(async move {
            let result = app
                .oneshot(
                    Request::builder()
                        .method("POST")
                        .uri("/v1/invoke/fake/echo")
                        .extension(axum::extract::ConnectInfo(
                            "127.0.0.1:45000".parse::<SocketAddr>().unwrap(),
                        ))
                        .header("content-type", "application/json")
                        .header("x-agent-access-request-id", "shutdown-body-drain")
                        .body(body)
                        .unwrap(),
                )
                .await
                .unwrap();
            let status = result.status();
            let bytes = axum::body::to_bytes(result.into_body(), 64 * 1024)
                .await
                .unwrap();
            completed
                .send((
                    status,
                    serde_json::from_slice::<serde_json::Value>(&bytes).unwrap(),
                ))
                .unwrap();
            Ok(())
        });
        body_started.await.unwrap();
        let coordinator = ShutdownCoordinator::new();
        coordinator.trigger(ShutdownCause::Signal("SIGTERM"));
        let mut drain = Box::pin(drain_lifecycle(
            state,
            coordinator,
            servers,
            tokio::spawn(async {}),
            tokio::spawn(async {}),
            Arc::new(tokio::sync::Mutex::new(Vec::new())),
            Duration::from_secs(2),
        ));
        assert!(
            tokio::time::timeout(Duration::from_millis(25), &mut drain)
                .await
                .is_err()
        );
        release_body.send(()).unwrap();
        drain.await.unwrap();
        let (status, envelope) = response.await.unwrap();
        assert_eq!(status, StatusCode::OK, "{envelope}");
        assert_eq!(envelope["decision"], "allow");
        let audit = std::fs::read_to_string(directory.path().join("audit.jsonl")).unwrap();
        assert_eq!(audit.lines().count(), 1);
    }

    #[tokio::test]
    async fn admitted_request_is_cut_off_when_shutdown_timeout_expires() {
        let coordinator = ShutdownCoordinator::new();
        let mut servers = JoinSet::new();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let (entered_tx, entered_rx) = tokio::sync::oneshot::channel();
        let entered_tx = Arc::new(Mutex::new(Some(entered_tx)));
        let app = Router::new().route(
            "/",
            get({
                let entered_tx = Arc::clone(&entered_tx);
                move || {
                    let entered_tx = Arc::clone(&entered_tx);
                    async move {
                        if let Some(tx) = entered_tx.lock().unwrap().take() {
                            let _ = tx.send(());
                        }
                        future::pending::<()>().await;
                        "unreachable"
                    }
                }
            }),
        );
        spawn_public_server(&mut servers, listener, app, coordinator.clone());
        let client = tokio::spawn(raw_http_get(addr));
        entered_rx.await.unwrap();

        coordinator.trigger(ShutdownCause::Signal("SIGTERM"));
        assert!(
            drain_servers_until_deadline(&mut servers, &coordinator, Duration::from_millis(25))
                .await
        );
        servers.abort_all();
        while servers.join_next().await.is_some() {}
        client.abort();
    }

    #[tokio::test]
    async fn reload_task_drain_waits_for_signal_task_before_snapshotting_children() {
        let coordinator = ShutdownCoordinator::new();
        let reload_tasks = Arc::new(tokio::sync::Mutex::new(Vec::new()));
        coordinator.trigger(ShutdownCause::Signal("SIGTERM"));
        let reload_signal_task = tokio::spawn({
            let reload_tasks = Arc::clone(&reload_tasks);
            async move {
                tokio::time::sleep(Duration::from_millis(20)).await;
                reload_tasks.lock().await.push(tokio::spawn(async {
                    future::pending::<()>().await;
                }));
            }
        });
        let shutdown_signal_task = tokio::spawn(async {});

        assert!(
            drain_reload_tasks_until_deadline(
                reload_signal_task,
                shutdown_signal_task,
                reload_tasks,
                &coordinator,
                Duration::from_millis(75),
            )
            .await
        );
    }

    #[tokio::test]
    async fn listener_error_triggers_drain_and_returns_original_error() {
        let coordinator = ShutdownCoordinator::new();
        let mut servers = JoinSet::new();
        servers.spawn(async { Err(anyhow::anyhow!("injected listener failure")) });
        let observed_shutdown = Arc::new(Notify::new());
        servers.spawn({
            let coordinator = coordinator.clone();
            let observed_shutdown = Arc::clone(&observed_shutdown);
            async move {
                let _ = coordinator.wait().await;
                observed_shutdown.notify_one();
                Ok(())
            }
        });
        let state = test_reloadable_state().await;
        let reload_tasks = Arc::new(tokio::sync::Mutex::new(Vec::new()));
        let reload_signal_task = tokio::spawn(async {});
        let shutdown_signal_task = tokio::spawn(async {});

        let error = drain_lifecycle(
            state,
            coordinator,
            servers,
            reload_signal_task,
            shutdown_signal_task,
            reload_tasks,
            Duration::from_secs(1),
        )
        .await
        .unwrap_err();

        assert!(error.to_string().contains("injected listener failure"));
        tokio::time::timeout(Duration::from_millis(25), observed_shutdown.notified())
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn reload_requests_start_tracked_reloads_until_the_source_ends() {
        let state = test_reloadable_state().await;
        let coordinator = ShutdownCoordinator::new();
        let reload_tasks = Arc::new(tokio::sync::Mutex::new(Vec::new()));
        let (request, requests) = tokio::sync::mpsc::unbounded_channel();
        let requests = futures_util::stream::unfold(requests, |mut requests| async move {
            requests.recv().await.map(|()| ((), requests))
        })
        .boxed();
        let loop_task = tokio::spawn(run_reload_signal_loop(
            requests,
            state,
            coordinator,
            Arc::clone(&reload_tasks),
        ));
        request.send(()).unwrap();
        drop(request);
        tokio::time::timeout(Duration::from_secs(2), loop_task)
            .await
            .expect("an ended request source stops the reload loop")
            .unwrap();
        let handles = reload_tasks.lock().await.drain(..).collect::<Vec<_>>();
        assert_eq!(handles.len(), 1);
        for handle in handles {
            tokio::time::timeout(Duration::from_secs(2), handle)
                .await
                .unwrap()
                .unwrap();
        }
    }

    #[tokio::test]
    async fn reload_task_tracking_reaps_finished_handles_before_push() {
        let completed = tokio::spawn(async {});
        while !completed.is_finished() {
            tokio::task::yield_now().await;
        }
        let pending = tokio::spawn(future::pending::<()>());
        let replacement = tokio::spawn(future::pending::<()>());
        let mut handles = vec![completed, pending];

        track_reload_task(&mut handles, replacement);

        assert_eq!(handles.len(), 2);
        assert!(handles.iter().all(|handle| !handle.is_finished()));
        for handle in handles {
            handle.abort();
        }
    }

    async fn raw_http_get(addr: SocketAddr) {
        let stream = tokio::net::TcpStream::connect(addr).await.unwrap();
        stream.writable().await.unwrap();
        let _ = stream.try_write(b"GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n");
        let mut buf = [0_u8; 128];
        loop {
            stream.readable().await.unwrap();
            match stream.try_read(&mut buf) {
                Ok(_) => break,
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => continue,
                Err(_) => break,
            }
        }
    }

    async fn test_reloadable_state() -> Arc<ReloadableState> {
        let config = temp_path("minimal-broker.toml");
        let spool = temp_path("minimal-spool");
        std::fs::write(
            &config,
            format!(
                r#"
[deployment]
environment = "development"

[identity]
mode = "anonymous"
authority = "toml"

[policy]
authority = "toml"
default_decision = "deny"

[limits]
upload_spool_dir = "{}"
"#,
                spool.display()
            ),
        )
        .unwrap();
        build_reloadable_state(
            config,
            Arc::new(backend_registry()),
            broker_build_status(),
            None,
            Duration::from_secs(1),
            Duration::from_secs(1),
        )
        .await
        .unwrap()
    }

    fn temp_path(name: &str) -> PathBuf {
        let mut path = std::env::temp_dir();
        path.push(format!(
            "agent-access-broker-lifecycle-test-{}-{}-{name}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        path
    }
}
