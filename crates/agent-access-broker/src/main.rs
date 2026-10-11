use agent_access_broker::{
    BuildProvenance, backend_registry, broker_build_status, build_gateway_router,
    build_public_router, build_reloadable_state, validate_shutdown_timeout,
};
use agent_access_core::{
    AuditStoreType, AuditVerifyReport, ConfigError, StateLockSet, load_broker_config,
    resolve_node_id, validate_broker_config, validate_broker_config_file,
    verify_sqlite_audit_database,
};
use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use std::env;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::sync::watch;
use tokio::task::{JoinHandle, JoinSet};
use tracing_subscriber::EnvFilter;
use tracing_subscriber::prelude::*;

const DEFAULT_LOG_FILTER: &str = "agent_access_broker=info,agent_access_core=info,agent_access_provider=info,axum=warn,tower=warn";

#[derive(Debug, Parser)]
#[command(name = "agent-access-broker")]
#[command(about = "Agent Access Broker service")]
struct Cli {
    #[arg(long, global = true)]
    config: Option<PathBuf>,
    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Debug, Subcommand)]
enum Command {
    Config {
        #[command(subcommand)]
        command: ConfigCommand,
    },
    /// Offline audit store commands; the broker must be stopped.
    Audit {
        #[command(subcommand)]
        command: AuditCommand,
    },
    Serve {
        #[arg(long, default_value = "127.0.0.1:8787")]
        listen: SocketAddr,
        #[arg(long)]
        gateway_listen: Option<SocketAddr>,
        #[arg(long)]
        max_http_body_hard_cap_bytes: Option<u64>,
        #[arg(long, default_value_t = 30_000)]
        reload_timeout_ms: u64,
        #[arg(long, default_value_t = 30_000)]
        shutdown_timeout_ms: u64,
    },
}

#[derive(Debug, Subcommand)]
enum ConfigCommand {
    Validate,
}

#[derive(Debug, Subcommand)]
enum AuditCommand {
    /// Checks the SQLite audit database: schema, `PRAGMA integrity_check`,
    /// and the full-text index integrity check.
    Verify,
}

/// Exit status for a command that does not apply to the configuration.
const EXIT_USAGE: i32 = 2;

fn main() -> Result<()> {
    let cli = Cli::parse();
    let config = cli.config.unwrap_or_else(default_config_path);
    match cli.command.unwrap_or(Command::Serve {
        listen: "127.0.0.1:8787".parse().expect("default listen address"),
        gateway_listen: None,
        max_http_body_hard_cap_bytes: None,
        reload_timeout_ms: 30_000,
        shutdown_timeout_ms: 30_000,
    }) {
        Command::Config {
            command: ConfigCommand::Validate,
        } => match validate_broker_config_file(&config, &Arc::new(backend_registry())) {
            Ok(()) => {
                println!("broker config valid: {}", config.display());
                Ok(())
            }
            Err(error) => exit_config_error(error),
        },
        Command::Audit {
            command: AuditCommand::Verify,
        } => audit_verify(&config),
        Command::Serve {
            listen,
            gateway_listen,
            max_http_body_hard_cap_bytes,
            reload_timeout_ms,
            shutdown_timeout_ms,
        } => serve(
            config,
            listen,
            gateway_listen,
            max_http_body_hard_cap_bytes,
            reload_timeout_ms,
            shutdown_timeout_ms,
        ),
    }
}

fn serve(
    config_path: PathBuf,
    listen: SocketAddr,
    gateway_listen: Option<SocketAddr>,
    max_http_body_hard_cap_bytes: Option<u64>,
    reload_timeout_ms: u64,
    shutdown_timeout_ms: u64,
) -> Result<()> {
    let invalid_filter = init_tracing_for_serve()?;
    if let Some(error) = invalid_filter {
        tracing::warn!(
            event = "logging_filter_invalid",
            envVar = "RUST_LOG",
            error = %error,
            fallback = DEFAULT_LOG_FILTER,
        );
    }
    emit_broker_starting(
        &config_path,
        listen,
        gateway_listen,
        reload_timeout_ms,
        shutdown_timeout_ms,
        max_http_body_hard_cap_bytes,
    );
    let result = serve_after_tracing(
        config_path,
        listen,
        gateway_listen,
        max_http_body_hard_cap_bytes,
        reload_timeout_ms,
        shutdown_timeout_ms,
    );
    if let Err(error) = &result {
        tracing::error!(event = "broker_start_failed", error = %error);
    }
    result
}

fn serve_after_tracing(
    config_path: PathBuf,
    listen: SocketAddr,
    gateway_listen: Option<SocketAddr>,
    max_http_body_hard_cap_bytes: Option<u64>,
    reload_timeout_ms: u64,
    shutdown_timeout_ms: u64,
) -> Result<()> {
    let reload_timeout = Duration::from_millis(reload_timeout_ms);
    let shutdown_timeout = Duration::from_millis(shutdown_timeout_ms);
    validate_shutdown_timeout(shutdown_timeout)?;
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?;
    let result = runtime.block_on(run_service(
        config_path,
        listen,
        gateway_listen,
        max_http_body_hard_cap_bytes,
        reload_timeout,
        shutdown_timeout,
    ));
    runtime.shutdown_timeout(shutdown_timeout);
    result
}

fn init_tracing_for_serve() -> Result<Option<String>> {
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

fn emit_broker_starting(
    config_path: &Path,
    listen: SocketAddr,
    gateway_listen: Option<SocketAddr>,
    reload_timeout_ms: u64,
    shutdown_timeout_ms: u64,
    body_hard_cap: Option<u64>,
) {
    let build = broker_build_status();
    match (body_hard_cap, build.build_provenance) {
        (Some(body_hard_cap), BuildProvenance::Release) => tracing::info!(
            event = "broker_starting",
            brokerVersion = build.broker_version,
            buildCommit = build.build_commit.expect("release builds have a commit"),
            buildProvenance = "release",
            configPath = %config_path.display(),
            publicListen = %listen,
            gatewayListen = gateway_listen.map(|addr| addr.to_string()).unwrap_or_default(),
            reloadTimeoutMs = reload_timeout_ms,
            shutdownTimeoutMs = shutdown_timeout_ms,
            bodyHardCapBytes = body_hard_cap,
        ),
        (None, BuildProvenance::Release) => tracing::info!(
            event = "broker_starting",
            brokerVersion = build.broker_version,
            buildCommit = build.build_commit.expect("release builds have a commit"),
            buildProvenance = "release",
            configPath = %config_path.display(),
            publicListen = %listen,
            gatewayListen = gateway_listen.map(|addr| addr.to_string()).unwrap_or_default(),
            reloadTimeoutMs = reload_timeout_ms,
            shutdownTimeoutMs = shutdown_timeout_ms,
        ),
        (Some(body_hard_cap), BuildProvenance::Unavailable) => tracing::info!(
            event = "broker_starting",
            brokerVersion = build.broker_version,
            buildProvenance = "unavailable",
            configPath = %config_path.display(),
            publicListen = %listen,
            gatewayListen = gateway_listen.map(|addr| addr.to_string()).unwrap_or_default(),
            reloadTimeoutMs = reload_timeout_ms,
            shutdownTimeoutMs = shutdown_timeout_ms,
            bodyHardCapBytes = body_hard_cap,
        ),
        (None, BuildProvenance::Unavailable) => tracing::info!(
            event = "broker_starting",
            brokerVersion = build.broker_version,
            buildProvenance = "unavailable",
            configPath = %config_path.display(),
            publicListen = %listen,
            gatewayListen = gateway_listen.map(|addr| addr.to_string()).unwrap_or_default(),
            reloadTimeoutMs = reload_timeout_ms,
            shutdownTimeoutMs = shutdown_timeout_ms,
        ),
    }
}

async fn run_service(
    config_path: PathBuf,
    listen: SocketAddr,
    gateway_listen: Option<SocketAddr>,
    max_http_body_hard_cap_bytes: Option<u64>,
    reload_timeout: Duration,
    shutdown_timeout: Duration,
) -> Result<()> {
    let state = build_reloadable_state(
        config_path,
        Arc::new(backend_registry()),
        max_http_body_hard_cap_bytes,
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
    let reload_tasks = Arc::new(tokio::sync::Mutex::new(Vec::new()));
    let reload_signal_task = spawn_reload_signal_task(
        state.clone(),
        coordinator.clone(),
        Arc::clone(&reload_tasks),
    );
    let shutdown_signal_task = tokio::spawn(shutdown_signal_task(coordinator.clone()));
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
    state: Arc<agent_access_broker::ReloadableState>,
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

async fn shutdown_signal_task(coordinator: ShutdownCoordinator) {
    tokio::select! {
        cause = wait_for_shutdown_signal() => {
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
fn spawn_reload_signal_task(
    state: Arc<agent_access_broker::ReloadableState>,
    coordinator: ShutdownCoordinator,
    reload_tasks: Arc<tokio::sync::Mutex<Vec<JoinHandle<()>>>>,
) -> JoinHandle<()> {
    tokio::spawn(async move {
        let Ok(signal) = reload_signal_receiver() else {
            return;
        };
        run_reload_signal_loop(signal, state, coordinator, reload_tasks).await;
    })
}

#[cfg(unix)]
fn reload_signal_receiver() -> std::io::Result<tokio::signal::unix::Signal> {
    tokio::signal::unix::signal(tokio::signal::unix::SignalKind::user_defined2())
}

#[cfg(unix)]
async fn run_reload_signal_loop(
    mut signal: tokio::signal::unix::Signal,
    state: Arc<agent_access_broker::ReloadableState>,
    coordinator: ShutdownCoordinator,
    reload_tasks: Arc<tokio::sync::Mutex<Vec<JoinHandle<()>>>>,
) {
    loop {
        tokio::select! {
            _ = coordinator.wait() => break,
            received = signal.recv() => {
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

#[cfg(not(unix))]
fn spawn_reload_signal_task(
    _state: Arc<agent_access_broker::ReloadableState>,
    coordinator: ShutdownCoordinator,
    _reload_tasks: Arc<tokio::sync::Mutex<Vec<JoinHandle<()>>>>,
) -> JoinHandle<()> {
    tokio::spawn(async move {
        let _ = coordinator.wait().await;
    })
}

/// `audit verify`: holds the audit state lock (so no broker may own the
/// store) while it checks the SQLite audit database. Exits 1 when a check
/// finds a problem and 2 when audit is not `type = "sqlite"`.
fn audit_verify(config_path: &Path) -> Result<()> {
    let config = match load_broker_config(config_path, &Arc::new(backend_registry()))
        .and_then(|config| validate_broker_config(&config).map(|()| config))
    {
        Ok(config) => config,
        Err(error) => return exit_config_error(error),
    };
    let Some(audit) = config
        .audit
        .as_ref()
        .filter(|audit| audit.kind == AuditStoreType::Sqlite)
    else {
        let configured = match &config.audit {
            Some(audit) => format!("audit.type = \"{}\"", audit.kind.as_str()),
            None => "audit is disabled".to_string(),
        };
        eprintln!("audit verify requires [audit] type = \"sqlite\"; {configured}");
        std::process::exit(EXIT_USAGE);
    };
    let node_id = resolve_node_id(&config.deployment)?;
    let _lock = StateLockSet::acquire_audit_for_config(&config, config_path, &node_id)
        .map_err(|error| anyhow::anyhow!(error.operator_message()))?;
    let path = Path::new(&audit.path);
    let report = verify_sqlite_audit_database(path).map_err(anyhow::Error::msg)?;
    print_audit_verify_report(path, &report);
    if !report.is_ok() {
        eprintln!("audit database verification found problems");
        std::process::exit(1);
    }
    println!("audit database verified");
    Ok(())
}

fn print_audit_verify_report(path: &Path, report: &AuditVerifyReport) {
    println!("audit database: {}", path.display());
    if let Some(database_id) = &report.database_id {
        println!("database_id: {database_id}");
    }
    for check in &report.checks {
        if check.problems.is_empty() {
            println!("{}: ok", check.name);
        } else {
            println!("{}: {} problem(s)", check.name, check.problems.len());
            for problem in &check.problems {
                println!("  - {problem}");
            }
        }
    }
}

fn exit_config_error(error: ConfigError) -> Result<()> {
    eprintln!("{error}");
    for item in error.errors() {
        eprintln!("- {item}");
    }
    std::process::exit(3);
}

fn default_config_path() -> PathBuf {
    env::var_os("AGENT_ACCESS_BROKER_CONFIG")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("/etc/agent-access/broker.toml"))
}

#[cfg(test)]
mod tests {
    use super::*;
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
    const SIGNAL_SMOKE_CHILD_TEST: &str = "tests::unix_signal_smoke_child_harness";

    #[test]
    fn serve_tracing_filter_uses_default_valid_override_and_invalid_fallback() {
        let (default_filter, default_error) = env_filter_for_serve_value(None);
        assert_filter_contains(
            &default_filter,
            &[
                "agent_access_broker=info",
                "agent_access_core=info",
                "agent_access_provider=info",
                "axum=warn",
                "tower=warn",
            ],
        );
        assert!(default_error.is_none());

        let (override_filter, override_error) =
            env_filter_for_serve_value(Some("agent_access_broker=debug,agent_access_core=warn"));
        assert_filter_contains(
            &override_filter,
            &["agent_access_broker=debug", "agent_access_core=warn"],
        );
        assert!(override_error.is_none());

        let (fallback_filter, fallback_error) =
            env_filter_for_serve_value(Some("agent_access_broker=notalevel"));
        assert_filter_contains(
            &fallback_filter,
            &[
                "agent_access_broker=info",
                "agent_access_core=info",
                "agent_access_provider=info",
                "axum=warn",
                "tower=warn",
            ],
        );
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
            "tests::__nonexistent_unix_signal_smoke_child_harness__",
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
                signal,
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

    #[test]
    fn serve_defaults_shutdown_timeout() {
        let cli = Cli::parse_from(["agent-access-broker", "serve"]);
        let Some(Command::Serve {
            shutdown_timeout_ms,
            ..
        }) = cli.command
        else {
            panic!("expected serve command");
        };
        assert_eq!(shutdown_timeout_ms, 30_000);
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

    async fn test_reloadable_state() -> Arc<agent_access_broker::ReloadableState> {
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
            "agent-access-broker-main-test-{}-{}-{name}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        path
    }
}
