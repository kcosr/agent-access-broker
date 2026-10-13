//! The broker application: command parsing, the configuration and audit
//! commands, and the `serve` process around [`crate::lifecycle`].
use crate::composition::{BrokerComposition, CompositionError};
use crate::lifecycle::{self, LoggingMode, ServeOptions, SignalSource};
use crate::{BrokerBuildStatus, BuildProvenance};
use agent_access_core::{
    API_CATALOG_VERSION, AuditStoreType, AuditVerifyReport, BrokerConfig, ConfigError,
    SEND_SCHEMA_VERSION, StateLockSet, load_broker_config, resolve_node_id, validate_broker_config,
    validate_broker_config_file, verify_sqlite_audit_database,
};
use clap::{Args, CommandFactory, FromArgMatches, Parser, Subcommand};
use std::ffi::OsString;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::process::{ExitCode, Termination};
use std::time::Duration;

/// Names the configuration file when `--config` is absent.
const CONFIG_ENV: &str = "AGENT_ACCESS_BROKER_CONFIG";
/// The configuration file when neither `--config` nor [`CONFIG_ENV`] names one.
const DEFAULT_CONFIG_PATH: &str = "/etc/agent-access/broker.toml";
const DEFAULT_LISTEN: &str = "127.0.0.1:8787";
const DEFAULT_TIMEOUT_MS: u64 = 30_000;

const EXIT_SUCCESS: u8 = 0;
const EXIT_FAILURE: u8 = 1;
/// A command that does not apply to the configuration, or invalid arguments.
const EXIT_USAGE: u8 = 2;
/// An invalid configuration or composition.
const EXIT_CONFIG: u8 = 3;

/// The executable that links the host: its command name and description,
/// its version, and the source revision its release build recorded.
///
/// The identity labels the command line and build status only. The
/// configuration path, state, keys and locks never depend on it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AssemblyIdentity {
    name: &'static str,
    about: Option<&'static str>,
    version: &'static str,
    release_commit: Option<&'static str>,
}

impl AssemblyIdentity {
    pub const fn new(name: &'static str, version: &'static str) -> Self {
        Self {
            name,
            about: None,
            version,
            release_commit: None,
        }
    }

    /// The description shown in command-line help.
    pub const fn with_about(mut self, about: &'static str) -> Self {
        self.about = Some(about);
        self
    }

    /// The full source revision recorded by a release build with
    /// provenance. Without one, build provenance is unavailable.
    pub const fn with_release_commit(mut self, commit: &'static str) -> Self {
        self.release_commit = Some(commit);
        self
    }

    /// The build status served at `/v1/broker/status` and logged at startup.
    pub fn build_status(&self) -> BrokerBuildStatus {
        BrokerBuildStatus {
            broker_version: self.version,
            build_commit: self.release_commit,
            build_provenance: match self.release_commit {
                Some(_) => BuildProvenance::Release,
                None => BuildProvenance::Unavailable,
            },
            catalog_version: API_CATALOG_VERSION,
            send_schema_version: SEND_SCHEMA_VERSION,
        }
    }
}

/// A broker executable. It owns command parsing, logging, the async runtime,
/// configuration validation, offline audit verification, and serving with
/// state locks, readiness, reload and bounded shutdown.
#[derive(Debug)]
pub struct BrokerApplication {
    composition: BrokerComposition,
    identity: AssemblyIdentity,
}

impl BrokerApplication {
    pub fn new(composition: BrokerComposition, identity: AssemblyIdentity) -> Self {
        Self {
            composition,
            identity,
        }
    }

    /// Runs the command the process arguments name.
    pub fn run_from_env(&self) -> BrokerExit {
        self.run_from(std::env::args_os())
    }

    /// Runs the command `args` name; the first item is the program name.
    pub fn run_from<I, T>(&self, args: I) -> BrokerExit
    where
        I: IntoIterator<Item = T>,
        T: Into<OsString> + Clone,
    {
        let cli = match self.parse(args) {
            Ok(cli) => cli,
            Err(error) => {
                // Help goes to stdout and exits 0; argument errors go to
                // stderr and exit 2.
                let _ = error.print();
                return BrokerExit::status(u8::try_from(error.exit_code()).unwrap_or(EXIT_USAGE));
            }
        };
        let config_path = cli.config.unwrap_or_else(default_config_path);
        match cli.command.unwrap_or_default() {
            Command::Config {
                command: ConfigCommand::Validate,
            } => self.validate_config(&config_path),
            Command::Audit {
                command: AuditCommand::Verify,
            } => self.verify_audit(&config_path),
            Command::Serve(args) => self.serve(args.into_options(config_path)),
        }
    }

    fn command(&self) -> clap::Command {
        let command = Cli::command().name(self.identity.name);
        match self.identity.about {
            Some(about) => command.about(about),
            None => command,
        }
    }

    fn parse<I, T>(&self, args: I) -> Result<Cli, clap::Error>
    where
        I: IntoIterator<Item = T>,
        T: Into<OsString> + Clone,
    {
        let mut command = self.command();
        let matches = command.try_get_matches_from_mut(args)?;
        Cli::from_arg_matches(&matches).map_err(|error| error.format(&mut command))
    }

    fn validate_config(&self, config_path: &Path) -> BrokerExit {
        match validate_broker_config_file(config_path, self.composition.registry()) {
            Ok(()) => {
                println!("broker config valid: {}", config_path.display());
                BrokerExit::status(EXIT_SUCCESS)
            }
            Err(error) => config_error(&error),
        }
    }

    /// `audit verify`: checks the SQLite audit database while holding the
    /// audit state lock, so no broker may own the store. Exits 1 when a check
    /// finds a problem and 2 when audit is not `type = "sqlite"`.
    fn verify_audit(&self, config_path: &Path) -> BrokerExit {
        let config = match load_broker_config(config_path, self.composition.registry())
            .and_then(|config| validate_broker_config(&config).map(|()| config))
        {
            Ok(config) => config,
            Err(error) => return config_error(&error),
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
            return BrokerExit::status(EXIT_USAGE);
        };
        match verify_locked_audit_database(&config, config_path, Path::new(&audit.path)) {
            Ok(true) => {
                println!("audit database verified");
                BrokerExit::status(EXIT_SUCCESS)
            }
            Ok(false) => {
                eprintln!("audit database verification found problems");
                BrokerExit::status(EXIT_FAILURE)
            }
            Err(error) => BrokerExit::failed(error),
        }
    }

    /// `serve` as a process: a multi-thread runtime running the lifecycle with
    /// process signals and the process-global log subscriber.
    fn serve(&self, options: ServeOptions) -> BrokerExit {
        let shutdown_timeout = options.shutdown_timeout;
        let runtime = match tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
        {
            Ok(runtime) => runtime,
            Err(error) => return BrokerExit::failed(error.into()),
        };
        let result = runtime.block_on(lifecycle::serve(
            self.composition.clone(),
            self.identity,
            options,
            SignalSource::process(),
            LoggingMode::Process,
        ));
        runtime.shutdown_timeout(shutdown_timeout);
        match result {
            Ok(()) => BrokerExit::status(EXIT_SUCCESS),
            Err(error) => BrokerExit::failed(error),
        }
    }
}

/// Prints each check of the database at `path`, holding the audit state lock
/// meanwhile, and returns whether every check passed.
fn verify_locked_audit_database(
    config: &BrokerConfig,
    config_path: &Path,
    path: &Path,
) -> anyhow::Result<bool> {
    let node_id = resolve_node_id(&config.deployment)?;
    let _lock = StateLockSet::acquire_audit_for_config(config, config_path, &node_id)
        .map_err(|error| anyhow::anyhow!(error.operator_message()))?;
    let report = verify_sqlite_audit_database(path).map_err(anyhow::Error::msg)?;
    print_audit_verify_report(path, &report);
    Ok(report.is_ok())
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

fn config_error(error: &ConfigError) -> BrokerExit {
    eprintln!("{error}");
    for item in error.errors() {
        eprintln!("- {item}");
    }
    BrokerExit::status(EXIT_CONFIG)
}

fn default_config_path() -> PathBuf {
    std::env::var_os(CONFIG_ENV)
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(DEFAULT_CONFIG_PATH))
}

/// How a broker command ended. Returned from `main`, it reports a failure
/// that the command has not already printed and exits with the command's
/// status: 0 on success, 1 on failure, 2 for a usage error, and 3 when the
/// configuration or the composition is invalid.
#[derive(Debug)]
#[must_use]
pub struct BrokerExit {
    code: u8,
    failure: Option<Failure>,
}

#[derive(Debug)]
enum Failure {
    Error(anyhow::Error),
    Composition(CompositionError),
}

impl BrokerExit {
    /// The process exit status.
    pub fn code(&self) -> u8 {
        self.code
    }

    fn status(code: u8) -> Self {
        Self {
            code,
            failure: None,
        }
    }

    fn failed(error: anyhow::Error) -> Self {
        Self {
            code: EXIT_FAILURE,
            failure: Some(Failure::Error(error)),
        }
    }
}

impl From<CompositionError> for BrokerExit {
    fn from(error: CompositionError) -> Self {
        Self {
            code: EXIT_CONFIG,
            failure: Some(Failure::Composition(error)),
        }
    }
}

impl Termination for BrokerExit {
    fn report(self) -> ExitCode {
        match self.failure {
            Some(Failure::Error(error)) => eprintln!("Error: {error:?}"),
            Some(Failure::Composition(error)) => {
                eprintln!("{error}");
                for problem in error.problems() {
                    eprintln!("- {problem}");
                }
            }
            None => {}
        }
        ExitCode::from(self.code)
    }
}

#[derive(Debug, Parser)]
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
    Serve(ServeArgs),
}

/// Without a subcommand the broker serves with default settings.
impl Default for Command {
    fn default() -> Self {
        Self::Serve(ServeArgs::default())
    }
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

#[derive(Debug, Clone, PartialEq, Eq, Args)]
struct ServeArgs {
    #[arg(long, default_value = DEFAULT_LISTEN)]
    listen: SocketAddr,
    #[arg(long)]
    gateway_listen: Option<SocketAddr>,
    #[arg(long)]
    max_http_body_hard_cap_bytes: Option<u64>,
    #[arg(long, default_value_t = DEFAULT_TIMEOUT_MS)]
    reload_timeout_ms: u64,
    #[arg(long, default_value_t = DEFAULT_TIMEOUT_MS)]
    shutdown_timeout_ms: u64,
}

impl Default for ServeArgs {
    fn default() -> Self {
        Self {
            listen: DEFAULT_LISTEN.parse().expect("default listen address"),
            gateway_listen: None,
            max_http_body_hard_cap_bytes: None,
            reload_timeout_ms: DEFAULT_TIMEOUT_MS,
            shutdown_timeout_ms: DEFAULT_TIMEOUT_MS,
        }
    }
}

impl ServeArgs {
    fn into_options(self, config_path: PathBuf) -> ServeOptions {
        ServeOptions {
            config_path,
            listen: self.listen,
            gateway_listen: self.gateway_listen,
            body_hard_cap: self.max_http_body_hard_cap_bytes,
            reload_timeout: Duration::from_millis(self.reload_timeout_ms),
            shutdown_timeout: Duration::from_millis(self.shutdown_timeout_ms),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::backend_registry;

    const IDENTITY: AssemblyIdentity =
        AssemblyIdentity::new("example-broker", "1.2.3").with_about("Example broker service");

    fn application() -> BrokerApplication {
        BrokerApplication::new(
            BrokerComposition::from_registry(backend_registry()),
            IDENTITY,
        )
    }

    fn run(args: &[&str]) -> u8 {
        application()
            .run_from(std::iter::once("example-broker").chain(args.iter().copied()))
            .code()
    }

    fn write_config(directory: &Path, body: &str) -> PathBuf {
        let path = directory.join("broker.toml");
        std::fs::write(&path, body).unwrap();
        path
    }

    const MINIMAL_CONFIG: &str = r#"
[deployment]
environment = "development"

[identity]
mode = "anonymous"
authority = "toml"

[policy]
authority = "toml"
default_decision = "deny"
"#;

    #[test]
    fn serve_is_the_default_command_with_default_settings() {
        let application = application();
        let explicit = application
            .parse(["example-broker", "serve"])
            .unwrap()
            .command;
        let Some(Command::Serve(explicit)) = explicit else {
            panic!("expected serve command");
        };
        assert_eq!(explicit, ServeArgs::default());
        assert_eq!(explicit.shutdown_timeout_ms, 30_000);
        assert!(
            application
                .parse(["example-broker"])
                .unwrap()
                .command
                .is_none()
        );
    }

    #[test]
    fn the_identity_names_and_describes_the_command() {
        let command = application().command();
        assert_eq!(command.get_name(), "example-broker");
        assert_eq!(
            command.get_about().map(ToString::to_string).as_deref(),
            Some("Example broker service")
        );
    }

    #[test]
    fn help_exits_zero_and_argument_errors_exit_two() {
        assert_eq!(run(&["--help"]), 0);
        assert_eq!(run(&["no-such-command"]), 2);
        assert_eq!(run(&["serve", "--listen", "not-an-address"]), 2);
    }

    #[test]
    fn config_validate_exits_zero_for_valid_and_three_for_invalid_config() {
        let directory = tempfile::tempdir().unwrap();
        let valid = write_config(directory.path(), MINIMAL_CONFIG);
        assert_eq!(
            run(&["--config", valid.to_str().unwrap(), "config", "validate"]),
            0
        );
        let invalid = write_config(directory.path(), "[identity]\nmode = \"anonymous\"\n");
        assert_eq!(
            run(&["--config", invalid.to_str().unwrap(), "config", "validate"]),
            3
        );
        let missing = directory.path().join("missing.toml");
        assert_eq!(
            run(&["--config", missing.to_str().unwrap(), "config", "validate"]),
            3
        );
    }

    #[test]
    fn audit_verify_exits_two_without_sqlite_audit_and_three_for_invalid_config() {
        let directory = tempfile::tempdir().unwrap();
        let disabled = write_config(directory.path(), MINIMAL_CONFIG);
        assert_eq!(
            run(&["--config", disabled.to_str().unwrap(), "audit", "verify"]),
            2
        );
        let invalid = write_config(directory.path(), "not toml =");
        assert_eq!(
            run(&["--config", invalid.to_str().unwrap(), "audit", "verify"]),
            3
        );
    }

    #[test]
    fn composition_errors_exit_three() {
        let error = BrokerComposition::builder()
            .native(&agent_access_fake::FAKE_BACKEND)
            .native(&agent_access_fake::FAKE_BACKEND)
            .build()
            .unwrap_err();
        assert_eq!(BrokerExit::from(error).code(), 3);
    }

    #[test]
    fn the_build_status_follows_the_recorded_release_commit() {
        const COMMIT: &str = "0123456789abcdef0123456789abcdef01234567";
        let unavailable = IDENTITY.build_status();
        assert_eq!(unavailable.broker_version, "1.2.3");
        assert_eq!(unavailable.build_commit, None);
        assert_eq!(unavailable.build_provenance, BuildProvenance::Unavailable);
        assert_eq!(unavailable.catalog_version, API_CATALOG_VERSION);
        assert_eq!(unavailable.send_schema_version, SEND_SCHEMA_VERSION);
        let release = IDENTITY.with_release_commit(COMMIT).build_status();
        assert_eq!(release.build_commit, Some(COMMIT));
        assert_eq!(release.build_provenance, BuildProvenance::Release);
    }
}
