//! One run of a command: `<path> describe`, `invoke` or `verify` under a
//! supervisor that holds the run's budget permit, and how a run that ended
//! without a document to read fails.
//!
//! The process gets an empty environment plus the command's configured `env`
//! and the network variables core supplies, its configured working directory
//! and the request on stdin; nothing travels in its arguments. A run that
//! never started applied nothing; after the spawn, a generic failure leaves
//! a write's outcome unknown. Each failure logs one `command_import_failed`
//! line without command output; the command's stderr joins it only when the
//! operator set `log_stderr`. Commands run on Unix only; elsewhere every run
//! fails before it starts.
use agent_access_core::CommandImportConfig;
use agent_access_core::imports::{CommandPermit, CommandProcessFacts, CommandRequest};
use agent_access_provider::{MutationReceipt, ProviderError, ReasonCode};
use std::ffi::OsString;
use tokio::time::Instant;

/// The command operation a process runs, passed as its only argument.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum CommandOperation {
    Describe,
    Invoke,
    Verify,
}

impl CommandOperation {
    pub(crate) fn argument(self) -> &'static str {
        match self {
            Self::Describe => "describe",
            Self::Invoke => "invoke",
            Self::Verify => "verify",
        }
    }
}

/// One run of `command`.
pub(crate) struct Run<'a> {
    /// The import whose command runs, named in failure logs.
    pub(crate) service: &'a str,
    pub(crate) command: &'a CommandImportConfig,
    pub(crate) operation: CommandOperation,
    /// The budget permit the run's supervisor holds until the process group
    /// is reaped and its pipes are drained.
    pub(crate) permit: CommandPermit,
    /// The request written to stdin; `None` closes stdin at once, as for
    /// `describe`.
    pub(crate) request: Option<CommandRequest>,
    pub(crate) deadline: Instant,
    pub(crate) max_output_bytes: usize,
    /// The network variables core sets beside the configured `env`.
    pub(crate) environment: Vec<(&'static str, OsString)>,
    pub(crate) facts: CommandProcessFacts,
}

/// The bytes a `max_output_bytes` setting allows.
pub(crate) fn output_limit(command: &CommandImportConfig) -> usize {
    usize::try_from(command.max_output_bytes).unwrap_or(usize::MAX)
}

/// A run whose leader exited 0 and closed its pipes in time.
#[cfg_attr(not(unix), allow(dead_code, reason = "commands run on Unix only"))]
pub(crate) struct Completed {
    /// The document to read.
    pub(crate) stdout: Vec<u8>,
    stderr: Vec<u8>,
}

#[cfg_attr(not(unix), allow(dead_code, reason = "commands run on Unix only"))]
impl Completed {
    /// Logs a contract violation found in the document, as a run failure
    /// is logged.
    pub(crate) fn log_violation(
        &self,
        service: &str,
        command: &CommandImportConfig,
        operation: CommandOperation,
        category: &str,
    ) {
        log_failure(
            service,
            command,
            operation,
            category,
            FailureDetails {
                exit_code: Some(0),
                stderr: Some(&self.stderr),
                ..FailureDetails::default()
            },
        );
    }
}

/// Starts the run's process and waits until it completes. Dropping the
/// future drops the supervisor's handle, which kills the process group at
/// once; the supervisor still reaps it and drains its pipes before it
/// returns the permit. A failure is logged.
#[cfg(unix)]
pub(crate) async fn execute(run: Run<'_>) -> Result<Completed, RunFailure> {
    let (service, command, operation) = (run.service, run.command, run.operation);
    let outcome = match unix::start(run) {
        Ok(handle) => handle.outcome().await,
        Err(error) => {
            let (failure, spawn_error) = match error {
                crate::supervisor::StartError::Cancelled => (RunFailure::Cancelled, None),
                crate::supervisor::StartError::DeadlineExceeded => {
                    (RunFailure::DeadlineBeforeStart, None)
                }
                crate::supervisor::StartError::Spawn(error) => {
                    (RunFailure::Spawn, Some(error.kind()))
                }
            };
            log_failure(
                service,
                command,
                operation,
                failure.category(),
                FailureDetails {
                    spawn_error,
                    ..FailureDetails::default()
                },
            );
            return Err(failure);
        }
    };
    match RunFailure::of(&outcome) {
        None => Ok(Completed {
            stdout: outcome.stdout,
            stderr: outcome.stderr.kept,
        }),
        Some(failure) => {
            let exit = outcome.exit;
            log_failure(
                service,
                command,
                operation,
                failure.category(),
                FailureDetails {
                    exit_code: exit.and_then(|exit| exit.code),
                    signal: exit.and_then(|exit| exit.signal),
                    stderr: Some(&outcome.stderr.kept),
                    spawn_error: None,
                },
            );
            Err(failure)
        }
    }
}

/// Commands run on Unix only: the run fails before anything starts, and its
/// permit returns at once.
#[cfg(not(unix))]
pub(crate) async fn execute(run: Run<'_>) -> Result<Completed, RunFailure> {
    let Run {
        service,
        command,
        operation,
        permit,
        request,
        deadline,
        max_output_bytes,
        environment,
        facts,
    } = run;
    drop((
        permit,
        request,
        deadline,
        max_output_bytes,
        environment,
        facts,
    ));
    let failure = RunFailure::Spawn;
    log_failure(
        service,
        command,
        operation,
        failure.category(),
        FailureDetails {
            spawn_error: Some(std::io::ErrorKind::Unsupported),
            ..FailureDetails::default()
        },
    );
    Err(failure)
}

#[cfg(unix)]
mod unix {
    use super::{Run, RunFailure};
    use crate::process::{CommandLaunch, StdinPayload};
    use crate::supervisor::{
        self, ProcessOutcome, StartError, SupervisionLimits, SupervisorHandle, Termination,
    };
    use agent_access_core::imports::CommandRequest;
    use std::ffi::OsString;
    use std::path::PathBuf;

    /// The request on a process's stdin. The supervisor drops it once
    /// written or abandoned, which zeroizes it.
    struct RequestBytes(CommandRequest);

    impl AsRef<[u8]> for RequestBytes {
        fn as_ref(&self) -> &[u8] {
            self.0.stdin()
        }
    }

    pub(super) fn start(
        run: Run<'_>,
    ) -> Result<SupervisorHandle<crate::process::OsSignals>, StartError> {
        let launch = CommandLaunch {
            program: PathBuf::from(&run.command.path),
            operation: run.operation,
            env: run
                .command
                .env
                .iter()
                .map(|(name, value)| (OsString::from(name), OsString::from(value)))
                .chain(
                    run.environment
                        .into_iter()
                        .map(|(name, value)| (OsString::from(name), value)),
                )
                .collect(),
            working_dir: PathBuf::from(&run.command.working_dir),
        };
        let stdin = match run.request {
            Some(request) => StdinPayload::new(RequestBytes(request)),
            None => StdinPayload::empty(),
        };
        supervisor::start_command(
            run.permit,
            &launch,
            stdin,
            SupervisionLimits {
                deadline: run.deadline,
                max_output_bytes: run.max_output_bytes,
            },
            run.facts,
        )
    }

    impl RunFailure {
        /// The failure of `outcome`, or `None` for a leader that exited 0
        /// and closed its pipes in time, whose stdout is the document.
        pub(super) fn of(outcome: &ProcessOutcome) -> Option<Self> {
            Some(match outcome.termination {
                Termination::TimedOut => Self::TimedOut,
                Termination::Killed => Self::Stopped,
                Termination::OutputExceeded => Self::OutputLimit,
                Termination::PipesHeldOpen => Self::PipesHeldOpen,
                Termination::Unobserved => Self::Unobserved,
                Termination::Exited => match outcome.exit {
                    Some(exit) if exit.code == Some(0) => return None,
                    Some(exit) if exit.signal.is_some() => Self::Signal,
                    Some(_) => Self::ExitStatus,
                    None => Self::Unobserved,
                },
            })
        }
    }
}

/// Why a run left no document to read.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(not(unix), allow(dead_code, reason = "commands run on Unix only"))]
pub(crate) enum RunFailure {
    /// The executable could not be started.
    Spawn,
    /// The Broker began shutting down before the process started.
    Cancelled,
    /// The command deadline passed before the process started.
    DeadlineBeforeStart,
    /// The command deadline passed and the group was killed.
    TimedOut,
    /// Shutdown killed the group.
    Stopped,
    /// The leader exited with a non-zero status.
    ExitStatus,
    /// A signal the Broker did not send ended the leader.
    Signal,
    /// Stdout exceeded its limit and the group was killed.
    OutputLimit,
    /// Stdout or stderr stayed open after the post-exit drain.
    PipesHeldOpen,
    /// The leader's exit could not be observed.
    Unobserved,
}

impl RunFailure {
    /// The violation category the failure log names.
    pub(crate) fn category(self) -> &'static str {
        match self {
            Self::Spawn => "spawn_failed",
            Self::Cancelled => "shutdown_before_start",
            Self::DeadlineBeforeStart => "deadline_before_start",
            Self::TimedOut => "timeout",
            Self::Stopped => "shutdown",
            Self::ExitStatus => "exit_status",
            Self::Signal => "signal",
            Self::OutputLimit => "output_limit",
            Self::PipesHeldOpen => "pipes_held_open",
            Self::Unobserved => "exit_unobserved",
        }
    }

    /// Whether the process started, so a write may have been applied.
    pub(crate) fn started(self) -> bool {
        !matches!(
            self,
            Self::Spawn | Self::Cancelled | Self::DeadlineBeforeStart
        )
    }

    /// The failure of an `invoke` call: nothing was applied before the
    /// spawn, and afterwards a write's outcome is unknown. Callers never see
    /// output, exit statuses or paths.
    pub(crate) fn invocation_error(self, read_only: bool) -> ProviderError {
        let error = self.error();
        if read_only {
            error
        } else if self.started() {
            error.with_mutation_receipt(MutationReceipt::unknown())
        } else {
            error.with_mutation_receipt(MutationReceipt::not_applied())
        }
    }

    /// The failure of an `invoke` or `verify` call, without a receipt.
    pub(crate) fn error(self) -> ProviderError {
        let (reason, message) = match self {
            Self::Spawn => (
                ReasonCode::OperationFailed,
                "The tool could not be started.",
            ),
            Self::Cancelled | Self::Stopped => (
                ReasonCode::OperationCancelled,
                "operation stopped during broker shutdown",
            ),
            Self::DeadlineBeforeStart => (
                ReasonCode::UpstreamTimeout,
                "The tool did not start in time.",
            ),
            Self::TimedOut => (
                ReasonCode::UpstreamTimeout,
                "The tool did not finish in time.",
            ),
            Self::ExitStatus
            | Self::Signal
            | Self::OutputLimit
            | Self::PipesHeldOpen
            | Self::Unobserved => (ReasonCode::OperationFailed, "The tool failed."),
        };
        ProviderError::error(reason, message)
    }
}

/// What a failure log line reports about the process.
#[derive(Default)]
struct FailureDetails<'a> {
    exit_code: Option<i32>,
    signal: Option<i32>,
    /// The kept stderr, logged only with `log_stderr`.
    stderr: Option<&'a [u8]>,
    /// Why the executable could not be started, without its path.
    spawn_error: Option<std::io::ErrorKind>,
}

/// Who a failure log line names: the import, the action of the current
/// hook (the operation outside one), and the Broker request ID of the current
/// invocation (empty outside one, as for discovery).
fn log_subject(service: &str, operation: CommandOperation) -> (String, String, String) {
    let action = agent_access_provider::current_provider_action()
        .map(|(_, action)| action)
        .unwrap_or_else(|| operation.argument().to_owned());
    let request_id = agent_access_provider::current_correlation_context()
        .map(|correlation| correlation.broker_request_id)
        .unwrap_or_default();
    (service.to_owned(), action, request_id)
}

/// Logs one `command_import_failed` line: the import, the action, the Broker
/// request ID, the operation, the exit status or signal and `category`,
/// never command output or paths. With `log_stderr`, the process's kept
/// stderr joins it, control characters escaped.
fn log_failure(
    service: &str,
    command: &CommandImportConfig,
    operation: CommandOperation,
    category: &str,
    details: FailureDetails<'_>,
) {
    let (service, action, request_id) = log_subject(service, operation);
    let stderr = details
        .stderr
        .filter(|_| command.log_stderr)
        .map(escaped_stderr);
    tracing::warn!(
        event = "command_import_failed",
        service = %service,
        action = %action,
        request_id = %request_id,
        operation = operation.argument(),
        exit_code = ?details.exit_code,
        signal = ?details.signal,
        violation = category,
        spawn_error = details.spawn_error.map(|kind| kind.to_string()).as_deref(),
        stderr = stderr.as_deref(),
        "command import process failed"
    );
}

/// Stderr as text with control characters other than tab escaped.
fn escaped_stderr(kept: &[u8]) -> String {
    let mut escaped = String::with_capacity(kept.len());
    for ch in String::from_utf8_lossy(kept).chars() {
        if ch.is_control() && ch != '\t' {
            escaped.extend(ch.escape_default());
        } else {
            escaped.push(ch);
        }
    }
    escaped
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn each_operation_is_its_own_single_argument() {
        assert_eq!(CommandOperation::Describe.argument(), "describe");
        assert_eq!(CommandOperation::Invoke.argument(), "invoke");
        assert_eq!(CommandOperation::Verify.argument(), "verify");
    }

    #[cfg(unix)]
    #[test]
    fn only_a_zero_exit_with_closed_pipes_leaves_a_document() {
        use crate::process::{ProcessExit, StderrCapture};
        use crate::supervisor::{ProcessOutcome, Termination};
        let outcome = |termination, code, signal| ProcessOutcome {
            termination,
            exit: Some(ProcessExit { code, signal }),
            stdout: b"{}".to_vec(),
            stderr: StderrCapture::default(),
            duration: std::time::Duration::ZERO,
        };
        assert_eq!(
            RunFailure::of(&outcome(Termination::Exited, Some(0), None)),
            None
        );
        for (termination, code, signal, failure) in [
            (Termination::Exited, Some(3), None, RunFailure::ExitStatus),
            (Termination::Exited, None, Some(11), RunFailure::Signal),
            (Termination::TimedOut, None, Some(9), RunFailure::TimedOut),
            (Termination::Killed, None, Some(9), RunFailure::Stopped),
            (
                Termination::OutputExceeded,
                Some(0),
                None,
                RunFailure::OutputLimit,
            ),
            (
                Termination::PipesHeldOpen,
                Some(0),
                None,
                RunFailure::PipesHeldOpen,
            ),
        ] {
            assert_eq!(
                RunFailure::of(&outcome(termination, code, signal)),
                Some(failure)
            );
        }
    }

    #[test]
    fn failures_before_the_spawn_applied_nothing_and_after_it_are_unknown() {
        let receipt = |failure: RunFailure| {
            failure
                .invocation_error(false)
                .result
                .map(|result| result["mutationStatus"].clone())
        };
        assert_eq!(receipt(RunFailure::Spawn).unwrap(), "not_applied");
        assert_eq!(receipt(RunFailure::Cancelled).unwrap(), "not_applied");
        assert_eq!(
            receipt(RunFailure::DeadlineBeforeStart).unwrap(),
            "not_applied"
        );
        assert_eq!(
            RunFailure::DeadlineBeforeStart.error().reason_code(),
            ReasonCode::UpstreamTimeout
        );
        for failure in [
            RunFailure::TimedOut,
            RunFailure::Stopped,
            RunFailure::ExitStatus,
            RunFailure::Signal,
            RunFailure::OutputLimit,
            RunFailure::PipesHeldOpen,
            RunFailure::Unobserved,
        ] {
            assert_eq!(receipt(failure).unwrap(), "unknown");
        }
        assert!(RunFailure::TimedOut.invocation_error(true).result.is_none());
        assert_eq!(
            RunFailure::TimedOut.error().reason_code(),
            ReasonCode::UpstreamTimeout
        );
        assert_eq!(
            RunFailure::Cancelled.error().reason_code(),
            ReasonCode::OperationCancelled
        );
        assert_eq!(
            RunFailure::Spawn.error().reason_code(),
            ReasonCode::OperationFailed
        );
    }

    #[tokio::test]
    async fn failure_logs_name_the_import_and_its_hook() {
        assert_eq!(
            log_subject("ticketing", CommandOperation::Describe),
            ("ticketing".into(), "describe".into(), String::new())
        );
        let hook = agent_access_provider::host::hook_context(
            "ticketing",
            "import.discover",
            agent_access_provider::HookPhase::CredentialVerification,
            &[],
        );
        let subject = agent_access_provider::host::with_hook_context(hook, async {
            log_subject("ticketing", CommandOperation::Describe)
        })
        .await;
        assert_eq!(
            subject,
            ("ticketing".into(), "import.discover".into(), String::new())
        );
    }

    #[test]
    fn logged_stderr_escapes_control_characters_and_keeps_tabs() {
        assert_eq!(
            escaped_stderr(b"line\tone\nline\x1b[31m two\r"),
            "line\tone\\nline\\u{1b}[31m two\\r"
        );
    }
}
