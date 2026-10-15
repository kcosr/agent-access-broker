//! The supervisor of one command process.
//!
//! After the spawn, the child, its pipes, the four I/O branches and the
//! budget permit move into one supervisor task, separate from the
//! invocation future, which awaits the outcome through a channel. The
//! supervisor registers with the command registry before it spawns, so
//! shutdown can kill its process group whatever became of the invocation.
//! It returns the permit only after the group is killed and reaped and every
//! I/O branch has finished. It records the process facts into the run's
//! shared cell before it returns the permit, so they outlive the invocation;
//! it never finalizes or audits a call.
use crate::process::{
    self, CommandLaunch, GroupSignals, KillCause, OsSignals, POST_EXIT_DRAIN, ProcessExit,
    SignalLock, StderrCapture, StdinPayload, StdoutCapture, SupervisedProcess, read_stderr,
    read_stdout, write_stdin,
};
use agent_access_core::imports::{
    CommandPermit, CommandProcessControl, CommandProcessFacts, LiveCommandProcess,
};
use std::io;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::oneshot;
use tokio::time::Instant;

#[cfg(test)]
mod double;

/// The bounds of one process.
#[derive(Debug, Clone, Copy)]
pub(crate) struct SupervisionLimits {
    /// The command deadline: the earlier of admission plus the command
    /// timeout and the host operation deadline.
    pub(crate) deadline: Instant,
    pub(crate) max_output_bytes: usize,
}

/// Why no process was started. Either way nothing ran: `not_applied`.
#[derive(Debug)]
pub(crate) enum StartError {
    /// The Broker is shutting down (`operation_cancelled`).
    Cancelled,
    /// The command deadline passed before the spawn (`upstream_timeout`).
    DeadlineExceeded,
    /// The executable could not be started (`operation_failed`).
    Spawn(io::Error),
}

/// How a started process ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Termination {
    /// The leader exited and the pipes closed within the post-exit drain.
    Exited,
    /// The command deadline passed and the group was killed.
    TimedOut,
    /// Stdout exceeded `max_output_bytes` and the group was killed.
    OutputExceeded,
    /// A kill request, from a dropped handle or shutdown, ended the group.
    Killed,
    /// Stdout or stderr stayed open after the post-exit drain: a
    /// descendant left the process group.
    PipesHeldOpen,
    /// The leader's exit could not be observed.
    Unobserved,
}

/// The result of one supervised process. Its `Debug` shows only the sizes
/// of the command's output, never the output itself.
pub(crate) struct ProcessOutcome {
    pub(crate) termination: Termination,
    /// The reaped leader's status; `None` when it was not reaped.
    pub(crate) exit: Option<ProcessExit>,
    /// Stdout up to `max_output_bytes`; empty when it overflowed.
    pub(crate) stdout: Vec<u8>,
    pub(crate) stderr: StderrCapture,
    pub(crate) duration: Duration,
}

impl std::fmt::Debug for ProcessOutcome {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ProcessOutcome")
            .field("termination", &self.termination)
            .field("exit", &self.exit)
            .field("stdout_bytes", &self.stdout.len())
            .field("stderr_kept_bytes", &self.stderr.kept.len())
            .field("stderr_truncated", &self.stderr.truncated)
            .field("duration", &self.duration)
            .finish()
    }
}

impl ProcessOutcome {
    fn unobserved() -> Self {
        Self {
            termination: Termination::Unobserved,
            exit: None,
            stdout: Vec::new(),
            stderr: StderrCapture::default(),
            duration: Duration::ZERO,
        }
    }

    /// Whether the process broke the command contract: too much stdout, or
    /// pipes held open past the drain.
    pub(crate) fn contract_violation(&self) -> bool {
        matches!(
            self.termination,
            Termination::OutputExceeded | Termination::PipesHeldOpen
        )
    }

    /// Whether the leader ended on its own with a failure, a non-zero exit
    /// or a signal the Broker did not send, which leaves no document to read
    /// but breaks no command contract. A clean exit's verdict waits for its
    /// document; a run the Broker stopped has none.
    pub(crate) fn ended_on_its_own(&self) -> bool {
        self.termination == Termination::Exited
            && self.exit.is_some_and(|exit| exit.code != Some(0))
    }
}

/// The invocation's side of a supervised process. Dropping it before the
/// process group is released kills the group at once; the supervisor still
/// reaps, drains and only then returns the permit.
pub(crate) struct SupervisorHandle<S: GroupSignals> {
    lock: Arc<SignalLock<S>>,
    outcome: oneshot::Receiver<ProcessOutcome>,
    #[cfg(test)]
    group: i32,
}

impl<S: GroupSignals> SupervisorHandle<S> {
    /// Waits for the supervisor's outcome.
    pub(crate) async fn outcome(mut self) -> ProcessOutcome {
        (&mut self.outcome)
            .await
            .unwrap_or_else(|_| ProcessOutcome::unobserved())
    }

    #[cfg(test)]
    pub(crate) fn process_group(&self) -> i32 {
        self.group
    }
}

impl<S: GroupSignals> Drop for SupervisorHandle<S> {
    fn drop(&mut self) {
        self.lock.kill(KillCause::Requested);
    }
}

/// Starts `launch` under a supervisor that owns `permit` and records into
/// `facts`.
pub(crate) fn start_command(
    permit: CommandPermit,
    launch: &CommandLaunch,
    stdin: StdinPayload,
    limits: SupervisionLimits,
    facts: CommandProcessFacts,
) -> Result<SupervisorHandle<OsSignals>, StartError> {
    start(
        permit,
        OsSignals,
        || process::spawn(launch),
        stdin,
        limits,
        facts,
    )
}

/// Registers a supervisor for `permit`, spawns the process unless a kill
/// was already requested or the deadline has passed, and hands both to the
/// supervisor task. The facts count the process as spawned once the
/// supervisor owns it with its pipes.
pub(crate) fn start<P: SupervisedProcess, S: GroupSignals>(
    permit: CommandPermit,
    signals: S,
    spawn: impl FnOnce() -> io::Result<P>,
    stdin: StdinPayload,
    limits: SupervisionLimits,
    facts: CommandProcessFacts,
) -> Result<SupervisorHandle<S>, StartError> {
    let lock = Arc::new(SignalLock::new(signals));
    let control: Arc<dyn CommandProcessControl> = lock.clone();
    let live = permit
        .register(control)
        .map_err(|_| StartError::Cancelled)?;
    if !lock.may_spawn() {
        return Err(StartError::Cancelled);
    }
    // A permit granted at or after the deadline starts nothing.
    if Instant::now() >= limits.deadline {
        return Err(StartError::DeadlineExceeded);
    }
    let mut process = match spawn() {
        Ok(process) => process,
        Err(error) => {
            lock.release_unsignalled();
            return Err(StartError::Spawn(error));
        }
    };
    let group = process.group();
    lock.go_live(group);
    let Some(pipes) = process.take_pipes() else {
        // Kill while the unreaped leader still reserves the group ID; the
        // runtime reaps the dropped child.
        lock.kill_and_release();
        return Err(StartError::Spawn(io::Error::other(
            "the spawned command has no pipes",
        )));
    };
    facts.record_spawned();
    let (deliver, outcome) = oneshot::channel();
    // The task owns the process through a guard that exists before the
    // task first runs, so dropping the task unpolled still kills the group.
    let owned = Owned {
        process,
        _live: live,
        lock: Arc::clone(&lock),
    };
    tokio::spawn(supervise(
        owned,
        pipes,
        stdin,
        limits,
        Supervision { facts, deliver },
    ));
    Ok(SupervisorHandle {
        lock,
        outcome,
        #[cfg(test)]
        group,
    })
}

/// What the supervisor task owns: the process, its registration and its
/// signal lock. Dropping it, however the task ends and even before the task
/// first runs, kills a still-live group before the process is dropped and
/// then the permit returned.
struct Owned<P: SupervisedProcess, S: GroupSignals> {
    process: P,
    /// The registration and its permit, held until dropped.
    _live: LiveCommandProcess,
    lock: Arc<SignalLock<S>>,
}

impl<P: SupervisedProcess, S: GroupSignals> Drop for Owned<P, S> {
    fn drop(&mut self) {
        self.lock.kill_and_release();
    }
}

type Pipes<P> = (
    <P as SupervisedProcess>::Stdin,
    <P as SupervisedProcess>::Stdout,
    <P as SupervisedProcess>::Stderr,
);

/// Where the supervisor reports: the run's facts cell and the invocation's
/// outcome channel.
struct Supervision {
    facts: CommandProcessFacts,
    deliver: oneshot::Sender<ProcessOutcome>,
}

/// The supervisor task: drives the stdin writer, the stdout and stderr
/// readers and the exit watcher concurrently, so no pipe can block another,
/// and kills the group at the deadline or on output overflow. When the
/// leader exits it kills and releases the group, reaps the leader, aborts
/// the writer and drains the readers for at most [`POST_EXIT_DRAIN`].
async fn supervise<P: SupervisedProcess, S: GroupSignals>(
    mut owned: Owned<P, S>,
    (stdin_pipe, stdout_pipe, stderr_pipe): Pipes<P>,
    stdin: StdinPayload,
    limits: SupervisionLimits,
    Supervision { facts, deliver }: Supervision,
) {
    let started = Instant::now();
    let lock = Arc::clone(&owned.lock);
    let mut stdout = StdoutCapture::default();
    let mut stderr = StderrCapture::default();
    let (observed, exit, drained) = {
        let mut writer = Box::pin(write_stdin(stdin_pipe, stdin));
        let mut stdout_reader = Box::pin(read_stdout(
            stdout_pipe,
            limits.max_output_bytes,
            &mut stdout,
            || lock.kill(KillCause::OutputExceeded),
        ));
        let mut stderr_reader = Box::pin(read_stderr(stderr_pipe, &mut stderr));
        let deadline = tokio::time::sleep_until(limits.deadline);
        tokio::pin!(deadline);
        let (mut writing, mut reading_stdout, mut reading_stderr, mut timing) =
            (true, true, true, true);
        let exited = {
            let exit = owned.process.exited();
            tokio::pin!(exit);
            loop {
                tokio::select! {
                    biased;
                    result = &mut exit => break result,
                    () = &mut deadline, if timing => {
                        timing = false;
                        lock.kill(KillCause::Deadline);
                    }
                    () = &mut writer, if writing => writing = false,
                    () = &mut stdout_reader, if reading_stdout => reading_stdout = false,
                    () = &mut stderr_reader, if reading_stderr => reading_stderr = false,
                }
            }
        };
        // The stdin writer is aborted at exit.
        drop(writer);
        let observed = exited.is_ok();
        let exit = if observed {
            lock.kill_and_release();
            owned.process.reap().await.ok()
        } else {
            lock.release_unsignalled();
            None
        };
        let stdout_closed = async {
            if reading_stdout {
                stdout_reader.as_mut().await;
            }
        };
        let stderr_closed = async {
            if reading_stderr {
                stderr_reader.as_mut().await;
            }
        };
        let drained = tokio::time::timeout(POST_EXIT_DRAIN, async {
            tokio::join!(stdout_closed, stderr_closed);
        })
        .await
        .is_ok();
        (observed, exit, drained)
    };
    // Stdout can also overflow while draining after the exit, when the group
    // is already released and records no kill cause.
    let termination = match (observed, lock.kill_cause()) {
        (false, _) => Termination::Unobserved,
        (true, Some(KillCause::Deadline)) => Termination::TimedOut,
        (true, Some(KillCause::OutputExceeded)) => Termination::OutputExceeded,
        (true, Some(KillCause::Requested)) => Termination::Killed,
        (true, None) if stdout.overflowed => Termination::OutputExceeded,
        (true, None) if !drained => Termination::PipesHeldOpen,
        (true, None) => Termination::Exited,
    };
    let outcome = ProcessOutcome {
        termination,
        exit,
        stdout: if stdout.overflowed {
            Vec::new()
        } else {
            stdout.bytes
        },
        stderr,
        duration: started.elapsed(),
    };
    facts.record_finished(
        outcome.exit.and_then(|exit| exit.code),
        outcome.exit.and_then(|exit| exit.signal),
        outcome.duration,
    );
    if outcome.contract_violation() {
        facts.record_contract_violation();
    } else if outcome.ended_on_its_own() {
        facts.record_contract_kept();
    }
    // The facts are recorded, then the process is dropped and the permit
    // returns to the budget before the supervisor leaves the registry, all
    // before the outcome is delivered.
    drop(lock);
    drop(owned);
    let _ = deliver.send(outcome);
}

#[cfg(test)]
mod tests {
    use super::double::{GROUP, ProcessDriver, RecordingSignals, fake_process};
    use super::*;
    use agent_access_core::imports::{CommandProcessFactsSnapshot, CommandRegistry};
    use futures_util::FutureExt;
    use tokio::io::AsyncReadExt;

    const COMMAND: &str = "fake";

    fn far() -> Instant {
        Instant::now() + Duration::from_secs(30)
    }

    fn limits(deadline: Instant, max_output_bytes: usize) -> SupervisionLimits {
        SupervisionLimits {
            deadline,
            max_output_bytes,
        }
    }

    fn exited_ok() -> ProcessExit {
        ProcessExit {
            code: Some(0),
            signal: None,
        }
    }

    async fn started(
        registry: &CommandRegistry,
        signals: &RecordingSignals,
        stdin: &[u8],
        stdin_capacity: usize,
        limits: SupervisionLimits,
    ) -> (SupervisorHandle<RecordingSignals>, ProcessDriver) {
        started_with_facts(
            registry,
            signals,
            stdin,
            stdin_capacity,
            limits,
            CommandProcessFacts::new(),
        )
        .await
    }

    async fn started_with_facts(
        registry: &CommandRegistry,
        signals: &RecordingSignals,
        stdin: &[u8],
        stdin_capacity: usize,
        limits: SupervisionLimits,
        facts: CommandProcessFacts,
    ) -> (SupervisorHandle<RecordingSignals>, ProcessDriver) {
        let permit = registry.acquire(COMMAND, 1, far()).await.unwrap();
        let (process, driver) = fake_process(exited_ok(), stdin_capacity);
        let handle = start(
            permit,
            signals.clone(),
            move || Ok(process),
            StdinPayload::new(stdin.to_vec()),
            limits,
            facts,
        )
        .unwrap();
        (handle, driver)
    }

    /// Waits until the supervisor has returned its permit and left the
    /// registry.
    async fn released(registry: &CommandRegistry) {
        tokio::time::timeout(Duration::from_secs(5), async {
            while registry.live_processes() != 0 || registry.in_use(COMMAND) != 0 {
                tokio::time::sleep(Duration::from_millis(1)).await;
            }
        })
        .await
        .expect("the supervisor returns its permit");
    }

    async fn killed(signals: &RecordingSignals, count: usize) {
        tokio::time::timeout(Duration::from_secs(5), async {
            while signals.kills() < count {
                tokio::time::sleep(Duration::from_millis(1)).await;
            }
        })
        .await
        .expect("the supervisor kills the group");
    }

    #[tokio::test]
    async fn the_exit_path_kills_before_reaping_and_returns_the_permit_before_delivery() {
        let registry = CommandRegistry::new();
        let signals = RecordingSignals::default();
        let (handle, mut driver) =
            started(&registry, &signals, b"request", 1024, limits(far(), 1024)).await;
        driver.write_stdout(b"{\"ok\":true}").await;
        driver.write_stderr(b"diagnostic").await;
        let mut request = Vec::new();
        driver.stdin.read_to_end(&mut request).await.unwrap();
        assert_eq!(request, b"request");

        driver.exit();
        driver.reaping().await;
        assert_eq!(signals.groups(), [GROUP]);
        assert_eq!(registry.in_use(COMMAND), 1);
        driver.finish_reaping();
        driver.close_output();
        let outcome = handle.outcome().await;

        assert_eq!(outcome.termination, Termination::Exited);
        assert_eq!(outcome.exit, Some(exited_ok()));
        assert_eq!(outcome.stdout, b"{\"ok\":true}");
        assert_eq!(outcome.stderr.kept, b"diagnostic");
        assert_eq!(registry.in_use(COMMAND), 0);
        assert_eq!(registry.live_processes(), 0);
        assert_eq!(signals.groups(), [GROUP]);
    }

    #[tokio::test]
    async fn a_handle_drop_before_reaping_kills_the_group_at_once() {
        let registry = CommandRegistry::new();
        let signals = RecordingSignals::default();
        let (handle, mut driver) =
            started(&registry, &signals, b"request", 1024, limits(far(), 1024)).await;

        drop(handle);
        assert_eq!(signals.groups(), [GROUP]);
        assert_eq!(registry.in_use(COMMAND), 1);

        // The kill ends the leader; the exit path kills what is left of the
        // group before it reaps.
        driver.exit();
        driver.reaping().await;
        assert_eq!(signals.groups(), [GROUP, GROUP]);
        driver.finish_reaping();
        driver.close_output();
        released(&registry).await;
        assert_eq!(signals.kills(), 2);
    }

    #[tokio::test]
    async fn a_handle_drop_while_reaping_sends_no_signal() {
        let registry = CommandRegistry::new();
        let signals = RecordingSignals::default();
        let (handle, mut driver) =
            started(&registry, &signals, b"", 1024, limits(far(), 1024)).await;
        driver.exit();
        driver.reaping().await;
        assert_eq!(signals.kills(), 1);

        drop(handle);
        assert_eq!(signals.kills(), 1);

        driver.finish_reaping();
        driver.close_output();
        released(&registry).await;
        assert_eq!(signals.kills(), 1);
    }

    #[tokio::test]
    async fn a_handle_drop_while_draining_after_exit_sends_no_signal() {
        let registry = CommandRegistry::new();
        let signals = RecordingSignals::default();
        let (handle, mut driver) =
            started(&registry, &signals, b"", 1024, limits(far(), 1024)).await;
        driver.exit();
        driver.reaping().await;
        driver.finish_reaping();
        // Stdout stays open, so the supervisor is draining.
        tokio::time::sleep(Duration::from_millis(100)).await;
        assert_eq!(registry.in_use(COMMAND), 1);

        drop(handle);
        assert_eq!(signals.kills(), 1);

        driver.close_output();
        released(&registry).await;
        assert_eq!(signals.kills(), 1);
    }

    #[tokio::test]
    async fn a_handle_drop_during_outcome_delivery_sends_no_signal() {
        let registry = CommandRegistry::new();
        let signals = RecordingSignals::default();
        let (handle, mut driver) =
            started(&registry, &signals, b"", 1024, limits(far(), 1024)).await;
        driver.close_output();
        driver.exit();
        driver.reaping().await;
        driver.finish_reaping();
        // The outcome is sent but not yet received.
        released(&registry).await;

        drop(handle);
        assert_eq!(signals.kills(), 1);
    }

    #[tokio::test]
    async fn the_stdin_writer_is_aborted_at_exit() {
        let registry = CommandRegistry::new();
        let signals = RecordingSignals::default();
        // The process never reads a request larger than its stdin pipe.
        let (handle, mut driver) =
            started(&registry, &signals, &[b'r'; 1024], 64, limits(far(), 1024)).await;
        driver.exit();
        driver.reaping().await;
        driver.finish_reaping();
        driver.close_output();
        let outcome = handle.outcome().await;

        assert_eq!(outcome.termination, Termination::Exited);
        let mut written = Vec::new();
        driver.stdin.read_to_end(&mut written).await.unwrap();
        assert!(written.len() < 1024);
    }

    #[tokio::test]
    async fn the_command_deadline_kills_the_group() {
        let registry = CommandRegistry::new();
        let signals = RecordingSignals::default();
        let deadline = Instant::now() + Duration::from_millis(50);
        let (handle, mut driver) =
            started(&registry, &signals, b"", 1024, limits(deadline, 1024)).await;

        killed(&signals, 1).await;
        driver.exit();
        driver.reaping().await;
        driver.finish_reaping();
        driver.close_output();
        let outcome = handle.outcome().await;

        assert_eq!(outcome.termination, Termination::TimedOut);
        assert!(!outcome.contract_violation());
        assert_eq!(signals.groups(), [GROUP, GROUP]);
    }

    #[tokio::test]
    async fn stdout_over_the_cap_kills_the_group() {
        let registry = CommandRegistry::new();
        let signals = RecordingSignals::default();
        let facts = CommandProcessFacts::new();
        let (handle, mut driver) = started_with_facts(
            &registry,
            &signals,
            b"",
            1024,
            limits(far(), 8),
            facts.clone(),
        )
        .await;

        driver.write_stdout(b"0123456789").await;
        killed(&signals, 1).await;
        driver.write_stdout(b"discarded").await;
        driver.exit();
        driver.reaping().await;
        driver.finish_reaping();
        driver.close_output();
        let outcome = handle.outcome().await;

        assert_eq!(outcome.termination, Termination::OutputExceeded);
        assert!(outcome.contract_violation());
        assert!(outcome.stdout.is_empty());
        assert_eq!(facts.snapshot().contract_violation, Some(true));
    }

    #[tokio::test]
    async fn stdout_overflowing_after_the_exit_is_a_contract_violation() {
        let registry = CommandRegistry::new();
        let signals = RecordingSignals::default();
        let facts = CommandProcessFacts::new();
        let (handle, mut driver) = started_with_facts(
            &registry,
            &signals,
            b"",
            1024,
            limits(far(), 8),
            facts.clone(),
        )
        .await;

        // The process writes past the cap and exits before the supervisor
        // first reads stdout, so the overflow is found while draining.
        driver.write_stdout(b"0123456789").await;
        driver.exit();
        driver.reaping().await;
        driver.finish_reaping();
        driver.close_output();
        let outcome = handle.outcome().await;

        assert_eq!(outcome.termination, Termination::OutputExceeded);
        assert!(outcome.contract_violation());
        assert!(outcome.stdout.is_empty());
        assert_eq!(facts.snapshot().contract_violation, Some(true));
        assert_eq!(signals.groups(), [GROUP]);
    }

    #[test]
    fn a_supervisor_dropped_before_it_first_runs_kills_the_group() {
        let registry = CommandRegistry::new();
        let signals = RecordingSignals::default();
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let (handle, _driver) = runtime.block_on(async {
            let permit = registry.acquire(COMMAND, 1, far()).await.unwrap();
            let (process, driver) = fake_process(exited_ok(), 1024);
            let handle = start(
                permit,
                signals.clone(),
                move || Ok(process),
                StdinPayload::empty(),
                limits(far(), 1024),
                CommandProcessFacts::new(),
            )
            .unwrap();
            (handle, driver)
        });
        assert!(signals.groups().is_empty());

        // The runtime shuts down before the supervisor task first runs.
        drop(runtime);
        assert_eq!(signals.groups(), [GROUP]);
        assert_eq!(registry.in_use(COMMAND), 0);
        assert_eq!(registry.live_processes(), 0);
        drop(handle);
        assert_eq!(signals.groups(), [GROUP]);
    }

    #[test]
    fn outcomes_never_show_command_output_in_debug() {
        let stdout = b"stdout-document".to_vec();
        let stderr = b"stderr-diagnostic".to_vec();
        let outcome = ProcessOutcome {
            termination: Termination::Exited,
            exit: Some(exited_ok()),
            stdout: stdout.clone(),
            stderr: StderrCapture {
                kept: stderr.clone(),
                truncated: false,
            },
            duration: Duration::ZERO,
        };
        let debug = format!("{outcome:?}");
        assert!(!debug.contains(&format!("{stdout:?}")), "{debug}");
        assert!(!debug.contains(&format!("{stderr:?}")), "{debug}");
        assert!(!debug.contains("stdout-document"), "{debug}");
        assert!(debug.contains("stdout_bytes: 15"), "{debug}");
    }

    #[tokio::test]
    async fn facts_outlive_a_dropped_handle_and_are_final_before_the_permit_returns() {
        let registry = CommandRegistry::new();
        let signals = RecordingSignals::default();
        let facts = CommandProcessFacts::new();
        let (handle, mut driver) = started_with_facts(
            &registry,
            &signals,
            b"",
            1024,
            limits(far(), 1024),
            facts.clone(),
        )
        .await;
        assert_eq!(
            facts.snapshot(),
            CommandProcessFactsSnapshot {
                spawned: true,
                ..Default::default()
            }
        );

        // The host interrupted the invocation; the facts known then stay
        // readable, and the rest arrive once the leader is reaped.
        drop(handle);
        driver.exit();
        driver.reaping().await;
        assert_eq!(facts.snapshot().exit_code, None);
        driver.finish_reaping();
        driver.close_output();
        released(&registry).await;

        let recorded = facts.snapshot();
        assert!(recorded.spawned);
        assert_eq!(recorded.exit_code, Some(0));
        assert_eq!(recorded.signal, None);
        assert!(recorded.duration_ms.is_some());
        // A clean exit's verdict waits for its document.
        assert_eq!(recorded.contract_violation, None);
    }

    #[tokio::test]
    async fn a_kill_requested_during_the_spawn_kills_once_the_group_is_live() {
        let registry = CommandRegistry::new();
        let signals = RecordingSignals::default();
        let permit = registry.acquire(COMMAND, 1, far()).await.unwrap();
        let (process, mut driver) = fake_process(exited_ok(), 1024);
        let handle = start(
            permit,
            signals.clone(),
            || {
                // Shutdown starts while the process is being spawned.
                let _ = registry.close_and_drain(Duration::ZERO).now_or_never();
                assert!(signals.groups().is_empty());
                Ok(process)
            },
            StdinPayload::empty(),
            limits(far(), 1024),
            CommandProcessFacts::new(),
        )
        .unwrap();
        assert_eq!(signals.groups(), [GROUP]);

        driver.exit();
        driver.reaping().await;
        driver.finish_reaping();
        driver.close_output();
        let outcome = handle.outcome().await;
        assert_eq!(outcome.termination, Termination::Killed);
        assert_eq!(registry.in_use(COMMAND), 0);
    }

    #[tokio::test]
    async fn a_call_after_shutdown_began_never_spawns() {
        let registry = CommandRegistry::new();
        let signals = RecordingSignals::default();
        let permit = registry.acquire(COMMAND, 1, far()).await.unwrap();
        assert_eq!(registry.close_and_drain(Duration::ZERO).await, 0);
        let mut spawned = false;
        let facts = CommandProcessFacts::new();

        let error = start(
            permit,
            signals.clone(),
            || {
                spawned = true;
                Ok(fake_process(exited_ok(), 1024).0)
            },
            StdinPayload::empty(),
            limits(far(), 1024),
            facts.clone(),
        )
        .err()
        .unwrap();

        assert!(matches!(error, StartError::Cancelled));
        assert!(!spawned);
        assert!(!facts.snapshot().spawned);
        assert!(signals.groups().is_empty());
        assert_eq!(registry.in_use(COMMAND), 0);
    }

    #[tokio::test]
    async fn a_permit_whose_deadline_has_passed_never_spawns() {
        let registry = CommandRegistry::new();
        let signals = RecordingSignals::default();
        let permit = registry.acquire(COMMAND, 1, far()).await.unwrap();
        let facts = CommandProcessFacts::new();
        let mut spawned = false;

        let error = start(
            permit,
            signals.clone(),
            || {
                spawned = true;
                Ok(fake_process(exited_ok(), 1024).0)
            },
            StdinPayload::empty(),
            limits(Instant::now(), 1024),
            facts.clone(),
        )
        .err()
        .unwrap();

        assert!(matches!(error, StartError::DeadlineExceeded));
        assert!(!spawned);
        assert!(!facts.snapshot().spawned);
        assert!(signals.groups().is_empty());
        assert_eq!(registry.in_use(COMMAND), 0);
        assert_eq!(registry.live_processes(), 0);
    }

    #[tokio::test]
    async fn a_spawn_failure_returns_the_permit_without_a_signal() {
        let registry = CommandRegistry::new();
        let signals = RecordingSignals::default();
        let permit = registry.acquire(COMMAND, 1, far()).await.unwrap();

        let error = start::<super::double::FakeProcess, _>(
            permit,
            signals.clone(),
            || Err(io::Error::from(io::ErrorKind::NotFound)),
            StdinPayload::empty(),
            limits(far(), 1024),
            CommandProcessFacts::new(),
        )
        .err()
        .unwrap();

        assert!(matches!(error, StartError::Spawn(_)));
        assert!(signals.groups().is_empty());
        assert_eq!(registry.in_use(COMMAND), 0);
        assert_eq!(registry.live_processes(), 0);
    }

    #[tokio::test]
    async fn shutdown_waits_for_a_killed_supervisor_to_reap_and_return_its_permit() {
        let registry = CommandRegistry::new();
        let signals = RecordingSignals::default();
        let (handle, mut driver) =
            started(&registry, &signals, b"", 1024, limits(far(), 1024)).await;
        // The invocation already finalized.
        drop(handle);
        let mut drain = Box::pin(registry.close_and_drain(Duration::from_secs(5)));
        assert!(drain.as_mut().now_or_never().is_none());

        driver.exit();
        driver.reaping().await;
        assert_eq!(registry.in_use(COMMAND), 1);
        driver.finish_reaping();
        driver.close_output();

        assert_eq!(drain.await, 0);
        assert_eq!(registry.in_use(COMMAND), 0);
    }

    #[tokio::test]
    async fn excess_stderr_is_discarded_without_failing() {
        let registry = CommandRegistry::new();
        let signals = RecordingSignals::default();
        let (handle, mut driver) =
            started(&registry, &signals, b"", 1024, limits(far(), 1024)).await;
        for _ in 0..3 {
            driver
                .write_stderr(&[b'e'; process::STDERR_KEPT_BYTES])
                .await;
        }
        driver.exit();
        driver.reaping().await;
        driver.finish_reaping();
        driver.close_output();
        let outcome = handle.outcome().await;

        assert_eq!(outcome.termination, Termination::Exited);
        assert_eq!(outcome.stderr.kept.len(), process::STDERR_KEPT_BYTES);
        assert!(outcome.stderr.truncated);
    }

    #[tokio::test]
    async fn a_closed_stdin_ends_the_write_without_failing() {
        let (ours, theirs) = tokio::io::duplex(8);
        drop(theirs);
        tokio::time::timeout(
            Duration::from_secs(5),
            write_stdin(ours, StdinPayload::new(vec![b'r'; 64])),
        )
        .await
        .expect("a closed stdin ends the write");
    }
}
