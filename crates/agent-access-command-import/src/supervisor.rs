//! The supervisor of one command process.
//!
//! After the spawn, the child, its pipes, the four I/O branches and the
//! budget permit move into one supervisor task, separate from the
//! invocation future, which awaits the outcome through a channel. The
//! supervisor registers with the command registry before it spawns, so
//! shutdown can kill its process group whatever became of the invocation.
//! It returns the permit only after the group is killed and reaped and every
//! I/O branch has finished. It never finalizes or audits a call.
use crate::process::{
    self, CommandLaunch, GroupSignals, KillCause, OsSignals, POST_EXIT_DRAIN, ProcessExit,
    SignalLock, StderrCapture, StdinPayload, StdoutCapture, SupervisedProcess, read_stderr,
    read_stdout, write_stdin,
};
use agent_access_core::imports::{CommandPermit, CommandProcessControl, LiveCommandProcess};
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

/// The result of one supervised process.
#[derive(Debug)]
pub(crate) struct ProcessOutcome {
    pub(crate) termination: Termination,
    /// The reaped leader's status; `None` when it was not reaped.
    pub(crate) exit: Option<ProcessExit>,
    /// Stdout up to `max_output_bytes`; empty when it overflowed.
    pub(crate) stdout: Vec<u8>,
    pub(crate) stderr: StderrCapture,
    pub(crate) duration: Duration,
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

/// Starts `launch` under a supervisor that owns `permit`.
pub(crate) fn start_command(
    permit: CommandPermit,
    launch: &CommandLaunch,
    stdin: StdinPayload,
    limits: SupervisionLimits,
) -> Result<SupervisorHandle<OsSignals>, StartError> {
    start(permit, OsSignals, || process::spawn(launch), stdin, limits)
}

/// Registers a supervisor for `permit`, spawns the process unless a kill
/// was already requested, and hands both to the supervisor task.
pub(crate) fn start<P: SupervisedProcess, S: GroupSignals>(
    permit: CommandPermit,
    signals: S,
    spawn: impl FnOnce() -> io::Result<P>,
    stdin: StdinPayload,
    limits: SupervisionLimits,
) -> Result<SupervisorHandle<S>, StartError> {
    let lock = Arc::new(SignalLock::new(signals));
    let control: Arc<dyn CommandProcessControl> = lock.clone();
    let live = permit
        .register(control)
        .map_err(|_| StartError::Cancelled)?;
    if !lock.may_spawn() {
        return Err(StartError::Cancelled);
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
    let (deliver, outcome) = oneshot::channel();
    tokio::spawn(supervise(
        process,
        pipes,
        Arc::clone(&lock),
        live,
        stdin,
        limits,
        deliver,
    ));
    Ok(SupervisorHandle {
        lock,
        outcome,
        #[cfg(test)]
        group,
    })
}

/// Kills a still-live group if the supervisor task ends abnormally, before
/// its permit is returned.
struct KillOnUnwind<'a, S: GroupSignals>(&'a SignalLock<S>);

impl<S: GroupSignals> Drop for KillOnUnwind<'_, S> {
    fn drop(&mut self) {
        self.0.kill_and_release();
    }
}

type Pipes<P> = (
    <P as SupervisedProcess>::Stdin,
    <P as SupervisedProcess>::Stdout,
    <P as SupervisedProcess>::Stderr,
);

/// The supervisor task: drives the stdin writer, the stdout and stderr
/// readers and the exit watcher concurrently, so no pipe can block another,
/// and kills the group at the deadline or on output overflow. When the
/// leader exits it kills and releases the group, reaps the leader, aborts
/// the writer and drains the readers for at most [`POST_EXIT_DRAIN`].
async fn supervise<P: SupervisedProcess, S: GroupSignals>(
    mut process: P,
    (stdin_pipe, stdout_pipe, stderr_pipe): Pipes<P>,
    lock: Arc<SignalLock<S>>,
    live: LiveCommandProcess,
    stdin: StdinPayload,
    limits: SupervisionLimits,
    deliver: oneshot::Sender<ProcessOutcome>,
) {
    let started = Instant::now();
    let unwind = KillOnUnwind(&lock);
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
            let exit = process.exited();
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
            process.reap().await.ok()
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
    let termination = match (observed, lock.kill_cause()) {
        (false, _) => Termination::Unobserved,
        (true, Some(KillCause::Deadline)) => Termination::TimedOut,
        (true, Some(KillCause::OutputExceeded)) => Termination::OutputExceeded,
        (true, Some(KillCause::Requested)) => Termination::Killed,
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
    drop(unwind);
    drop(process);
    // The permit returns to the budget before the supervisor leaves the
    // registry, and both before the outcome is delivered.
    drop(live);
    let _ = deliver.send(outcome);
}

#[cfg(test)]
mod tests {
    use super::double::{GROUP, ProcessDriver, RecordingSignals, fake_process};
    use super::*;
    use crate::process::CommandOperation;
    use agent_access_core::imports::CommandRegistry;
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
        let permit = registry.acquire(COMMAND, 1, far()).await.unwrap();
        let (process, driver) = fake_process(exited_ok(), stdin_capacity);
        let handle = start(
            permit,
            signals.clone(),
            move || Ok(process),
            StdinPayload::new(stdin.to_vec()),
            limits,
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

    #[test]
    fn each_operation_is_its_own_single_argument() {
        assert_eq!(CommandOperation::Describe.argument(), "describe");
        assert_eq!(CommandOperation::Invoke.argument(), "invoke");
        assert_eq!(CommandOperation::Verify.argument(), "verify");
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
        let (handle, mut driver) = started(&registry, &signals, b"", 1024, limits(far(), 8)).await;

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

        let error = start(
            permit,
            signals.clone(),
            || {
                spawned = true;
                Ok(fake_process(exited_ok(), 1024).0)
            },
            StdinPayload::empty(),
            limits(far(), 1024),
        )
        .err()
        .unwrap();

        assert!(matches!(error, StartError::Cancelled));
        assert!(!spawned);
        assert!(signals.groups().is_empty());
        assert_eq!(registry.in_use(COMMAND), 0);
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
