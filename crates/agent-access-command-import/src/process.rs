//! One command process: how it is started, its I/O branches and their
//! bounds, exit observation without reaping, and the signal lock, which alone
//! may signal its process group.
//!
//! A command runs as `<path> <operation>` in a new process group, with an
//! empty environment plus the configured variables, its working directory,
//! and stdin, stdout and stderr piped. Request data never travels in its
//! arguments or environment.
use agent_access_core::imports::CommandProcessControl;
use std::ffi::OsString;
use std::future::Future;
use std::io;
use std::path::PathBuf;
use std::process::Stdio;
use std::sync::{Mutex, MutexGuard};
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

/// The stderr bytes kept; the rest is drained and discarded.
pub(crate) const STDERR_KEPT_BYTES: usize = 4 * 1024;
/// How long stdout and stderr may stay open after the leader is reaped.
pub(crate) const POST_EXIT_DRAIN: Duration = Duration::from_secs(1);
const READ_CHUNK_BYTES: usize = 8 * 1024;
/// How often a leader's exit is checked when child signals are unavailable.
const EXIT_POLL_INTERVAL: Duration = Duration::from_millis(50);

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

/// How to start one command process. `env` is the whole environment: the
/// configured variables and the network settings.
#[derive(Debug, Clone)]
pub(crate) struct CommandLaunch {
    pub(crate) program: PathBuf,
    pub(crate) operation: CommandOperation,
    pub(crate) env: Vec<(OsString, OsString)>,
    pub(crate) working_dir: PathBuf,
}

/// The bytes written to a process's stdin. They are dropped once written or
/// abandoned, so a zeroizing buffer is wiped then.
pub(crate) struct StdinPayload(Box<dyn AsRef<[u8]> + Send + Sync>);

impl StdinPayload {
    pub(crate) fn new(bytes: impl AsRef<[u8]> + Send + Sync + 'static) -> Self {
        Self(Box::new(bytes))
    }

    /// No request, as for `describe`: stdin is closed at once.
    pub(crate) fn empty() -> Self {
        Self::new([0_u8; 0])
    }

    fn bytes(&self) -> &[u8] {
        (*self.0).as_ref()
    }
}

/// How the leader ended, once reaped.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct ProcessExit {
    pub(crate) code: Option<i32>,
    pub(crate) signal: Option<i32>,
}

impl From<std::process::ExitStatus> for ProcessExit {
    fn from(status: std::process::ExitStatus) -> Self {
        use std::os::unix::process::ExitStatusExt;
        Self {
            code: status.code(),
            signal: status.signal(),
        }
    }
}

/// What the supervisor needs from a started process. The OS implementation
/// is [`OsProcess`]; tests substitute a process-control double.
pub(crate) trait SupervisedProcess: Send + 'static {
    type Stdin: AsyncWrite + Unpin + Send + 'static;
    type Stdout: AsyncRead + Unpin + Send + 'static;
    type Stderr: AsyncRead + Unpin + Send + 'static;

    /// The leader's process ID, which is also its process group ID.
    fn group(&self) -> i32;

    /// The three pipes, once.
    fn take_pipes(&mut self) -> Option<(Self::Stdin, Self::Stdout, Self::Stderr)>;

    /// Resolves once the leader has exited, leaving it unreaped so that its
    /// process ID, and with it the group ID, stays reserved.
    fn exited(&mut self) -> impl Future<Output = io::Result<()>> + Send;

    /// Reaps the exited leader, releasing its process ID.
    fn reap(&mut self) -> impl Future<Output = io::Result<ProcessExit>> + Send;
}

/// Sends `SIGKILL` to a process group. Only a [`SignalLock`] calls it.
pub(crate) trait GroupSignals: Send + Sync + 'static {
    fn kill_group(&self, group: i32);
}

/// Process group signals through the operating system.
#[derive(Debug, Clone, Copy, Default)]
pub(crate) struct OsSignals;

impl GroupSignals for OsSignals {
    fn kill_group(&self, group: i32) {
        // Group IDs 0 and 1 would name the Broker's own group or every
        // process; a started leader's ID is never either.
        if group <= 1 {
            return;
        }
        // SAFETY: kill has no memory-safety preconditions; a negative ID
        // names a process group. A group whose members all exited fails with
        // ESRCH, which needs no handling.
        unsafe {
            libc::kill(-group, libc::SIGKILL);
        }
    }
}

/// Why a supervisor's process group was killed, first cause first.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum KillCause {
    /// The command deadline passed.
    Deadline,
    /// Stdout exceeded `max_output_bytes`.
    OutputExceeded,
    /// The supervisor's handle was dropped, or the Broker is shutting down.
    Requested,
}

/// The only way to signal a process group. It guards one state: before the
/// spawn, `live`, or `released`. A kill request sends `SIGKILL` only while
/// the group is live. The exit path sends its own `SIGKILL` and marks the
/// group released under the same lock, before reaping releases the leader's
/// ID, so a kill can never reach a reused ID; requests after release are
/// no-ops. A request before the spawn prevents it, or kills the group as
/// soon as it is live.
pub(crate) struct SignalLock<S: GroupSignals> {
    state: Mutex<SignalState>,
    signals: S,
}

struct SignalState {
    phase: GroupPhase,
    cause: Option<KillCause>,
}

#[derive(Clone, Copy)]
enum GroupPhase {
    NotStarted,
    Live(i32),
    Released,
}

impl<S: GroupSignals> SignalLock<S> {
    pub(crate) fn new(signals: S) -> Self {
        Self {
            state: Mutex::new(SignalState {
                phase: GroupPhase::NotStarted,
                cause: None,
            }),
            signals,
        }
    }

    fn state(&self) -> MutexGuard<'_, SignalState> {
        self.state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    /// Kills the group now if it is live, remembering the first cause; a
    /// request before the spawn is remembered, and one after release is
    /// ignored.
    pub(crate) fn kill(&self, cause: KillCause) {
        let mut state = self.state();
        let group = match state.phase {
            GroupPhase::Released => return,
            GroupPhase::NotStarted => None,
            GroupPhase::Live(group) => Some(group),
        };
        state.cause.get_or_insert(cause);
        if let Some(group) = group {
            self.signals.kill_group(group);
        }
    }

    /// Whether the process may be spawned: no kill was requested.
    pub(crate) fn may_spawn(&self) -> bool {
        let state = self.state();
        matches!(state.phase, GroupPhase::NotStarted) && state.cause.is_none()
    }

    /// Marks the spawned group live; a kill requested during the spawn is
    /// carried out now.
    pub(crate) fn go_live(&self, group: i32) {
        let mut state = self.state();
        if !matches!(state.phase, GroupPhase::NotStarted) {
            return;
        }
        state.phase = GroupPhase::Live(group);
        if state.cause.is_some() {
            self.signals.kill_group(group);
        }
    }

    /// The exit path: kills whatever is left of the live group, then marks
    /// it released.
    pub(crate) fn kill_and_release(&self) {
        let mut state = self.state();
        if let GroupPhase::Live(group) = state.phase {
            self.signals.kill_group(group);
        }
        state.phase = GroupPhase::Released;
    }

    /// Releases without signalling: the spawn failed, or the leader's exit
    /// could not be observed, so its ID may no longer be reserved.
    pub(crate) fn release_unsignalled(&self) {
        self.state().phase = GroupPhase::Released;
    }

    /// The first reason the group was killed, if it was.
    pub(crate) fn kill_cause(&self) -> Option<KillCause> {
        self.state().cause
    }
}

impl<S: GroupSignals> CommandProcessControl for SignalLock<S> {
    fn request_kill(&self) {
        self.kill(KillCause::Requested);
    }
}

/// A started command process.
pub(crate) struct OsProcess {
    child: tokio::process::Child,
    pid: i32,
}

/// Starts `launch` in a new process group with only its configured
/// environment and piped stdio. Nothing reaps the child behind the
/// supervisor's back: it is waited on only through [`SupervisedProcess`].
pub(crate) fn spawn(launch: &CommandLaunch) -> io::Result<OsProcess> {
    let mut command = tokio::process::Command::new(&launch.program);
    command
        .arg(launch.operation.argument())
        .env_clear()
        .envs(launch.env.iter().map(|(key, value)| (key, value)))
        .current_dir(&launch.working_dir)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .process_group(0)
        .kill_on_drop(false);
    let mut child = command.spawn()?;
    match child
        .id()
        .and_then(|pid| i32::try_from(pid).ok())
        .filter(|pid| *pid > 1)
    {
        Some(pid) => Ok(OsProcess { child, pid }),
        None => {
            let _ = child.start_kill();
            Err(io::Error::other("the spawned command has no process ID"))
        }
    }
}

impl SupervisedProcess for OsProcess {
    type Stdin = tokio::process::ChildStdin;
    type Stdout = tokio::process::ChildStdout;
    type Stderr = tokio::process::ChildStderr;

    fn group(&self) -> i32 {
        self.pid
    }

    fn take_pipes(&mut self) -> Option<(Self::Stdin, Self::Stdout, Self::Stderr)> {
        Some((
            self.child.stdin.take()?,
            self.child.stdout.take()?,
            self.child.stderr.take()?,
        ))
    }

    async fn exited(&mut self) -> io::Result<()> {
        use tokio::signal::unix::{SignalKind, signal};
        // Listen before checking: an exit after the check still wakes the
        // wait. Other children's exits wake it too, and are checked again.
        // Without a child signal stream, poll instead.
        let mut child_signals = signal(SignalKind::child()).ok();
        loop {
            if leader_exited(self.pid)? {
                return Ok(());
            }
            match child_signals.as_mut() {
                Some(signals) => {
                    if signals.recv().await.is_none() {
                        child_signals = None;
                    }
                }
                None => tokio::time::sleep(EXIT_POLL_INTERVAL).await,
            }
        }
    }

    async fn reap(&mut self) -> io::Result<ProcessExit> {
        let status = match self.child.try_wait()? {
            Some(status) => status,
            None => self.child.wait().await?,
        };
        Ok(status.into())
    }
}

/// Whether the leader has exited, without reaping it.
fn leader_exited(pid: i32) -> io::Result<bool> {
    let id = libc::id_t::try_from(pid).map_err(io::Error::other)?;
    loop {
        // SAFETY: an all-zero siginfo_t is a valid value for waitid to fill,
        // and its zero si_pid stays when no child has changed state.
        let mut info: libc::siginfo_t = unsafe { std::mem::zeroed() };
        // SAFETY: `info` is a valid, writable siginfo_t for the call.
        let result = unsafe {
            libc::waitid(
                libc::P_PID,
                id,
                &mut info,
                libc::WEXITED | libc::WNOWAIT | libc::WNOHANG,
            )
        };
        if result == 0 {
            // SAFETY: waitid succeeded, so `info` is initialized; si_pid is
            // the exited child's ID, or zero when it is still running.
            return Ok(unsafe { info.si_pid() } != 0);
        }
        let error = io::Error::last_os_error();
        if error.kind() != io::ErrorKind::Interrupted {
            return Err(error);
        }
    }
}

/// The stdin branch: writes the request, then closes stdin. A process that
/// closes stdin or exits first ends the write, which is not a failure.
pub(crate) async fn write_stdin<W: AsyncWrite + Unpin>(mut pipe: W, payload: StdinPayload) {
    if pipe.write_all(payload.bytes()).await.is_ok() {
        let _ = pipe.shutdown().await;
    }
}

/// Stdout as read so far.
#[derive(Debug, Default)]
pub(crate) struct StdoutCapture {
    pub(crate) bytes: Vec<u8>,
    pub(crate) overflowed: bool,
}

/// The stdout branch: reads to EOF into `capture`, keeping at most `cap`
/// bytes. The first byte past `cap` discards what was kept and calls
/// `on_overflow`; the rest is drained and discarded.
pub(crate) async fn read_stdout<R: AsyncRead + Unpin>(
    mut pipe: R,
    cap: usize,
    capture: &mut StdoutCapture,
    on_overflow: impl FnOnce(),
) {
    let mut on_overflow = Some(on_overflow);
    let mut chunk = vec![0_u8; READ_CHUNK_BYTES];
    loop {
        let read = match pipe.read(&mut chunk).await {
            Ok(0) | Err(_) => return,
            Ok(read) => read,
        };
        if capture.overflowed {
            continue;
        }
        if capture.bytes.len() + read > cap {
            capture.overflowed = true;
            capture.bytes = Vec::new();
            if let Some(on_overflow) = on_overflow.take() {
                on_overflow();
            }
        } else {
            capture.bytes.extend_from_slice(&chunk[..read]);
        }
    }
}

/// Stderr as read so far: its first [`STDERR_KEPT_BYTES`].
#[derive(Debug, Default)]
pub(crate) struct StderrCapture {
    pub(crate) kept: Vec<u8>,
    pub(crate) truncated: bool,
}

/// The stderr branch: reads to EOF into `capture`, keeping the first
/// [`STDERR_KEPT_BYTES`] and discarding the rest. Excess stderr never fails
/// a call.
pub(crate) async fn read_stderr<R: AsyncRead + Unpin>(mut pipe: R, capture: &mut StderrCapture) {
    let mut chunk = vec![0_u8; READ_CHUNK_BYTES];
    loop {
        let read = match pipe.read(&mut chunk).await {
            Ok(0) | Err(_) => return,
            Ok(read) => read,
        };
        let room = STDERR_KEPT_BYTES - capture.kept.len();
        capture.kept.extend_from_slice(&chunk[..read.min(room)]);
        if read > room {
            capture.truncated = true;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::supervisor::{SupervisionLimits, SupervisorHandle, Termination, start_command};
    use agent_access_core::imports::CommandRegistry;
    use std::path::Path;
    use tokio::time::Instant;

    const PATH: &str = "/usr/bin:/bin";

    fn fixture(name: &str) -> PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures/process")
            .join(name)
    }

    fn launch(name: &str, env: &[(&str, &str)]) -> CommandLaunch {
        CommandLaunch {
            program: fixture(name),
            operation: CommandOperation::Invoke,
            env: [("PATH", PATH)]
                .iter()
                .chain(env)
                .map(|(key, value)| (OsString::from(key), OsString::from(value)))
                .collect(),
            working_dir: PathBuf::from("/"),
        }
    }

    fn limits(timeout: Duration, max_output_bytes: usize) -> SupervisionLimits {
        SupervisionLimits {
            deadline: Instant::now() + timeout,
            max_output_bytes,
        }
    }

    async fn start(
        registry: &CommandRegistry,
        launch: &CommandLaunch,
        stdin: StdinPayload,
        limits: SupervisionLimits,
    ) -> SupervisorHandle<OsSignals> {
        let permit = registry
            .acquire("fixture", 4, limits.deadline)
            .await
            .unwrap();
        start_command(permit, launch, stdin, limits).unwrap()
    }

    fn temp_file(name: &str) -> PathBuf {
        std::env::temp_dir().join(format!(
            "command-import-{name}-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ))
    }

    /// The leader was reaped by its supervisor: it is no longer this
    /// process's child, so no zombie of it remains.
    fn assert_reaped(pid: i32) {
        // SAFETY: waitpid with WNOHANG and a null status pointer only
        // queries the child table.
        let result = unsafe { libc::waitpid(pid, std::ptr::null_mut(), libc::WNOHANG) };
        assert_eq!(result, -1, "leader {pid} is still this process's child");
        assert_eq!(
            io::Error::last_os_error().raw_os_error(),
            Some(libc::ECHILD)
        );
    }

    /// A process outside this process's children has stopped running: it is
    /// gone, or a zombie awaiting its new parent.
    #[cfg(target_os = "linux")]
    fn assert_not_running(pid: i32) {
        let deadline = std::time::Instant::now() + Duration::from_secs(5);
        loop {
            let state = std::fs::read_to_string(format!("/proc/{pid}/stat"))
                .ok()
                .and_then(|stat| {
                    let (_, rest) = stat.rsplit_once(')')?;
                    rest.trim_start().chars().next()
                });
            if matches!(state, None | Some('Z' | 'X')) {
                return;
            }
            assert!(
                std::time::Instant::now() < deadline,
                "process {pid} is still running ({state:?})"
            );
            std::thread::sleep(Duration::from_millis(10));
        }
    }

    fn read_pid(path: &Path) -> i32 {
        std::fs::read_to_string(path)
            .unwrap_or_else(|error| panic!("{}: {error}", path.display()))
            .trim()
            .parse()
            .unwrap()
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn a_process_gets_only_its_operation_argument_and_configured_environment() {
        let registry = CommandRegistry::new();
        let mut command = launch(
            "environment.sh",
            &[("LANG", "C.UTF-8"), ("EXAMPLE_SETTING", "value")],
        );
        command.working_dir = std::env::temp_dir();
        let handle = start(
            &registry,
            &command,
            StdinPayload::new(b"{\"token\":\"secret-example\"}".to_vec()),
            limits(Duration::from_secs(10), 64 * 1024),
        )
        .await;
        let outcome = handle.outcome().await;

        assert_eq!(outcome.termination, Termination::Exited);
        assert_eq!(outcome.exit.unwrap().code, Some(0));
        let mut environment = outcome
            .stdout
            .split(|byte| *byte == 0)
            .filter(|entry| !entry.is_empty())
            .map(|entry| String::from_utf8_lossy(entry).into_owned())
            .collect::<Vec<_>>();
        environment.sort();
        assert_eq!(
            environment,
            [
                "EXAMPLE_SETTING=value",
                "LANG=C.UTF-8",
                &format!("PATH={PATH}")
            ]
        );
        let stderr = String::from_utf8(outcome.stderr.kept).unwrap();
        let working_dir = std::env::temp_dir().canonicalize().unwrap();
        assert_eq!(
            stderr.lines().collect::<Vec<_>>(),
            ["1", "invoke", working_dir.to_str().unwrap()]
        );
        assert!(!stderr.contains("secret-example"));
    }

    #[tokio::test]
    async fn stdout_and_the_exit_status_are_returned_once_the_process_exits() {
        let registry = CommandRegistry::new();
        let handle = start(
            &registry,
            &launch("echo.sh", &[]),
            StdinPayload::new(b"{\"action\":\"issue.view\"}".to_vec()),
            limits(Duration::from_secs(10), 64 * 1024),
        )
        .await;
        let group = handle.process_group();
        let outcome = handle.outcome().await;

        assert_eq!(outcome.termination, Termination::Exited);
        assert!(!outcome.contract_violation());
        assert_eq!(
            outcome.exit,
            Some(ProcessExit {
                code: Some(0),
                signal: None
            })
        );
        assert_eq!(
            String::from_utf8(outcome.stdout).unwrap().trim(),
            r#"{"ok":true,"result":{"bytes":23}}"#
        );
        assert!(outcome.duration < Duration::from_secs(10));
        assert_reaped(group);
        assert_eq!(registry.in_use("fixture"), 0);
        assert_eq!(registry.live_processes(), 0);
    }

    #[tokio::test]
    async fn stderr_beyond_pipe_capacity_is_truncated_without_blocking_the_call() {
        let registry = CommandRegistry::new();
        let outcome = start(
            &registry,
            &launch("stderr-flood.sh", &[]),
            StdinPayload::new(vec![b'r'; 1024]),
            limits(Duration::from_secs(20), 64 * 1024),
        )
        .await
        .outcome()
        .await;

        assert_eq!(outcome.termination, Termination::Exited);
        assert_eq!(outcome.stderr.kept, vec![b'e'; STDERR_KEPT_BYTES]);
        assert!(outcome.stderr.truncated);
        assert_eq!(outcome.stdout, b"{\"ok\":true}\n");
    }

    #[tokio::test]
    async fn stdout_written_before_reading_stdin_does_not_block_either_pipe() {
        let registry = CommandRegistry::new();
        let outcome = start(
            &registry,
            &launch("early-stdout.sh", &[]),
            StdinPayload::new(vec![b'r'; 1024 * 1024]),
            limits(Duration::from_secs(20), 1024 * 1024),
        )
        .await
        .outcome()
        .await;

        assert_eq!(outcome.termination, Termination::Exited);
        assert_eq!(outcome.stdout, vec![b'o'; 256 * 1024]);
    }

    #[tokio::test]
    async fn a_process_that_never_reads_stdin_still_finishes() {
        let registry = CommandRegistry::new();
        let outcome = start(
            &registry,
            &launch("ignores-stdin.sh", &[]),
            StdinPayload::new(vec![b'r'; 1024 * 1024]),
            limits(Duration::from_secs(20), 64 * 1024),
        )
        .await
        .outcome()
        .await;

        assert_eq!(outcome.termination, Termination::Exited);
        assert_eq!(outcome.stdout, b"{\"ok\":true}\n");
        assert_eq!(registry.in_use("fixture"), 0);
    }

    #[tokio::test]
    async fn stdout_over_the_cap_kills_the_group_as_a_contract_violation() {
        let registry = CommandRegistry::new();
        let started = std::time::Instant::now();
        let handle = start(
            &registry,
            &launch("overflow.sh", &[]),
            StdinPayload::empty(),
            limits(Duration::from_secs(20), 1024),
        )
        .await;
        let group = handle.process_group();
        let outcome = handle.outcome().await;

        assert_eq!(outcome.termination, Termination::OutputExceeded);
        assert!(outcome.contract_violation());
        assert!(outcome.stdout.is_empty());
        assert_eq!(outcome.exit.unwrap().signal, Some(libc::SIGKILL));
        assert!(started.elapsed() < Duration::from_secs(10));
        assert_reaped(group);
        assert_eq!(registry.in_use("fixture"), 0);
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn the_command_deadline_kills_the_whole_group() {
        let registry = CommandRegistry::new();
        let member_file = temp_file("member");
        let started = std::time::Instant::now();
        let handle = start(
            &registry,
            &launch(
                "group-member.sh",
                &[("MEMBER_PID_FILE", member_file.to_str().unwrap())],
            ),
            StdinPayload::empty(),
            limits(Duration::from_secs(2), 64 * 1024),
        )
        .await;
        let group = handle.process_group();
        let outcome = handle.outcome().await;

        assert_eq!(outcome.termination, Termination::TimedOut);
        assert!(!outcome.contract_violation());
        assert_eq!(outcome.exit.unwrap().signal, Some(libc::SIGKILL));
        assert!(started.elapsed() < Duration::from_secs(10));
        assert_reaped(group);
        let member = read_pid(&member_file);
        let _ = std::fs::remove_file(&member_file);
        assert_not_running(member);
        assert_eq!(registry.in_use("fixture"), 0);
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn a_descendant_holding_the_pipes_fails_the_call_after_the_drain() {
        let registry = CommandRegistry::new();
        let descendant_file = temp_file("descendant");
        let handle = start(
            &registry,
            &launch(
                "descendant.sh",
                &[("DESCENDANT_PID_FILE", descendant_file.to_str().unwrap())],
            ),
            StdinPayload::empty(),
            limits(Duration::from_secs(20), 64 * 1024),
        )
        .await;
        let group = handle.process_group();
        let reaped_by = std::time::Instant::now();
        let outcome = handle.outcome().await;
        let descendant = read_pid(&descendant_file);
        let _ = std::fs::remove_file(&descendant_file);
        // SAFETY: kill has no memory-safety preconditions.
        unsafe {
            libc::kill(descendant, libc::SIGKILL);
        }

        assert_eq!(outcome.termination, Termination::PipesHeldOpen);
        assert!(outcome.contract_violation());
        assert_eq!(outcome.exit.unwrap().code, Some(0));
        assert!(reaped_by.elapsed() >= POST_EXIT_DRAIN);
        assert_reaped(group);
        assert_not_running(descendant);
        assert_eq!(registry.in_use("fixture"), 0);
    }

    #[tokio::test]
    async fn a_missing_program_fails_to_spawn_and_returns_its_permit() {
        let registry = CommandRegistry::new();
        let permit = registry
            .acquire("fixture", 1, Instant::now() + Duration::from_secs(5))
            .await
            .unwrap();
        let error = start_command(
            permit,
            &launch("missing.sh", &[]),
            StdinPayload::empty(),
            limits(Duration::from_secs(5), 1024),
        )
        .err()
        .unwrap();

        assert!(matches!(
            error,
            crate::supervisor::StartError::Spawn(error) if error.kind() == io::ErrorKind::NotFound
        ));
        assert_eq!(registry.in_use("fixture"), 0);
        assert_eq!(registry.live_processes(), 0);
    }

    #[tokio::test]
    async fn repeated_handle_drops_release_each_permit_only_after_cleanup() {
        let registry = CommandRegistry::new();
        let deadline = Instant::now() + Duration::from_secs(30);
        let mut permit = registry.acquire("fixture", 1, deadline).await.unwrap();
        for _ in 0..3 {
            let handle = start_command(
                permit,
                &launch("sleep.sh", &[]),
                StdinPayload::empty(),
                SupervisionLimits {
                    deadline,
                    max_output_bytes: 1024,
                },
            )
            .unwrap();
            let group = handle.process_group();
            let mut waiting = Box::pin(registry.acquire("fixture", 1, deadline));
            assert!(
                tokio::time::timeout(Duration::from_millis(50), &mut waiting)
                    .await
                    .is_err()
            );
            // The host drops the invocation, as at the HTTP MCP deadline.
            drop(handle);
            permit = waiting.await.unwrap();
            // The waiting call got the permit only after the cleanup.
            assert_reaped(group);
            assert_eq!(registry.live_processes(), 0);
        }
        drop(permit);
        assert_eq!(registry.in_use("fixture"), 0);
    }

    #[tokio::test]
    async fn shutdown_kills_and_reaps_a_process_whose_call_already_ended() {
        let registry = CommandRegistry::new();
        let handle = start(
            &registry,
            &launch("sleep.sh", &[]),
            StdinPayload::empty(),
            limits(Duration::from_secs(30), 1024),
        )
        .await;
        let group = handle.process_group();
        // The invocation was finalized and its handle already gone.
        drop(handle);

        assert_eq!(registry.close_and_drain(Duration::from_secs(10)).await, 0);
        assert_reaped(group);
        assert_eq!(registry.in_use("fixture"), 0);
        assert_eq!(registry.live_processes(), 0);
    }

    #[tokio::test]
    async fn shutdown_kills_a_running_process_and_releases_its_permit() {
        let registry = CommandRegistry::new();
        let handle = start(
            &registry,
            &launch("sleep.sh", &[]),
            StdinPayload::empty(),
            limits(Duration::from_secs(30), 1024),
        )
        .await;
        let group = handle.process_group();

        assert_eq!(registry.close_and_drain(Duration::from_secs(10)).await, 0);
        let outcome = handle.outcome().await;
        assert_eq!(outcome.termination, Termination::Killed);
        assert_reaped(group);
        assert_eq!(registry.in_use("fixture"), 0);
    }
}
