//! A process-control double: a fake process whose exit, reaping and pipes
//! the test drives, and group signals that are recorded instead of sent.
use crate::process::{GroupSignals, ProcessExit, SupervisedProcess};
use std::io;
use std::sync::{Arc, Mutex};
use tokio::io::{AsyncWriteExt, DuplexStream};
use tokio::sync::oneshot;

/// The fake process group ID.
pub(crate) const GROUP: i32 = 4242;
const OUTPUT_PIPE_CAPACITY: usize = 64 * 1024;

/// Records every group kill instead of sending it.
#[derive(Clone, Default)]
pub(crate) struct RecordingSignals(Arc<Mutex<Vec<i32>>>);

impl RecordingSignals {
    pub(crate) fn groups(&self) -> Vec<i32> {
        self.0.lock().unwrap().clone()
    }

    pub(crate) fn kills(&self) -> usize {
        self.0.lock().unwrap().len()
    }
}

impl GroupSignals for RecordingSignals {
    fn kill_group(&self, group: i32) {
        self.0.lock().unwrap().push(group);
    }
}

/// The supervisor's side of the fake process.
pub(crate) struct FakeProcess {
    pipes: Option<(DuplexStream, DuplexStream, DuplexStream)>,
    exit: Option<oneshot::Receiver<()>>,
    reaping: Option<oneshot::Sender<()>>,
    reap_gate: Option<oneshot::Receiver<()>>,
    status: ProcessExit,
}

/// The test's side of the fake process.
pub(crate) struct ProcessDriver {
    /// Reads what the supervisor writes to stdin.
    pub(crate) stdin: DuplexStream,
    stdout: Option<DuplexStream>,
    stderr: Option<DuplexStream>,
    exit: Option<oneshot::Sender<()>>,
    reaping: Option<oneshot::Receiver<()>>,
    reap_gate: Option<oneshot::Sender<()>>,
}

/// A fake process that exits with `status`, whose stdin pipe holds
/// `stdin_capacity` bytes.
pub(crate) fn fake_process(
    status: ProcessExit,
    stdin_capacity: usize,
) -> (FakeProcess, ProcessDriver) {
    let (stdin_ours, stdin_theirs) = tokio::io::duplex(stdin_capacity);
    let (stdout_ours, stdout_theirs) = tokio::io::duplex(OUTPUT_PIPE_CAPACITY);
    let (stderr_ours, stderr_theirs) = tokio::io::duplex(OUTPUT_PIPE_CAPACITY);
    let (exit, exited) = oneshot::channel();
    let (reaping, reaping_started) = oneshot::channel();
    let (reap_gate, reap_gate_open) = oneshot::channel();
    (
        FakeProcess {
            pipes: Some((stdin_ours, stdout_ours, stderr_ours)),
            exit: Some(exited),
            reaping: Some(reaping),
            reap_gate: Some(reap_gate_open),
            status,
        },
        ProcessDriver {
            stdin: stdin_theirs,
            stdout: Some(stdout_theirs),
            stderr: Some(stderr_theirs),
            exit: Some(exit),
            reaping: Some(reaping_started),
            reap_gate: Some(reap_gate),
        },
    )
}

impl ProcessDriver {
    pub(crate) async fn write_stdout(&mut self, bytes: &[u8]) {
        let pipe = self.stdout.as_mut().expect("stdout is open");
        pipe.write_all(bytes).await.unwrap();
    }

    pub(crate) async fn write_stderr(&mut self, bytes: &[u8]) {
        let pipe = self.stderr.as_mut().expect("stderr is open");
        pipe.write_all(bytes).await.unwrap();
    }

    /// Closes stdout and stderr, as a process and its descendants do when
    /// they end.
    pub(crate) fn close_output(&mut self) {
        self.stdout = None;
        self.stderr = None;
    }

    /// The leader exits; the supervisor observes it unreaped.
    pub(crate) fn exit(&mut self) {
        let _ = self.exit.take().expect("the leader exits once").send(());
    }

    /// Waits until the supervisor starts reaping, which it then cannot
    /// finish until [`Self::finish_reaping`].
    pub(crate) async fn reaping(&mut self) {
        self.reaping
            .take()
            .expect("reaping starts once")
            .await
            .expect("the supervisor reaps");
    }

    pub(crate) fn finish_reaping(&mut self) {
        let _ = self.reap_gate.take().expect("reaping ends once").send(());
    }
}

impl SupervisedProcess for FakeProcess {
    type Stdin = DuplexStream;
    type Stdout = DuplexStream;
    type Stderr = DuplexStream;

    fn group(&self) -> i32 {
        GROUP
    }

    fn take_pipes(&mut self) -> Option<(DuplexStream, DuplexStream, DuplexStream)> {
        self.pipes.take()
    }

    async fn exited(&mut self) -> io::Result<()> {
        let exit = self.exit.take().expect("the exit is observed once");
        let _ = exit.await;
        Ok(())
    }

    async fn reap(&mut self) -> io::Result<ProcessExit> {
        if let Some(reaping) = self.reaping.take() {
            let _ = reaping.send(());
        }
        if let Some(gate) = self.reap_gate.take() {
            let _ = gate.await;
        }
        Ok(self.status)
    }
}
