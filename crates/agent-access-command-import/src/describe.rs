//! A minimal blocking runner for `<path> describe`, used by discovery until
//! the process supervisor replaces it.
//!
//! The process gets an empty environment plus the configured `env`, the
//! configured working directory, closed stdin, discarded stderr, and its own
//! process group. Stdout is capped; the deadline kills the whole group. The
//! group is signalled only while the leader is unreaped, so its ID cannot have
//! been reused.
use agent_access_core::CommandImportConfig;
use std::io::Read;
use std::process::{Command, Stdio};
use std::sync::mpsc;
use std::time::{Duration, Instant};

/// How long stdout may stay open after the process exits.
const POST_EXIT_DRAIN: Duration = Duration::from_secs(1);
const POLL: Duration = Duration::from_millis(10);

/// Why `describe` produced no manifest. Messages never include the path,
/// output or exit status.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum DescribeFailure {
    /// The executable could not be started.
    Spawn,
    /// The process did not finish before the deadline.
    Timeout,
    /// Stdout exceeded the limit.
    OutputTooLarge,
    /// The process exited unsuccessfully or by a signal.
    Failed,
    /// A process the command started kept its stdout open after it exited.
    PipesOpen,
}

/// Runs `<path> describe` and returns its stdout.
pub(crate) fn run(
    config: &CommandImportConfig,
    limit: usize,
    timeout: Duration,
) -> Result<Vec<u8>, DescribeFailure> {
    let deadline = Instant::now() + timeout;
    let mut command = Command::new(&config.path);
    command
        .arg("describe")
        .env_clear()
        .envs(&config.env)
        .current_dir(&config.working_dir)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null());
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        command.process_group(0);
    }
    let mut child = command.spawn().map_err(|_| DescribeFailure::Spawn)?;
    let mut stdout = child.stdout.take().ok_or(DescribeFailure::Spawn)?;
    let (sender, output) = mpsc::channel();
    std::thread::spawn(move || {
        let mut buffer = Vec::new();
        // One byte over the limit proves an overflow without reading more.
        let result = (&mut stdout)
            .take(limit as u64 + 1)
            .read_to_end(&mut buffer)
            .map(|_| buffer);
        let _ = sender.send(result);
    });
    let mut collected = None;
    let status = loop {
        if collected.is_none()
            && let Ok(result) = output.try_recv()
        {
            match result {
                Ok(buffer) if buffer.len() <= limit => collected = Some(buffer),
                _ => {
                    kill_unreaped_group(&mut child);
                    return Err(DescribeFailure::OutputTooLarge);
                }
            }
        }
        match child.try_wait() {
            Ok(Some(status)) => break status,
            Ok(None) if Instant::now() >= deadline => {
                kill_unreaped_group(&mut child);
                return Err(DescribeFailure::Timeout);
            }
            Ok(None) => std::thread::sleep(POLL),
            Err(_) => {
                kill_unreaped_group(&mut child);
                return Err(DescribeFailure::Failed);
            }
        }
    };
    let stdout = match collected {
        Some(buffer) => buffer,
        None => match output.recv_timeout(POST_EXIT_DRAIN) {
            Ok(Ok(buffer)) if buffer.len() <= limit => buffer,
            Ok(_) => return Err(DescribeFailure::OutputTooLarge),
            Err(_) => return Err(DescribeFailure::PipesOpen),
        },
    };
    if !status.success() {
        return Err(DescribeFailure::Failed);
    }
    Ok(stdout)
}

/// Kills the process group and reaps the leader. Called only after
/// `try_wait` found the leader running, so it is still unreaped and its
/// group ID cannot belong to another process.
fn kill_unreaped_group(child: &mut std::process::Child) {
    #[cfg(unix)]
    if let Ok(group) = i32::try_from(child.id()) {
        // SAFETY: `kill` has no memory-safety preconditions; the negative
        // ID names the group this child leads.
        unsafe {
            libc::kill(-group, libc::SIGKILL);
        }
    }
    let _ = child.kill();
    let _ = child.wait();
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    fn fixture(name: &str) -> CommandImportConfig {
        CommandImportConfig {
            path: format!("{}/tests/fixtures/{name}", env!("CARGO_MANIFEST_DIR")),
            timeout: "30s".into(),
            max_output_bytes: 1024 * 1024,
            max_concurrent: 4,
            working_dir: "/".into(),
            network: Default::default(),
            log_stderr: false,
            env: BTreeMap::from([
                ("PATH".into(), "/usr/bin:/bin".into()),
                ("FIXTURE_MARKER".into(), "configured".into()),
            ]),
        }
    }

    #[test]
    fn describe_runs_with_only_the_configured_environment() {
        let output = run(&fixture("echo-env.sh"), 4096, Duration::from_secs(10)).unwrap();
        let output = String::from_utf8(output).unwrap();
        let mut lines = output.lines().collect::<Vec<_>>();
        lines.sort_unstable();
        // `sh` may add PWD, SHLVL and `_` itself; nothing is inherited.
        let inherited = lines
            .iter()
            .filter(|line| {
                !["FIXTURE_MARKER=", "PATH=", "PWD=", "SHLVL=", "_=", "ARG="]
                    .iter()
                    .any(|prefix| line.starts_with(prefix))
            })
            .collect::<Vec<_>>();
        assert!(inherited.is_empty(), "{inherited:?}");
        assert!(lines.contains(&"FIXTURE_MARKER=configured"));
        assert!(lines.contains(&"ARG=describe"));
    }

    #[test]
    fn failures_are_reported_without_output() {
        assert_eq!(
            run(&fixture("fail.sh"), 4096, Duration::from_secs(10)),
            Err(DescribeFailure::Failed)
        );
        assert_eq!(
            run(&fixture("missing.sh"), 4096, Duration::from_secs(10)),
            Err(DescribeFailure::Spawn)
        );
        assert_eq!(
            run(&fixture("flood.sh"), 4096, Duration::from_secs(10)),
            Err(DescribeFailure::OutputTooLarge)
        );
        let started = Instant::now();
        assert_eq!(
            run(&fixture("sleep.sh"), 4096, Duration::from_millis(300)),
            Err(DescribeFailure::Timeout)
        );
        assert!(started.elapsed() < Duration::from_secs(5));
    }
}
