//! The process facts of one command run.
//!
//! A command's supervisor records what happened to its process into a shared
//! cell: whether it was spawned, how the leader ended, how long it ran, and
//! whether it broke the command contract. The cell outlives the invocation
//! future, so whoever finalizes the call reads the facts known at that moment
//! even when the host interrupted the invocation; facts not yet known, such
//! as the exit status of a process still being reaped, read as `None`.
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::Duration;

/// The facts of one command run, as known when read.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct CommandProcessFactsSnapshot {
    /// The process was started. Only a failure before the spawn leaves it
    /// `false`; the operation counts as dispatched once it is `true`.
    pub spawned: bool,
    /// The reaped leader's exit code, when it exited normally.
    pub exit_code: Option<i32>,
    /// The signal that ended the reaped leader, when one did.
    pub signal: Option<i32>,
    /// Milliseconds from the spawn until the leader was reaped and its pipes
    /// drained.
    pub duration_ms: Option<u64>,
    /// The process broke the command contract, such as by exceeding its
    /// output limit or leaving its pipes open after it exited.
    pub contract_violation: bool,
}

/// A shared cell of one command run's process facts. Clones share the cell.
#[derive(Clone, Default)]
pub struct CommandProcessFacts {
    inner: Arc<Mutex<CommandProcessFactsSnapshot>>,
}

impl CommandProcessFacts {
    pub fn new() -> Self {
        Self::default()
    }

    fn facts(&self) -> MutexGuard<'_, CommandProcessFactsSnapshot> {
        self.inner
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    /// The process was started.
    pub fn record_spawned(&self) {
        self.facts().spawned = true;
    }

    /// The leader was reaped with `exit_code` or by `signal`, if it was
    /// reaped at all, `duration` after the spawn.
    pub fn record_finished(&self, exit_code: Option<i32>, signal: Option<i32>, duration: Duration) {
        let mut facts = self.facts();
        facts.exit_code = exit_code;
        facts.signal = signal;
        facts.duration_ms = Some(u64::try_from(duration.as_millis()).unwrap_or(u64::MAX));
    }

    /// The process or its response broke the command contract.
    pub fn record_contract_violation(&self) {
        self.facts().contract_violation = true;
    }

    /// The facts recorded so far.
    pub fn snapshot(&self) -> CommandProcessFactsSnapshot {
        *self.facts()
    }
}

impl std::fmt::Debug for CommandProcessFacts {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.snapshot().fmt(formatter)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn clones_share_the_facts_recorded_so_far() {
        let facts = CommandProcessFacts::new();
        let reader = facts.clone();
        assert_eq!(reader.snapshot(), CommandProcessFactsSnapshot::default());

        facts.record_spawned();
        assert!(reader.snapshot().spawned);
        assert_eq!(reader.snapshot().exit_code, None);

        facts.record_finished(None, Some(9), Duration::from_millis(1500));
        facts.record_contract_violation();
        assert_eq!(
            reader.snapshot(),
            CommandProcessFactsSnapshot {
                spawned: true,
                exit_code: None,
                signal: Some(9),
                duration_ms: Some(1500),
                contract_violation: true,
            }
        );
    }
}
