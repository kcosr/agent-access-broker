//! Per-command process budgets and the live process supervisors of command
//! imports, shared by every runtime generation of one Broker.
//!
//! Each approved command name has one budget. Every import of the command,
//! and each of its `describe`, `invoke` and `verify` runs, draws from it,
//! whichever generation admitted the call. A caller passes its own
//! generation's `max_concurrent`: a permit is granted only while fewer
//! permits than that limit are outstanding, so a reload that lowers the limit
//! holds new calls until usage falls below it, while permits already granted
//! keep counting. Waiters are served in arrival order.
//!
//! A permit belongs to the supervisor of the process it admits. The
//! supervisor registers its kill control here before it spawns and keeps the
//! permit until its process group is killed and reaped and its pipes are
//! drained. Shutdown closes the registry, which fails waiting calls and calls
//! not yet registered, asks every live supervisor to kill its process group,
//! and waits until each has released its permit.
use std::collections::{BTreeMap, VecDeque};
use std::fmt;
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::Duration;
use tokio::sync::{Notify, oneshot};

/// The kill control a process supervisor registers with the
/// [`CommandRegistry`].
pub trait CommandProcessControl: Send + Sync {
    /// Asks the supervisor to kill its process group now. It must not block
    /// on I/O, may be called any number of times, and is a no-op once the
    /// supervisor has released the group.
    fn request_kill(&self);
}

/// Why a command permit was not granted.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum CommandAcquireError {
    /// The Broker is shutting down; the call must not start a process.
    #[error("command registry is closed")]
    Closed,
    /// The call's deadline passed while it waited for a permit.
    #[error("no command permit was available before the deadline")]
    DeadlineExceeded,
}

/// The registry closed before a permit's supervisor registered; the call
/// must not start a process.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("command registry is closed")]
pub struct CommandRegistryClosed;

/// The command budgets and live process supervisors of one Broker. Clones
/// share the same registry; runtime generations carry it from one to the
/// next.
#[derive(Clone, Default)]
pub struct CommandRegistry {
    inner: Arc<RegistryInner>,
}

#[derive(Default)]
struct RegistryInner {
    state: Mutex<RegistryState>,
    /// Notified whenever a supervisor leaves the registry.
    supervisors_changed: Notify,
}

#[derive(Default)]
struct RegistryState {
    closed: bool,
    next_id: u64,
    budgets: BTreeMap<String, Budget>,
    supervisors: BTreeMap<u64, LiveSupervisor>,
}

struct LiveSupervisor {
    command: String,
    control: Arc<dyn CommandProcessControl>,
}

#[derive(Default)]
struct Budget {
    in_use: usize,
    waiters: VecDeque<Waiter>,
}

struct Waiter {
    id: u64,
    limit: usize,
    grant: oneshot::Sender<()>,
}

impl RegistryState {
    fn next_id(&mut self) -> u64 {
        let id = self.next_id;
        self.next_id += 1;
        id
    }

    /// Grants queued waiters in arrival order while the head waiter's limit
    /// admits another permit.
    fn grant_waiters(&mut self, command: &str) {
        let Some(budget) = self.budgets.get_mut(command) else {
            return;
        };
        while budget
            .waiters
            .front()
            .is_some_and(|waiter| budget.in_use < waiter.limit)
        {
            let waiter = budget.waiters.pop_front().expect("a waiter is queued");
            // A queued waiter's receiver lives until it leaves the queue, so
            // this send succeeds; count the permit only if it did.
            if waiter.grant.send(()).is_ok() {
                budget.in_use += 1;
            }
        }
        self.prune(command);
    }

    fn release(&mut self, command: &str) {
        if let Some(budget) = self.budgets.get_mut(command) {
            budget.in_use = budget
                .in_use
                .checked_sub(1)
                .expect("a released command permit was counted");
        }
        self.grant_waiters(command);
    }

    fn prune(&mut self, command: &str) {
        if self
            .budgets
            .get(command)
            .is_some_and(|budget| budget.in_use == 0 && budget.waiters.is_empty())
        {
            self.budgets.remove(command);
        }
    }
}

impl CommandRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    /// Whether `other` is this same registry.
    pub fn ptr_eq(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.inner, &other.inner)
    }

    fn state(&self) -> MutexGuard<'_, RegistryState> {
        self.inner
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    /// Waits until `command`'s budget grants a permit under `limit`, the
    /// caller's generation's `max_concurrent`, or until `deadline`. Waiters
    /// are served in arrival order; a call whose deadline has already passed
    /// gets no permit. Dropping the future withdraws the request, releasing a
    /// permit granted to it in the meantime.
    pub async fn acquire(
        &self,
        command: &str,
        limit: usize,
        deadline: tokio::time::Instant,
    ) -> Result<CommandPermit, CommandAcquireError> {
        let mut pending = {
            let mut state = self.state();
            if state.closed {
                return Err(CommandAcquireError::Closed);
            }
            if tokio::time::Instant::now() >= deadline {
                return Err(CommandAcquireError::DeadlineExceeded);
            }
            let id = state.next_id();
            let budget = state.budgets.entry(command.to_owned()).or_default();
            if budget.waiters.is_empty() && budget.in_use < limit {
                budget.in_use += 1;
                return Ok(CommandPermit::new(self.clone(), command));
            }
            let (grant, receiver) = oneshot::channel();
            budget.waiters.push_back(Waiter { id, limit, grant });
            PendingPermit {
                registry: self,
                command,
                id,
                receiver: Some(receiver),
            }
        };
        let receiver = pending
            .receiver
            .as_mut()
            .expect("a pending permit has its receiver");
        let outcome = tokio::time::timeout_at(deadline, receiver).await;
        match outcome {
            Ok(Ok(())) => {
                pending.receiver = None;
                Ok(CommandPermit::new(self.clone(), command))
            }
            // Closing dropped the queued grant.
            Ok(Err(_)) => {
                pending.receiver = None;
                Err(CommandAcquireError::Closed)
            }
            // Dropping `pending` withdraws the request.
            Err(_) => Err(CommandAcquireError::DeadlineExceeded),
        }
    }

    /// Permits of `command` currently outstanding.
    pub fn in_use(&self, command: &str) -> usize {
        self.state()
            .budgets
            .get(command)
            .map_or(0, |budget| budget.in_use)
    }

    /// Calls of `command` waiting for a permit.
    pub fn waiting(&self, command: &str) -> usize {
        self.state()
            .budgets
            .get(command)
            .map_or(0, |budget| budget.waiters.len())
    }

    /// Supervisors that have not yet released their permit.
    pub fn live_processes(&self) -> usize {
        self.state().supervisors.len()
    }

    pub fn is_closed(&self) -> bool {
        self.state().closed
    }

    /// Closes the registry for shutdown, then asks every live supervisor,
    /// including those whose invocation has already been finalized, to kill
    /// its process group, and waits up to `timeout` for all of them to
    /// release their permits. Waiting calls fail, and calls holding a permit
    /// but not yet registered fail when they register. Returns the number of
    /// supervisors still live, which are logged.
    pub async fn close_and_drain(&self, timeout: Duration) -> usize {
        let controls = {
            let mut state = self.state();
            state.closed = true;
            // Dropping the queued grants fails their waiters as closed.
            for budget in state.budgets.values_mut() {
                budget.waiters.clear();
            }
            state.budgets.retain(|_, budget| budget.in_use != 0);
            state
                .supervisors
                .values()
                .map(|supervisor| Arc::clone(&supervisor.control))
                .collect::<Vec<_>>()
        };
        for control in controls {
            control.request_kill();
        }
        let _ = tokio::time::timeout(timeout, self.supervisors_released()).await;
        let unfinished = {
            let state = self.state();
            state
                .supervisors
                .values()
                .map(|supervisor| supervisor.command.clone())
                .collect::<Vec<_>>()
        };
        if !unfinished.is_empty() {
            tracing::error!(
                event = "command_process_shutdown_unfinished",
                count = unfinished.len(),
                commands = ?unfinished,
                "command processes were not reaped within the shutdown budget"
            );
        }
        unfinished.len()
    }

    async fn supervisors_released(&self) {
        loop {
            let changed = self.inner.supervisors_changed.notified();
            tokio::pin!(changed);
            changed.as_mut().enable();
            if self.state().supervisors.is_empty() {
                return;
            }
            changed.await;
        }
    }

    /// Withdraws a waiter whose acquisition ended without taking its permit.
    fn withdraw(&self, command: &str, id: u64, receiver: &mut oneshot::Receiver<()>) {
        let mut state = self.state();
        let queued = state.budgets.get_mut(command).and_then(|budget| {
            let index = budget.waiters.iter().position(|waiter| waiter.id == id)?;
            budget.waiters.remove(index)
        });
        if queued.is_some() {
            // A withdrawn head waiter with a lower limit may have held back
            // the waiters behind it.
            state.grant_waiters(command);
        } else if receiver.try_recv().is_ok() {
            // Granted after the caller stopped waiting: give it back.
            state.release(command);
        }
    }
}

impl fmt::Debug for CommandRegistry {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let state = self.state();
        formatter
            .debug_struct("CommandRegistry")
            .field("closed", &state.closed)
            .field("budgets", &state.budgets.len())
            .field("live_processes", &state.supervisors.len())
            .finish()
    }
}

/// A queued acquisition; dropping it before it completes withdraws it.
struct PendingPermit<'a> {
    registry: &'a CommandRegistry,
    command: &'a str,
    id: u64,
    receiver: Option<oneshot::Receiver<()>>,
}

impl Drop for PendingPermit<'_> {
    fn drop(&mut self) {
        if let Some(mut receiver) = self.receiver.take() {
            self.registry.withdraw(self.command, self.id, &mut receiver);
        }
    }
}

/// One unit of a command's budget. Only this move-only permit can register a
/// process. The unit returns after the permit and any response-worker leases
/// have been dropped.
pub struct CommandPermit {
    unit: Arc<CommandBudgetUnit>,
}

struct CommandBudgetUnit {
    registry: CommandRegistry,
    command: String,
}

impl Drop for CommandBudgetUnit {
    fn drop(&mut self) {
        self.registry.state().release(&self.command);
    }
}

/// Keeps a response worker in the shared command budget without registering a
/// live process or permitting another process to start. Delivery must not retain it.
pub struct CommandBudgetLease {
    _unit: Arc<CommandBudgetUnit>,
}

impl CommandPermit {
    fn new(registry: CommandRegistry, command: &str) -> Self {
        Self {
            unit: Arc::new(CommandBudgetUnit {
                registry,
                command: command.to_owned(),
            }),
        }
    }

    /// The command whose budget this permit belongs to.
    pub fn command(&self) -> &str {
        &self.unit.command
    }

    /// Retain this unit while processing captured output after the process has
    /// exited. The lease cannot register a process and does not affect process drain.
    pub fn retain_budget(&self) -> CommandBudgetLease {
        CommandBudgetLease {
            _unit: Arc::clone(&self.unit),
        }
    }

    /// Registers the supervisor that will own this permit's process, before
    /// it spawns. Once the registry has closed this fails and returns the
    /// permit to the budget: the call must not start a process.
    pub fn register(
        self,
        control: Arc<dyn CommandProcessControl>,
    ) -> Result<LiveCommandProcess, CommandRegistryClosed> {
        let id = {
            let mut state = self.unit.registry.state();
            if state.closed {
                drop(state);
                drop(self);
                return Err(CommandRegistryClosed);
            }
            let id = state.next_id();
            state.supervisors.insert(
                id,
                LiveSupervisor {
                    command: self.unit.command.clone(),
                    control,
                },
            );
            id
        };
        Ok(LiveCommandProcess {
            permit: Some(self),
            id,
        })
    }
}

impl fmt::Debug for CommandPermit {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CommandPermit")
            .field("command", &self.command())
            .finish()
    }
}

/// A registered supervisor and the permit it owns. The supervisor drops it
/// only after its process group has been killed and reaped and every I/O
/// branch has finished: its permit drops first, then the supervisor leaves the
/// registry. A response worker can still retain the budget unit afterward.
pub struct LiveCommandProcess {
    permit: Option<CommandPermit>,
    id: u64,
}

impl LiveCommandProcess {
    /// The command whose budget this process draws from.
    pub fn command(&self) -> &str {
        self.permit.as_ref().map_or("", CommandPermit::command)
    }
}

impl Drop for LiveCommandProcess {
    fn drop(&mut self) {
        let Some(permit) = self.permit.take() else {
            return;
        };
        let registry = permit.unit.registry.clone();
        drop(permit);
        registry.state().supervisors.remove(&self.id);
        registry.inner.supervisors_changed.notify_waiters();
    }
}

impl fmt::Debug for LiveCommandProcess {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("LiveCommandProcess")
            .field("command", &self.command())
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use futures_util::FutureExt;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use tokio::time::Instant;

    fn far() -> Instant {
        Instant::now() + Duration::from_secs(30)
    }

    async fn permit(registry: &CommandRegistry, command: &str, limit: usize) -> CommandPermit {
        registry.acquire(command, limit, far()).await.unwrap()
    }

    /// A supervisor stand-in: counts kill requests and, unless told to
    /// ignore them, hands its registration to the test to release.
    struct FakeSupervisor {
        kills: AtomicUsize,
        on_kill: Mutex<Option<oneshot::Sender<()>>>,
    }

    impl FakeSupervisor {
        fn new() -> (Arc<Self>, oneshot::Receiver<()>) {
            let (sender, receiver) = oneshot::channel();
            (
                Arc::new(Self {
                    kills: AtomicUsize::new(0),
                    on_kill: Mutex::new(Some(sender)),
                }),
                receiver,
            )
        }
    }

    impl CommandProcessControl for FakeSupervisor {
        fn request_kill(&self) {
            self.kills.fetch_add(1, Ordering::SeqCst);
            if let Some(sender) = self.on_kill.lock().unwrap().take() {
                let _ = sender.send(());
            }
        }
    }

    #[tokio::test]
    async fn permits_are_granted_up_to_the_limit_then_in_arrival_order() {
        let registry = CommandRegistry::new();
        let first = permit(&registry, "ticketing", 2).await;
        let _second = permit(&registry, "ticketing", 2).await;
        assert_eq!(registry.in_use("ticketing"), 2);

        let mut third = Box::pin(registry.acquire("ticketing", 2, far()));
        assert!(third.as_mut().now_or_never().is_none());
        let mut fourth = Box::pin(registry.acquire("ticketing", 2, far()));
        assert!(fourth.as_mut().now_or_never().is_none());
        assert_eq!(registry.waiting("ticketing"), 2);

        drop(first);
        let third = third.await.unwrap();
        assert!(fourth.as_mut().now_or_never().is_none());
        assert_eq!(registry.in_use("ticketing"), 2);
        drop(third);
        let fourth = fourth.await.unwrap();
        assert_eq!(fourth.command(), "ticketing");
        assert_eq!(registry.waiting("ticketing"), 0);
    }

    #[tokio::test]
    async fn commands_have_separate_budgets() {
        let registry = CommandRegistry::new();
        let _ticketing = permit(&registry, "ticketing", 1).await;
        let _inventory = permit(&registry, "inventory", 1).await;
        assert_eq!(registry.in_use("ticketing"), 1);
        assert_eq!(registry.in_use("inventory"), 1);
    }

    #[tokio::test]
    async fn response_worker_retains_budget_after_process_reaping() {
        let registry = CommandRegistry::new();
        let process_permit = permit(&registry, "ticketing", 1).await;
        let worker = process_permit.retain_budget();
        let (control, _killed) = FakeSupervisor::new();
        let live = process_permit.register(control).unwrap();
        let mut next = Box::pin(registry.acquire("ticketing", 1, far()));
        assert!(next.as_mut().now_or_never().is_none());
        drop(live);
        assert_eq!(registry.live_processes(), 0);
        assert_eq!(registry.in_use("ticketing"), 1);
        assert!(next.as_mut().now_or_never().is_none());
        drop(worker);
        let next = next.await.unwrap();
        assert_eq!(registry.in_use("ticketing"), 1);
        drop(next);
        assert_eq!(registry.in_use("ticketing"), 0);
    }

    #[tokio::test]
    async fn retained_response_workers_are_not_live_processes_during_shutdown() {
        let registry = CommandRegistry::new();
        let process_permit = permit(&registry, "ticketing", 1).await;
        let first = process_permit.retain_budget();
        let second = process_permit.retain_budget();
        drop(process_permit);
        assert_eq!(registry.close_and_drain(Duration::ZERO).await, 0);
        assert_eq!(registry.in_use("ticketing"), 1);
        drop(first);
        assert_eq!(registry.in_use("ticketing"), 1);
        drop(second);
        assert_eq!(registry.in_use("ticketing"), 0);
    }

    #[tokio::test(start_paused = true)]
    async fn a_call_without_a_permit_fails_at_its_deadline_and_leaves_the_queue() {
        let registry = CommandRegistry::new();
        let held = permit(&registry, "ticketing", 1).await;
        let started = Instant::now();
        let error = registry
            .acquire("ticketing", 1, started + Duration::from_secs(5))
            .await
            .unwrap_err();
        assert_eq!(error, CommandAcquireError::DeadlineExceeded);
        assert_eq!(started.elapsed(), Duration::from_secs(5));
        assert_eq!(registry.waiting("ticketing"), 0);
        assert_eq!(registry.in_use("ticketing"), 1);
        drop(held);
        assert_eq!(registry.in_use("ticketing"), 0);
    }

    #[tokio::test]
    async fn a_call_whose_deadline_has_passed_gets_no_permit() {
        let registry = CommandRegistry::new();
        let expired = Instant::now();
        assert_eq!(
            registry.acquire("ticketing", 4, expired).await.unwrap_err(),
            CommandAcquireError::DeadlineExceeded
        );
        assert_eq!(registry.in_use("ticketing"), 0);
        assert_eq!(registry.waiting("ticketing"), 0);
    }

    #[tokio::test]
    async fn a_lowered_limit_holds_new_calls_until_usage_falls_below_it() {
        let registry = CommandRegistry::new();
        let mut held = Vec::new();
        for _ in 0..3 {
            held.push(permit(&registry, "ticketing", 4).await);
        }
        // A newer generation lowered max_concurrent to 2.
        let mut lowered = Box::pin(registry.acquire("ticketing", 2, far()));
        assert!(lowered.as_mut().now_or_never().is_none());
        held.pop();
        assert!(lowered.as_mut().now_or_never().is_none());
        assert_eq!(registry.in_use("ticketing"), 2);
        held.pop();
        let granted = lowered.await.unwrap();
        assert_eq!(registry.in_use("ticketing"), 2);
        drop(granted);
        drop(held);
        assert_eq!(registry.in_use("ticketing"), 0);
    }

    #[tokio::test]
    async fn a_raised_limit_grants_at_once() {
        let registry = CommandRegistry::new();
        let _held = permit(&registry, "ticketing", 1).await;
        let raised = registry.acquire("ticketing", 2, far()).now_or_never();
        assert!(matches!(raised, Some(Ok(_))));
    }

    #[tokio::test]
    async fn overlapping_generations_share_one_budget() {
        let startup = CommandRegistry::new();
        // Each generation carries a clone of the registry.
        let reloaded = startup.clone();
        assert!(startup.ptr_eq(&reloaded));
        let _old = permit(&startup, "ticketing", 1).await;
        let mut new = Box::pin(reloaded.acquire("ticketing", 1, far()));
        assert!(new.as_mut().now_or_never().is_none());
        assert!(!startup.ptr_eq(&CommandRegistry::new()));
    }

    #[tokio::test]
    async fn a_withdrawn_head_waiter_lets_the_next_waiter_in() {
        let registry = CommandRegistry::new();
        let _held = permit(&registry, "ticketing", 2).await;
        // The head waiter's lower limit holds back a later, higher one.
        let mut head = Box::pin(registry.acquire("ticketing", 1, far()));
        assert!(head.as_mut().now_or_never().is_none());
        let mut next = Box::pin(registry.acquire("ticketing", 2, far()));
        assert!(next.as_mut().now_or_never().is_none());
        drop(head);
        let granted = next.await.unwrap();
        assert_eq!(registry.in_use("ticketing"), 2);
        drop(granted);
    }

    #[tokio::test]
    async fn a_permit_granted_to_a_withdrawn_call_returns_to_the_budget() {
        let registry = CommandRegistry::new();
        let held = permit(&registry, "ticketing", 1).await;
        let mut waiting = Box::pin(registry.acquire("ticketing", 1, far()));
        assert!(waiting.as_mut().now_or_never().is_none());
        // The release grants the waiter, which stops waiting before it
        // observes the grant.
        drop(held);
        assert_eq!(registry.in_use("ticketing"), 1);
        drop(waiting);
        assert_eq!(registry.in_use("ticketing"), 0);
        assert_eq!(registry.waiting("ticketing"), 0);
    }

    #[tokio::test]
    async fn closing_fails_waiting_new_and_unregistered_calls() {
        let registry = CommandRegistry::new();
        let held = permit(&registry, "ticketing", 1).await;
        let mut waiting = Box::pin(registry.acquire("ticketing", 1, far()));
        assert!(waiting.as_mut().now_or_never().is_none());

        assert_eq!(registry.close_and_drain(Duration::ZERO).await, 0);
        assert!(registry.is_closed());
        assert_eq!(waiting.await.unwrap_err(), CommandAcquireError::Closed);
        assert_eq!(
            registry.acquire("ticketing", 1, far()).await.unwrap_err(),
            CommandAcquireError::Closed
        );
        let (control, _killed) = FakeSupervisor::new();
        assert_eq!(held.register(control).unwrap_err(), CommandRegistryClosed);
        assert_eq!(registry.in_use("ticketing"), 0);
        assert_eq!(registry.live_processes(), 0);
    }

    #[tokio::test]
    async fn drain_kills_every_live_supervisor_and_waits_for_its_release() {
        let registry = CommandRegistry::new();
        let mut supervisors = Vec::new();
        for _ in 0..2 {
            let (control, killed) = FakeSupervisor::new();
            let live = permit(&registry, "ticketing", 2)
                .await
                .register(control.clone())
                .unwrap();
            // The supervisor releases its permit only after the kill.
            tokio::spawn(async move {
                let _ = killed.await;
                tokio::task::yield_now().await;
                drop(live);
            });
            supervisors.push(control);
        }
        assert_eq!(registry.live_processes(), 2);

        let unfinished = registry.close_and_drain(Duration::from_secs(5)).await;

        assert_eq!(unfinished, 0);
        assert_eq!(registry.live_processes(), 0);
        assert_eq!(registry.in_use("ticketing"), 0);
        for control in supervisors {
            assert_eq!(control.kills.load(Ordering::SeqCst), 1);
        }
    }

    #[tokio::test(start_paused = true)]
    async fn drain_reports_supervisors_still_live_at_its_deadline() {
        let registry = CommandRegistry::new();
        let (stuck, _ignored) = FakeSupervisor::new();
        let live = permit(&registry, "ticketing", 1)
            .await
            .register(stuck.clone())
            .unwrap();
        let (done, killed) = FakeSupervisor::new();
        let released = permit(&registry, "inventory", 1)
            .await
            .register(done)
            .unwrap();
        tokio::spawn(async move {
            let _ = killed.await;
            drop(released);
        });

        let unfinished = registry.close_and_drain(Duration::from_secs(1)).await;

        assert_eq!(unfinished, 1);
        assert_eq!(stuck.kills.load(Ordering::SeqCst), 1);
        assert_eq!(registry.in_use("ticketing"), 1);
        assert_eq!(registry.in_use("inventory"), 0);
        drop(live);
        assert_eq!(registry.live_processes(), 0);
        assert_eq!(registry.in_use("ticketing"), 0);
    }

    #[tokio::test]
    async fn a_supervisor_returns_its_permit_before_it_leaves_the_registry() {
        let registry = CommandRegistry::new();
        let (control, _killed) = FakeSupervisor::new();
        let live = permit(&registry, "ticketing", 1)
            .await
            .register(control)
            .unwrap();
        assert_eq!(live.command(), "ticketing");
        let mut drained = Box::pin(registry.close_and_drain(Duration::from_secs(5)));
        assert!(drained.as_mut().now_or_never().is_none());
        let observer = registry.clone();
        let observed = tokio::spawn(async move {
            observer.supervisors_released().await;
            observer.in_use("ticketing")
        });
        tokio::task::yield_now().await;
        drop(live);
        assert_eq!(observed.await.unwrap(), 0);
        assert_eq!(drained.await, 0);
    }
}
