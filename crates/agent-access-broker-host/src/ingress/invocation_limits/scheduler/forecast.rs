//! Pure service scheduling. Histories, queues and ring turns here are copies;
//! neither observations nor trial admissions can reserve real capacity.
use super::*;
use std::collections::HashSet;

#[derive(Clone)]
struct ModelTicket {
    id: u64,
    opportunity_ns: u64,
    rate_deadline: Option<Instant>,
    hard_deadline: Option<AdmissionDeadline>,
}

impl ModelTicket {
    fn fits(&self, now: Instant, now_ns: u64, at_ns: u64) -> bool {
        let at = instant_for(now, now_ns, at_ns);
        self.rate_deadline.is_none_or(|deadline| at <= deadline)
            && self
                .hard_deadline
                .is_none_or(|deadline| at < deadline.at && now < deadline.at)
    }
}

#[derive(Clone)]
struct ModelQueue {
    limit: InvocationLimit,
    window: KeyWindow,
    entries: VecDeque<ModelTicket>,
    usable: bool,
    enforce_personal: bool,
}

#[derive(Clone)]
struct Model {
    ring: VecDeque<String>,
    queues: HashMap<String, ModelQueue>,
    shared: Option<(InvocationLimit, KeyWindow)>,
}

#[derive(Default)]
pub(super) struct Plan {
    pub opportunities: HashMap<u64, u64>,
    pub rejected: HashSet<u64>,
}

impl Model {
    fn new(
        state: &LimiterState,
        service: &str,
        override_limit: Option<(&str, InvocationLimit)>,
        now: Instant,
        now_ns: u64,
    ) -> Self {
        let mut model = Self {
            ring: state
                .scheduler
                .services
                .get(service)
                .map(|queue| queue.ring.clone())
                .unwrap_or_default(),
            queues: HashMap::new(),
            shared: state.aggregate_limits.get(service).map(|limit| {
                (
                    *limit,
                    aggregate_window_copy(state, service, *limit, now_ns),
                )
            }),
        };
        for principal in &model.ring {
            let key = (principal.clone(), service.to_owned());
            let queue = &state.scheduler.queues[&key];
            let settings = &state.scheduler.settings[&key];
            let supplied = override_limit
                .filter(|(name, _)| *name == principal)
                .map(|(_, limit)| limit);
            let current = cached_limit(&state.scheduler, &key);
            let limit = supplied.or(current).unwrap_or(queue.limit);
            let unchanged = limit == queue.limit && settings.revision == queue.revision;
            let entries = queue
                .entries
                .iter()
                .filter(|entry| {
                    entry.ticket.cancellation.reason().is_none()
                        && entry
                            .ticket
                            .hard_deadline
                            .is_none_or(|bound| now < bound.at)
                })
                .map(|entry| ModelTicket {
                    id: entry.ticket.id,
                    opportunity_ns: if unchanged {
                        entry.opportunity_ns
                    } else {
                        u64::MAX
                    },
                    rate_deadline: Some(entry.ticket.rate_deadline),
                    hard_deadline: entry.ticket.hard_deadline,
                })
                .collect();
            model.queues.insert(
                principal.clone(),
                ModelQueue {
                    limit,
                    window: window_copy(state, &key, limit, now_ns),
                    entries,
                    // A supplied limit is an already-fenced observation/read,
                    // or the explicit stored-rate fallback for terminal audit.
                    usable: supplied.is_some() || current.is_some(),
                    enforce_personal: true,
                },
            );
        }
        model
            .ring
            .retain(|principal| !model.queues[principal].entries.is_empty());
        if let Some((principal, limit)) = override_limit {
            model
                .queues
                .entry(principal.to_owned())
                .or_insert_with(|| ModelQueue {
                    limit,
                    window: window_copy(
                        state,
                        &(principal.to_owned(), service.to_owned()),
                        limit,
                        now_ns,
                    ),
                    entries: VecDeque::new(),
                    usable: true,
                    enforce_personal: true,
                });
        }
        model
    }

    fn earliest(&mut self, principal: &str, cursor: u64) -> u64 {
        let queue = self.queues.get_mut(principal).unwrap();
        let personal = if queue.enforce_personal {
            next_capacity(&mut queue.window, queue.limit.requests(), cursor)
        } else {
            cursor
        };
        let shared = self.shared.as_mut().map_or(cursor, |(limit, window)| {
            next_capacity(window, limit.requests(), cursor)
        });
        personal.max(shared)
    }

    fn take(&mut self, index: usize, at_ns: u64) -> ModelTicket {
        let principal = self.ring.remove(index).unwrap();
        let queue = self.queues.get_mut(&principal).unwrap();
        let ticket = queue.entries.pop_front().unwrap();
        if queue.enforce_personal {
            queue.window.expire(at_ns);
            queue.window.record(at_ns);
        }
        if let Some((_, window)) = &mut self.shared {
            window.expire(at_ns);
            window.record(at_ns);
        }
        if !queue.entries.is_empty() {
            self.ring.push_back(principal);
        }
        ticket
    }

    fn remove_head(&mut self, index: usize) -> ModelTicket {
        let principal = &self.ring[index];
        let queue = self.queues.get_mut(principal).unwrap();
        let ticket = queue.entries.pop_front().unwrap();
        if queue.entries.is_empty() {
            self.ring.remove(index);
        }
        ticket
    }

    /// Ring order decides among eligible heads at the same virtual time. The
    /// trial mode keeps every accepted peer represented even if the newcomer's
    /// arrival would move that peer beyond its bound.
    fn schedule(&self, now: Instant, now_ns: u64, retain_infeasible: bool) -> Plan {
        let mut model = self.clone();
        let mut plan = Plan::default();
        let mut cursor = now_ns;
        loop {
            let mut next = None;
            let mut refused = None;
            for index in 0..model.ring.len() {
                let principal = model.ring[index].clone();
                if !model.queues[&principal].usable {
                    continue;
                }
                let at = model.earliest(&principal, cursor);
                if !retain_infeasible && !model.queues[&principal].entries[0].fits(now, now_ns, at)
                {
                    refused = Some(index);
                    break;
                }
                next = Some(next.map_or(at, |earlier: u64| earlier.min(at)));
            }
            if let Some(index) = refused {
                plan.rejected.insert(model.remove_head(index).id);
                continue;
            }
            let Some(at) = next else { break };
            cursor = at;
            let index = (0..model.ring.len())
                .find(|&index| {
                    let principal = model.ring[index].clone();
                    model.queues[&principal].usable && model.earliest(&principal, cursor) == cursor
                })
                .expect("the earliest capacity belongs to an eligible head");
            let ticket = model.take(index, cursor);
            plan.opportunities.insert(ticket.id, cursor);
        }
        plan
    }

    /// Models the same due batches as the real driver. Due opportunities keep
    /// their rate-wait eligibility through timer latency; all debits still use
    /// the current time, and reforecast follows each batch's actual debits.
    fn settle(&mut self, now: Instant, now_ns: u64) -> HashSet<u64> {
        let mut rejected = HashSet::new();
        loop {
            loop {
                let index = (0..self.ring.len()).find(|&index| {
                    let principal = self.ring[index].clone();
                    let queue = &self.queues[&principal];
                    queue.usable
                        && queue.entries[0].opportunity_ns <= now_ns
                        && self.earliest(&principal, now_ns) == now_ns
                });
                let Some(index) = index else { break };
                self.take(index, now_ns);
            }
            let plan = self.schedule(now, now_ns, false);
            for queue in self.queues.values_mut() {
                queue.entries.retain_mut(|entry| {
                    if plan.rejected.contains(&entry.id) {
                        return false;
                    }
                    if let Some(at) = plan.opportunities.get(&entry.id) {
                        entry.opportunity_ns = *at;
                    }
                    true
                });
            }
            rejected.extend(plan.rejected);
            self.ring
                .retain(|principal| !self.queues[principal].entries.is_empty());
            let ready = (0..self.ring.len()).any(|index| {
                let principal = self.ring[index].clone();
                self.queues[&principal].usable
                    && self.queues[&principal].entries[0].opportunity_ns <= now_ns
                    && self.earliest(&principal, now_ns) == now_ns
            });
            if !ready {
                return rejected;
            }
        }
    }

    fn candidate(&mut self, principal: &str) {
        let queue = self.queues.get_mut(principal).unwrap();
        if queue.entries.is_empty() {
            self.ring.push_back(principal.to_owned());
        }
        queue.entries.push_back(ModelTicket {
            id: 0, // Real queued tickets start at one.
            opportunity_ns: u64::MAX,
            rate_deadline: None,
            hard_deadline: None,
        });
    }
}

pub(super) fn forecast_existing(
    state: &LimiterState,
    service: &str,
    now: Instant,
    now_ns: u64,
) -> Plan {
    Model::new(state, service, None, now, now_ns).schedule(now, now_ns, false)
}

pub(super) struct Projection {
    pub counted: u64,
    pub queued: u64,
    pub available: u32,
    pub next_ns: u64,
    pub scope: InvocationLimitScope,
    pub limiting_limit: InvocationLimit,
    /// A decision must settle these peers before using the hypothetical turn.
    /// Read-only observations deliberately leave this work to the real driver.
    pub requires_settlement: bool,
}

pub(super) fn project(
    state: &LimiterState,
    key: &Key,
    limit: InvocationLimit,
    now: Instant,
    now_ns: u64,
) -> Projection {
    let mut joint = Model::new(state, &key.1, Some((&key.0, limit)), now, now_ns);
    let actual_pending = service_keys(&state.scheduler, &key.1)
        .iter()
        .map(|key| state.scheduler.queues[key].entries.len())
        .sum::<usize>();
    let counted = joint.queues[&key.0].window.total;
    let pending = joint.queues[&key.0]
        .entries
        .iter()
        .map(|entry| entry.id)
        .collect::<Vec<_>>();
    let refused = joint.settle(now, now_ns);
    let remaining_pending = joint
        .queues
        .values()
        .map(|queue| queue.entries.len())
        .sum::<usize>();
    let queued = pending.iter().filter(|id| !refused.contains(id)).count() as u64;
    let personal_remaining =
        u64::from(limit.requests()).saturating_sub(joint.queues[&key.0].window.total);
    let shared_remaining = joint
        .shared
        .as_ref()
        .map(|(limit, window)| u64::from(limit.requests()).saturating_sub(window.total));
    joint.candidate(&key.0);
    let next_ns = joint.schedule(now, now_ns, true).opportunities[&0];

    let mut personal = Model::new(state, &key.1, Some((&key.0, limit)), now, now_ns);
    personal.shared = None;
    personal.ring.retain(|principal| *principal == key.0);
    personal.queues.retain(|principal, _| *principal == key.0);
    personal.settle(now, now_ns);
    personal.candidate(&key.0);
    let personal_next = personal.schedule(now, now_ns, true).opportunities[&0];
    // Empty allowances alone do not establish an equal-time constraint: the
    // shared window may open before the personal one. Replay the same settled
    // ring with only this caller's personal allowance unconstrained, retaining
    // peer limits and shared contention when identifying a genuine tie.
    let shared_tie = if next_ns == personal_next && next_ns > now_ns && joint.shared.is_some() {
        let mut shared_only = joint.clone();
        shared_only.queues.get_mut(&key.0).unwrap().enforce_personal = false;
        shared_only.schedule(now, now_ns, true).opportunities[&0] == next_ns
    } else {
        false
    };
    let scope = if next_ns > personal_next || shared_tie {
        InvocationLimitScope::Service
    } else {
        InvocationLimitScope::Principal
    };
    let limiting_limit = match scope {
        InvocationLimitScope::Service => state.aggregate_limits[&key.1],
        InvocationLimitScope::Principal => limit,
    };
    Projection {
        counted,
        queued,
        available: if next_ns == now_ns {
            personal_remaining.min(shared_remaining.unwrap_or(u64::MAX)) as u32
        } else {
            0
        },
        next_ns,
        scope,
        limiting_limit,
        requires_settlement: actual_pending != remaining_pending,
    }
}
