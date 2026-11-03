//! One timer/arbitration driver per service. Slow personal settings reads run
//! separately and cannot hold up eligible peers or hard-deadline removal.
use super::*;

impl InvocationLimiter {
    pub(super) async fn drive_service(
        self: Arc<Self>,
        service: String,
        notify: Arc<Notify>,
        driver_id: u64,
    ) {
        loop {
            let changed = notify.notified();
            tokio::pin!(changed);
            changed.as_mut().enable();
            let wake = {
                let mut state = self.state.lock().unwrap();
                if !service_current(&state.scheduler, &service, driver_id) {
                    return;
                }
                let now = Instant::now();
                let now_ns = duration_ns(self.clock.monotonic());
                self.process_service(&mut state, &service, now, now_ns);
                if !service_current(&state.scheduler, &service, driver_id) {
                    return;
                }
                let mut wake: Option<Instant> = None;
                for principal in &state.scheduler.services[&service].ring {
                    let key = (principal.clone(), service.clone());
                    let queue = &state.scheduler.queues[&key];
                    for entry in &queue.entries {
                        if let Some(bound) = entry.ticket.hard_deadline {
                            wake = Some(wake.map_or(bound.at, |at| at.min(bound.at)));
                        }
                    }
                    if queue_usable(&state.scheduler, &key)
                        && let Some(head) = queue.entries.front()
                        && head.opportunity_ns != u64::MAX
                    {
                        let at = instant_for(now, now_ns, head.opportunity_ns);
                        wake = Some(wake.map_or(at, |other| other.min(at)));
                    }
                }
                wake
            };
            tokio::select! {
                _ = changed => {},
                _ = async {
                    match wake {
                        Some(at) => tokio::time::sleep_until(at).await,
                        None => std::future::pending::<()>().await,
                    }
                } => {},
            }
        }
    }

    /// Existing due opportunities form a batch. Reforecasting only after that
    /// batch preserves rate-deadline eligibility despite a late timer wake.
    pub(super) fn process_service(
        &self,
        state: &mut LimiterState,
        service: &str,
        initial_now: Instant,
        initial_ns: u64,
    ) {
        let keys = service_keys(&state.scheduler, service);
        for key in &keys {
            if let Some(limit) = cached_limit(&state.scheduler, key) {
                let revision = state.scheduler.settings[key].revision;
                let queue = state.scheduler.queues.get_mut(key).unwrap();
                if queue.limit != limit || queue.revision != revision {
                    queue.limit = limit;
                    queue.revision = revision;
                    for entry in &mut queue.entries {
                        entry.opportunity_ns = u64::MAX;
                    }
                }
            }
        }
        let mut refused = Vec::new();
        loop {
            let now = initial_now.max(Instant::now());
            self.prune_service(state, service, now, &mut refused);
            loop {
                let now_ns = initial_ns.max(duration_ns(self.clock.monotonic()));
                let Some(key) = due_key(state, service, now_ns) else {
                    break;
                };
                let head = &state.scheduler.queues[&key].entries[0];
                if let Some(reason) = head.ticket.cancellation.reason() {
                    let ticket = take_ticket(state, &key, 0, false);
                    ticket.finish(Err(InvocationAdmissionError::Cancelled(
                        ticket.removal(reason),
                    )));
                    continue;
                }
                let now = initial_now.max(Instant::now());
                if head
                    .ticket
                    .hard_deadline
                    .is_some_and(|bound| now >= bound.at)
                {
                    let limit = state.scheduler.queues[&key].limit;
                    refused.push((key.clone(), take_ticket(state, &key, 0, false), limit));
                    continue;
                }
                let limit = state.scheduler.queues[&key].limit;
                // Both histories are checked and debited under this lock, at
                // one actual timestamp. Simulation never supplies a debit time.
                let actual_ns = initial_ns.max(duration_ns(self.clock.monotonic()));
                record(state, &key, limit, actual_ns);
                let ticket = take_ticket(state, &key, 0, true);
                ticket.finish(Ok(InvocationAdmissionGrant {
                    waited: true,
                    waited_milliseconds: milliseconds(
                        now.saturating_duration_since(ticket.enqueued),
                    ),
                }));
            }
            let now = initial_now.max(Instant::now());
            let now_ns = initial_ns.max(duration_ns(self.clock.monotonic()));
            let plan = forecast_existing(state, service, now, now_ns);
            for key in service_keys(&state.scheduler, service) {
                let removed = state.scheduler.queues[&key]
                    .entries
                    .iter()
                    .filter(|entry| plan.rejected.contains(&entry.ticket.id))
                    .map(|entry| entry.ticket.id)
                    .collect::<Vec<_>>();
                for id in removed {
                    let queue = &state.scheduler.queues[&key];
                    let limit = queue.limit;
                    let index = queue
                        .entries
                        .iter()
                        .position(|entry| entry.ticket.id == id)
                        .unwrap();
                    refused.push((key.clone(), take_ticket(state, &key, index, false), limit));
                }
                if let Some(queue) = state.scheduler.queues.get_mut(&key) {
                    for entry in &mut queue.entries {
                        if let Some(at) = plan.opportunities.get(&entry.ticket.id) {
                            entry.opportunity_ns = *at;
                        }
                    }
                }
            }
            if due_key(state, service, now_ns).is_none() {
                break;
            }
        }
        let now = initial_now.max(Instant::now());
        let now_ns = initial_ns.max(duration_ns(self.clock.monotonic()));
        for (key, ticket, limit) in refused {
            let projection = project(state, &key, limit, now, now_ns);
            let rejection = self.rejection(
                &ticket.service,
                &projection,
                ticket.max_wait,
                ticket.enqueued,
                ticket.rate_deadline,
                ticket.hard_deadline,
                true,
                now,
                now_ns,
            );
            ticket.finish(Err(InvocationAdmissionError::RateLimited(rejection)));
        }
    }

    fn prune_service(
        &self,
        state: &mut LimiterState,
        service: &str,
        now: Instant,
        refused: &mut Vec<(Key, Arc<Ticket>, InvocationLimit)>,
    ) {
        for key in service_keys(&state.scheduler, service) {
            let removals = state.scheduler.queues[&key]
                .entries
                .iter()
                .enumerate()
                .filter_map(|(index, entry)| {
                    let reason = entry.ticket.cancellation.reason();
                    (reason.is_some()
                        || entry
                            .ticket
                            .hard_deadline
                            .is_some_and(|bound| now >= bound.at))
                    .then_some((index, reason))
                })
                .collect::<Vec<_>>();
            for (index, reason) in removals.into_iter().rev() {
                let limit = state.scheduler.queues[&key].limit;
                let ticket = take_ticket(state, &key, index, false);
                if let Some(reason) = reason {
                    ticket.finish(Err(InvocationAdmissionError::Cancelled(
                        ticket.removal(reason),
                    )));
                } else {
                    refused.push((key.clone(), ticket, limit));
                }
            }
        }
    }

    pub(super) fn remove(&self, key: &Key, id: u64, reason: AdmissionCancellationReason) {
        let mut state = self.state.lock().unwrap();
        let index = state
            .scheduler
            .queues
            .get(key)
            .and_then(|queue| queue.entries.iter().position(|entry| entry.ticket.id == id));
        if let Some(index) = index {
            let ticket = take_ticket(&mut state, key, index, false);
            ticket.finish(Err(InvocationAdmissionError::Cancelled(
                ticket.removal(reason),
            )));
            notify_service(&state.scheduler, &key.1);
        }
    }
}

fn service_current(state: &SchedulerState, service: &str, driver_id: u64) -> bool {
    state
        .services
        .get(service)
        .is_some_and(|queue| queue.driver_id == driver_id)
}

fn due_key(state: &LimiterState, service: &str, now_ns: u64) -> Option<Key> {
    let queue = state.scheduler.services.get(service)?;
    queue.ring.iter().find_map(|principal| {
        let key = (principal.clone(), service.to_owned());
        let queue = &state.scheduler.queues[&key];
        (queue_usable(&state.scheduler, &key)
            && queue.entries[0].opportunity_ns <= now_ns
            && capacity_available(state, &key, queue.limit, now_ns))
        .then_some(key)
    })
}

pub(super) fn take_ticket(
    state: &mut LimiterState,
    key: &Key,
    index: usize,
    advance_turn: bool,
) -> Arc<Ticket> {
    let queue = state.scheduler.queues.get_mut(key).unwrap();
    let ticket = queue.entries.remove(index).unwrap().ticket;
    let empty = queue.entries.is_empty();
    let service = state.scheduler.services.get_mut(&key.1).unwrap();
    if empty || advance_turn {
        service.ring.retain(|principal| *principal != key.0);
        if !empty {
            service.ring.push_back(key.0.clone());
        }
    }
    let empty_service = service.ring.is_empty();
    if empty {
        state
            .scheduler
            .queues
            .remove(key)
            .unwrap()
            .refresh_stop
            .cancel();
    }
    state.scheduler.settings[key].notify.notify_waiters();
    if empty_service {
        let service = state.scheduler.services.remove(&key.1).unwrap();
        service.notify.notify_waiters();
    }
    ticket
}
