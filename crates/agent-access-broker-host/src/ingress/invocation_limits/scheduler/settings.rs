use super::*;

impl InvocationLimiter {
    pub(super) async fn resolve(
        self: &Arc<Self>,
        epoch: u64,
        key: &Key,
        resolver: &InvocationLimitResolver,
        purpose: ResolutionPurpose,
        stopped: Option<&CancellationToken>,
    ) -> Result<Resolved, InvocationAdmissionError> {
        loop {
            if stopped.is_some_and(CancellationToken::is_cancelled) {
                return Err(cancelled(AdmissionCancellationReason::OwnerAbandoned));
            }
            let (identity, revision, changing, cached, notify) = {
                let mut state = self.state.lock().unwrap();
                check_epoch(&state.scheduler, epoch)?;
                let settings = state.scheduler.settings.entry(key.clone()).or_default();
                (
                    settings.identity.clone(),
                    settings.revision,
                    settings.changing != 0,
                    settings
                        .cached
                        .filter(|(cached_epoch, _)| *cached_epoch == epoch)
                        .map(|(_, limit)| limit),
                    settings.notify.clone(),
                )
            };
            let lease = SettingsReadLease {
                limiter: self.clone(),
                key: key.clone(),
                identity,
            };
            // Enable the waiter before checking the revision again: notifications
            // cannot be lost between clearing a write fence and awaiting it.
            let changed = notify.notified();
            tokio::pin!(changed);
            changed.as_mut().enable();
            if changing {
                let still_changing = {
                    let state = self.state.lock().unwrap();
                    check_epoch(&state.scheduler, epoch)?;
                    state
                        .scheduler
                        .settings
                        .get(key)
                        .is_some_and(|s| s.changing != 0)
                };
                if still_changing {
                    tokio::select! {
                        _ = changed => {},
                        _ = async { match stopped { Some(token) => token.cancelled().await, None => std::future::pending::<()>().await } } => {
                            return Err(cancelled(AdmissionCancellationReason::OwnerAbandoned));
                        }
                    }
                }
                continue;
            }
            if let Some(limit) = cached
                && purpose == ResolutionPurpose::QueueWake
            {
                return Ok(Resolved {
                    limit,
                    revision,
                    lease,
                });
            }
            if stopped.is_some_and(CancellationToken::is_cancelled) {
                return Err(cancelled(AdmissionCancellationReason::OwnerAbandoned));
            }
            let result = resolver().await;
            // An already-started blocking store read keeps its owner until it
            // returns, but its abandoned result cannot publish settings or
            // start a replacement read after a fence changes.
            if stopped.is_some_and(CancellationToken::is_cancelled) {
                return Err(cancelled(AdmissionCancellationReason::OwnerAbandoned));
            }
            let mut state = self.state.lock().unwrap();
            check_epoch(&state.scheduler, epoch)?;
            let settings = state
                .scheduler
                .settings
                .get_mut(key)
                .expect("active settings read retains its fence");
            if !Arc::ptr_eq(&settings.identity, &lease.identity)
                || settings.revision != revision
                || settings.changing != 0
            {
                continue;
            }
            let limit = result.map_err(|error| InvocationAdmissionError::Resolution {
                error,
                waited: false,
                waited_milliseconds: 0,
            })?;
            if purpose != ResolutionPurpose::Observation {
                // New requests retain the existing fresh-read/fail-closed
                // contract. A changed pair discovered without a host mutation
                // notification must also fence older concurrent reads.
                if settings.cached.is_some_and(|(cached_epoch, cached_limit)| {
                    cached_epoch == epoch && cached_limit != limit
                }) {
                    settings.revision = settings
                        .revision
                        .checked_add(1)
                        .expect("settings revision exhausted");
                    settings.notify.notify_waiters();
                }
                settings.cached = Some((epoch, limit));
            }
            let revision = settings.revision;
            if purpose != ResolutionPurpose::Observation {
                notify_service(&state.scheduler, &key.1);
            }
            return Ok(Resolved {
                limit,
                revision,
                lease,
            });
        }
    }

    pub(super) async fn resolve_initial(
        self: &Arc<Self>,
        key: &Key,
        request: &InvocationAdmissionRequest,
    ) -> Result<Resolved, InvocationAdmissionError> {
        let stopped = CancellationToken::new();
        let _stop_on_return = stopped.clone().drop_guard();
        let limiter = self.clone();
        let key = key.clone();
        let epoch = request.epoch;
        // The host resolver captures this request's original permits and
        // admission registration. This worker can only resolve settings;
        // dropping its result can never enqueue or grant an invocation.
        let resolver = request.resolve_limit.clone();
        let mut read = tokio::spawn(
            async move {
                limiter
                    .resolve(
                        epoch,
                        &key,
                        &resolver,
                        ResolutionPurpose::NewAdmission,
                        Some(&stopped),
                    )
                    .await
            }
            .instrument(tracing::Span::current()),
        );
        tokio::select! {
            biased;
            reason = request.cancellation.cancelled() => Err(cancelled(reason)),
            _ = async { match request.hard_deadline { Some(deadline) => tokio::time::sleep_until(deadline.at).await, None => std::future::pending::<()>().await } } => {
                Err(InvocationAdmissionError::Deadline(request.hard_deadline.expect("deadline timer enabled").kind))
            }
            result = &mut read => result.unwrap_or_else(|_| Err(InvocationAdmissionError::Resolution {
                error: ProviderError::error(ReasonCode::OperationFailed, "rate settings resolution task failed"),
                waited: false,
                waited_milliseconds: 0,
            })),
        }
    }

    /// One queued refresh per key, independent of the service's timer driver.
    /// Noncancelable reads retain their owner, but cannot recreate a queue.
    pub(super) async fn refresh_key(
        self: Arc<Self>,
        key: Key,
        notify: Arc<Notify>,
        driver_id: u64,
    ) {
        loop {
            let changed = notify.notified();
            tokio::pin!(changed);
            changed.as_mut().enable();
            let pending = {
                let mut state = self.state.lock().unwrap();
                let Some(queue) = state
                    .scheduler
                    .queues
                    .get(&key)
                    .filter(|queue| queue.driver_id == driver_id)
                else {
                    return;
                };
                if cached_limit(&state.scheduler, &key).is_some()
                    || state.scheduler.settings[&key].refreshing.is_some()
                {
                    None
                } else {
                    let head = &queue.entries[0].ticket;
                    let pending = (
                        head.epoch,
                        head.resolver.clone(),
                        queue.refresh_stop.clone(),
                    );
                    state.scheduler.settings.get_mut(&key).unwrap().refreshing = Some(driver_id);
                    Some(pending)
                }
            };
            let Some((epoch, resolver, stopped)) = pending else {
                changed.await;
                continue;
            };
            let outcome = self
                .resolve(
                    epoch,
                    &key,
                    &resolver,
                    ResolutionPurpose::QueueWake,
                    Some(&stopped),
                )
                .await;
            drop(resolver);
            let current = {
                let mut state = self.state.lock().unwrap();
                if let Some(settings) = state.scheduler.settings.get_mut(&key)
                    && settings.refreshing == Some(driver_id)
                {
                    settings.refreshing = None;
                    settings.notify.notify_waiters();
                }
                let current = state
                    .scheduler
                    .queues
                    .get(&key)
                    .is_some_and(|queue| queue.driver_id == driver_id);
                if current {
                    if let Err(error) = &outcome {
                        while state.scheduler.queues.contains_key(&key) {
                            let ticket = driver::take_ticket(&mut state, &key, 0, false);
                            let error = match error {
                                InvocationAdmissionError::Resolution { error, .. } => {
                                    InvocationAdmissionError::Resolution {
                                        error: error.clone(),
                                        waited: true,
                                        waited_milliseconds: milliseconds(
                                            ticket.enqueued.elapsed(),
                                        ),
                                    }
                                }
                                InvocationAdmissionError::Cancelled(removal) => {
                                    InvocationAdmissionError::Cancelled(
                                        ticket.removal(removal.reason),
                                    )
                                }
                                InvocationAdmissionError::RateLimited(_)
                                | InvocationAdmissionError::Deadline(_) => unreachable!(),
                            };
                            ticket.finish(Err(error));
                        }
                    }
                    notify_service(&state.scheduler, &key.1);
                }
                current
            };
            // Dropping the successful settings lease also takes the state lock.
            // Do it before sleeping and outside the preceding critical section.
            drop(outcome);
            if !current {
                let mut state = self.state.lock().unwrap();
                let unused = !state
                    .keys
                    .get(&key.0)
                    .is_some_and(|services| services.contains_key(&key.1))
                    && !state.scheduler.queues.contains_key(&key)
                    && state.scheduler.settings.get(&key).is_some_and(|settings| {
                        settings.changing == 0
                            && settings.refreshing.is_none()
                            && Arc::strong_count(&settings.identity) == 1
                    });
                if unused {
                    state.scheduler.settings.remove(&key);
                }
                return;
            }
        }
    }
}

pub(crate) struct InvocationLimitUpdate {
    pub(super) limiter: Arc<InvocationLimiter>,
    pub(super) key: Key,
    pub(super) finished: bool,
}
impl InvocationLimitUpdate {
    pub(crate) fn finish(mut self, success: bool) {
        self.complete(success);
    }
    fn complete(&mut self, success: bool) {
        if self.finished {
            return;
        }
        self.finished = true;
        let mut state = self.limiter.state.lock().unwrap();
        let settings = state
            .scheduler
            .settings
            .get_mut(&self.key)
            .expect("write fence exists");
        settings.changing -= 1;
        if success {
            settings.revision = settings
                .revision
                .checked_add(1)
                .expect("settings revision exhausted");
            settings.cached = None;
        }
        settings.notify.notify_waiters();
        notify_service(&state.scheduler, &self.key.1);
        // A read may have been abandoned while this write kept its fence
        // alive. The final writer also retires an otherwise unused key.
        if !state
            .keys
            .get(&self.key.0)
            .is_some_and(|services| services.contains_key(&self.key.1))
            && !state.scheduler.queues.contains_key(&self.key)
            && state
                .scheduler
                .settings
                .get(&self.key)
                .is_some_and(|settings| {
                    settings.changing == 0
                        && Arc::strong_count(&settings.identity) == 1
                        && settings.refreshing.is_none()
                })
        {
            state.scheduler.settings.remove(&self.key);
        }
    }
}
impl Drop for InvocationLimitUpdate {
    fn drop(&mut self) {
        self.complete(false);
    }
}
