//! SDK sessions have no authentication authority. Every operation is admitted by
//! the HTTP edge; this manager binds routing state to the exact credential.
use super::{Admitted, CURRENT_REQUEST, ProtocolPermits};
use crate::state::{ReloadableState, RuntimeSnapshot};
use agent_access_core::{AttestedIdentityProof, IdentityFailure};
use futures_util::Stream;
use rmcp::{
    model::{ClientJsonRpcMessage, ServerJsonRpcMessage},
    transport::common::server_side_http::ServerSseMessage,
    transport::{
        WorkerTransport,
        streamable_http_server::session::{
            SessionId, SessionManager,
            local::{LocalSessionManager, LocalSessionWorker},
        },
    },
};
use sha2::{Digest, Sha256};
use std::{
    collections::HashMap,
    sync::Arc,
    time::{Duration, Instant},
};
use tokio::sync::{Mutex, Semaphore};

pub(super) struct Sessions {
    pub inner: LocalSessionManager,
    bindings: Mutex<HashMap<SessionId, Binding>>,
    proof_worker: Arc<Semaphore>,
}
struct Binding {
    view: agent_access_core::mcp::McpView,
    owner: String,
    principal: String,
    context: String,
    generation: u64,
    proof: Option<AttestedIdentityProof>,
    caller_security_epoch: Option<u64>,
    security_profile: String,
    created: Instant,
    used: Instant,
}
#[derive(Debug)]
pub(super) struct SessionError;
impl std::fmt::Display for SessionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("MCP session unavailable")
    }
}
impl std::error::Error for SessionError {}
fn security_profile(config: &agent_access_core::BrokerConfig) -> String {
    // These internal configuration values are never returned or logged. A hash
    // of their deterministic representation separates transport/identity/context
    // changes from ordinary provider, policy, credential, and audit reloads.
    let material = format!(
        "{:?}",
        (
            &config.mcp,
            &config.identity,
            &config.execution_context,
            &config.broker_tokens,
            &config.managed_store,
            &config.network.trusted_proxies
        )
    );
    format!("{:x}", Sha256::digest(material.as_bytes()))
}
impl Sessions {
    pub fn new() -> Arc<Self> {
        let mut inner = LocalSessionManager::default();
        inner.session_config.channel_capacity = 4;
        inner.session_config.keep_alive = None; // Broker owns idle/absolute expiry.
        inner.session_config.sse_retry = None;
        inner.session_config.completed_cache_ttl = Duration::ZERO;
        inner.session_config.init_timeout = Some(Duration::from_secs(30));
        Arc::new(Self {
            inner,
            bindings: Mutex::new(HashMap::new()),
            proof_worker: Arc::new(Semaphore::new(1)),
        })
    }
    pub async fn reap(&self, snapshot: Arc<RuntimeSnapshot>) {
        self.reap_config(snapshot.generation, snapshot.runtime.config())
            .await;
    }

    #[cfg(test)]
    pub async fn count(&self) -> usize {
        self.bindings.lock().await.len()
    }

    async fn reap_config(&self, generation: u64, broker_config: &agent_access_core::BrokerConfig) {
        let config = &broker_config.mcp;
        let security_profile = security_profile(broker_config);
        let ids: Vec<_> = {
            let bindings = self.bindings.lock().await;
            bindings
                .iter()
                .filter(|(_, b)| {
                    // A request admitted against an older snapshot must not reap
                    // sessions that were created under a newer generation.
                    b.generation <= generation
                        && (!config.enabled
                            || b.security_profile != security_profile
                            || b.created.elapsed()
                                >= Duration::from_millis(config.session_max_lifetime_ms)
                            || b.used.elapsed()
                                >= Duration::from_millis(config.session_idle_timeout_ms))
                })
                .map(|(id, _)| id.clone())
                .collect()
        };
        for id in ids {
            let _ = self.close_session(&id).await;
        }
    }

    /// Check bounded batches without holding the session lock during store I/O.
    /// Only authoritative stale evidence closes a session; unavailable storage
    /// retains unconfirmed entries. SDK closure never invokes authenticated
    /// cancellation, so independently owned admitted operations can complete.
    pub async fn prune_attested(
        &self,
        state: Arc<ReloadableState>,
        snapshot: Arc<RuntimeSnapshot>,
        principal: Option<&str>,
        retain: Option<Arc<ProtocolPermits>>,
    ) -> Result<(), IdentityFailure> {
        const BATCH: usize = 64;
        let (mut candidates, epoch_stale) = {
            let bindings = self.bindings.lock().await;
            let mut candidates = Vec::new();
            let mut epoch_stale = Vec::new();
            for (id, binding) in bindings.iter() {
                if binding.generation > snapshot.generation {
                    continue;
                }
                if binding
                    .caller_security_epoch
                    .is_some_and(|epoch| epoch != snapshot.caller_security_epoch)
                {
                    epoch_stale.push(id.clone());
                } else if let Some(proof) = &binding.proof {
                    candidates.push((
                        id.clone(),
                        proof.clone(),
                        principal == Some(&binding.principal),
                    ));
                }
            }
            (candidates, epoch_stale)
        };
        for id in epoch_stale {
            let _ = self.close_session(&id).await;
        }
        // An initialize has one store batch, with its resolved human first.
        // Remaining slots reclaim globally capped sessions after a human remap.
        // Complete sweeps belong to background maintenance.
        if principal.is_some() {
            candidates.sort_unstable_by_key(|(_, _, own)| !own);
            candidates.truncate(BATCH);
        }
        if candidates.is_empty() {
            return Ok(());
        }
        for batch in candidates.chunks(BATCH) {
            let mut stale = Vec::new();
            if !batch.is_empty() {
                // Queue each batch separately so pending initialize requests
                // can run between background batches. Move the permit into the
                // actual worker so waiter cancellation cannot release it early.
                let waiting = self.proof_worker.clone().acquire_owned();
                #[cfg(test)]
                let worker = {
                    tokio::pin!(waiting);
                    match futures_util::poll!(waiting.as_mut()) {
                        std::task::Poll::Ready(result) => result,
                        std::task::Poll::Pending => {
                            if principal.is_some() {
                                state.mcp_prune_waiting.notify_one();
                            }
                            waiting.await
                        }
                    }
                };
                #[cfg(not(test))]
                let worker = waiting.await;
                let worker = worker.map_err(|_| IdentityFailure::Unavailable)?;
                let store = snapshot
                    .runtime
                    .managed_store()
                    .cloned()
                    .ok_or(IdentityFailure::Unavailable)?;
                let proofs = batch
                    .iter()
                    .map(|(_, proof, _)| proof.clone())
                    .collect::<Vec<_>>();
                let retained = retain.clone();
                let state = state.clone();
                #[cfg(test)]
                let background = principal.is_none();
                #[cfg(test)]
                let batch_size = batch.len();
                let current = tokio::task::spawn_blocking(move || {
                    let _retained = retained;
                    let _worker = worker;
                    #[cfg(test)]
                    let barrier = state.wait_mcp_prune_barrier(background, batch_size);
                    #[cfg(not(test))]
                    let _ = state;
                    let current = store.batch_proof_current(&proofs);
                    drop(_worker);
                    drop(_retained);
                    #[cfg(test)]
                    if let Some(barrier) = barrier {
                        barrier.completed.notify_one();
                    }
                    current
                })
                .await
                .map_err(|_| IdentityFailure::Unavailable)?
                .map_err(|_| IdentityFailure::Unavailable)?;
                if current.len() != batch.len() {
                    return Err(IdentityFailure::Unavailable);
                }
                for ((id, _, _), current) in batch.iter().zip(current) {
                    if !current {
                        stale.push(id.clone());
                    }
                }
            }
            for id in stale {
                let _ = self.close_session(&id).await;
            }
        }
        Ok(())
    }
    pub async fn owned(&self, id: &SessionId, request: &Admitted) -> bool {
        let mut bindings = self.bindings.lock().await;
        let Some(b) = bindings.get_mut(id) else {
            return false;
        };
        let config = &request.snapshot.runtime.config().mcp;
        if b.view != request.view
            || b.owner != request.owner
            || b.context != request.context.as_str()
            || b.security_profile != security_profile(request.snapshot.runtime.config())
        {
            return false;
        }
        if b.created.elapsed() >= Duration::from_millis(config.session_max_lifetime_ms)
            || b.used.elapsed() >= Duration::from_millis(config.session_idle_timeout_ms)
        {
            drop(bindings);
            let _ = self.close_session(id).await;
            return false;
        }
        b.used = Instant::now();
        true
    }
    pub async fn can_create(&self, request: &Admitted) -> bool {
        let bindings = self.bindings.lock().await;
        let config = &request.snapshot.runtime.config().mcp;
        bindings.len() < config.max_sessions
            && bindings
                .values()
                .filter(|b| b.principal == request.identity.principal)
                .count()
                < config.max_sessions_per_principal
    }
}
impl SessionManager for Sessions {
    type Error = SessionError;
    type Transport = WorkerTransport<LocalSessionWorker>;
    async fn create_session(&self) -> Result<(SessionId, Self::Transport), Self::Error> {
        let request = CURRENT_REQUEST
            .try_with(Clone::clone)
            .map_err(|_| SessionError)?;
        let config = &request.snapshot.runtime.config().mcp;
        let mut bindings = self.bindings.lock().await;
        if bindings.len() >= config.max_sessions
            || bindings
                .values()
                .filter(|b| b.principal == request.identity.principal)
                .count()
                >= config.max_sessions_per_principal
        {
            return Err(SessionError);
        }
        let (id, transport) = self
            .inner
            .create_session()
            .await
            .map_err(|_| SessionError)?;
        bindings.insert(
            id.clone(),
            Binding {
                view: request.view.clone(),
                owner: request.owner.clone(),
                principal: request.identity.principal.clone(),
                context: request.context.to_string(),
                generation: request.snapshot.generation,
                proof: request.identity_pin.proof.clone(),
                caller_security_epoch: request.identity_pin.caller_security_epoch,
                security_profile: security_profile(request.snapshot.runtime.config()),
                created: Instant::now(),
                used: Instant::now(),
            },
        );
        request.created_sessions.lock().unwrap().push(id.clone());
        Ok((id, transport))
    }
    async fn initialize_session(
        &self,
        id: &SessionId,
        message: ClientJsonRpcMessage,
    ) -> Result<ServerJsonRpcMessage, Self::Error> {
        match self.inner.initialize_session(id, message).await {
            Ok(r) => Ok(r),
            Err(_) => {
                let _ = self.close_session(id).await;
                Err(SessionError)
            }
        }
    }
    async fn has_session(&self, id: &SessionId) -> Result<bool, Self::Error> {
        Ok(self.bindings.lock().await.contains_key(id)
            && self.inner.has_session(id).await.map_err(|_| SessionError)?)
    }
    async fn close_session(&self, id: &SessionId) -> Result<(), Self::Error> {
        // Leave the expired binding reachable by the reaper if this future is
        // canceled while waiting for SDK cleanup. Expiry still denies admission.
        let result = self.inner.close_session(id).await.map_err(|_| SessionError);
        self.bindings.lock().await.remove(id);
        result
    }
    async fn create_stream(
        &self,
        id: &SessionId,
        message: ClientJsonRpcMessage,
    ) -> Result<impl Stream<Item = ServerSseMessage> + Send + Sync + 'static, Self::Error> {
        self.inner
            .create_stream(id, message)
            .await
            .map_err(|_| SessionError)
    }
    async fn accept_message(
        &self,
        id: &SessionId,
        message: ClientJsonRpcMessage,
    ) -> Result<(), Self::Error> {
        self.inner
            .accept_message(id, message)
            .await
            .map_err(|_| SessionError)
    }
    async fn create_standalone_stream(
        &self,
        _id: &SessionId,
    ) -> Result<impl Stream<Item = ServerSseMessage> + Send + Sync + 'static, Self::Error> {
        Ok(futures_util::stream::empty())
    }
    async fn resume(
        &self,
        _id: &SessionId,
        _event: String,
    ) -> Result<impl Stream<Item = ServerSseMessage> + Send + Sync + 'static, Self::Error> {
        Ok(futures_util::stream::empty())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[tokio::test]
    async fn stale_snapshot_cleanup_does_not_remove_newer_sessions() {
        let sessions = Sessions::new();
        let id = SessionId::from("new-generation-session".to_owned());
        sessions.bindings.lock().await.insert(
            id.clone(),
            Binding {
                view: agent_access_core::mcp::McpView::Aggregate,
                owner: "owner".into(),
                principal: "user".into(),
                context: "default".into(),
                generation: 2,
                proof: None,
                caller_security_epoch: None,
                security_profile: "new-profile".into(),
                created: Instant::now(),
                used: Instant::now(),
            },
        );
        let mut config = agent_access_core::parse_broker_config_raw("session-test", "[identity]\nmode=\"anonymous\"\nauthority=\"toml\"\n[policy]\nauthority=\"toml\"\ndefault_decision=\"deny\"\n", &std::sync::Arc::new(crate::backend_registry()))
        .unwrap();
        config.mcp.enabled = true;
        sessions.reap_config(1, &config).await;
        assert!(sessions.bindings.lock().await.contains_key(&id));
        sessions.reap_config(3, &config).await;
        assert!(!sessions.bindings.lock().await.contains_key(&id));
    }
}
