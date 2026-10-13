use crate::BrokerBuildStatus;
use crate::ingress::guards::{IngressGuards, IngressPermit};
use crate::ingress::invocation_limits::InvocationLimiter;
use crate::ingress::source::SourceResolver;
use crate::ingress::spool::UploadSpoolBudgets;
use crate::reload::ReloadAttemptSummary;
use agent_access_core::microsoft_oidc::{
    MicrosoftOidcClock, MicrosoftOidcHttpClient, MicrosoftOidcProviderMetadata,
    MicrosoftOidcRuntimeConfig, SystemMicrosoftOidcClock,
};
use agent_access_core::{
    AuditRuntimeRegistry, BackendRegistry, BrokerRuntime, ManagedStoreError,
    OidcProviderStateReconcileRequest, RuntimeError, StateLockSet,
};
use arc_swap::ArcSwap;
use chrono::{DateTime, Duration as ChronoDuration, Utc};
use openidconnect::{AsyncHttpClient, HttpRequest, HttpResponse};
use std::fmt;
use std::future::Future;
use std::path::PathBuf;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, RwLock as StdRwLock, Weak};
use std::time::{Duration, Instant};
use tokio::sync::{Mutex as TokioMutex, RwLock};

const READINESS_CACHE_TTL: Duration = Duration::from_secs(1);
const MICROSOFT_METADATA_MAX_AGE_SECONDS: i64 = 3600;
const MICROSOFT_REFRESH_THROTTLE_SECONDS: i64 = 30;
const MICROSOFT_EAGER_DISCOVERY_TIMEOUT: Duration = Duration::from_secs(2);

#[derive(Clone)]
pub(crate) struct AppState {
    pub(crate) reloadable: Arc<ReloadableState>,
}

pub struct ReloadableState {
    pub(crate) config_path: PathBuf,
    /// Backends this process links; every reload parses with them.
    pub(crate) backends: Arc<BackendRegistry>,
    /// The linking assembly's build status, served at `/v1/broker/status`.
    /// It never changes across reloads.
    pub(crate) build_status: Arc<BrokerBuildStatus>,
    pub(crate) active: ArcSwap<RuntimeSnapshot>,
    /// Serializes caller-security publication against final attested admission.
    /// Never hold this synchronous lock across an await.
    caller_security_publication: StdRwLock<()>,
    pub(crate) active_lock_set: ArcSwap<StateLockSet>,
    pub(crate) state_lock_history: Mutex<Vec<Weak<StateLockSet>>>,
    pub(crate) policy_mutation_lock: TokioMutex<()>,
    pub(crate) reload_lock: TokioMutex<()>,
    pub(crate) reload_in_progress: AtomicBool,
    pub(crate) shared_ingress: Arc<IngressGuards>,
    /// Per-(principal, service) invocation windows; history survives reloads.
    pub(crate) shared_invocations: Arc<InvocationLimiter>,
    pub(crate) shared_spool: Arc<UploadSpoolBudgets>,
    pub(crate) operations: Arc<crate::operations::OperationRegistry>,
    pub(crate) body_hard_cap: usize,
    pub(crate) reload_timeout: Duration,
    pub(crate) shutdown_timeout: Duration,
    pub(crate) audit_registry: Arc<AuditRuntimeRegistry>,
    pub(crate) last_reload_attempt: Mutex<Option<ReloadAttemptSummary>>,
    #[cfg(test)]
    pub(crate) mcp_admission_barrier: Mutex<Option<Arc<McpAdmissionBarrier>>>,
    #[cfg(test)]
    pub(crate) mcp_discovery_barrier: Mutex<Option<Arc<McpAdmissionBarrier>>>,
    #[cfg(test)]
    pub(crate) mcp_cleanup_completed: tokio::sync::Notify,
    #[cfg(test)]
    pub(crate) mcp_intake_barrier: Mutex<Option<Arc<McpBlockingBarrier>>>,
    #[cfg(test)]
    pub(crate) mcp_preprotocol_barrier:
        Mutex<Option<(crate::mcp::PreProtocolPhase, Arc<McpBlockingBarrier>)>>,
    #[cfg(test)]
    pub(crate) mcp_prune_barrier: Mutex<Option<Arc<McpBlockingBarrier>>>,
    #[cfg(test)]
    pub(crate) mcp_background_prune_barrier: Mutex<Option<(usize, Arc<McpBlockingBarrier>)>>,
    #[cfg(test)]
    pub(crate) mcp_prune_waiting: tokio::sync::Notify,
    #[cfg(test)]
    pub(crate) mcp_reap_completed: tokio::sync::Notify,
    #[cfg(test)]
    pub(crate) mcp_session_count: std::sync::atomic::AtomicUsize,
}

#[cfg(test)]
pub(crate) struct McpAdmissionBarrier {
    pub(crate) reached: tokio::sync::Notify,
    pub(crate) release: tokio::sync::Semaphore,
}

#[cfg(test)]
#[derive(Default)]
pub(crate) struct McpBlockingBarrier {
    pub(crate) reached: tokio::sync::Notify,
    pub(crate) completed: tokio::sync::Notify,
    released: Mutex<bool>,
    changed: std::sync::Condvar,
}

#[cfg(test)]
impl McpBlockingBarrier {
    pub(crate) fn release(&self) {
        *self.released.lock().unwrap() = true;
        self.changed.notify_all();
    }

    fn wait(&self) {
        self.reached.notify_one();
        let _released = self
            .changed
            .wait_while(self.released.lock().unwrap(), |released| !*released)
            .unwrap();
    }
}

#[derive(Clone)]
pub(crate) struct RuntimeSnapshot {
    pub(crate) generation: u64,
    pub(crate) caller_security_epoch: u64,
    pub(crate) loaded_at: String,
    pub(crate) config_hash: String,
    pub(crate) runtime: BrokerRuntime,
    pub(crate) source_resolver: Arc<SourceResolver>,
    pub(crate) readiness_cache: Arc<ReadinessCache>,
    pub(crate) state_locks: Arc<StateLockSet>,
    pub(crate) microsoft_oidc: Option<Arc<MicrosoftOidcProviderRuntime>>,
}

#[derive(Debug, Clone)]
pub(crate) struct MicrosoftOidcTransportError;

impl fmt::Display for MicrosoftOidcTransportError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("Microsoft OIDC transport is unavailable")
    }
}

impl std::error::Error for MicrosoftOidcTransportError {}

pub(crate) trait MicrosoftOidcTransport: Send + Sync {
    fn call<'a>(
        &'a self,
        request: HttpRequest,
    ) -> Pin<
        Box<
            dyn Future<Output = Result<HttpResponse, MicrosoftOidcTransportError>>
                + Send
                + Sync
                + 'a,
        >,
    >;
}

#[derive(Clone)]
pub(crate) struct DynamicMicrosoftOidcTransport(Arc<dyn MicrosoftOidcTransport>);

impl<'a> AsyncHttpClient<'a> for DynamicMicrosoftOidcTransport {
    type Error = MicrosoftOidcTransportError;
    type Future = Pin<
        Box<
            dyn Future<Output = Result<HttpResponse, MicrosoftOidcTransportError>>
                + Send
                + Sync
                + 'a,
        >,
    >;

    fn call(&'a self, request: HttpRequest) -> Self::Future {
        self.0.call(request)
    }
}

#[derive(Clone)]
struct ProductionMicrosoftOidcTransport {
    client: MicrosoftOidcHttpClient,
}

impl MicrosoftOidcTransport for ProductionMicrosoftOidcTransport {
    fn call<'a>(
        &'a self,
        request: HttpRequest,
    ) -> Pin<
        Box<
            dyn Future<Output = Result<HttpResponse, MicrosoftOidcTransportError>>
                + Send
                + Sync
                + 'a,
        >,
    > {
        Box::pin(async move {
            self.client
                .call(request)
                .await
                .map_err(|_| MicrosoftOidcTransportError)
        })
    }
}

pub(crate) struct MicrosoftOidcProviderRuntime {
    config: MicrosoftOidcRuntimeConfig,
    transport: DynamicMicrosoftOidcTransport,
    clock: Arc<dyn MicrosoftOidcClock>,
    provider_generation: AtomicU64,
    metadata_available: AtomicBool,
    metadata: RwLock<Option<MicrosoftOidcProviderMetadata>>,
    refresh_lock: TokioMutex<()>,
    last_discovery_attempt: Mutex<Option<DateTime<Utc>>>,
    last_unknown_key_refresh: Mutex<Option<UnknownKeyRefresh>>,
}

#[derive(Clone, Copy)]
struct UnknownKeyRefresh {
    metadata_loaded_at: DateTime<Utc>,
    attempted_at: DateTime<Utc>,
    succeeded: bool,
}

impl fmt::Debug for MicrosoftOidcProviderRuntime {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MicrosoftOidcProviderRuntime")
            .field("config", &self.config)
            .field("provider_generation", &self.provider_generation())
            .field("available", &self.available())
            .finish_non_exhaustive()
    }
}

impl MicrosoftOidcProviderRuntime {
    fn production(
        config: MicrosoftOidcRuntimeConfig,
        outbound_tls: &agent_access_core::PreparedOutboundTls,
    ) -> Result<Arc<Self>, ManagedStoreError> {
        let client = MicrosoftOidcHttpClient::new(outbound_tls).map_err(|_| {
            ManagedStoreError::Unavailable(
                "Microsoft OIDC HTTP client configuration failed".to_string(),
            )
        })?;
        Ok(Self::with_components(
            config,
            Arc::new(ProductionMicrosoftOidcTransport { client }),
            Arc::new(SystemMicrosoftOidcClock),
        ))
    }

    fn with_components(
        config: MicrosoftOidcRuntimeConfig,
        transport: Arc<dyn MicrosoftOidcTransport>,
        clock: Arc<dyn MicrosoftOidcClock>,
    ) -> Arc<Self> {
        Arc::new(Self {
            config,
            transport: DynamicMicrosoftOidcTransport(transport),
            clock,
            provider_generation: AtomicU64::new(0),
            metadata_available: AtomicBool::new(false),
            metadata: RwLock::new(None),
            refresh_lock: TokioMutex::new(()),
            last_discovery_attempt: Mutex::new(None),
            last_unknown_key_refresh: Mutex::new(None),
        })
    }

    pub(crate) fn config(&self) -> &MicrosoftOidcRuntimeConfig {
        &self.config
    }

    pub(crate) fn clock(&self) -> &dyn MicrosoftOidcClock {
        self.clock.as_ref()
    }

    pub(crate) fn clock_arc(&self) -> Arc<dyn MicrosoftOidcClock> {
        Arc::clone(&self.clock)
    }

    pub(crate) fn http_client(&self) -> &DynamicMicrosoftOidcTransport {
        &self.transport
    }

    fn set_provider_generation(&self, generation: u64) {
        self.provider_generation
            .store(generation, Ordering::Release);
    }

    pub(crate) fn provider_generation(&self) -> u64 {
        self.provider_generation.load(Ordering::Acquire)
    }

    pub(crate) fn available(&self) -> bool {
        self.provider_generation() != 0 && self.metadata_available.load(Ordering::Acquire)
    }

    async fn initialize(&self) -> Result<(), MicrosoftOidcTransportError> {
        self.ensure_metadata(false).await.map(|_| ())
    }

    async fn initialize_best_effort(&self) -> bool {
        match tokio::time::timeout(MICROSOFT_EAGER_DISCOVERY_TIMEOUT, self.initialize()).await {
            Ok(Ok(())) => true,
            Ok(Err(_)) => false,
            Err(_) => {
                *self.last_discovery_attempt.lock().unwrap() = None;
                false
            }
        }
    }

    async fn ensure_metadata(
        &self,
        require_fresh: bool,
    ) -> Result<MicrosoftOidcProviderMetadata, MicrosoftOidcTransportError> {
        let now = self.clock.now();
        if let Some(metadata) = self.metadata.read().await.clone()
            && (!require_fresh
                || now.signed_duration_since(metadata.loaded_at())
                    < ChronoDuration::seconds(MICROSOFT_METADATA_MAX_AGE_SECONDS))
        {
            return Ok(metadata);
        }

        let _guard = self.refresh_lock.lock().await;
        let now = self.clock.now();
        if let Some(metadata) = self.metadata.read().await.clone()
            && (!require_fresh
                || now.signed_duration_since(metadata.loaded_at())
                    < ChronoDuration::seconds(MICROSOFT_METADATA_MAX_AGE_SECONDS))
        {
            return Ok(metadata);
        }
        if self
            .last_discovery_attempt
            .lock()
            .unwrap()
            .is_some_and(|last| {
                now.signed_duration_since(last)
                    < ChronoDuration::seconds(MICROSOFT_REFRESH_THROTTLE_SECONDS)
            })
        {
            return Err(MicrosoftOidcTransportError);
        }
        *self.last_discovery_attempt.lock().unwrap() = Some(now);
        let discovered =
            MicrosoftOidcProviderMetadata::discover(self.config.tenant_id(), &self.transport, now)
                .await
                .map_err(|_| {
                    if self
                        .metadata
                        .try_read()
                        .is_ok_and(|metadata| metadata.is_some())
                    {
                        self.metadata_available.store(false, Ordering::Release);
                    }
                    MicrosoftOidcTransportError
                })?;
        *self.metadata.write().await = Some(discovered.clone());
        self.metadata_available.store(true, Ordering::Release);
        Ok(discovered)
    }

    pub(crate) async fn metadata_for_start(
        &self,
    ) -> Result<MicrosoftOidcProviderMetadata, MicrosoftOidcTransportError> {
        self.ensure_metadata(false).await
    }

    pub(crate) async fn metadata_for_token_validation(
        &self,
    ) -> Result<MicrosoftOidcProviderMetadata, MicrosoftOidcTransportError> {
        self.ensure_metadata(true).await
    }

    pub(crate) async fn refresh_unknown_key(
        &self,
        current: &MicrosoftOidcProviderMetadata,
    ) -> Result<MicrosoftOidcProviderMetadata, MicrosoftOidcTransportError> {
        let _guard = self.refresh_lock.lock().await;
        let now = self.clock.now();
        if let Some(latest) = self.metadata.read().await.clone()
            && latest.loaded_at() > current.loaded_at()
        {
            return Ok(latest);
        }
        let last_refresh = *self.last_unknown_key_refresh.lock().unwrap();
        if let Some(last_refresh) = last_refresh
            && last_refresh.metadata_loaded_at == current.loaded_at()
            && now.signed_duration_since(last_refresh.attempted_at)
                < ChronoDuration::seconds(MICROSOFT_REFRESH_THROTTLE_SECONDS)
        {
            return if last_refresh.succeeded {
                self.metadata
                    .read()
                    .await
                    .clone()
                    .ok_or(MicrosoftOidcTransportError)
            } else {
                Err(MicrosoftOidcTransportError)
            };
        }
        *self.last_unknown_key_refresh.lock().unwrap() = Some(UnknownKeyRefresh {
            metadata_loaded_at: current.loaded_at(),
            attempted_at: now,
            succeeded: false,
        });
        let jwks = openidconnect::core::CoreJsonWebKeySet::fetch_async(
            current.metadata().jwks_uri(),
            &self.transport,
        )
        .await
        .map_err(|_| MicrosoftOidcTransportError)?;
        let refreshed = current
            .with_refreshed_jwks(jwks, now)
            .map_err(|_| MicrosoftOidcTransportError)?;
        *self.metadata.write().await = Some(refreshed.clone());
        *self.last_unknown_key_refresh.lock().unwrap() = Some(UnknownKeyRefresh {
            metadata_loaded_at: current.loaded_at(),
            attempted_at: now,
            succeeded: true,
        });
        Ok(refreshed)
    }
}

struct CachedReadiness {
    checked_at: Instant,
    result: Result<(), String>,
}

pub(crate) struct ReadinessCache {
    ttl: Duration,
    state: Mutex<Option<CachedReadiness>>,
}

pub(crate) struct RequestPermits {
    pub(crate) _global: IngressPermit,
    pub(crate) _principal: IngressPermit,
}

impl ReadinessCache {
    pub(crate) fn new(ttl: Duration) -> Self {
        Self {
            ttl,
            state: Mutex::new(None),
        }
    }

    pub(crate) async fn check(&self, runtime: BrokerRuntime) -> Result<(), String> {
        let now = Instant::now();
        if let Some(cached) = self.state.lock().unwrap().as_ref()
            && now.duration_since(cached.checked_at) < self.ttl
        {
            return cached.result.clone();
        }
        let result = runtime.readiness().await.map_err(|error| error.to_string());
        *self.state.lock().unwrap() = Some(CachedReadiness {
            checked_at: now,
            result: result.clone(),
        });
        result
    }
}

impl RuntimeSnapshot {
    pub(crate) fn resolve_execution_context(
        &self,
        headers: &axum::http::HeaderMap,
    ) -> Result<agent_access_core::ExecutionContext, agent_access_core::IdentityFailure> {
        self.runtime
            .admit_ingress(headers)?
            .execution_context()
            .map_err(|failure| match failure {
                agent_access_core::ExecutionContextFailure::Required => {
                    agent_access_core::IdentityFailure::ExecutionContextRequired
                }
                agent_access_core::ExecutionContextFailure::Invalid => {
                    agent_access_core::IdentityFailure::ExecutionContextInvalid
                }
            })
    }

    pub(crate) fn new(
        generation: u64,
        config_hash: String,
        runtime: BrokerRuntime,
        state_locks: Arc<StateLockSet>,
    ) -> Arc<Self> {
        Arc::new(Self {
            generation,
            caller_security_epoch: 1,
            loaded_at: Utc::now().to_rfc3339(),
            config_hash,
            source_resolver: Arc::new(SourceResolver::new(runtime.trusted_proxies())),
            readiness_cache: Arc::new(ReadinessCache::new(READINESS_CACHE_TTL)),
            runtime,
            state_locks,
            microsoft_oidc: None,
        })
    }

    pub(crate) async fn new_microsoft_oidc_candidate(
        generation: u64,
        config_hash: String,
        runtime: BrokerRuntime,
        state_locks: Arc<StateLockSet>,
    ) -> Result<Arc<Self>, ManagedStoreError> {
        Self::new_microsoft_oidc_candidate_with_components(
            generation,
            config_hash,
            runtime,
            state_locks,
            None,
            None,
        )
        .await
    }

    async fn new_microsoft_oidc_candidate_with_components(
        generation: u64,
        config_hash: String,
        runtime: BrokerRuntime,
        state_locks: Arc<StateLockSet>,
        transport: Option<Arc<dyn MicrosoftOidcTransport>>,
        clock: Option<Arc<dyn MicrosoftOidcClock>>,
    ) -> Result<Arc<Self>, ManagedStoreError> {
        let microsoft_oidc = match runtime.microsoft_oidc().cloned() {
            Some(config) => {
                let provider = match (transport, clock) {
                    (Some(transport), Some(clock)) => {
                        MicrosoftOidcProviderRuntime::with_components(config, transport, clock)
                    }
                    (None, None) => {
                        MicrosoftOidcProviderRuntime::production(config, runtime.outbound_tls())?
                    }
                    _ => {
                        return Err(ManagedStoreError::Unavailable(
                            "Microsoft OIDC test components are incomplete".to_string(),
                        ));
                    }
                };
                if !provider.initialize_best_effort().await {
                    tracing::warn!(
                        event = "microsoft_oidc_unavailable",
                        configGeneration = generation,
                        "Microsoft OIDC discovery is temporarily unavailable"
                    );
                }
                Some(provider)
            }
            None => None,
        };
        Ok(Arc::new(Self {
            generation,
            caller_security_epoch: 1,
            loaded_at: Utc::now().to_rfc3339(),
            config_hash,
            source_resolver: Arc::new(SourceResolver::new(runtime.trusted_proxies())),
            readiness_cache: Arc::new(ReadinessCache::new(READINESS_CACHE_TTL)),
            runtime,
            state_locks,
            microsoft_oidc,
        }))
    }

    pub(crate) fn reconcile_microsoft_oidc_provider(&self) -> Result<(), ManagedStoreError> {
        self.reconcile_microsoft_oidc_provider_with_fallback(None)
    }

    pub(crate) fn reconcile_microsoft_oidc_provider_with_fallback(
        &self,
        previous_runtime: Option<&BrokerRuntime>,
    ) -> Result<(), ManagedStoreError> {
        let store = self.runtime.managed_store().or_else(|| {
            previous_runtime.and_then(|previous_runtime| previous_runtime.managed_store())
        });
        let Some(store) = store else {
            return if self.microsoft_oidc.is_some() {
                Err(ManagedStoreError::OidcProviderUnavailable)
            } else {
                Ok(())
            };
        };
        if let Some(provider) = self.microsoft_oidc.as_ref() {
            let config = provider.config();
            let state = store.reconcile_oidc_provider_state(OidcProviderStateReconcileRequest {
                tenant_id: config.tenant_id().to_string(),
                client_id: config.client_id().to_string(),
                enabled: true,
                config_fingerprint: config.config_fingerprint().to_string(),
                external_membership_ttl_seconds: config.external_membership_ttl_seconds(),
                invalidate_existing_evidence: false,
                actor: "system".to_string(),
            })?;
            provider.set_provider_generation(state.config_generation);
            return Ok(());
        }
        let Some(existing) = store.oidc_provider_state()? else {
            return Ok(());
        };
        if existing.enabled {
            store.reconcile_oidc_provider_state(OidcProviderStateReconcileRequest {
                tenant_id: existing.tenant_id,
                client_id: existing.client_id,
                enabled: false,
                config_fingerprint: existing.config_fingerprint,
                external_membership_ttl_seconds: existing.external_membership_ttl_seconds,
                invalidate_existing_evidence: false,
                actor: "system".to_string(),
            })?;
        }
        Ok(())
    }

    #[cfg(test)]
    pub(crate) async fn new_with_microsoft_oidc_components(
        generation: u64,
        config_hash: String,
        runtime: BrokerRuntime,
        state_locks: Arc<StateLockSet>,
        transport: Arc<dyn MicrosoftOidcTransport>,
        clock: Arc<dyn MicrosoftOidcClock>,
    ) -> Result<Arc<Self>, ManagedStoreError> {
        let snapshot = Self::new_microsoft_oidc_candidate_with_components(
            generation,
            config_hash,
            runtime,
            state_locks,
            Some(transport),
            Some(clock),
        )
        .await?;
        snapshot.reconcile_microsoft_oidc_provider()?;
        Ok(snapshot)
    }
}

impl ReloadableState {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn from_snapshot(
        config_path: PathBuf,
        backends: Arc<BackendRegistry>,
        build_status: BrokerBuildStatus,
        snapshot: Arc<RuntimeSnapshot>,
        body_hard_cap: usize,
        reload_timeout: Duration,
        shutdown_timeout: Duration,
        audit_registry: Arc<AuditRuntimeRegistry>,
    ) -> Self {
        Self {
            config_path,
            backends,
            build_status: Arc::new(build_status),
            active: ArcSwap::from(Arc::clone(&snapshot)),
            caller_security_publication: StdRwLock::new(()),
            active_lock_set: ArcSwap::from(Arc::clone(&snapshot.state_locks)),
            state_lock_history: Mutex::new(vec![Arc::downgrade(&snapshot.state_locks)]),
            policy_mutation_lock: TokioMutex::new(()),
            reload_lock: TokioMutex::new(()),
            reload_in_progress: AtomicBool::new(false),
            shared_ingress: Arc::new(IngressGuards::new()),
            shared_invocations: Arc::new(InvocationLimiter::new()),
            shared_spool: Arc::new(UploadSpoolBudgets::new()),
            operations: Arc::new(crate::operations::OperationRegistry::default()),
            body_hard_cap,
            reload_timeout,
            shutdown_timeout,
            audit_registry,
            last_reload_attempt: Mutex::new(None),
            #[cfg(test)]
            mcp_admission_barrier: Mutex::new(None),
            #[cfg(test)]
            mcp_discovery_barrier: Mutex::new(None),
            #[cfg(test)]
            mcp_cleanup_completed: tokio::sync::Notify::new(),
            #[cfg(test)]
            mcp_intake_barrier: Mutex::new(None),
            #[cfg(test)]
            mcp_preprotocol_barrier: Mutex::new(None),
            #[cfg(test)]
            mcp_prune_barrier: Mutex::new(None),
            #[cfg(test)]
            mcp_background_prune_barrier: Mutex::new(None),
            #[cfg(test)]
            mcp_prune_waiting: tokio::sync::Notify::new(),
            #[cfg(test)]
            mcp_reap_completed: tokio::sync::Notify::new(),
            #[cfg(test)]
            mcp_session_count: std::sync::atomic::AtomicUsize::new(0),
        }
    }

    /// Replaces the invocation limiter, for tests that control its clock.
    #[cfg(test)]
    pub(crate) fn with_invocation_limiter(mut self, limiter: InvocationLimiter) -> Self {
        self.shared_invocations = Arc::new(limiter);
        self
    }

    pub(crate) fn current(&self) -> Arc<RuntimeSnapshot> {
        self.active.load_full()
    }

    #[cfg(test)]
    pub(crate) async fn wait_mcp_admission_barrier(&self) {
        let barrier = self.mcp_admission_barrier.lock().unwrap().take();
        if let Some(barrier) = barrier {
            barrier.reached.notify_one();
            barrier.release.acquire().await.unwrap().forget();
        }
    }

    #[cfg(test)]
    pub(crate) async fn wait_mcp_discovery_barrier(&self) {
        let barrier = self.mcp_discovery_barrier.lock().unwrap().take();
        if let Some(barrier) = barrier {
            barrier.reached.notify_one();
            barrier.release.acquire().await.unwrap().forget();
        }
    }

    #[cfg(test)]
    pub(crate) fn wait_mcp_intake_barrier(&self) -> Option<Arc<McpBlockingBarrier>> {
        let barrier = self.mcp_intake_barrier.lock().unwrap().take();
        if let Some(barrier) = &barrier {
            barrier.wait();
        }
        barrier
    }

    #[cfg(test)]
    pub(crate) fn wait_mcp_prune_barrier(
        &self,
        background: bool,
        batch_size: usize,
    ) -> Option<Arc<McpBlockingBarrier>> {
        let barrier = if background {
            let mut pending = self.mcp_background_prune_barrier.lock().unwrap();
            if pending
                .as_ref()
                .is_some_and(|(expected, _)| *expected == batch_size)
            {
                pending.take().map(|(_, barrier)| barrier)
            } else {
                None
            }
        } else {
            None
        }
        .or_else(|| self.mcp_prune_barrier.lock().unwrap().take());
        if let Some(barrier) = &barrier {
            barrier.wait();
        }
        barrier
    }

    #[cfg(test)]
    pub(crate) fn wait_mcp_preprotocol_barrier(&self, phase: crate::mcp::PreProtocolPhase) {
        let barrier = {
            let mut pending = self.mcp_preprotocol_barrier.lock().unwrap();
            if pending
                .as_ref()
                .is_some_and(|(expected, _)| *expected == phase)
            {
                pending.take().map(|(_, barrier)| barrier)
            } else {
                None
            }
        };
        if let Some(barrier) = barrier {
            barrier.wait();
        }
    }

    /// Publish the loaded caller contract and its process-local epoch together.
    /// Comparing loaded secrets, rather than secret references, prevents an ABA
    /// rotation from restoring an earlier session's authority.
    pub(crate) fn publish_snapshot(&self, mut next: Arc<RuntimeSnapshot>) -> Arc<RuntimeSnapshot> {
        let _publication = self.caller_security_publication.write().unwrap();
        let previous = self.current();
        let changed =
            previous.runtime.caller_security_binding() != next.runtime.caller_security_binding();
        Arc::make_mut(&mut next).caller_security_epoch = if changed {
            previous
                .caller_security_epoch
                .checked_add(1)
                .expect("caller security epoch exhausted")
        } else {
            previous.caller_security_epoch
        };
        self.active.store(next.clone());
        next
    }

    /// The caller check and authoritative store read share one publication
    /// fence. A successful closure is the attested identity admission point;
    /// an already admitted operation is independent of later reloads.
    pub(crate) fn with_caller_security<T>(
        &self,
        expected_epoch: u64,
        stale: agent_access_core::IdentityFailure,
        check: impl FnOnce(&RuntimeSnapshot) -> Result<T, agent_access_core::IdentityFailure>,
    ) -> Result<T, agent_access_core::IdentityFailure> {
        let _publication = self
            .caller_security_publication
            .read()
            .map_err(|_| agent_access_core::IdentityFailure::Unavailable)?;
        let current = self.current();
        if current.caller_security_epoch != expected_epoch {
            return Err(stale);
        }
        check(&current)
    }

    /// The broker's effective node ID. Reload never changes it.
    pub fn node_id(&self) -> String {
        self.current().runtime.node_id().to_string()
    }

    #[allow(dead_code)]
    pub(crate) async fn managed_policy_mutation<T, F>(
        &self,
        operation: F,
    ) -> Result<T, ManagedStoreError>
    where
        T: Send + 'static,
        F: FnOnce(BrokerRuntime) -> Result<T, ManagedStoreError> + Send + 'static,
    {
        let Ok(_guard) = self.policy_mutation_lock.try_lock() else {
            return Err(ManagedStoreError::ReloadInProgress);
        };
        let runtime = self.current().runtime.clone();
        tokio::task::spawn_blocking(move || operation(runtime))
            .await
            .map_err(|error| {
                ManagedStoreError::Unavailable(format!(
                    "managed policy mutation task failed: {error}"
                ))
            })?
    }

    pub(crate) async fn managed_policy_mutation_from_snapshot<T, F>(
        self: &Arc<Self>,
        snapshot: Arc<RuntimeSnapshot>,
        operation: F,
    ) -> Result<T, ManagedStoreError>
    where
        T: Send + 'static,
        F: FnOnce(BrokerRuntime) -> Result<T, ManagedStoreError> + Send + 'static,
    {
        self.imported_service_mutation(snapshot, move |runtime| {
            let result = operation(runtime.clone())?;
            Ok((runtime, result))
        })
        .await
    }

    pub(crate) async fn token_store_call_from_snapshot<T, F>(
        self: &Arc<Self>,
        snapshot: Arc<RuntimeSnapshot>,
        operation: F,
    ) -> Result<T, ManagedStoreError>
    where
        T: Send + 'static,
        F: FnOnce(BrokerRuntime) -> Result<T, ManagedStoreError> + Send + 'static,
    {
        let state = self.clone();
        // The owner survives cancellation of the HTTP response waiter. Never
        // release the reload fence while its blocking database write still runs.
        tokio::spawn(async move {
            let _guard = state.policy_mutation_lock.lock().await;
            if !Arc::ptr_eq(&state.current(), &snapshot) {
                return Err(ManagedStoreError::VersionConflict);
            }
            let runtime = snapshot.runtime.clone();
            tokio::task::spawn_blocking(move || operation(runtime))
                .await
                .map_err(|error| {
                    ManagedStoreError::Unavailable(format!(
                        "managed policy mutation task failed: {error}"
                    ))
                })?
        })
        .await
        .map_err(|error| {
            ManagedStoreError::Unavailable(format!("managed mutation owner failed: {error}"))
        })?
    }

    /// Own the complete DB commit and runtime publication even when the HTTP
    /// waiter disappears. Adapter discovery and preparation happen before this.
    pub(crate) async fn imported_service_mutation<T, F>(
        self: &Arc<Self>,
        snapshot: Arc<RuntimeSnapshot>,
        operation: F,
    ) -> Result<T, ManagedStoreError>
    where
        T: Send + 'static,
        F: FnOnce(BrokerRuntime) -> Result<(BrokerRuntime, T), ManagedStoreError> + Send + 'static,
    {
        let state = self.clone();
        tokio::spawn(async move {
            let _guard = state.policy_mutation_lock.lock().await;
            if !Arc::ptr_eq(&state.current(), &snapshot) {
                return Err(ManagedStoreError::VersionConflict);
            }
            let runtime = snapshot.runtime.clone();
            let (runtime, result) = tokio::task::spawn_blocking(move || operation(runtime))
                .await
                .map_err(|_| {
                    ManagedStoreError::Unavailable("import mutation owner failed".into())
                })??;
            if snapshot.runtime.shares_import_catalog(&runtime) {
                // Ordinary policy mutations publish through their shared ArcSwap.
                // Keep snapshot identity stable for admitted OIDC/token operations.
                return Ok(result);
            }
            let next = RuntimeSnapshot {
                runtime,
                ..(*snapshot).clone()
            };
            snapshot
                .runtime
                .retire_superseded_import_dispatch(&next.runtime);
            let next = state.publish_snapshot(Arc::new(next));
            next.runtime.warn_aggregate_mcp_names();
            Ok(result)
        })
        .await
        .map_err(|_| ManagedStoreError::Unavailable("import publication owner failed".into()))?
    }

    pub(crate) fn last_reload_attempt(&self) -> Option<ReloadAttemptSummary> {
        self.last_reload_attempt.lock().unwrap().clone()
    }

    pub(crate) fn set_last_reload_attempt(&self, summary: ReloadAttemptSummary) {
        *self.last_reload_attempt.lock().unwrap() = Some(summary);
    }

    pub(crate) fn live_state_lock_sets(&self) -> Vec<Arc<StateLockSet>> {
        let active = self.active_lock_set.load_full();
        let mut history = self.state_lock_history.lock().unwrap();
        let mut live = vec![active];
        for lock_set in history.iter().filter_map(Weak::upgrade) {
            if !live.iter().any(|existing| Arc::ptr_eq(existing, &lock_set)) {
                live.push(lock_set);
            }
        }
        *history = live.iter().map(Arc::downgrade).collect();
        live
    }

    pub(crate) fn track_state_lock_set(&self, lock_set: &Arc<StateLockSet>) {
        let mut history = self.state_lock_history.lock().unwrap();
        let mut live = history.iter().filter_map(Weak::upgrade).collect::<Vec<_>>();
        if !live.iter().any(|existing| Arc::ptr_eq(existing, lock_set)) {
            live.push(Arc::clone(lock_set));
        }
        *history = live.iter().map(Arc::downgrade).collect();
    }

    pub fn close_operation_admission(&self) {
        self.operations.close();
    }

    pub async fn shutdown_operations(&self, timeout: Duration) -> usize {
        self.operations.shutdown(timeout).await
    }

    pub fn cancel_terminal_audits(&self) -> usize {
        self.audit_registry.cancel_terminal_audits()
    }

    pub async fn shutdown_audit(&self, timeout: Duration) -> Result<(), RuntimeError> {
        self.audit_registry.shutdown_and_drain(timeout).await
    }
}

#[cfg(test)]
mod execution_context_tests {
    use super::*;
    use agent_access_core::{EXECUTION_CONTEXT_HEADER, parse_broker_config_raw};
    use axum::http::{HeaderMap, HeaderValue};

    fn runtime(execution_context: &str) -> BrokerRuntime {
        let config = parse_broker_config_raw(
            "state-execution-context-test.toml",
            &format!(
                r#"
                {execution_context}

                [identity]
                mode = "anonymous"
                authority = "toml"

                [policy]
                authority = "toml"
                default_decision = "deny"
                "#
            ),
            &std::sync::Arc::new(crate::backend_registry()),
        )
        .expect("test broker config is valid");
        BrokerRuntime::new(config).expect("test runtime builds")
    }

    fn context_header(value: &str) -> HeaderMap {
        let mut headers = HeaderMap::new();
        headers.insert(
            EXECUTION_CONTEXT_HEADER,
            HeaderValue::from_str(value).unwrap(),
        );
        headers
    }

    #[test]
    fn snapshots_retain_generation_coherent_execution_context_resolvers() {
        let old = RuntimeSnapshot::new(1, "old".to_string(), runtime(""), StateLockSet::empty());
        let candidate = RuntimeSnapshot::new(
            2,
            "candidate".to_string(),
            runtime(
                r#"
                [execution_context]
                allowed_values = ["internal"]
                "#,
            ),
            StateLockSet::empty(),
        );

        assert_eq!(
            old.resolve_execution_context(&HeaderMap::new())
                .unwrap()
                .as_str(),
            "default"
        );
        assert!(
            candidate
                .resolve_execution_context(&HeaderMap::new())
                .is_err()
        );
        assert!(
            candidate
                .resolve_execution_context(&context_header("internal"))
                .is_err()
        );

        // An in-flight request retaining the old snapshot retains the resolver
        // built from that snapshot's configuration.
        assert_eq!(
            old.resolve_execution_context(&HeaderMap::new())
                .unwrap()
                .as_str(),
            "default"
        );
    }
}
