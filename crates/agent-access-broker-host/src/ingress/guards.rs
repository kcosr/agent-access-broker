use agent_access_core::{ProviderError, ReasonCode, SourceContext};
use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

tokio::task_local! {
    /// The transport admission lease is shared by handler and supervised-operation
    /// owners rather than charged again after body extraction.
    pub(crate) static REQUEST_PERMIT: IngressPermit;
    pub(crate) static SOURCE_RATE_CHARGED: std::cell::RefCell<Option<String>>;
}

const MAX_RATE_LIMIT_KEYS: usize = 8192;
const MAX_PRINCIPAL_CONCURRENCY_KEYS: usize = 8192;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum IngressLimitKind {
    GlobalConcurrency,
    PrincipalConcurrency,
    PrincipalBodyConcurrency,
    SourceConcurrency,
    AnonymousBodyConcurrency,
    AuthSourceRate,
    AuthPrincipalRate,
    LimiterCapacity,
}

impl IngressLimitKind {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::GlobalConcurrency => "global_concurrency",
            Self::PrincipalConcurrency => "principal_concurrency",
            Self::PrincipalBodyConcurrency => "principal_body_concurrency",
            Self::SourceConcurrency => "source_concurrency",
            Self::AnonymousBodyConcurrency => "anonymous_body_concurrency",
            Self::AuthSourceRate => "auth_source_rate",
            Self::AuthPrincipalRate => "auth_principal_rate",
            Self::LimiterCapacity => "limiter_capacity",
        }
    }
}

#[derive(Debug, Clone)]
pub(crate) struct IngressLimitError {
    kind: IngressLimitKind,
    limit: u32,
    error: ProviderError,
}

impl IngressLimitError {
    fn new(kind: IngressLimitKind, limit: u32, error: ProviderError) -> Self {
        Self { kind, limit, error }
    }

    pub(crate) fn kind(&self) -> IngressLimitKind {
        self.kind
    }

    pub(crate) fn limit(&self) -> u32 {
        self.limit
    }

    pub(crate) fn provider_error(&self) -> &ProviderError {
        &self.error
    }

    pub(crate) fn into_provider_error(self) -> ProviderError {
        self.error
    }
}

/// Concurrency safeguards and the fixed-window authentication budgets.
/// Authenticated service invocations are rate limited separately, per
/// principal and service, by [`super::invocation_limits::InvocationLimiter`].
pub(crate) struct IngressGuards {
    global_inflight: Mutex<u32>,
    anonymous_body_inflight: Mutex<u32>,
    source_inflight: Mutex<BTreeMap<String, u32>>,
    principal_body_inflight: Mutex<BTreeMap<String, u32>>,
    principal_inflight: Mutex<BTreeMap<String, u32>>,
    auth_source_rates: Mutex<BTreeMap<String, RateWindow>>,
    auth_principal_rates: Mutex<BTreeMap<String, RateWindow>>,
}

impl IngressGuards {
    pub(crate) fn new() -> Self {
        Self {
            global_inflight: Mutex::new(0),
            anonymous_body_inflight: Mutex::new(0),
            source_inflight: Mutex::new(BTreeMap::new()),
            principal_body_inflight: Mutex::new(BTreeMap::new()),
            principal_inflight: Mutex::new(BTreeMap::new()),
            auth_source_rates: Mutex::new(BTreeMap::new()),
            auth_principal_rates: Mutex::new(BTreeMap::new()),
        }
    }

    pub(crate) fn try_global_concurrency(
        self: &Arc<Self>,
        limit: u32,
    ) -> Result<IngressPermit, IngressLimitError> {
        if let Ok(Some(permit)) = REQUEST_PERMIT
            .try_with(|permit| Arc::ptr_eq(self, &permit.0.guards).then(|| permit.clone()))
        {
            return Ok(permit);
        }
        let mut inflight = self.global_inflight.lock().unwrap();
        if *inflight >= limit {
            return Err(limit_error(
                IngressLimitKind::GlobalConcurrency,
                limit,
                concurrency_error(limit),
            ));
        }
        *inflight += 1;
        Ok(IngressPermit(Arc::new(IngressPermitInner {
            guards: self.clone(),
            kind: IngressPermitKind::Global,
        })))
    }

    pub(crate) fn try_anonymous_body_concurrency(
        self: &Arc<Self>,
        limit: u32,
    ) -> Result<IngressPermit, IngressLimitError> {
        let mut inflight = self.anonymous_body_inflight.lock().unwrap();
        if *inflight >= limit {
            return Err(limit_error(
                IngressLimitKind::AnonymousBodyConcurrency,
                limit,
                concurrency_error(limit),
            ));
        }
        *inflight += 1;
        Ok(IngressPermit(Arc::new(IngressPermitInner {
            guards: self.clone(),
            kind: IngressPermitKind::AnonymousBody,
        })))
    }

    pub(crate) fn try_principal_concurrency(
        self: &Arc<Self>,
        principal: &str,
        limit: u32,
    ) -> Result<IngressPermit, IngressLimitError> {
        let mut inflight = self.principal_inflight.lock().unwrap();
        inflight.retain(|_, count| *count > 0);
        if !inflight.contains_key(principal) && inflight.len() >= MAX_PRINCIPAL_CONCURRENCY_KEYS {
            return Err(limit_error(
                IngressLimitKind::LimiterCapacity,
                MAX_PRINCIPAL_CONCURRENCY_KEYS as u32,
                limiter_capacity_error(),
            ));
        }
        let count = inflight.entry(principal.to_string()).or_insert(0);
        if *count >= limit {
            return Err(limit_error(
                IngressLimitKind::PrincipalConcurrency,
                limit,
                concurrency_error(limit),
            ));
        }
        *count += 1;
        Ok(IngressPermit(Arc::new(IngressPermitInner {
            guards: self.clone(),
            kind: IngressPermitKind::Principal(principal.to_string()),
        })))
    }

    pub(crate) fn try_principal_body_concurrency(
        self: &Arc<Self>,
        principal: &str,
        limit: u32,
    ) -> Result<IngressPermit, IngressLimitError> {
        let mut inflight = self.principal_body_inflight.lock().unwrap();
        if !inflight.contains_key(principal) && inflight.len() >= MAX_PRINCIPAL_CONCURRENCY_KEYS {
            return Err(limit_error(
                IngressLimitKind::LimiterCapacity,
                MAX_PRINCIPAL_CONCURRENCY_KEYS as u32,
                limiter_capacity_error(),
            ));
        }
        let count = inflight.entry(principal.to_owned()).or_default();
        if *count >= limit {
            return Err(limit_error(
                IngressLimitKind::PrincipalBodyConcurrency,
                limit,
                concurrency_error(limit),
            ));
        }
        *count += 1;
        Ok(IngressPermit(Arc::new(IngressPermitInner {
            guards: self.clone(),
            kind: IngressPermitKind::PrincipalBody(principal.to_owned()),
        })))
    }

    pub(crate) fn try_source_concurrency(
        self: &Arc<Self>,
        source: &str,
        limit: u32,
    ) -> Result<IngressPermit, IngressLimitError> {
        let mut inflight = self.source_inflight.lock().unwrap();
        if !inflight.contains_key(source) && inflight.len() >= MAX_PRINCIPAL_CONCURRENCY_KEYS {
            return Err(limit_error(
                IngressLimitKind::LimiterCapacity,
                MAX_PRINCIPAL_CONCURRENCY_KEYS as u32,
                limiter_capacity_error(),
            ));
        }
        let count = inflight.entry(source.to_owned()).or_default();
        if *count >= limit {
            return Err(limit_error(
                IngressLimitKind::SourceConcurrency,
                limit,
                concurrency_error(limit),
            ));
        }
        *count += 1;
        Ok(IngressPermit(Arc::new(IngressPermitInner {
            guards: self.clone(),
            kind: IngressPermitKind::Source(source.to_owned()),
        })))
    }

    pub(crate) fn check_auth_source_rate(
        &self,
        source: &str,
        limit: u32,
    ) -> Result<(), IngressLimitError> {
        if SOURCE_RATE_CHARGED
            .try_with(|charged| charged.borrow().as_deref() == Some(source))
            .unwrap_or(false)
        {
            return Ok(());
        }
        let result = check_rate(
            &mut self.auth_source_rates.lock().unwrap(),
            source,
            limit,
            IngressLimitKind::AuthSourceRate,
        );
        if result.is_ok() {
            let _ = SOURCE_RATE_CHARGED
                .try_with(|charged| *charged.borrow_mut() = Some(source.to_owned()));
        }
        result
    }

    pub(crate) fn check_auth_principal_rate(
        &self,
        principal: &str,
        limit: u32,
    ) -> Result<(), IngressLimitError> {
        check_rate(
            &mut self.auth_principal_rates.lock().unwrap(),
            principal,
            limit,
            IngressLimitKind::AuthPrincipalRate,
        )
    }

    fn release_global(&self) {
        let mut inflight = self.global_inflight.lock().unwrap();
        *inflight = inflight.saturating_sub(1);
    }

    fn release_principal(&self, principal: &str) {
        let mut inflight = self.principal_inflight.lock().unwrap();
        if let Some(count) = inflight.get_mut(principal) {
            *count = count.saturating_sub(1);
            if *count == 0 {
                inflight.remove(principal);
            }
        }
    }
}

#[derive(Clone)]
pub(crate) struct IngressPermit(Arc<IngressPermitInner>);

struct IngressPermitInner {
    guards: Arc<IngressGuards>,
    kind: IngressPermitKind,
}

enum IngressPermitKind {
    Global,
    AnonymousBody,
    Principal(String),
    PrincipalBody(String),
    Source(String),
}

impl Drop for IngressPermitInner {
    fn drop(&mut self) {
        match &self.kind {
            IngressPermitKind::Global => self.guards.release_global(),
            IngressPermitKind::AnonymousBody => {
                let mut inflight = self.guards.anonymous_body_inflight.lock().unwrap();
                *inflight = inflight.saturating_sub(1);
            }
            IngressPermitKind::PrincipalBody(source) => {
                let mut inflight = self.guards.principal_body_inflight.lock().unwrap();
                if let Some(count) = inflight.get_mut(source) {
                    *count = count.saturating_sub(1);
                    if *count == 0 {
                        inflight.remove(source);
                    }
                }
            }
            IngressPermitKind::Source(source) => {
                let mut inflight = self.guards.source_inflight.lock().unwrap();
                if let Some(count) = inflight.get_mut(source) {
                    *count = count.saturating_sub(1);
                    if *count == 0 {
                        inflight.remove(source);
                    }
                }
            }
            IngressPermitKind::Principal(principal) => self.guards.release_principal(principal),
        }
    }
}

#[derive(Debug, Clone)]
struct RateWindow {
    started: Instant,
    count: u32,
}

fn check_rate(
    windows: &mut BTreeMap<String, RateWindow>,
    key: &str,
    limit: u32,
    kind: IngressLimitKind,
) -> Result<(), IngressLimitError> {
    let now = Instant::now();
    windows.retain(|_, window| now.duration_since(window.started) < Duration::from_secs(60));
    if !windows.contains_key(key) && windows.len() >= MAX_RATE_LIMIT_KEYS {
        return Err(limit_error(
            IngressLimitKind::LimiterCapacity,
            MAX_RATE_LIMIT_KEYS as u32,
            limiter_capacity_error(),
        ));
    }
    let window = windows.entry(key.to_string()).or_insert(RateWindow {
        started: now,
        count: 0,
    });
    if now.duration_since(window.started) >= Duration::from_secs(60) {
        window.started = now;
        window.count = 0;
    }
    if window.count >= limit {
        return Err(limit_error(
            kind,
            limit,
            ProviderError::error(ReasonCode::RateLimited, "rate limit exceeded"),
        ));
    }
    window.count += 1;
    Ok(())
}

fn concurrency_error(limit: u32) -> ProviderError {
    ProviderError::error(
        ReasonCode::ConcurrencyLimited,
        format!("concurrency limit exceeded ({limit})"),
    )
}

fn limiter_capacity_error() -> ProviderError {
    ProviderError::error(ReasonCode::RateLimited, "rate limiter capacity exceeded")
}

fn limit_error(kind: IngressLimitKind, limit: u32, error: ProviderError) -> IngressLimitError {
    IngressLimitError::new(kind, limit, error)
}

/// The caller's full source IP address for logs and audit. Authentication
/// budgets key on the grouped [`super::source::auth_source_key`] instead.
pub(crate) fn source_log_address(source: &SourceContext) -> String {
    source
        .remote
        .parse::<SocketAddr>()
        .map(|addr| addr.ip().to_string())
        .unwrap_or_else(|_| source.remote.clone())
}
