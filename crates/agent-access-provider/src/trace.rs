//! Upstream request trace events.
use crate::contract::{ContractViolation, HookContext};
use crate::correlation::current_hook_context;
use crate::{ProviderReason, ReasonCode, UpstreamCall, current_provider_action};

/// One completed upstream HTTP request, reported by a backend.
#[non_exhaustive]
pub struct UpstreamTrace<'a> {
    pub provider: &'a str,
    pub upstream_operation: &'a str,
    pub upstream_origin: &'a str,
    pub method: &'a str,
    pub status: Option<u16>,
    pub duration_ms: u64,
    pub attempt: u32,
    pub egress_proxy_mode: &'a str,
    /// The provider's classification: a reason its current hook may report,
    /// one of its registered domain reasons, or a host port's failure it
    /// passes on. A classification outside the hook's contract, or made
    /// outside any provider hook, is recorded as
    /// `broker_provider_contract_failed`.
    pub reason_code: Option<ProviderReason>,
    pub path_template: Option<&'a str>,
}

impl<'a> UpstreamTrace<'a> {
    /// `provider`'s `method` request for `call` to `upstream_origin`, which
    /// completed after `duration_ms` over the `egress_proxy_mode` route. It
    /// records no status, reason or path template until the builders below
    /// add them.
    pub fn new(
        provider: &'a str,
        call: UpstreamCall<'a>,
        upstream_origin: &'a str,
        method: &'a str,
        egress_proxy_mode: &'a str,
        duration_ms: u64,
    ) -> Self {
        Self {
            provider,
            upstream_operation: call.operation,
            upstream_origin,
            method,
            status: None,
            duration_ms,
            attempt: call.attempt,
            egress_proxy_mode,
            reason_code: None,
            path_template: None,
        }
    }

    pub fn with_status(mut self, status: Option<u16>) -> Self {
        self.status = status;
        self
    }

    /// The provider's classification of the request, checked against its hook.
    pub fn with_reason_code(mut self, reason_code: Option<ProviderReason>) -> Self {
        self.reason_code = reason_code;
        self
    }

    pub fn with_path_template(mut self, path_template: Option<&'a str>) -> Self {
        self.path_template = path_template;
        self
    }
}

/// Emits the `upstream_request_completed` event under this crate's log
/// target, tagged with the invocation's service and action, after checking
/// the provider's classification against the current hook.
pub fn emit_upstream_request_completed(mut trace: UpstreamTrace<'_>) {
    let (service, action) = current_provider_action().unwrap_or_default();
    trace.reason_code = trace.reason_code.map(|reason| {
        checked_trace_reason(reason, &service, &action, current_hook_context().as_ref())
    });
    emit_upstream_request_completed_for(trace, &service, &action);
}

/// A provider's trace classification, checked against the hook that sent
/// the request: the reasons that hook may report, attributed to that hook's
/// own service. A classification made outside any provider hook, or under
/// another service's, cannot be checked and is rejected. A rejected one is
/// recorded as `broker_provider_contract_failed`, never the supplied code.
pub(crate) fn checked_trace_reason(
    reason: ProviderReason,
    service: &str,
    action: &str,
    hook: Option<&HookContext>,
) -> ProviderReason {
    let checked = match hook {
        None => Err(ContractViolation::MissingHookContext),
        Some(hook) if hook.service() != service => Err(ContractViolation::InconsistentHookContext),
        Some(hook) => hook.check_trace(reason),
    };
    match checked {
        Ok(()) => reason,
        Err(violation) => {
            tracing::warn!(
                event = "provider_contract_failed",
                service,
                action,
                phase = hook.map_or("", |hook| hook.phase().as_str()),
                emission = "upstream_trace",
                diagnosticCode = violation.diagnostic_code(),
                "provider outcome rejected by its hook contract"
            );
            ReasonCode::BrokerProviderContractFailed.into()
        }
    }
}

/// [`emit_upstream_request_completed`] for an invocation that may no longer
/// be the current one.
pub(crate) fn emit_upstream_request_completed_for(
    trace: UpstreamTrace<'_>,
    service: &str,
    action: &str,
) {
    let reason_code = upstream_reason_code(trace.status, trace.reason_code);
    let reason_code_field = reason_code.map(|reason| reason.as_str());
    macro_rules! event {
        ($level:ident, $($fields:tt)*) => {
            {
                tracing::$level!(
                event = "upstream_request_completed",
                provider = trace.provider,
                service = service,
                action = action,
                upstreamOperation = trace.upstream_operation,
                upstreamOrigin = trace.upstream_origin,
                "http.method" = trace.method,
                upstreamDurationMs = trace.duration_ms,
                upstreamAttempt = trace.attempt,
                "egressProxy.mode" = trace.egress_proxy_mode,
                $($fields)*
                );
            }
        };
    }

    macro_rules! emit_for_level {
        ($level:ident) => {
            match (trace.status, reason_code_field, trace.path_template) {
                (Some(status), Some(reason_code), Some(path_template)) => event!(
                    $level,
                    "http.statusCode" = status,
                    reasonCode = reason_code,
                    pathTemplate = path_template,
                ),
                (Some(status), Some(reason_code), None) => {
                    event!($level, "http.statusCode" = status, reasonCode = reason_code,)
                }
                (Some(status), None, Some(path_template)) => event!(
                    $level,
                    "http.statusCode" = status,
                    pathTemplate = path_template,
                ),
                (Some(status), None, None) => event!($level, "http.statusCode" = status,),
                (None, Some(reason_code), Some(path_template)) => event!(
                    $level,
                    reasonCode = reason_code,
                    pathTemplate = path_template,
                ),
                (None, Some(reason_code), None) => event!($level, reasonCode = reason_code,),
                (None, None, Some(path_template)) => {
                    event!($level, pathTemplate = path_template,)
                }
                (None, None, None) => event!($level,),
            }
        };
    }

    match (
        trace.status,
        reason_code.and_then(|reason| reason.standard()),
    ) {
        (_, Some(ReasonCode::UpstreamConnectionFailed))
        | (_, Some(ReasonCode::UpstreamProtocolFailed))
        | (_, Some(ReasonCode::UpstreamTimeout))
        | (_, Some(ReasonCode::UpstreamFailed)) => emit_for_level!(error),
        (Some(status), _) if (200..400).contains(&status) => emit_for_level!(info),
        (Some(status), _) if (400..500).contains(&status) => emit_for_level!(warn),
        _ => emit_for_level!(error),
    }
}

/// Default reason for an upstream status when the provider did not report a
/// more specific one.
fn upstream_reason_code(
    status: Option<u16>,
    reason_code: Option<ProviderReason>,
) -> Option<ProviderReason> {
    if reason_code.is_some() {
        return reason_code;
    }
    let status = status?;
    let reason = match status {
        100..=399 => return None,
        401 => ReasonCode::UpstreamUnauthorized,
        403 => ReasonCode::UpstreamForbidden,
        404 => ReasonCode::ScopeUnresolved,
        _ => ReasonCode::UpstreamFailed,
    };
    Some(reason.into())
}
