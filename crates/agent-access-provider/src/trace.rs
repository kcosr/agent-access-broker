//! Upstream request trace events.
use crate::{ReasonCode, current_provider_action};

/// One completed upstream HTTP request, reported by a backend.
pub struct UpstreamTrace<'a> {
    pub provider: &'a str,
    pub upstream_operation: &'a str,
    pub upstream_origin: &'a str,
    pub method: &'a str,
    pub status: Option<u16>,
    pub duration_ms: u64,
    pub attempt: u32,
    pub egress_proxy_mode: &'a str,
    pub reason_code: Option<ReasonCode>,
    pub path_template: Option<&'a str>,
}

/// Emits the `upstream_request_completed` event under this crate's log
/// target, tagged with the invocation's service and action.
pub fn emit_upstream_request_completed(trace: UpstreamTrace<'_>) {
    let (service, action) = current_provider_action().unwrap_or_default();
    emit_upstream_request_completed_for(trace, &service, &action);
}

/// [`emit_upstream_request_completed`] for an invocation that may no longer
/// be the current one.
pub(crate) fn emit_upstream_request_completed_for(
    trace: UpstreamTrace<'_>,
    service: &str,
    action: &str,
) {
    let reason_code = upstream_reason_code(trace.status, trace.reason_code);
    let reason_code_field = reason_code.map(ReasonCode::as_str);
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

    match (trace.status, reason_code) {
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
    reason_code: Option<ReasonCode>,
) -> Option<ReasonCode> {
    if reason_code.is_some() {
        return reason_code;
    }
    let status = status?;
    match status {
        100..=399 => None,
        401 => Some(ReasonCode::UpstreamUnauthorized),
        403 => Some(ReasonCode::UpstreamForbidden),
        404 => Some(ReasonCode::ScopeUnresolved),
        _ => Some(ReasonCode::UpstreamFailed),
    }
}
