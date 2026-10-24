//! Caller-only live limits for the existing single-service detail response.
use super::common::{CallerAdmission, emit_request_limited};
use crate::ingress::guards::{IngressLimitError, IngressPermit};
use crate::ingress::invocation_limits::{
    InvocationLimitResolver, InvocationObservationError, InvocationObservationValues,
};
use crate::ingress::source::auth_source_key;
use crate::state::{AppState, RuntimeSnapshot};
use agent_access_core::{
    BrokerResponse, DiscoveredService, IdentityContext, OperationContext, SourceContext,
    new_broker_request_id,
};
use serde::Serialize;
use serde_json::Value;
use std::sync::Arc;

/// Live state belongs to this host detail response, never the SDK descriptor or
/// service-list projection.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct ServiceDetail {
    #[serde(flatten)]
    service: DiscoveredService,
    scoped_mcp_ready: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    limits: Option<ServiceLimits>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ServiceLimits {
    scope: &'static str,
    state_scope: &'static str,
    instance_id: String,
    observed_at: String,
    invocations: InvocationObservationValues,
    capacity: ServiceCapacity,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ServiceCapacity {
    max_concurrent_requests: u32,
    max_concurrent_requests_per_principal: u32,
    principal_in_flight_requests: u32,
}

/// Called only after the transport's admitted identity and local visibility
/// worker have produced the static service. Resolution and observation remain
/// inside the transport's original absolute discovery deadline.
pub(crate) async fn service_detail(
    state: &AppState,
    snapshot: &Arc<RuntimeSnapshot>,
    identity: &IdentityContext,
    service: DiscoveredService,
) -> Result<ServiceDetail, InvocationObservationError> {
    let limiter = &state.reloadable.shared_invocations;
    let epoch = limiter
        .runtime_epoch(|| Arc::ptr_eq(&state.reloadable.current(), snapshot))
        .map_err(|_| InvocationObservationError::RuntimePublished)?;
    let scoped_mcp_ready = snapshot.runtime.scoped_mcp_ready(&service.service);
    // The anonymous bucket aggregates strangers and is not private caller
    // state. Preserve static anonymous discovery without exposing that bucket.
    if !identity.authenticated {
        limiter
            .runtime_epoch(|| Arc::ptr_eq(&state.reloadable.current(), snapshot))
            .map_err(|_| InvocationObservationError::RuntimePublished)?;
        return Ok(ServiceDetail {
            service,
            scoped_mcp_ready,
            limits: None,
        });
    }
    #[cfg(test)]
    {
        let barrier = state
            .reloadable
            .service_detail_limit_barrier
            .lock()
            .unwrap()
            .clone();
        if let Some(barrier) = barrier {
            barrier.reached.notify_one();
            let _released = barrier.release.acquire().await;
        }
    }
    let principal = identity.principal.clone();
    let service_name = service.service.clone();
    let runtime = snapshot.runtime.clone();
    let max_wait = runtime
        .configured_invocation_limits()
        .max_wait(&service_name);
    let resolve_limit: InvocationLimitResolver = Arc::new(move || {
        let runtime = runtime.clone();
        let principal = principal.clone();
        let service_name = service_name.clone();
        Box::pin(async move {
            runtime
                .effective_invocation_limit(&principal, &service_name)
                .await
                .map(|effective| effective.limit())
        })
    });
    let observed = limiter
        .observe(
            epoch,
            &identity.principal,
            &service.service,
            max_wait,
            resolve_limit,
        )
        .await?;
    let configured = snapshot.runtime.limits();
    let capacity = ServiceCapacity {
        max_concurrent_requests: configured.max_concurrent_requests,
        max_concurrent_requests_per_principal: configured.max_concurrent_requests_per_principal,
        principal_in_flight_requests: state
            .reloadable
            .shared_ingress
            .principal_in_flight_requests(&identity.principal),
    };
    limiter
        .runtime_epoch(|| Arc::ptr_eq(&state.reloadable.current(), snapshot))
        .map_err(|_| InvocationObservationError::RuntimePublished)?;
    Ok(ServiceDetail {
        service,
        scoped_mcp_ready,
        limits: Some(ServiceLimits {
            scope: "principal_service",
            state_scope: "broker_process",
            instance_id: observed.instance_id,
            observed_at: observed.observed_at,
            invocations: observed.invocations,
            capacity,
        }),
    })
}

pub(crate) async fn acquire_global_guard(
    state: &AppState,
    snapshot: &RuntimeSnapshot,
    agent_request_id: &str,
    service: String,
    action: String,
    source: &SourceContext,
) -> Result<IngressPermit, Box<BrokerResponse<Value>>> {
    match state
        .reloadable
        .service_detail_ingress
        .try_service_detail_global_concurrency(snapshot.runtime.limits().max_concurrent_requests)
    {
        Ok(permit) => Ok(permit),
        Err(error) => Err(limit_response(
            snapshot,
            agent_request_id,
            service,
            action,
            source,
            &IdentityContext::anonymous(),
            error,
            false,
        )
        .await),
    }
}

pub(crate) async fn acquire_caller_guard(
    state: &AppState,
    snapshot: &RuntimeSnapshot,
    agent_request_id: &str,
    service: String,
    action: String,
    source: &SourceContext,
    caller: CallerAdmission<'_>,
) -> Result<IngressPermit, Box<BrokerResponse<Value>>> {
    let identity = caller.identity;
    let limits = snapshot.runtime.limits();
    let permit = match state
        .reloadable
        .service_detail_ingress
        .try_service_detail_principal_concurrency(
            &identity.principal,
            limits.max_concurrent_requests_per_principal,
        ) {
        Ok(permit) => permit,
        Err(error) => {
            return Err(limit_response(
                snapshot,
                agent_request_id,
                service,
                action,
                source,
                identity,
                error,
                true,
            )
            .await);
        }
    };
    if !identity.authenticated {
        let shared = &state.reloadable.shared_ingress;
        let result = shared
            .check_auth_source_rate(
                &auth_source_key(source),
                limits.auth_requests_per_source_per_minute,
            )
            .and_then(|()| {
                shared.check_auth_principal_rate(
                    &identity.principal,
                    limits.auth_requests_per_principal_per_minute,
                )
            });
        if let Err(error) = result {
            return Err(limit_response(
                snapshot,
                agent_request_id,
                service,
                action,
                source,
                identity,
                error,
                true,
            )
            .await);
        }
    }
    Ok(permit)
}

#[allow(clippy::too_many_arguments)]
async fn limit_response(
    snapshot: &RuntimeSnapshot,
    agent_request_id: &str,
    service: String,
    action: String,
    source: &SourceContext,
    identity: &IdentityContext,
    error: IngressLimitError,
    has_identity: bool,
) -> Box<BrokerResponse<Value>> {
    let broker_request_id = new_broker_request_id();
    crate::observability::record_broker_request_id(&broker_request_id);
    emit_request_limited(
        &error,
        agent_request_id,
        &broker_request_id,
        &service,
        &action,
        Some(source),
        has_identity.then_some(identity),
    );
    Box::new(
        snapshot
            .runtime
            .admission_limit_error_response(
                OperationContext {
                    agent_request_id: agent_request_id.to_owned(),
                    broker_request_id,
                    identity: identity.clone(),
                    service,
                    action,
                    source: source.clone(),
                },
                error.into_provider_error(),
            )
            .await,
    )
}
