//! Admin management of per-principal service invocation limit overrides:
//! `/v1/admin/principals/{principal}/service-limits[/{service}]`.
//!
//! Overrides live in the managed store and apply only under managed identity
//! authority; TOML deployments configure
//! `limits.invocations.principal_overrides` instead, so these routes reject
//! TOML authority rather than writing overrides the runtime would ignore.
//! Every item is the effective limit the next admission would use.

use super::common::{
    ManagementAccess, ManagementContext, management_context, management_context_error_response,
    management_pre_audited_success_response, management_provider_error_response,
    management_store_call, management_store_error_response, management_success_response,
    management_write_audit_preflight,
};
use crate::state::AppState;
use agent_access_core::{InvocationLimit, InvocationLimitError, PrincipalServiceLimitWriteRequest};
use agent_access_provider::{ReasonCode, is_service_name};
use axum::body::Bytes;
use axum::extract::{ConnectInfo, Path, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::Response;
use serde::Deserialize;
use serde_json::{Value, json};
use std::net::SocketAddr;

const MANAGED_IDENTITY_REQUIRED: &str = "principal service limits require identity.authority = managed; TOML deployments configure limits.invocations.principal_overrides";

/// `PUT` body: exactly `{"requests":N,"windowSeconds":S}`.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ServiceLimitPutBody {
    requests: u64,
    window_seconds: u64,
}

/// `GET`: the effective limit for every configured service, ordered by
/// service. Dormant overrides for unconfigured services are not listed.
pub(crate) async fn list(
    State(state): State<AppState>,
    Path(principal): Path<String>,
    ConnectInfo(remote_addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
) -> Response {
    let operation = "admin.principals.service_limits.list";
    let context = match management_context(
        &state,
        remote_addr,
        &headers,
        operation,
        ManagementAccess::AdminRead,
    )
    .await
    {
        Ok(context) => context,
        Err(response) => return *response,
    };
    let target = Some(json!({"principal": principal}));
    if let Err(response) = require_managed_identity(&context, operation, target.clone()).await {
        return *response;
    }
    let principal_for_store = principal.clone();
    if let Err(error) = management_store_call(&context, move |store| {
        store.principal(&principal_for_store).map(|_| ())
    })
    .await
    {
        return management_store_error_response(&context, operation, target, error).await;
    }
    match context
        .snapshot
        .runtime
        .effective_invocation_limits(&principal)
        .await
    {
        Ok(limits) => management_success_response(&context, operation, target, json!(limits)).await,
        Err(error) => management_provider_error_response(&context, operation, target, error).await,
    }
}

/// `PUT`: creates or replaces the override and returns the new effective
/// item. The next admission for the principal and service uses it.
pub(crate) async fn set(
    State(state): State<AppState>,
    Path((principal, service)): Path<(String, String)>,
    ConnectInfo(remote_addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let operation = crate::handlers::management::audit_actions::ADMIN_PRINCIPALS_SERVICE_LIMITS_SET;
    let context = match management_context(
        &state,
        remote_addr,
        &headers,
        operation,
        ManagementAccess::AdminWrite,
    )
    .await
    {
        Ok(context) => context,
        Err(response) => return *response,
    };
    let target = Some(json!({"principal": principal, "service": service}));
    if let Err(response) = require_managed_identity(&context, operation, target.clone()).await {
        return *response;
    }
    if let Err(response) =
        require_configured_service(&context, operation, &service, target.clone()).await
    {
        return *response;
    }
    // Only the documented object form; serde would also accept a sequence.
    let body = match serde_json::from_slice::<Value>(&body)
        .ok()
        .filter(Value::is_object)
        .and_then(|body| serde_json::from_value::<ServiceLimitPutBody>(body).ok())
    {
        Some(body) => body,
        None => {
            return input_invalid(
                &context,
                operation,
                "request body must be {\"requests\":<integer>,\"windowSeconds\":<integer>}",
                target,
            )
            .await;
        }
    };
    let limit = match InvocationLimit::new(body.requests, body.window_seconds) {
        Ok(limit) => limit,
        Err(error) => {
            return input_invalid(&context, operation, limit_error_message(error), target).await;
        }
    };
    let target = Some(json!({
        "principal": principal,
        "service": service,
        "requests": limit.requests(),
        "windowSeconds": limit.window_seconds(),
    }));
    if let Err(response) =
        management_write_audit_preflight(&context, operation, target.clone()).await
    {
        return *response;
    }
    let request = PrincipalServiceLimitWriteRequest {
        principal_id: principal,
        service: service.clone(),
        limit,
        actor: context.identity.principal.clone(),
    };
    match management_store_call(&context, move |store| {
        store.upsert_principal_service_limit(request)
    })
    .await
    {
        Ok(_) => {
            let item = context
                .snapshot
                .runtime
                .configured_invocation_limits()
                .effective(&service, Some(limit));
            management_pre_audited_success_response(&context, operation, target, json!(item))
        }
        Err(error) => management_store_error_response(&context, operation, target, error).await,
    }
}

/// `DELETE`: removes the override, if any, and returns the effective item
/// that now applies (the service limit or default). Idempotent for an
/// existing principal without an override.
pub(crate) async fn clear(
    State(state): State<AppState>,
    Path((principal, service)): Path<(String, String)>,
    ConnectInfo(remote_addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
) -> Response {
    let operation =
        crate::handlers::management::audit_actions::ADMIN_PRINCIPALS_SERVICE_LIMITS_CLEAR;
    let context = match management_context(
        &state,
        remote_addr,
        &headers,
        operation,
        ManagementAccess::AdminWrite,
    )
    .await
    {
        Ok(context) => context,
        Err(response) => return *response,
    };
    let target = Some(json!({"principal": principal, "service": service}));
    if let Err(response) = require_managed_identity(&context, operation, target.clone()).await {
        return *response;
    }
    if let Err(response) =
        require_configured_service(&context, operation, &service, target.clone()).await
    {
        return *response;
    }
    if let Err(response) =
        management_write_audit_preflight(&context, operation, target.clone()).await
    {
        return *response;
    }
    let principal_for_store = principal.clone();
    let service_for_store = service.clone();
    match management_store_call(&context, move |store| {
        store.principal(&principal_for_store)?;
        store.delete_principal_service_limit(&principal_for_store, &service_for_store)
    })
    .await
    {
        Ok(_) => {
            let item = context
                .snapshot
                .runtime
                .configured_invocation_limits()
                .effective(&service, None);
            management_pre_audited_success_response(&context, operation, target, json!(item))
        }
        Err(error) => management_store_error_response(&context, operation, target, error).await,
    }
}

async fn require_managed_identity(
    context: &ManagementContext,
    operation: &str,
    target: Option<Value>,
) -> Result<(), Box<Response>> {
    if context.snapshot.runtime.config().identity.authority == "managed" {
        return Ok(());
    }
    Err(Box::new(
        input_invalid(context, operation, MANAGED_IDENTITY_REQUIRED, target).await,
    ))
}

/// Overrides may be written only for configured services: provider services
/// and gateway service names, the same set admission counts against.
async fn require_configured_service(
    context: &ManagementContext,
    operation: &str,
    service: &str,
    target: Option<Value>,
) -> Result<(), Box<Response>> {
    let message = if !is_service_name(service) {
        "service name is invalid"
    } else if context
        .snapshot
        .runtime
        .service_descriptor(service)
        .is_none()
    {
        "service is not configured"
    } else {
        return Ok(());
    };
    Err(Box::new(
        input_invalid(context, operation, message, target).await,
    ))
}

fn limit_error_message(error: InvocationLimitError) -> &'static str {
    match error {
        InvocationLimitError::RequestsOutOfRange => "requests must be an integer from 1 to 1000000",
        InvocationLimitError::WindowInvalid | InvocationLimitError::WindowOutOfRange => {
            "windowSeconds must be an integer from 1 to 86400"
        }
    }
}

async fn input_invalid(
    context: &ManagementContext,
    operation: &str,
    message: &str,
    target: Option<Value>,
) -> Response {
    management_context_error_response(
        context,
        StatusCode::BAD_REQUEST,
        operation,
        ReasonCode::InputInvalid,
        message,
        target,
    )
    .await
}
