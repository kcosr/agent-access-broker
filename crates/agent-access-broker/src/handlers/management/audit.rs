//! Audit queries over the SQLite audit store:
//!
//! - `GET /v1/admin/audit/events` (`admin.audit.events.list`) and
//!   `GET /v1/admin/audit/requests/{brokerRequestId}`
//!   (`admin.audit.requests.inspect`): policy-management callers; admins see
//!   every record, service policy managers the records of the services they
//!   manage now.
//! - `GET /v1/audit/events` (`audit.events.list`) and
//!   `GET /v1/audit/requests/{brokerRequestId}` (`audit.requests.inspect`):
//!   `/v1/tokens` callers, who see the records whose principal is their own.
//!
//! Like other management reads, successful queries are not written to audit
//! (see `UNAUDITED_READ_OPERATIONS`); every denial and failure keeps the
//! audited management error path. Queries read through the reader pool of
//! the runtime generation that admitted the request.

use super::common::{
    ManagementAccess, ManagementContext, management_audited_response, management_context,
    management_failure_envelope, management_success_response,
};
use crate::state::AppState;
use agent_access_core::{
    AuditCursorBinding, AuditEventFilters, AuditEventsQuery, AuditListRoute, AuditQueryError,
    AuditStoreInfo, AuditVisibility, Decision, PolicyReadScope, ReasonCode,
    parse_audit_broker_request_id, parse_audit_list_query, reject_audit_query_parameters,
};
use axum::extract::{ConnectInfo, Path, RawQuery, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::Response;
use serde::Serialize;
use serde_json::value::RawValue;
use serde_json::{Value, json};
use std::net::SocketAddr;

/// Who a route serves, and so its access rule and visibility.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Tier {
    /// Admins and service policy managers.
    Admin,
    /// Every managed user, for their own records.
    SelfService,
}

impl Tier {
    fn access(self) -> ManagementAccess {
        match self {
            Self::Admin => ManagementAccess::PolicyRead,
            Self::SelfService => ManagementAccess::UserManageToken,
        }
    }

    fn list_route(self) -> AuditListRoute {
        match self {
            Self::Admin => AuditListRoute::Admin,
            Self::SelfService => AuditListRoute::SelfService,
        }
    }

    fn options_operation(self) -> &'static str {
        match self {
            Self::Admin => "admin.audit.options",
            Self::SelfService => "audit.options",
        }
    }

    fn timeline_operation(self) -> &'static str {
        match self {
            Self::Admin => "admin.audit.requests.inspect",
            Self::SelfService => "audit.requests.inspect",
        }
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct EventsResult {
    items: Vec<Box<RawValue>>,
    next_cursor: Option<String>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct TimelineResult {
    broker_request_id: String,
    items: Vec<Box<RawValue>>,
}

pub(crate) async fn admin_options(
    State(state): State<AppState>,
    RawQuery(raw_query): RawQuery,
    ConnectInfo(remote_addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
) -> Response {
    options(state, raw_query, remote_addr, headers, Tier::Admin).await
}

pub(crate) async fn self_options(
    State(state): State<AppState>,
    RawQuery(raw_query): RawQuery,
    ConnectInfo(remote_addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
) -> Response {
    options(state, raw_query, remote_addr, headers, Tier::SelfService).await
}

async fn options(
    state: AppState,
    raw_query: Option<String>,
    remote_addr: SocketAddr,
    headers: HeaderMap,
    tier: Tier,
) -> Response {
    let operation = tier.options_operation();
    let context =
        match management_context(&state, remote_addr, &headers, operation, tier.access()).await {
            Ok(context) => context,
            Err(response) => return *response,
        };
    let (_, visibility) = match admit(&context, operation, tier, None).await {
        Ok(admitted) => admitted,
        Err(response) => return *response,
    };
    if let Err(message) = reject_audit_query_parameters(raw_query.as_deref()) {
        return input_invalid(&context, operation, &message, None).await;
    }
    let actions =
        super::audit_actions::suggestions(context.snapshot.runtime.resource_types(), &visibility);
    let options = agent_access_core::AuditOptions {
        services: vec![agent_access_core::AuditServiceOptions {
            service: "broker".to_string(),
            actions,
        }],
    };
    management_success_response(&context, operation, None, options).await
}

pub(crate) async fn admin_events_list(
    State(state): State<AppState>,
    RawQuery(raw_query): RawQuery,
    ConnectInfo(remote_addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
) -> Response {
    events_list(state, raw_query, remote_addr, headers, Tier::Admin).await
}

pub(crate) async fn admin_request_inspect(
    State(state): State<AppState>,
    Path(broker_request_id): Path<String>,
    RawQuery(raw_query): RawQuery,
    ConnectInfo(remote_addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
) -> Response {
    request_inspect(
        state,
        broker_request_id,
        raw_query,
        remote_addr,
        headers,
        Tier::Admin,
    )
    .await
}

pub(crate) async fn self_events_list(
    State(state): State<AppState>,
    RawQuery(raw_query): RawQuery,
    ConnectInfo(remote_addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
) -> Response {
    events_list(state, raw_query, remote_addr, headers, Tier::SelfService).await
}

pub(crate) async fn self_request_inspect(
    State(state): State<AppState>,
    Path(broker_request_id): Path<String>,
    RawQuery(raw_query): RawQuery,
    ConnectInfo(remote_addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
) -> Response {
    request_inspect(
        state,
        broker_request_id,
        raw_query,
        remote_addr,
        headers,
        Tier::SelfService,
    )
    .await
}

async fn events_list(
    state: AppState,
    raw_query: Option<String>,
    remote_addr: SocketAddr,
    headers: HeaderMap,
    tier: Tier,
) -> Response {
    let route = tier.list_route();
    let operation = route.operation();
    let context =
        match management_context(&state, remote_addr, &headers, operation, tier.access()).await {
            Ok(context) => context,
            Err(response) => return *response,
        };
    let (store, visibility) = match admit(&context, operation, tier, None).await {
        Ok(admitted) => admitted,
        Err(response) => return *response,
    };
    let params = match parse_audit_list_query(raw_query.as_deref(), route) {
        Ok(params) => params,
        Err(message) => return input_invalid(&context, operation, &message, None).await,
    };
    let binding = AuditCursorBinding {
        route,
        principal: &context.identity.principal,
        database_id: store
            .database_id()
            .expect("a queryable audit store has a database_id"),
    };
    let decoded = match params.cursor.as_deref() {
        Some(cursor) => binding
            .decode(cursor)
            .map(|(filters, position)| (filters, Some(position))),
        None => AuditEventFilters::from_params(params.filters, route).and_then(|filters| {
            binding.check_pageable(&filters)?;
            Ok((filters, None))
        }),
    };
    let (filters, after) = match decoded {
        Ok(decoded) => decoded,
        Err(message) => return input_invalid(&context, operation, &message, None).await,
    };
    let query = AuditEventsQuery {
        visibility,
        filters: filters.clone(),
        after,
        limit: params.limit,
    };
    match store.list_events(query).await {
        Ok(page) => {
            // Filters were checked to fit a cursor before the query ran.
            let next_cursor = page
                .next
                .and_then(|position| binding.encode(&filters, position));
            management_success_response(
                &context,
                operation,
                None,
                EventsResult {
                    items: page.items,
                    next_cursor,
                },
            )
            .await
        }
        Err(error) => query_error_response(&context, operation, error, None).await,
    }
}

async fn request_inspect(
    state: AppState,
    broker_request_id: String,
    raw_query: Option<String>,
    remote_addr: SocketAddr,
    headers: HeaderMap,
    tier: Tier,
) -> Response {
    let operation = tier.timeline_operation();
    let context =
        match management_context(&state, remote_addr, &headers, operation, tier.access()).await {
            Ok(context) => context,
            Err(response) => return *response,
        };
    let broker_request_id = parse_audit_broker_request_id(&broker_request_id);
    let target = broker_request_id
        .as_ref()
        .ok()
        .map(|id| json!({ "brokerRequestId": id }));
    let (store, visibility) = match admit(&context, operation, tier, target.clone()).await {
        Ok(admitted) => admitted,
        Err(response) => return *response,
    };
    let broker_request_id = match broker_request_id {
        Ok(id) => id,
        Err(message) => return input_invalid(&context, operation, &message, None).await,
    };
    if let Err(message) = reject_audit_query_parameters(raw_query.as_deref()) {
        return input_invalid(&context, operation, &message, target).await;
    }
    match store.request_timeline(&broker_request_id, visibility).await {
        Ok(items) if items.is_empty() => {
            error_response(
                &context,
                StatusCode::NOT_FOUND,
                operation,
                Decision::Deny,
                ReasonCode::AuditRequestNotFound,
                "no visible audit records for this brokerRequestId",
                target,
            )
            .await
        }
        Ok(items) => {
            management_success_response(
                &context,
                operation,
                None,
                TimelineResult {
                    broker_request_id,
                    items,
                },
            )
            .await
        }
        Err(error) => query_error_response(&context, operation, error, target).await,
    }
}

/// The queryable store of the generation that admitted the request, and
/// the caller's visibility. Audit disabled or JSONL is
/// `audit_query_unavailable`.
async fn admit<'a>(
    context: &'a ManagementContext,
    operation: &str,
    tier: Tier,
    target: Option<Value>,
) -> Result<(&'a AuditStoreInfo, AuditVisibility), Box<Response>> {
    let Some(store) = context
        .snapshot
        .runtime
        .audit_store()
        .filter(|store| store.supports_queries())
    else {
        return Err(Box::new(
            query_error_response(context, operation, AuditQueryError::Unavailable, target).await,
        ));
    };
    let visibility = match tier {
        Tier::SelfService => AuditVisibility::Principal(context.identity.principal.clone()),
        Tier::Admin => match &context.policy_management_scope {
            Some(PolicyReadScope::Global) => AuditVisibility::Global,
            Some(PolicyReadScope::Services { services }) => {
                AuditVisibility::Services(services.clone())
            }
            // Policy access always resolves a scope; fail closed regardless.
            None => {
                return Err(Box::new(
                    error_response(
                        context,
                        StatusCode::FORBIDDEN,
                        operation,
                        Decision::Deny,
                        ReasonCode::ManagementDenied,
                        "identity is not authorized to manage policy",
                        target,
                    )
                    .await,
                ));
            }
        },
    };
    Ok((store, visibility))
}

async fn query_error_response(
    context: &ManagementContext,
    operation: &str,
    error: AuditQueryError,
    target: Option<Value>,
) -> Response {
    let reason_code = error.reason_code();
    let decision = match error {
        AuditQueryError::Timeout | AuditQueryError::Failed(_) => Decision::Error,
        AuditQueryError::Unavailable | AuditQueryError::ConcurrencyLimited => Decision::Deny,
    };
    if let AuditQueryError::Failed(detail) = &error {
        tracing::error!(
            event = "audit_query_failed",
            nodeId = context.snapshot.runtime.node_id(),
            operation,
            agentRequestId = context.request_id.as_str(),
            brokerRequestId = context.broker_request_id.as_str(),
            principal = context.identity.principal.as_str(),
            error = detail.as_str(),
        );
    }
    let status = StatusCode::from_u16(reason_code.http_status())
        .unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
    error_response(
        context,
        status,
        operation,
        decision,
        reason_code,
        error.message(),
        target,
    )
    .await
}

async fn input_invalid(
    context: &ManagementContext,
    operation: &str,
    message: &str,
    target: Option<Value>,
) -> Response {
    error_response(
        context,
        StatusCode::BAD_REQUEST,
        operation,
        Decision::Deny,
        ReasonCode::InputInvalid,
        message,
        target,
    )
    .await
}

/// An audited management error response.
async fn error_response(
    context: &ManagementContext,
    status: StatusCode,
    operation: &str,
    decision: Decision,
    reason_code: ReasonCode,
    message: &str,
    target: Option<Value>,
) -> Response {
    let envelope =
        management_failure_envelope(context, operation, decision, reason_code, message, target);
    management_audited_response(context, status, envelope).await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn query_errors_map_to_documented_statuses() {
        for (error, status, reason) in [
            (AuditQueryError::Unavailable, 404, "audit_query_unavailable"),
            (
                AuditQueryError::ConcurrencyLimited,
                429,
                "concurrency_limited",
            ),
            (AuditQueryError::Timeout, 503, "audit_query_timeout"),
            (AuditQueryError::Failed("x".into()), 500, "operation_failed"),
        ] {
            assert_eq!(error.reason_code().http_status(), status);
            assert_eq!(error.reason_code().as_str(), reason);
        }
    }

    #[test]
    fn tiers_use_the_reviewed_access_rules() {
        assert!(matches!(Tier::Admin.access(), ManagementAccess::PolicyRead));
        assert!(matches!(
            Tier::SelfService.access(),
            ManagementAccess::UserManageToken
        ));
        assert_eq!(
            Tier::Admin.list_route().operation(),
            "admin.audit.events.list"
        );
        assert_eq!(
            Tier::SelfService.timeline_operation(),
            "audit.requests.inspect"
        );
    }
}
