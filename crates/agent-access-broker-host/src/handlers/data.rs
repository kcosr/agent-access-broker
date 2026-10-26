use crate::handlers::common::{
    CallerAdmission, PendingIdentity, acquire_caller_guard, acquire_global_concurrency_guard,
    admit_service_invocation, check_auth_source_rate_guard, discovery_unavailable_envelope,
    envelope_response, input_error_envelope, not_found_envelope, request_id_from_headers,
    resolve_request_identity_pending,
};
use crate::observability;
use crate::state::{AppState, RequestPermits, RuntimeSnapshot};
use agent_access_core::{
    BrokerResponse, ErrorBody, ExecutionContext, GovernedIdentityFailureContext,
    GovernedOperationContext, IdentityContext, IdentitySummary, InvokeRequest, OperationContext,
    ResourceAccessQuery, ResponseEnvelope, SourceContext, new_broker_request_id,
    upload_spool_file_prefix,
};
use agent_access_provider::{
    BrokerBodyPart, BrokerBodyPartSpec, Decision, ProviderError, ProviderReason,
    ProviderResultStreamSource, RESULT_METADATA_HEADER, ReasonCode, ResourceScopes, is_action_name,
    is_service_name,
};
use axum::Json;
use axum::body::Body;
use axum::extract::multipart::{MultipartError, MultipartRejection};
use axum::extract::{ConnectInfo, FromRequest, MatchedPath, Multipart, Path, RawQuery, State};
use axum::http::header::{ACCEPT, CACHE_CONTROL, CONTENT_TYPE};
use axum::http::{HeaderMap, HeaderValue, Method, Request, StatusCode};
use axum::response::IntoResponse;
use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64;
use bytes::Bytes;
use futures_util::StreamExt;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::error::Error as StdError;
use std::net::SocketAddr;
use std::path::Path as FsPath;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::AsyncWriteExt;

pub(crate) const RAW_RESULT_MIME: &str = "application/octet-stream";
const RAW_METADATA_HEADER_LIMIT: usize = 16_384;
const RAW_METADATA_JSON_LIMIT: usize = RAW_METADATA_HEADER_LIMIT / 4 * 3;

enum ParsedInvokeRequest {
    Json(InvokeRequest),
    Multipart(MultipartInvokeRequest),
}

struct MultipartInvokeRequest {
    request: InvokeRequest,
    multipart: Multipart,
}

struct DiscoveryContext {
    snapshot: std::sync::Arc<RuntimeSnapshot>,
    identity: IdentityContext,
    execution_context: Option<ExecutionContext>,
    _permits: Arc<RequestPermits>,
}

#[derive(Debug, Clone, Copy)]
struct DiscoveryMode {
    resolve_execution_context: bool,
}

pub(crate) async fn healthz() -> impl IntoResponse {
    Json(json!({"status": "ok"}))
}

pub(crate) async fn readyz(State(state): State<AppState>) -> impl IntoResponse {
    let snapshot = state.reloadable.current();
    match snapshot
        .readiness_cache
        .check(snapshot.runtime.clone())
        .await
    {
        Ok(()) => (StatusCode::OK, Json(json!({"status": "ready"}))).into_response(),
        Err(_) => (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(json!({"status": "not_ready", "reason": "active runtime is not ready"})),
        )
            .into_response(),
    }
}

pub(crate) async fn me(
    State(state): State<AppState>,
    ConnectInfo(remote_addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
) -> impl IntoResponse {
    let request_id = match request_id_from_headers(&headers, String::new(), String::new()) {
        Ok(request_id) => request_id,
        Err(response) => return envelope_response(*response).into_response(),
    };
    let request_headers = headers.clone();
    let context = match discovery_context(
        &state,
        remote_addr,
        headers,
        request_id.clone(),
        String::new(),
        String::new(),
        DiscoveryMode {
            resolve_execution_context: false,
        },
    )
    .await
    {
        Ok(context) => context,
        Err(response) => return *response,
    };
    let microsoft_membership =
        match me_microsoft_membership(&context.snapshot, &context.identity).await {
            Ok(membership) => membership,
            Err(error) => {
                return envelope_response(discovery_error_envelope(
                    request_id,
                    new_broker_request_id(),
                    String::new(),
                    String::new(),
                    error.reason_code(),
                    "Microsoft membership is unavailable",
                ))
                .into_response();
            }
        };
    match me_service_limits(&context.snapshot, &context.identity, &request_headers).await {
        Ok(service_limits) => (
            StatusCode::OK,
            Json(MeResponse {
                identity: context.identity.summary(),
                service_limits,
                microsoft_membership,
            }),
        )
            .into_response(),
        Err(error) => envelope_response(discovery_error_envelope(
            request_id,
            new_broker_request_id(),
            String::new(),
            String::new(),
            error.reason_code(),
            &error.message,
        ))
        .into_response(),
    }
}

/// `GET /v1/me`: the identity summary plus the caller's service invocation
/// limits.
#[derive(Debug, serde::Serialize)]
#[serde(rename_all = "camelCase")]
struct MeResponse {
    #[serde(flatten)]
    identity: IdentitySummary,
    service_limits: Vec<SelfServiceLimit>,
    /// Present for a caller whose principal has a Microsoft login method.
    #[serde(skip_serializing_if = "Option::is_none")]
    microsoft_membership: Option<MeMicrosoftMembership>,
}

/// The caller's Microsoft group evidence window (`null` without evidence)
/// and its membership renewal status (`null` without a renewal row). Read
/// after renewal admission, so it reflects a renewal the request waited for.
#[derive(Debug, serde::Serialize)]
#[serde(rename_all = "camelCase")]
struct MeMicrosoftMembership {
    valid_until: Option<String>,
    renewal: Option<agent_access_core::OidcMembershipRenewalStatus>,
}

/// The caller's Microsoft membership, for a managed principal with a
/// Microsoft login method.
async fn me_microsoft_membership(
    snapshot: &RuntimeSnapshot,
    identity: &IdentityContext,
) -> Result<Option<MeMicrosoftMembership>, agent_access_core::ManagedStoreError> {
    let Some(store) = snapshot.runtime.managed_store().cloned() else {
        return Ok(None);
    };
    if !identity.authenticated {
        return Ok(None);
    }
    let principal = identity.principal.clone();
    let membership = tokio::task::spawn_blocking(move || store.microsoft_membership(&principal))
        .await
        .map_err(|_| {
            agent_access_core::ManagedStoreError::Unavailable(
                "Microsoft membership read failed".into(),
            )
        })??;
    Ok(membership.map(|membership| MeMicrosoftMembership {
        valid_until: membership.valid_until,
        renewal: membership
            .renewal
            .as_ref()
            .map(agent_access_core::OidcMembershipRenewalRecord::status),
    }))
}

/// One `serviceLimits` item. Deliberately omits whether the value is a
/// principal override or a default.
#[derive(Debug, serde::Serialize)]
#[serde(rename_all = "camelCase")]
struct SelfServiceLimit {
    service: String,
    requests: u32,
    window_seconds: u32,
}

/// Effective limits for the services `/v1/services` would list for this
/// request: the same identity, agent-token caveats, grants, and execution
/// context. `/v1/me` never requires an execution context, so a missing,
/// invalid, or token-denied context yields an empty list instead of an error.
async fn me_service_limits(
    snapshot: &RuntimeSnapshot,
    identity: &IdentityContext,
    headers: &HeaderMap,
) -> Result<Vec<SelfServiceLimit>, ProviderError> {
    let Ok(execution_context) = snapshot.resolve_execution_context(headers) else {
        return Ok(Vec::new());
    };
    if snapshot
        .runtime
        .admit_agent_invoke_execution_context(identity, &execution_context)
        .is_err()
    {
        return Ok(Vec::new());
    }
    let visible = snapshot
        .runtime
        .policy_visible_services(identity, &execution_context)
        .into_iter()
        .map(|service| service.service.clone())
        .collect::<BTreeSet<_>>();
    if visible.is_empty() {
        return Ok(Vec::new());
    }
    Ok(snapshot
        .runtime
        .effective_invocation_limits(&identity.principal)
        .await?
        .into_iter()
        .filter(|limit| visible.contains(&limit.service))
        .map(|limit| SelfServiceLimit {
            service: limit.service,
            requests: limit.requests,
            window_seconds: limit.window_seconds,
        })
        .collect())
}

/// Registered resource types for resource editors and labels. Needs only an
/// authenticated caller, not an execution context.
pub(crate) async fn resource_types(
    State(state): State<AppState>,
    ConnectInfo(remote_addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
) -> impl IntoResponse {
    observability::record_operation("resource_types.list");
    let request_id = match request_id_from_headers(
        &headers,
        "broker".to_string(),
        crate::handlers::management::audit_actions::RESOURCE_TYPES.to_string(),
    ) {
        Ok(request_id) => request_id,
        Err(response) => return envelope_response(*response).into_response(),
    };
    match discovery_context(
        &state,
        remote_addr,
        headers,
        request_id.clone(),
        "broker".to_string(),
        crate::handlers::management::audit_actions::RESOURCE_TYPES.to_string(),
        DiscoveryMode {
            resolve_execution_context: false,
        },
    )
    .await
    {
        // Like the spec routes, this needs an authenticated caller even where
        // other discovery admits anonymous identities.
        Ok(context) if !context.identity.authenticated => {
            envelope_response(context.snapshot.runtime.identity_error_response(
                request_id,
                new_broker_request_id(),
                agent_access_core::IdentityFailure::Required,
            ))
            .into_response()
        }
        Ok(context) => (
            StatusCode::OK,
            Json(serde_json::json!({
                "resourceTypes": context.snapshot.runtime.resource_type_metadata()
            })),
        )
            .into_response(),
        Err(response) => *response,
    }
}

pub(crate) async fn broker_status(
    State(state): State<AppState>,
    ConnectInfo(remote_addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
) -> impl IntoResponse {
    observability::record_operation("broker.status");
    let request_id = match request_id_from_headers(
        &headers,
        "broker".to_string(),
        crate::handlers::management::audit_actions::BROKER_STATUS.to_string(),
    ) {
        Ok(request_id) => request_id,
        Err(response) => return envelope_response(*response).into_response(),
    };
    match discovery_context(
        &state,
        remote_addr,
        headers,
        request_id,
        "broker".to_string(),
        crate::handlers::management::audit_actions::BROKER_STATUS.to_string(),
        DiscoveryMode {
            resolve_execution_context: false,
        },
    )
    .await
    {
        Ok(_) => {
            let mut response =
                (StatusCode::OK, Json(&*state.reloadable.build_status)).into_response();
            response
                .headers_mut()
                .insert(CACHE_CONTROL, HeaderValue::from_static("no-store"));
            response
        }
        Err(response) => *response,
    }
}

pub(crate) async fn capabilities(
    State(state): State<AppState>,
    ConnectInfo(remote_addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
) -> impl IntoResponse {
    let request_id = match request_id_from_headers(&headers, String::new(), String::new()) {
        Ok(request_id) => request_id,
        Err(response) => return envelope_response(*response).into_response(),
    };
    match discovery_context(
        &state,
        remote_addr,
        headers,
        request_id.clone(),
        String::new(),
        String::new(),
        DiscoveryMode {
            resolve_execution_context: true,
        },
    )
    .await
    {
        Ok(context) => {
            discovery_blocking(request_id.clone(), move || {
                let _permits = context._permits;
                let body = context.snapshot.runtime.capabilities(
                    &context.identity,
                    context
                        .execution_context
                        .as_ref()
                        .expect("governed discovery resolves an execution context"),
                );
                (StatusCode::OK, Json(body)).into_response()
            })
            .await
        }
        Err(response) => *response,
    }
}

pub(crate) async fn services(
    State(state): State<AppState>,
    ConnectInfo(remote_addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
) -> impl IntoResponse {
    let request_id = match request_id_from_headers(&headers, String::new(), String::new()) {
        Ok(request_id) => request_id,
        Err(response) => return envelope_response(*response).into_response(),
    };
    match discovery_context(
        &state,
        remote_addr,
        headers,
        request_id.clone(),
        String::new(),
        String::new(),
        DiscoveryMode {
            resolve_execution_context: true,
        },
    )
    .await
    {
        Ok(context) => {
            discovery_blocking(request_id.clone(), move || {
                let _permits = context._permits;
                (
                    StatusCode::OK,
                    Json(
                        context.snapshot.runtime.visible_services(
                            &context.identity,
                            context
                                .execution_context
                                .as_ref()
                                .expect("governed discovery resolves an execution context"),
                        ),
                    ),
                )
                    .into_response()
            })
            .await
        }
        Err(response) => *response,
    }
}

pub(crate) async fn service(
    State(state): State<AppState>,
    Path(service): Path<String>,
    ConnectInfo(remote_addr): ConnectInfo<SocketAddr>,
    method: Method,
    matched_path: MatchedPath,
    headers: HeaderMap,
) -> impl IntoResponse {
    let request_id = match request_id_from_headers(&headers, service.clone(), String::new()) {
        Ok(request_id) => request_id,
        Err(response) => {
            return service_detail_no_store(envelope_response(*response).into_response());
        }
    };
    if !is_service_name(&service) {
        let response = input_error_envelope(
            request_id,
            new_broker_request_id(),
            "service name is invalid",
        );
        return service_detail_no_store(envelope_response(response).into_response());
    }
    let service_detail =
        crate::ingress::body::is_service_detail_route(&method, Some(matched_path.as_str()));
    let deadline = crate::ingress::request_lifetime::RequestLifetime::current()
        .deadline()
        .expect("service detail retains its transport body deadline")
        .at;
    let work = service_detail_response(
        &state,
        service,
        remote_addr,
        headers,
        request_id.clone(),
        service_detail,
    );
    let response = match tokio::time::timeout_at(deadline, work).await {
        Ok(response) if tokio::time::Instant::now() < deadline => response,
        Ok(_) | Err(_) => {
            tracing::warn!(event = "discovery_unavailable", cause = "control_deadline");
            envelope_response(discovery_unavailable_envelope(request_id)).into_response()
        }
    };
    service_detail_no_store(response)
}

fn service_detail_no_store(mut response: axum::response::Response) -> axum::response::Response {
    response
        .headers_mut()
        .insert(CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response
}

async fn service_detail_response(
    state: &AppState,
    service: String,
    remote_addr: SocketAddr,
    headers: HeaderMap,
    request_id: String,
    service_detail: bool,
) -> axum::response::Response {
    use crate::ingress::guards::{REQUEST_PERMIT, SOURCE_RATE_CHARGED};

    // Identity/context assembly can itself own a noncancelable store read.
    // Its owner keeps the transport lease if the route deadline or client
    // drops this receiver before DiscoveryContext has acquired its permits.
    let transport_permit = REQUEST_PERMIT
        .try_with(Clone::clone)
        .expect("service detail retains its transport admission lease");
    let source_rate_charged = SOURCE_RATE_CHARGED
        .try_with(|charged| charged.borrow().clone())
        .unwrap_or_default();
    let lifetime = crate::ingress::request_lifetime::RequestLifetime::current();
    let renewal = crate::membership_renewal::RenewalContext::current();
    let context_state = state.clone();
    let context_request_id = request_id.clone();
    let context_service = service.clone();
    let span = tracing::Span::current();
    let context = tokio::spawn(tracing::Instrument::instrument(
        async move {
            renewal
                .scope(lifetime.scope(REQUEST_PERMIT.scope(
                    transport_permit,
                    SOURCE_RATE_CHARGED.scope(
                        std::cell::RefCell::new(source_rate_charged),
                        async {
                            #[cfg(test)]
                            {
                                let barrier = context_state
                                    .reloadable
                                    .service_detail_context_barrier
                                    .lock()
                                    .unwrap()
                                    .clone();
                                if let Some(barrier) = barrier {
                                    let _ =
                                        tokio::task::spawn_blocking(move || barrier.wait()).await;
                                }
                            }
                            discovery_context_with_capacity(
                                &context_state,
                                remote_addr,
                                headers,
                                context_request_id,
                                context_service,
                                String::new(),
                                DiscoveryMode {
                                    resolve_execution_context: true,
                                },
                                service_detail,
                            )
                            .await
                        },
                    ),
                )))
                .await
        },
        span,
    ))
    .await;
    let context = match context {
        Ok(Ok(context)) => context,
        Ok(Err(response)) => return *response,
        Err(_) => {
            tracing::warn!(event = "discovery_unavailable", cause = "context_worker");
            return envelope_response(discovery_unavailable_envelope(request_id)).into_response();
        }
    };
    // The worker owns a permit reference even when the deadline or request
    // cancels its JoinHandle. It returns the admitted context with static data.
    let permits = context._permits.clone();
    let static_detail = tokio::task::spawn_blocking(move || {
        let capabilities = context.snapshot.runtime.service_capabilities(
            &context.identity,
            context
                .execution_context
                .as_ref()
                .expect("governed discovery resolves an execution context"),
            &service,
        );
        (context, service, capabilities)
    })
    .await;
    let response = match static_detail {
        Ok((context, service, Some(capabilities))) => {
            let state = state.clone();
            // Managed limit reads also contain a noncancelable store worker.
            // Keep the admitted context alive until that read finishes if the
            // enclosing route deadline or client drops this result receiver.
            let live_detail = tokio::spawn(async move {
                let _permits = context._permits;
                super::discovery_limits::service_detail(
                    &state,
                    &context.snapshot,
                    &context.identity,
                    capabilities,
                )
                .await
            })
            .await;
            match live_detail {
                Ok(Ok(detail)) => (StatusCode::OK, Json(detail)).into_response(),
                Ok(Err(error)) => {
                    let (cause, reason_code) = match error {
                        crate::ingress::invocation_limits::InvocationObservationError::RuntimePublished => ("runtime_replaced", None),
                        crate::ingress::invocation_limits::InvocationObservationError::Resolution(error) => (
                            "effective_limit_read", Some(error.reason_code().as_str().to_owned()),
                        ),
                    };
                    tracing::warn!(
                        event = "discovery_unavailable",
                        cause,
                        reasonCode = reason_code.as_deref().unwrap_or(""),
                        service
                    );
                    envelope_response(discovery_unavailable_envelope(request_id)).into_response()
                }
                Err(_) => {
                    tracing::warn!(event = "discovery_unavailable", cause = "live_worker");
                    envelope_response(discovery_unavailable_envelope(request_id)).into_response()
                }
            }
        }
        Ok((_, service, None)) => envelope_response(not_found_envelope(
            request_id,
            new_broker_request_id(),
            service,
        ))
        .into_response(),
        Err(_) => {
            tracing::warn!(event = "discovery_unavailable", cause = "static_worker");
            envelope_response(discovery_unavailable_envelope(request_id)).into_response()
        }
    };
    // Delivery owns both control permits. Body middleware retains its copy of
    // the same global lease; this does not acquire a second shared permit.
    retain_discovery_permits(response, permits)
}

fn retain_discovery_permits(
    response: axum::response::Response,
    permits: Arc<RequestPermits>,
) -> axum::response::Response {
    let (parts, body) = response.into_parts();
    let frames = futures_util::stream::unfold((body, permits), |(mut body, permits)| async move {
        http_body_util::BodyExt::frame(&mut body)
            .await
            .map(|frame| (frame, (body, permits)))
    });
    axum::response::Response::from_parts(parts, Body::new(http_body_util::StreamBody::new(frames)))
}

fn retain_discovery_context_error(
    response: Box<axum::response::Response>,
    permits: &Arc<RequestPermits>,
    service_detail: bool,
) -> Box<axum::response::Response> {
    if service_detail {
        Box::new(retain_discovery_permits(*response, permits.clone()))
    } else {
        response
    }
}

/// Query parsing is deliberately deferred until after service visibility. Axum
/// typed query extractors would disclose validation details to hidden callers.
pub(crate) async fn service_resource_access(
    State(state): State<AppState>,
    Path(service): Path<String>,
    ConnectInfo(remote_addr): ConnectInfo<SocketAddr>,
    RawQuery(query): RawQuery,
    headers: HeaderMap,
) -> axum::response::Response {
    service_discovery_response(state, service, remote_addr, query, headers, true).await
}

pub(crate) async fn service_actions(
    State(state): State<AppState>,
    Path(service): Path<String>,
    ConnectInfo(remote_addr): ConnectInfo<SocketAddr>,
    RawQuery(query): RawQuery,
    headers: HeaderMap,
) -> axum::response::Response {
    service_discovery_response(state, service, remote_addr, query, headers, false).await
}

async fn service_discovery_response(
    state: AppState,
    service: String,
    remote_addr: SocketAddr,
    query: Option<String>,
    headers: HeaderMap,
    resource_access: bool,
) -> axum::response::Response {
    let request_id = match request_id_from_headers(&headers, service.clone(), String::new()) {
        Ok(request_id) => request_id,
        Err(response) => return envelope_response(*response).into_response(),
    };
    let invalid = |message: &str| {
        envelope_response(input_error_envelope(
            request_id.clone(),
            new_broker_request_id(),
            message,
        ))
        .into_response()
    };
    if !is_service_name(&service) {
        return invalid("service name is invalid");
    }
    let context = match discovery_context(
        &state,
        remote_addr,
        headers,
        request_id.clone(),
        service.clone(),
        String::new(),
        DiscoveryMode {
            resolve_execution_context: true,
        },
    )
    .await
    {
        Ok(context) => context,
        Err(response) => return *response,
    };
    discovery_blocking(request_id.clone(), move || {
        let _permits = context._permits;
        let invalid = |message: &str| {
            envelope_response(input_error_envelope(
                request_id.clone(),
                new_broker_request_id(),
                message,
            ))
            .into_response()
        };
        let Some(discovery) = context.snapshot.runtime.service_discovery(
            &context.identity,
            context
                .execution_context
                .as_ref()
                .expect("discovery context"),
            &service,
        ) else {
            return envelope_response(not_found_envelope(
                request_id,
                new_broker_request_id(),
                service,
            ))
            .into_response();
        };
        let fields = match discovery_query_fields(query.as_deref(), resource_access) {
            Ok(fields) => fields,
            Err(message) => return invalid(message),
        };
        let resource_type = match fields
            .get("resourceType")
            .map(|value| agent_access_provider::ResourceType::new(value.clone()))
            .transpose()
        {
            Ok(resource_type) => resource_type,
            Err(_) => return invalid("resourceType is invalid"),
        };
        let result = if resource_access {
            let limit = match fields
                .get("limit")
                .map(|value| value.parse::<usize>())
                .transpose()
            {
                Ok(limit) => limit,
                Err(_) => return invalid("limit must be an integer between 1 and 100"),
            };
            discovery
                .resource_access(&ResourceAccessQuery {
                    action: fields.get("action").cloned(),
                    resource_type,
                    prefix: fields.get("prefix").cloned(),
                    limit,
                    cursor: fields.get("cursor").cloned(),
                })
                .map(|result| Json(result).into_response())
        } else {
            discovery
                .actions(
                    fields.get("resource").map(String::as_str),
                    resource_type.as_ref(),
                    fields.get("prefix").map(String::as_str),
                )
                .map(|result| Json(result).into_response())
        };
        match result {
            Ok(response) => response,
            Err(message) => invalid(message),
        }
    })
    .await
}

/// File reads and credential decryption must not block async HTTP workers. The
/// closure owns request permits until all local discovery work has completed.
async fn discovery_blocking(
    request_id: String,
    work: impl FnOnce() -> axum::response::Response + Send + 'static,
) -> axum::response::Response {
    tokio::task::spawn_blocking(work).await.unwrap_or_else(|_| {
        envelope_response(discovery_unavailable_envelope(request_id)).into_response()
    })
}

fn discovery_query_fields(
    query: Option<&str>,
    resource_access: bool,
) -> Result<BTreeMap<String, String>, &'static str> {
    let allowed: &[&str] = if resource_access {
        &["action", "resourceType", "prefix", "limit", "cursor"]
    } else {
        &["resource", "resourceType", "prefix"]
    };
    let mut fields = BTreeMap::new();
    // URL decoding is safe here: both existence and caller visibility are known.
    for (name, value) in url::form_urlencoded::parse(query.unwrap_or_default().as_bytes()) {
        if !allowed.contains(&name.as_ref()) || value.is_empty() {
            return Err("discovery query contains an unknown or empty field");
        }
        if fields
            .insert(name.into_owned(), value.into_owned())
            .is_some()
        {
            return Err("discovery query fields must not be repeated");
        }
    }
    Ok(fields)
}

/// An invocation's identity failure: the source's authentication budget is
/// charged, then the identity error is finalized for the operation.
async fn invocation_identity_failure(
    state: &AppState,
    snapshot: &RuntimeSnapshot,
    context: GovernedIdentityFailureContext,
    failure: agent_access_core::IdentityFailure,
) -> Box<axum::response::Response> {
    if let Err(response) = check_auth_source_rate_guard(
        state,
        snapshot,
        &context.agent_request_id,
        context.service.clone(),
        context.action.clone(),
        &context.source,
    )
    .await
    {
        return Box::new(envelope_response(*response).into_response());
    }
    let response = snapshot
        .runtime
        .identity_error_response_for_operation(context, failure)
        .await;
    Box::new(envelope_response(response).into_response())
}

/// A discovery request's identity failure: the source's authentication
/// budget is charged, then the identity error is returned.
async fn discovery_identity_failure(
    state: &AppState,
    snapshot: &RuntimeSnapshot,
    request_id: &str,
    service: &str,
    action: &str,
    source: &SourceContext,
    failure: agent_access_core::IdentityFailure,
) -> Box<axum::response::Response> {
    if let Err(response) = check_auth_source_rate_guard(
        state,
        snapshot,
        request_id,
        service.to_string(),
        action.to_string(),
        source,
    )
    .await
    {
        return Box::new(envelope_response(*response).into_response());
    }
    let response = snapshot.runtime.identity_error_response(
        request_id.to_string(),
        new_broker_request_id(),
        failure,
    );
    Box::new(envelope_response(response).into_response())
}

async fn discovery_context(
    state: &AppState,
    remote_addr: SocketAddr,
    headers: HeaderMap,
    request_id: String,
    service: String,
    action: String,
    mode: DiscoveryMode,
) -> Result<DiscoveryContext, Box<axum::response::Response>> {
    discovery_context_with_capacity(
        state,
        remote_addr,
        headers,
        request_id,
        service,
        action,
        mode,
        false,
    )
    .await
}

#[allow(clippy::too_many_arguments)]
async fn discovery_context_with_capacity(
    state: &AppState,
    remote_addr: SocketAddr,
    headers: HeaderMap,
    request_id: String,
    service: String,
    action: String,
    mode: DiscoveryMode,
    service_detail: bool,
) -> Result<DiscoveryContext, Box<axum::response::Response>> {
    let snapshot = state.reloadable.current();
    let source = snapshot
        .source_resolver
        .source_context(remote_addr, &headers);
    let global_permit = if service_detail {
        super::discovery_limits::acquire_global_guard(
            state,
            &snapshot,
            &request_id,
            service.clone(),
            action.clone(),
            &source,
        )
        .await
    } else {
        acquire_global_concurrency_guard(
            state,
            &snapshot,
            &request_id,
            service.clone(),
            action.clone(),
            &source,
        )
        .await
    }
    .map_err(|response| Box::new(envelope_response(*response).into_response()))?;
    let execution_context = if mode.resolve_execution_context {
        Some(
            resolve_execution_context_or_response(
                state,
                &snapshot,
                &headers,
                request_id.clone(),
                service.clone(),
                action.clone(),
                &source,
            )
            .await?,
        )
    } else {
        None
    };
    let pending =
        match resolve_request_identity_pending(state, snapshot.clone(), headers.clone()).await {
            Ok(pending) => pending,
            Err(failure) => {
                return Err(discovery_identity_failure(
                    state,
                    &snapshot,
                    &request_id,
                    &service,
                    &action,
                    &source,
                    failure,
                )
                .await);
            }
        };
    let password_change_required = |request_id: String, service: String, action: String| {
        Box::new(
            envelope_response(discovery_error_envelope(
                request_id,
                new_broker_request_id(),
                service,
                action,
                ReasonCode::PasswordChangeRequired,
                "password change is required before discovery",
            ))
            .into_response(),
        )
    };
    if pending.value().password_change_required {
        return Err(password_change_required(request_id, service, action));
    }
    // A membership renewal wait holds the caller's capacity.
    let caller = CallerAdmission {
        identity: &pending.value().identity,
    };
    let principal_permit = if service_detail {
        super::discovery_limits::acquire_caller_guard(
            state,
            &snapshot,
            &request_id,
            service.clone(),
            action.clone(),
            &source,
            caller,
        )
        .await
    } else {
        acquire_caller_guard(
            state,
            &snapshot,
            &request_id,
            service.clone(),
            action.clone(),
            &source,
            caller,
        )
        .await
    }
    .map_err(|response| Box::new(envelope_response(*response).into_response()))?;
    let permits = Arc::new(RequestPermits {
        _global: global_permit,
        _principal: principal_permit,
    });
    let identity = match pending.admit(state, &snapshot, &headers).await {
        Ok(resolved) if resolved.password_change_required => {
            return Err(retain_discovery_context_error(
                password_change_required(request_id, service, action),
                &permits,
                service_detail,
            ));
        }
        Ok(resolved) => resolved.identity,
        Err(failure) => {
            let response = discovery_identity_failure(
                state,
                &snapshot,
                &request_id,
                &service,
                &action,
                &source,
                failure,
            )
            .await;
            return Err(retain_discovery_context_error(
                response,
                &permits,
                service_detail,
            ));
        }
    };
    observability::record_principal(&identity.principal);
    if let Some(execution_context) = execution_context.as_ref()
        && let Err(error) = snapshot
            .runtime
            .admit_agent_invoke_execution_context(&identity, execution_context)
    {
        let broker_request_id = new_broker_request_id();
        observability::record_broker_request_id(&broker_request_id);
        let response = snapshot
            .runtime
            .context_authorization_error_response(
                GovernedOperationContext {
                    admission: None,
                    operation: OperationContext {
                        agent_request_id: request_id,
                        broker_request_id,
                        identity,
                        service,
                        action,
                        source,
                    },
                    execution_context: execution_context.clone(),
                },
                error,
            )
            .await;
        return Err(retain_discovery_context_error(
            Box::new(envelope_response(response).into_response()),
            &permits,
            service_detail,
        ));
    }
    Ok(DiscoveryContext {
        snapshot,
        identity,
        execution_context,
        _permits: permits,
    })
}

#[allow(clippy::too_many_arguments)]
async fn resolve_execution_context_or_response(
    state: &AppState,
    snapshot: &RuntimeSnapshot,
    headers: &HeaderMap,
    agent_request_id: String,
    service: String,
    action: String,
    source: &SourceContext,
) -> Result<ExecutionContext, Box<axum::response::Response>> {
    match snapshot.resolve_execution_context(headers) {
        Ok(execution_context) => {
            observability::record_execution_context(&execution_context);
            Ok(execution_context)
        }
        Err(failure) => {
            check_auth_source_rate_guard(
                state,
                snapshot,
                &agent_request_id,
                service.clone(),
                action.clone(),
                source,
            )
            .await
            .map_err(|response| Box::new(envelope_response(*response).into_response()))?;
            let broker_request_id = new_broker_request_id();
            observability::record_broker_request_id(&broker_request_id);
            let response = snapshot
                .runtime
                .ingress_error_response_for_operation(
                    OperationContext {
                        agent_request_id,
                        broker_request_id,
                        identity: IdentityContext::anonymous(),
                        service,
                        action,
                        source: source.clone(),
                    },
                    failure,
                )
                .await;
            Err(Box::new(envelope_response(response).into_response()))
        }
    }
}

fn discovery_error_envelope(
    agent_request_id: String,
    broker_request_id: String,
    service: String,
    action: String,
    reason_code: impl Into<ProviderReason>,
    message: &str,
) -> BrokerResponse<Value> {
    let reason_code = reason_code.into();
    BrokerResponse {
        retry_after_seconds: None,
        status: reason_code.http_status(),
        envelope: ResponseEnvelope {
            agent_request_id,
            broker_request_id,
            decision: Decision::Deny,
            service,
            action,
            resource_scopes: ResourceScopes::new(),
            reason_code: Some(reason_code.into()),
            reason: Some(message.to_string()),
            result: None,
            error: Some(ErrorBody {
                message: message.to_string(),
            }),
        },
        stream: None,
    }
}

pub(crate) struct AdmittedInvocation {
    pub(crate) snapshot: std::sync::Arc<RuntimeSnapshot>,
    pub(crate) context: GovernedOperationContext,
    pub(crate) permits: RequestPermits,
}

enum InvocationIngress<'a> {
    Rest,
    HttpMcp(&'a crate::mcp::IdentityPin),
}

pub(crate) async fn admit_invoke(
    state: &AppState,
    snapshot: std::sync::Arc<RuntimeSnapshot>,
    remote_addr: SocketAddr,
    headers: &HeaderMap,
    service: String,
    action: String,
) -> Result<AdmittedInvocation, Box<axum::response::Response>> {
    admit_invoke_with_identity(
        state,
        snapshot,
        remote_addr,
        headers,
        service,
        action,
        InvocationIngress::Rest,
    )
    .await
}

pub(crate) async fn admit_mcp_invoke(
    state: &AppState,
    snapshot: std::sync::Arc<RuntimeSnapshot>,
    remote_addr: SocketAddr,
    headers: &HeaderMap,
    service: String,
    action: String,
    identity_pin: &crate::mcp::IdentityPin,
) -> Result<AdmittedInvocation, Box<axum::response::Response>> {
    admit_invoke_with_identity(
        state,
        snapshot,
        remote_addr,
        headers,
        service,
        action,
        InvocationIngress::HttpMcp(identity_pin),
    )
    .await
}

async fn admit_invoke_with_identity(
    state: &AppState,
    snapshot: std::sync::Arc<RuntimeSnapshot>,
    remote_addr: SocketAddr,
    headers: &HeaderMap,
    service: String,
    action: String,
    ingress: InvocationIngress<'_>,
) -> Result<AdmittedInvocation, Box<axum::response::Response>> {
    let (identity_pin, surface) = match ingress {
        InvocationIngress::Rest => (None, crate::admission::AdmissionSurface::RestInvoke),
        InvocationIngress::HttpMcp(pin) => (Some(pin), crate::admission::AdmissionSurface::HttpMcp),
    };
    let (context, permits, original_pin) = prepare_invocation_admission(
        state,
        snapshot.clone(),
        remote_addr,
        headers,
        service,
        action,
        identity_pin,
    )
    .await?;
    let lifetime = crate::ingress::request_lifetime::RequestLifetime::current();
    lifetime.complete_initial_admission();
    let recheck_snapshot = snapshot.clone();
    let reloadable = state.reloadable.clone();
    let recheck_headers = headers.clone();
    let revalidate: crate::admission::AdmissionRevalidation = Box::new(move |context, guard| {
        Box::pin(async move {
            let work_snapshot = recheck_snapshot.clone();
            let recheck = async move {
                match original_pin {
                    Some(pin) => {
                        #[cfg(test)]
                        reloadable.wait_mcp_admission_barrier().await;
                        pin.revalidate(reloadable, work_snapshot.clone(), recheck_headers)
                            .await
                    }
                    None => {
                        super::common::resolve_identity_without_renewal(
                            work_snapshot.clone(),
                            recheck_headers,
                        )
                        .await
                    }
                }
            };
            super::common::revalidate_after_admission(
                &recheck_snapshot,
                context,
                lifetime.deadline(),
                guard,
                recheck,
            )
            .await
        })
    });
    let (context, permits) =
        match admit_service_invocation(state, &snapshot, context, permits, revalidate, surface)
            .await
        {
            Ok(admitted) => admitted,
            Err(response) => return Err(Box::new(envelope_response(*response).into_response())),
        };
    Ok(AdmittedInvocation {
        snapshot,
        context,
        permits,
    })
}

async fn prepare_invocation_admission(
    state: &AppState,
    snapshot: std::sync::Arc<RuntimeSnapshot>,
    remote_addr: SocketAddr,
    headers: &HeaderMap,
    service: String,
    action: String,
    identity_pin: Option<&crate::mcp::IdentityPin>,
) -> Result<
    (
        GovernedOperationContext,
        RequestPermits,
        Option<crate::mcp::IdentityPin>,
    ),
    Box<axum::response::Response>,
> {
    let source = snapshot
        .source_resolver
        .source_context(remote_addr, headers);
    let agent_request_id = match request_id_from_headers(headers, service.clone(), action.clone()) {
        Ok(request_id) => request_id,
        Err(response) => return Err(Box::new(envelope_response(*response).into_response())),
    };
    if !is_service_name(&service) || !is_action_name(&action) {
        let response = input_error_envelope(
            agent_request_id,
            new_broker_request_id(),
            "service or action name is invalid",
        );
        return Err(Box::new(envelope_response(response).into_response()));
    }

    let global_permit = match acquire_global_concurrency_guard(
        state,
        &snapshot,
        &agent_request_id,
        service.clone(),
        action.clone(),
        &source,
    )
    .await
    {
        Ok(permit) => permit,
        Err(response) => return Err(Box::new(envelope_response(*response).into_response())),
    };

    let execution_context = if let Some(pin) = identity_pin {
        match pin.admission.execution_context() {
            Ok(context) => context,
            Err(error) => {
                let failure = match error {
                    agent_access_core::ExecutionContextFailure::Required => {
                        agent_access_core::IdentityFailure::ExecutionContextRequired
                    }
                    agent_access_core::ExecutionContextFailure::Invalid => {
                        agent_access_core::IdentityFailure::ExecutionContextInvalid
                    }
                };
                let response = snapshot
                    .runtime
                    .ingress_error_response_for_operation(
                        OperationContext {
                            agent_request_id,
                            broker_request_id: new_broker_request_id(),
                            identity: IdentityContext::anonymous(),
                            service,
                            action,
                            source,
                        },
                        failure,
                    )
                    .await;
                return Err(Box::new(envelope_response(response).into_response()));
            }
        }
    } else {
        match resolve_execution_context_or_response(
            state,
            &snapshot,
            headers,
            agent_request_id.clone(),
            service.clone(),
            action.clone(),
            &source,
        )
        .await
        {
            Ok(execution_context) => execution_context,
            Err(response) => return Err(response),
        }
    };

    // An MCP-dispatched operation revalidates the identity its intake
    // admitted; renewal admission ran there.
    let identity_result = if let Some(pin) = identity_pin {
        pin.revalidate(state.reloadable.clone(), snapshot.clone(), headers.clone())
            .await
            .map(|identity| (PendingIdentity::admitted(identity), Some(pin.clone())))
    } else {
        super::common::resolve_identity_pending_pinned(state, snapshot.clone(), headers.clone())
            .await
    };
    let failure_context = || GovernedIdentityFailureContext {
        admission: None,
        agent_request_id: agent_request_id.clone(),
        broker_request_id: new_broker_request_id(),
        service: service.clone(),
        action: action.clone(),
        source: source.clone(),
        execution_context: execution_context.clone(),
    };
    let (pending, original_pin) = match identity_result {
        Ok(pending) => pending,
        Err(failure) => {
            return Err(
                invocation_identity_failure(state, &snapshot, failure_context(), failure).await,
            );
        }
    };
    observability::record_principal(&pending.value().principal);
    // A membership renewal wait holds the caller's capacity.
    let principal_permit = match acquire_caller_guard(
        state,
        &snapshot,
        &agent_request_id,
        service.clone(),
        action.clone(),
        &source,
        CallerAdmission {
            identity: pending.value(),
        },
    )
    .await
    {
        Ok(permit) => permit,
        Err(response) => return Err(Box::new(envelope_response(*response).into_response())),
    };
    let identity = match pending.admit(state, &snapshot, headers).await {
        Ok(identity) => identity,
        Err(failure) => {
            return Err(
                invocation_identity_failure(state, &snapshot, failure_context(), failure).await,
            );
        }
    };

    let broker_request_id = new_broker_request_id();
    observability::record_broker_request_id(&broker_request_id);
    let context = GovernedOperationContext {
        admission: None,
        operation: OperationContext {
            agent_request_id,
            broker_request_id,
            identity,
            service,
            action,
            source,
        },
        execution_context,
    };
    Ok((
        context,
        RequestPermits {
            _global: global_permit,
            _principal: principal_permit,
        },
        original_pin,
    ))
}

pub(crate) async fn invoke_admitted_json(
    state: &AppState,
    admitted: AdmittedInvocation,
    request: InvokeRequest,
    control: agent_access_core::InvocationControl,
) -> agent_access_core::BrokerResponse<Value> {
    crate::operations::invoke(state, admitted, request, control, false)
        .await
        .0
}

pub(crate) async fn invoke(
    State(state): State<AppState>,
    Path((service, action)): Path<(String, String)>,
    ConnectInfo(remote_addr): ConnectInfo<SocketAddr>,
    request: Request<Body>,
) -> axum::response::Response {
    let headers = request.headers().clone();
    let snapshot = state.reloadable.current();
    // Refusals before admission, including rate and queue limits, never read
    // the body.
    let admitted =
        match admit_invoke(&state, snapshot, remote_addr, &headers, service, action).await {
            Ok(admitted) => admitted,
            Err(response) => return *response,
        };
    // A later refusal can leave the body unread, as for an upload refused
    // after its metadata part; the connection lingers so the client reads it.
    let (request, unread) = crate::ingress::lingering_close::track(request);
    let response = invoke_admitted(&state, admitted, &headers, request).await;
    unread.linger(response)
}

async fn invoke_admitted(
    state: &AppState,
    admitted: AdmittedInvocation,
    headers: &HeaderMap,
    request: Request<Body>,
) -> axum::response::Response {
    let raw_result_requested = accepts_raw_result(headers);
    let AdmittedInvocation {
        snapshot,
        context,
        permits,
    } = admitted;

    let action_descriptor = snapshot
        .runtime
        .service_descriptor(&context.operation.service)
        .and_then(|service| service.action(&context.operation.action).cloned());
    let raw_result_action = action_supports_raw_result(action_descriptor.as_ref());
    let exports_secrets = action_exports_secrets(action_descriptor.as_ref());
    if raw_result_requested && !raw_result_action {
        let response = snapshot
            .runtime
            .governed_operation_error_response(
                context,
                ProviderError::deny(
                    ReasonCode::InputInvalid,
                    "raw result streams are supported only for download actions",
                ),
            )
            .await;
        return envelope_response(response).into_response();
    }
    if raw_result_action && !raw_result_requested {
        // The public reason-code contract has no 406/not-acceptable code; use
        // the existing response-format failure bucket for download negotiation.
        let response = snapshot
            .runtime
            .governed_operation_error_response(
                context,
                ProviderError::deny(
                    ReasonCode::BodyFormatUnsupported,
                    "download actions require Accept: application/octet-stream",
                ),
            )
            .await;
        return envelope_response(response).into_response();
    }
    if raw_result_action && request_is_multipart(headers) {
        let response = snapshot
            .runtime
            .governed_operation_error_response(
                context,
                ProviderError::deny(
                    ReasonCode::BodyFormatUnsupported,
                    "download actions require a JSON request body",
                ),
            )
            .await;
        return envelope_response(response).into_response();
    }

    let parsed = match parse_invoke_request(request, state, &snapshot).await {
        Ok(parsed) => parsed,
        Err(error) => {
            let response = snapshot
                .runtime
                .governed_operation_error_response(context, error);
            let response = response.await;
            return envelope_response(response).into_response();
        }
    };

    let response = match parsed {
        ParsedInvokeRequest::Json(request) if raw_result_requested => {
            if snapshot
                .runtime
                .command_provider(&context.operation.service)
                .is_some()
            {
                let (response, permits) = crate::operations::invoke(
                    state,
                    AdmittedInvocation {
                        snapshot,
                        context,
                        permits,
                    },
                    request,
                    agent_access_core::InvocationControl::default(),
                    true,
                )
                .await;
                return raw_result_response(response, permits, exports_secrets).await;
            }
            snapshot
                .runtime
                .invoke_required_stream(context, request)
                .await
        }
        ParsedInvokeRequest::Json(request) => {
            let response = invoke_admitted_json(
                state,
                AdmittedInvocation {
                    snapshot,
                    context,
                    permits,
                },
                request,
                agent_access_core::InvocationControl::default(),
            )
            .await;
            return json_invoke_response(response, exports_secrets);
        }
        ParsedInvokeRequest::Multipart(request) => {
            invoke_multipart_after_metadata(state, &snapshot, context, request).await
        }
    };
    if raw_result_requested {
        return raw_result_response(response, Some(permits), exports_secrets)
            .await
            .into_response();
    }
    let _permits = permits;
    json_invoke_response(response, exports_secrets)
}

/// Responses from actions that deliberately export secrets are never cached.
fn json_invoke_response(
    response: agent_access_core::BrokerResponse<Value>,
    exports_secrets: bool,
) -> axum::response::Response {
    let mut response = envelope_response(response).into_response();
    if exports_secrets {
        response
            .headers_mut()
            .insert(CACHE_CONTROL, HeaderValue::from_static("no-store"));
    }
    response
}

async fn invoke_multipart_after_metadata(
    state: &AppState,
    snapshot: &RuntimeSnapshot,
    context: GovernedOperationContext,
    request: MultipartInvokeRequest,
) -> BrokerResponse<Value> {
    let prepared = match snapshot
        .runtime
        .begin_invoke(context, request.request)
        .await
    {
        Ok(prepared) => prepared,
        Err(response) => return *response,
    };
    let prepared = match snapshot.runtime.authorize_body_parts(prepared).await {
        Ok(prepared) => prepared,
        Err(response) => return *response,
    };
    let body_part_specs = prepared.body_part_specs().to_vec();
    let expected_upload_bytes = match expected_upload_bytes(&body_part_specs) {
        Ok(bytes) => bytes,
        Err(error) => return snapshot.runtime.fail_prepared_invoke(prepared, error).await,
    };
    let _spool_reservation = match state.reloadable.shared_spool.reserve(
        snapshot.runtime.upload_spool_dir(),
        snapshot.runtime.upload_spool_max_bytes(),
        expected_upload_bytes,
    ) {
        Ok(reservation) => reservation,
        Err(error) => return snapshot.runtime.fail_prepared_invoke(prepared, error).await,
    };
    let body_parts = match parse_multipart_body_parts(
        request.multipart,
        &body_part_specs,
        snapshot.runtime.upload_spool_dir(),
        snapshot.runtime.streaming_idle_timeout(),
    )
    .await
    {
        Ok(body_parts) => body_parts,
        Err(error) => return snapshot.runtime.fail_prepared_invoke(prepared, error).await,
    };
    snapshot
        .runtime
        .finish_prepared_invoke(prepared, body_parts)
        .await
}

fn expected_upload_bytes(specs: &[BrokerBodyPartSpec]) -> Result<u64, ProviderError> {
    specs.iter().try_fold(0_u64, |total, spec| {
        total.checked_add(spec.size).ok_or_else(|| {
            ProviderError::deny(
                ReasonCode::AttachmentSizeDenied,
                "attachments exceeded the configured total byte cap",
            )
        })
    })
}

async fn parse_invoke_request(
    request: Request<Body>,
    state: &AppState,
    snapshot: &RuntimeSnapshot,
) -> Result<ParsedInvokeRequest, ProviderError> {
    if request_is_multipart(request.headers()) {
        parse_multipart_invoke_request(request, state, snapshot).await
    } else {
        let bytes =
            axum::body::to_bytes(request.into_body(), snapshot.runtime.max_http_body_bytes())
                .await
                .map_err(body_buffer_error)?;
        serde_json::from_slice::<InvokeRequest>(&bytes)
            .map(ParsedInvokeRequest::Json)
            .map_err(|_| ProviderError::deny(ReasonCode::InputInvalid, "request body is invalid"))
    }
}

fn request_is_multipart(headers: &HeaderMap) -> bool {
    headers
        .get(CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .is_some_and(|value| value.starts_with("multipart/form-data"))
}

async fn parse_multipart_invoke_request(
    request: Request<Body>,
    state: &AppState,
    snapshot: &RuntimeSnapshot,
) -> Result<ParsedInvokeRequest, ProviderError> {
    let idle_timeout = snapshot.runtime.streaming_idle_timeout();
    let mut multipart = Multipart::from_request(request, state)
        .await
        .map_err(multipart_rejection_error)?;
    let Some(mut first) = tokio::time::timeout(idle_timeout, multipart.next_field())
        .await
        .map_err(upload_idle_timeout_error)?
        .map_err(multipart_error)?
    else {
        return Err(ProviderError::deny(
            ReasonCode::InputInvalid,
            "multipart request metadata is required",
        ));
    };
    if first.name() != Some("request") {
        return Err(ProviderError::deny(
            ReasonCode::InputInvalid,
            "multipart request metadata must be the first part",
        ));
    }
    // Metadata is ordinary JSON, independent of the much larger file-transfer
    // allowance. Check each chunk before extending the buffer so an unfinished
    // metadata part cannot consume the complete upload budget in memory.
    let metadata_cap = snapshot
        .runtime
        .max_http_body_bytes()
        .min(crate::ingress::body::JSON_BODY_CAP);
    let mut request_bytes = Vec::new();
    while let Some(chunk) = tokio::time::timeout(idle_timeout, first.chunk())
        .await
        .map_err(upload_idle_timeout_error)?
        .map_err(multipart_error)?
    {
        if chunk.len() > metadata_cap.saturating_sub(request_bytes.len()) {
            return Err(request_body_too_large_error());
        }
        request_bytes.extend_from_slice(&chunk);
    }
    drop(first);
    let invoke = serde_json::from_slice::<InvokeRequest>(&request_bytes).map_err(|_| {
        ProviderError::deny(
            ReasonCode::InputInvalid,
            "multipart request metadata is invalid",
        )
    })?;
    Ok(ParsedInvokeRequest::Multipart(MultipartInvokeRequest {
        request: invoke,
        multipart,
    }))
}

async fn parse_multipart_body_parts(
    mut multipart: Multipart,
    expected_specs: &[BrokerBodyPartSpec],
    spool_dir: &FsPath,
    idle_timeout: Duration,
) -> Result<Vec<BrokerBodyPart>, ProviderError> {
    let mut body_parts = Vec::new();
    let mut names = BTreeSet::new();
    let expected_specs = expected_specs
        .iter()
        .map(|spec| (spec.name.as_str(), spec))
        .collect::<BTreeMap<_, _>>();
    while let Some(field) = tokio::time::timeout(idle_timeout, multipart.next_field())
        .await
        .map_err(upload_idle_timeout_error)?
        .map_err(multipart_error)?
    {
        let name = field.name().unwrap_or("").to_string();
        if name.is_empty() {
            return Err(ProviderError::deny(
                ReasonCode::InputInvalid,
                "multipart file part name is required",
            ));
        }
        if !names.insert(name.clone()) {
            return Err(ProviderError::deny(
                ReasonCode::BodyMalformed,
                "multipart file part names must be unique",
            ));
        }
        let Some(spec) = expected_specs.get(name.as_str()) else {
            return Err(unexpected_attachment_part_error());
        };
        let file_name = field.file_name().map(ToString::to_string);
        let content_type = field.content_type().map(ToString::to_string);
        if file_name.as_deref() != Some(spec.file_name.as_str()) {
            return Err(ProviderError::deny(
                ReasonCode::BodyMalformed,
                "attachment filename did not match metadata",
            ));
        }
        if content_type.as_deref() != Some(spec.content_type.as_str()) {
            return Err(ProviderError::deny(
                ReasonCode::AttachmentMediaTypeDenied,
                "attachment content type did not match metadata",
            ));
        }
        let file = tempfile::Builder::new()
            .prefix(&upload_spool_file_prefix())
            .tempfile_in(spool_dir)
            .map_err(|_| {
                ProviderError::error(
                    ReasonCode::UpstreamFailed,
                    "temporary upload storage is unavailable",
                )
            })?;
        let mut async_file = tokio::fs::OpenOptions::new()
            .write(true)
            .open(file.path())
            .await
            .map_err(|_| {
                ProviderError::error(
                    ReasonCode::UpstreamFailed,
                    "temporary upload storage is unavailable",
                )
            })?;
        let mut field = field;
        let mut size = 0_u64;
        let mut hasher = Sha256::new();
        while let Some(chunk) = tokio::time::timeout(idle_timeout, field.chunk())
            .await
            .map_err(upload_idle_timeout_error)?
            .map_err(multipart_error)?
        {
            size = size
                .checked_add(chunk.len() as u64)
                .ok_or_else(attachment_size_mismatch_error)?;
            if size > spec.size {
                return Err(attachment_size_mismatch_error());
            }
            hasher.update(&chunk);
            async_file.write_all(&chunk).await.map_err(|_| {
                ProviderError::error(
                    ReasonCode::UpstreamFailed,
                    "temporary upload storage is unavailable",
                )
            })?;
        }
        if size != spec.size {
            return Err(ProviderError::deny(
                ReasonCode::AttachmentIntegrityMismatch,
                "attachment size did not match metadata",
            ));
        }
        let sha256 = hasher
            .finalize()
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>();
        if sha256 != spec.sha256 {
            return Err(ProviderError::deny(
                ReasonCode::AttachmentIntegrityMismatch,
                "attachment sha256 did not match metadata",
            ));
        }
        async_file.flush().await.map_err(|_| {
            ProviderError::error(
                ReasonCode::UpstreamFailed,
                "temporary upload storage is unavailable",
            )
        })?;
        drop(async_file);
        let (_file, path) = file.keep().map_err(|_| {
            ProviderError::error(
                ReasonCode::UpstreamFailed,
                "temporary upload storage is unavailable",
            )
        })?;
        body_parts.push(agent_access_provider::host::spooled_body_part(
            name,
            file_name,
            content_type,
            path,
            size,
            sha256,
        ));
    }
    if body_parts.len() != expected_specs.len() {
        return Err(ProviderError::deny(
            ReasonCode::BodyMalformed,
            "attachment file part is missing",
        ));
    }
    Ok(body_parts)
}

fn unexpected_attachment_part_error() -> ProviderError {
    ProviderError::deny(ReasonCode::BodyMalformed, "unexpected attachment file part")
}

fn attachment_size_mismatch_error() -> ProviderError {
    ProviderError::deny(
        ReasonCode::AttachmentIntegrityMismatch,
        "attachment size did not match metadata",
    )
}

fn multipart_rejection_error(error: MultipartRejection) -> ProviderError {
    if error.status() == StatusCode::PAYLOAD_TOO_LARGE || body_error_exceeds_limit(&error) {
        request_body_too_large_error()
    } else if crate::ingress::body::body_error_timed_out(&error) {
        request_body_timeout_error()
    } else {
        ProviderError::deny(ReasonCode::BodyMalformed, "multipart body is invalid")
    }
}

fn multipart_error(error: MultipartError) -> ProviderError {
    if error.status() == StatusCode::PAYLOAD_TOO_LARGE || body_error_exceeds_limit(&error) {
        request_body_too_large_error()
    } else if crate::ingress::body::body_error_timed_out(&error) {
        request_body_timeout_error()
    } else {
        ProviderError::deny(ReasonCode::BodyMalformed, "multipart body is invalid")
    }
}

fn body_buffer_error(error: axum::Error) -> ProviderError {
    if body_error_exceeds_limit(&error) {
        request_body_too_large_error()
    } else if crate::ingress::body::body_error_timed_out(&error) {
        request_body_timeout_error()
    } else {
        ProviderError::deny(ReasonCode::BodyMalformed, "request body is invalid")
    }
}

fn request_body_timeout_error() -> ProviderError {
    ProviderError::deny(
        ReasonCode::BodyMalformed,
        "request body receive deadline exceeded",
    )
}

// Transport and extractor body limits can wrap one another. Preserve the 413
// contract through every layer rather than recognizing only a direct source.
pub(crate) fn body_error_exceeds_limit(error: &(dyn StdError + 'static)) -> bool {
    let mut current = Some(error);
    while let Some(error) = current {
        if error.is::<http_body_util::LengthLimitError>() {
            return true;
        }
        current = if let Some(error) = error.downcast_ref::<std::io::Error>() {
            error
                .get_ref()
                .map(|inner| inner as &(dyn StdError + 'static))
        } else {
            error.source()
        };
    }
    false
}

fn upload_idle_timeout_error(_: tokio::time::error::Elapsed) -> ProviderError {
    ProviderError::deny(
        ReasonCode::BodyMalformed,
        "multipart upload stalled before completing",
    )
}

fn request_body_too_large_error() -> ProviderError {
    ProviderError::deny(
        ReasonCode::AttachmentSizeDenied,
        "request body exceeded the broker byte cap",
    )
}

fn accepts_raw_result(headers: &HeaderMap) -> bool {
    headers
        .get_all(ACCEPT)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .any(|value| value.split(',').any(raw_accept_entry_enabled))
}

fn raw_accept_entry_enabled(entry: &str) -> bool {
    let mut parts = entry.split(';');
    let Some(media_type) = parts.next().map(str::trim) else {
        return false;
    };
    if !media_type.eq_ignore_ascii_case(RAW_RESULT_MIME) {
        return false;
    }
    for parameter in parts {
        let Some((name, value)) = parameter.trim().split_once('=') else {
            continue;
        };
        if name.trim().eq_ignore_ascii_case("q") {
            return value
                .trim()
                .parse::<f32>()
                .is_ok_and(|quality| quality > 0.0);
        }
    }
    true
}

fn action_supports_raw_result(action: Option<&agent_access_provider::ActionDescriptor>) -> bool {
    action.is_some_and(|action| {
        matches!(
            action.io,
            agent_access_provider::ActionIo::RawDownload { .. }
        )
    })
}

fn action_exports_secrets(action: Option<&agent_access_provider::ActionDescriptor>) -> bool {
    action.is_some_and(|action| !action.sensitive_output_pointers.is_empty())
}

/// Each yielded chunk can keep a whole decoded allocation alive. Its admission
/// lease must therefore outlive the body if a transport still holds that chunk.
struct AdmittedDownloadChunk {
    bytes: Bytes,
    _permits: Arc<RequestPermits>,
}

impl AsRef<[u8]> for AdmittedDownloadChunk {
    fn as_ref(&self) -> &[u8] {
        &self.bytes
    }
}

fn admitted_download_chunk(bytes: Bytes, permits: &Arc<RequestPermits>) -> Bytes {
    Bytes::from_owner(AdmittedDownloadChunk {
        bytes,
        _permits: Arc::clone(permits),
    })
}

struct BoundedMetadata {
    bytes: Vec<u8>,
    limit: usize,
    attempted: usize,
}

impl std::io::Write for BoundedMetadata {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.attempted = self.bytes.len().saturating_add(bytes.len());
        if self.attempted > self.limit {
            return Err(std::io::Error::other("download metadata limit"));
        }
        self.bytes.extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

fn bounded_metadata(value: &impl serde::Serialize, limit: usize) -> Result<Vec<u8>, usize> {
    let mut output = BoundedMetadata {
        bytes: Vec::with_capacity(limit),
        limit,
        attempted: 0,
    };
    serde_json::to_writer(&mut output, value).map_err(|_| output.attempted)?;
    Ok(output.bytes)
}

async fn raw_result_response(
    mut response: BrokerResponse<Value>,
    permits: Option<RequestPermits>,
    exports_secrets: bool,
) -> axum::response::Response {
    if response.status >= 400 {
        return json_invoke_response(response, exports_secrets);
    }
    let Some(stream) = response.stream.take() else {
        return json_invoke_response(missing_stream_envelope(response), exports_secrets);
    };
    let metadata = match bounded_metadata(&response.envelope, RAW_METADATA_JSON_LIMIT) {
        Ok(metadata) => BASE64.encode(metadata),
        Err(attempted) => {
            let lower_bound = attempted.div_ceil(3).saturating_mul(4);
            tracing::warn!(
                event = "raw_download_metadata_refused",
                category = "serialization_limit",
                agentRequestId = %response.envelope.agent_request_id,
                brokerRequestId = %response.envelope.broker_request_id,
                service = %response.envelope.service,
                action = %response.envelope.action,
                headerCap = RAW_METADATA_HEADER_LIMIT,
                encodedLengthLowerBound = lower_bound,
                "download metadata could not be delivered"
            );
            // Dropping the unused stream records cancellation after its started
            // audit. It must not be drained and reported as completed delivery.
            return json_invoke_response(
                raw_delivery_error(
                    response,
                    ReasonCode::OperationFailed,
                    "download metadata exceeded the response header limit",
                ),
                exports_secrets,
            );
        }
    };
    let metadata_header = match HeaderValue::from_str(&metadata) {
        Ok(header) => header,
        Err(_) => {
            tracing::warn!(
                event = "raw_download_metadata_refused",
                category = "invalid_header",
                agentRequestId = %response.envelope.agent_request_id,
                brokerRequestId = %response.envelope.broker_request_id,
                service = %response.envelope.service,
                action = %response.envelope.action,
                headerCap = RAW_METADATA_HEADER_LIMIT,
                encodedLength = metadata.len(),
                "download metadata could not be delivered"
            );
            return json_invoke_response(
                raw_delivery_error(
                    response,
                    ReasonCode::OperationFailed,
                    "download metadata could not be delivered",
                ),
                exports_secrets,
            );
        }
    };
    let mut headers = HeaderMap::new();
    headers.insert(
        CONTENT_TYPE,
        HeaderValue::from_str(&stream.content_type)
            .unwrap_or_else(|_| HeaderValue::from_static(RAW_RESULT_MIME)),
    );
    headers.insert(RESULT_METADATA_HEADER, metadata_header);
    if exports_secrets {
        headers.insert(CACHE_CONTROL, HeaderValue::from_static("no-store"));
    }
    let permits = permits.map(Arc::new);
    let body = match stream.source {
        ProviderResultStreamSource::Memory(bytes) => {
            let bytes = Bytes::from(bytes);
            Body::from(match permits {
                Some(permits) => admitted_download_chunk(bytes, &permits),
                None => bytes,
            })
        }
        ProviderResultStreamSource::Stream(stream) => {
            let Some(stream) = stream.lock().ok().and_then(|mut stream| stream.take()) else {
                return json_invoke_response(missing_stream_envelope(response), exports_secrets);
            };
            if let Some(permits) = permits {
                Body::from_stream(
                    stream.map(move |chunk| {
                        chunk.map(|bytes| admitted_download_chunk(bytes, &permits))
                    }),
                )
            } else {
                Body::from_stream(stream)
            }
        }
    };
    (
        StatusCode::from_u16(response.status).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR),
        headers,
        body,
    )
        .into_response()
}

fn retained_mutation_outcome(result: Option<&Value>) -> Option<Value> {
    let result = result?;
    let status = result.get("mutationStatus")?.as_str()?;
    if !matches!(
        status,
        "applied" | "applied_verified" | "applied_unverified" | "unknown" | "not_applied"
    ) {
        return None;
    }
    let mut retained = json!({"mutationStatus":status,"retrySafe":false});
    if let Some(retry) = result.get("retrySafe").and_then(Value::as_bool) {
        retained["retrySafe"] = json!(retry);
    }
    for (field, cap) in [("verificationStage", 256), ("safeLocators", 4096)] {
        if let Some(value) = result.get(field)
            && let Ok(encoded) = bounded_metadata(value, cap)
            && let Ok(value) = serde_json::from_slice(&encoded)
        {
            retained[field] = value;
        }
    }
    Some(retained)
}

fn raw_delivery_error(
    mut response: BrokerResponse<Value>,
    reason_code: ReasonCode,
    message: &'static str,
) -> BrokerResponse<Value> {
    let result = retained_mutation_outcome(response.envelope.result.as_ref());
    response.retry_after_seconds = None;
    response.status = reason_code.http_status();
    response.envelope.decision = Decision::Error;
    response.envelope.reason_code = Some(reason_code.into());
    response.envelope.reason = Some(message.into());
    response.envelope.result = result;
    response.envelope.error = Some(ErrorBody {
        message: message.into(),
    });
    response.stream = None;
    response
}

fn missing_stream_envelope(response: BrokerResponse<Value>) -> BrokerResponse<Value> {
    raw_delivery_error(
        response,
        ReasonCode::UpstreamProtocolFailed,
        "provider result stream was not available",
    )
}

#[cfg(test)]
#[path = "data/download_tests.rs"]
mod download_tests;

#[cfg(test)]
mod tests {
    use super::{action_exports_secrets, action_supports_raw_result};
    use agent_access_provider::ActionDescriptor;
    use serde_json::json;

    #[test]
    fn raw_results_and_no_store_follow_the_action_descriptor() {
        let json_action = ActionDescriptor::new("item.view", "View", json!({}));
        let download = ActionDescriptor::new("item.download", "Download", json!({})).raw_download();
        let issuing = ActionDescriptor::new("token.issue", "Issue", json!({}))
            .sensitive_output("/result/issuedToken");

        assert!(action_supports_raw_result(Some(&download)));
        assert!(!action_supports_raw_result(Some(&json_action)));
        assert!(!action_supports_raw_result(None));
        assert!(action_exports_secrets(Some(&issuing)));
        assert!(!action_exports_secrets(Some(&download)));
        assert!(!action_exports_secrets(None));
    }
}
