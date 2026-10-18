use crate::handlers::auth::resolve_browser_cookie_identity_blocking;
use crate::handlers::common::{
    CallerAdmission, acquire_caller_guard, acquire_global_concurrency_guard,
    admit_service_invocation, check_auth_source_rate_guard, discovery_unavailable_envelope,
    envelope_response, input_error_envelope, not_found_envelope, request_id_from_headers,
    resolve_identity_blocking,
};
use crate::observability;
use crate::state::{AppState, RequestPermits, RuntimeSnapshot};
use agent_access_core::{
    BrokerResponse, ErrorBody, ExecutionContext, GovernedIdentityFailureContext,
    GovernedOperationContext, IdentityContext, IdentitySummary, InvokeRequest, OperationContext,
    ResourceListQuery, ResponseEnvelope, SourceContext, new_broker_request_id,
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
use axum::extract::{ConnectInfo, FromRequest, Multipart, Path, RawQuery, State};
use axum::http::header::{ACCEPT, CACHE_CONTROL, CONTENT_TYPE};
use axum::http::{HeaderMap, HeaderValue, Request, StatusCode};
use axum::response::IntoResponse;
use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64;
use futures_util::StreamExt;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::error::Error as StdError;
use std::net::SocketAddr;
use std::path::Path as FsPath;
use std::time::Duration;
use tokio::io::AsyncWriteExt;

pub(crate) const RAW_RESULT_MIME: &str = "application/octet-stream";

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
    _permits: RequestPermits,
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
    match me_service_limits(&context.snapshot, &context.identity, &request_headers).await {
        Ok(service_limits) => (
            StatusCode::OK,
            Json(MeResponse {
                identity: context.identity.summary(),
                service_limits,
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
    headers: HeaderMap,
) -> impl IntoResponse {
    let request_id = match request_id_from_headers(&headers, service.clone(), String::new()) {
        Ok(request_id) => request_id,
        Err(response) => return envelope_response(*response).into_response(),
    };
    if !is_service_name(&service) {
        let response = input_error_envelope(
            request_id,
            new_broker_request_id(),
            "service name is invalid",
        );
        return envelope_response(response).into_response();
    }
    match discovery_context(
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
        Ok(context) => {
            discovery_blocking(request_id.clone(), move || {
                let _permits = context._permits;
                match context.snapshot.runtime.service_capabilities(
                    &context.identity,
                    context
                        .execution_context
                        .as_ref()
                        .expect("governed discovery resolves an execution context"),
                    &service,
                ) {
                    Some(capabilities) => (StatusCode::OK, Json(capabilities)).into_response(),
                    None => {
                        let response =
                            not_found_envelope(request_id, new_broker_request_id(), service);
                        envelope_response(response).into_response()
                    }
                }
            })
            .await
        }
        Err(response) => *response,
    }
}

/// Query parsing is deliberately deferred until after service visibility. Axum
/// typed query extractors would disclose validation details to hidden callers.
pub(crate) async fn service_resources(
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
    resources: bool,
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
        let fields = match discovery_query_fields(query.as_deref(), resources) {
            Ok(fields) => fields,
            Err(message) => return invalid(message),
        };
        let targets = match fields
            .get("targets")
            .map(|value| agent_access_core::parse_action_targets_json(value))
            .transpose()
        {
            Ok(targets) => targets,
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
        let result = if resources {
            let limit = match fields
                .get("limit")
                .map(|value| value.parse::<usize>())
                .transpose()
            {
                Ok(limit) => limit,
                Err(_) => return invalid("limit must be an integer between 1 and 100"),
            };
            discovery
                .resources(&ResourceListQuery {
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
                    targets.as_ref(),
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
    resources: bool,
) -> Result<BTreeMap<String, String>, &'static str> {
    let allowed: &[&str] = if resources {
        &["resourceType", "prefix", "limit", "cursor"]
    } else {
        &["resource", "resourceType", "prefix", "targets"]
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

async fn discovery_context(
    state: &AppState,
    remote_addr: SocketAddr,
    headers: HeaderMap,
    request_id: String,
    service: String,
    action: String,
    mode: DiscoveryMode,
) -> Result<DiscoveryContext, Box<axum::response::Response>> {
    let snapshot = state.reloadable.current();
    let source = snapshot
        .source_resolver
        .source_context(remote_addr, &headers);
    let global_permit = acquire_global_concurrency_guard(
        state,
        &snapshot,
        &request_id,
        service.clone(),
        action.clone(),
        &source,
    )
    .await
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
    let identity_result = if !snapshot.runtime.has_configured_identity_header(&headers) {
        match resolve_browser_cookie_identity_blocking(snapshot.clone(), headers.clone()).await {
            Ok(Some(cookie_identity)) => {
                if cookie_identity.password_change_required {
                    return Err(Box::new(
                        envelope_response(discovery_error_envelope(
                            request_id,
                            new_broker_request_id(),
                            service,
                            action,
                            ReasonCode::PasswordChangeRequired,
                            "password change is required before discovery",
                        ))
                        .into_response(),
                    ));
                }
                Ok(cookie_identity.identity)
            }
            Ok(None) => resolve_identity_blocking(snapshot.clone(), headers.clone()).await,
            Err(failure) => Err(failure),
        }
    } else {
        resolve_identity_blocking(snapshot.clone(), headers.clone()).await
    };
    if identity_result.is_err() {
        check_auth_source_rate_guard(
            state,
            &snapshot,
            &request_id,
            service.clone(),
            action.clone(),
            &source,
        )
        .await
        .map_err(|response| Box::new(envelope_response(*response).into_response()))?;
    }
    let identity = match identity_result {
        Ok(identity) => identity,
        Err(failure) => {
            let response = snapshot.runtime.identity_error_response(
                request_id,
                new_broker_request_id(),
                failure,
            );
            return Err(Box::new(envelope_response(response).into_response()));
        }
    };
    let principal_permit = acquire_caller_guard(
        state,
        &snapshot,
        &request_id,
        service.clone(),
        action.clone(),
        &source,
        CallerAdmission {
            identity: &identity,
        },
    )
    .await
    .map_err(|response| Box::new(envelope_response(*response).into_response()))?;
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
        return Err(Box::new(envelope_response(response).into_response()));
    }
    Ok(DiscoveryContext {
        snapshot,
        identity,
        execution_context,
        _permits: RequestPermits {
            _global: global_permit,
            _principal: principal_permit,
        },
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
    // Retain the exact attested proof resolved at intake. Temporary-reference
    // ownership must never reconstruct one from the later identity mapping.
    pub(crate) identity_proof: Option<agent_access_core::AttestedIdentityProof>,
    pub(crate) permits: RequestPermits,
}

pub(crate) async fn admit_invoke(
    state: &AppState,
    snapshot: std::sync::Arc<RuntimeSnapshot>,
    remote_addr: SocketAddr,
    headers: &HeaderMap,
    service: String,
    action: String,
) -> Result<AdmittedInvocation, Box<axum::response::Response>> {
    admit_invoke_with_identity(state, snapshot, remote_addr, headers, service, action, None).await
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
        Some(identity_pin),
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
    identity_pin: Option<&crate::mcp::IdentityPin>,
) -> Result<AdmittedInvocation, Box<axum::response::Response>> {
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

    let mut ordinary_identity_proof = None;
    let identity_result = if let Some(pin) = identity_pin {
        pin.revalidate(state.reloadable.clone(), snapshot.clone(), headers.clone())
            .await
    } else {
        let intake_snapshot = snapshot.clone();
        let intake_headers = headers.clone();
        match tokio::task::spawn_blocking(move || {
            let admission = intake_snapshot.runtime.admit_ingress(&intake_headers)?;
            intake_snapshot
                .runtime
                .resolve_admitted_identity_with_proof(&intake_headers, &admission)
        })
        .await
        .unwrap_or(Err(agent_access_core::IdentityFailure::Unavailable))
        {
            Ok(resolved) => {
                // Ordinary HTTP admission resolves once. Keep its original
                // proof for reference ownership without adopting MCP's later
                // session revalidation or updating token usage a second time.
                ordinary_identity_proof = resolved.proof;
                Ok(resolved.identity)
            }
            Err(error) => Err(error),
        }
    };
    let identity = match identity_result {
        Ok(identity) => {
            observability::record_principal(&identity.principal);
            identity
        }
        Err(failure) => {
            if let Err(response) = check_auth_source_rate_guard(
                state,
                &snapshot,
                &agent_request_id,
                service.clone(),
                action.clone(),
                &source,
            )
            .await
            {
                return Err(Box::new(envelope_response(*response).into_response()));
            }
            let response = snapshot
                .runtime
                .identity_error_response_for_operation(
                    GovernedIdentityFailureContext {
                        agent_request_id,
                        broker_request_id: new_broker_request_id(),
                        service,
                        action,
                        source,
                        execution_context,
                    },
                    failure,
                )
                .await;
            return Err(Box::new(envelope_response(response).into_response()));
        }
    };

    let principal_permit = match acquire_caller_guard(
        state,
        &snapshot,
        &agent_request_id,
        service.clone(),
        action.clone(),
        &source,
        CallerAdmission {
            identity: &identity,
        },
    )
    .await
    {
        Ok(permit) => permit,
        Err(response) => return Err(Box::new(envelope_response(*response).into_response())),
    };

    let broker_request_id = new_broker_request_id();
    observability::record_broker_request_id(&broker_request_id);
    let context = GovernedOperationContext {
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
    // Every IO form (JSON, raw download, upload) and HTTP MCP action tools
    // admit here, so each request is charged exactly once.
    let mut context = match admit_service_invocation(state, &snapshot, context).await {
        Ok(context) => context,
        Err(response) => return Err(Box::new(envelope_response(*response).into_response())),
    };
    if let Some(pin) = identity_pin {
        #[cfg(test)]
        state.reloadable.wait_mcp_admission_barrier().await;
        // This authoritative proof comparison is the final identity admission
        // point, after every queued limiter/store operation and before provider
        // credentials or execution can be reached. Never rebind a stale request.
        match pin
            .revalidate(state.reloadable.clone(), snapshot.clone(), headers.clone())
            .await
        {
            Ok(identity) => context.operation.identity = identity,
            Err(failure) => {
                let response = snapshot
                    .runtime
                    .identity_error_response_for_operation(
                        GovernedIdentityFailureContext {
                            agent_request_id: context.operation.agent_request_id,
                            broker_request_id: context.operation.broker_request_id,
                            service: context.operation.service,
                            action: context.operation.action,
                            source: context.operation.source,
                            execution_context: context.execution_context,
                        },
                        failure,
                    )
                    .await;
                return Err(Box::new(envelope_response(response).into_response()));
            }
        }
    }
    let permits = RequestPermits {
        _global: global_permit,
        _principal: principal_permit,
    };

    Ok(AdmittedInvocation {
        snapshot,
        context,
        identity_proof: identity_pin
            .and_then(|pin| pin.proof.clone())
            .or(ordinary_identity_proof),
        permits,
    })
}

pub(crate) async fn invoke_admitted_json(
    state: &AppState,
    admitted: AdmittedInvocation,
    request: InvokeRequest,
    control: agent_access_core::InvocationControl,
) -> agent_access_core::BrokerResponse<Value> {
    crate::operations::invoke(state, admitted, request, control).await
}

pub(crate) async fn invoke(
    State(state): State<AppState>,
    Path((service, action)): Path<(String, String)>,
    ConnectInfo(remote_addr): ConnectInfo<SocketAddr>,
    request: Request<Body>,
) -> impl IntoResponse {
    let headers = request.headers().clone();
    let raw_result_requested = accepts_raw_result(&headers);
    let snapshot = state.reloadable.current();
    let admitted =
        match admit_invoke(&state, snapshot, remote_addr, &headers, service, action).await {
            Ok(admitted) => admitted,
            Err(response) => return *response,
        };
    let AdmittedInvocation {
        snapshot,
        context,
        identity_proof,
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
    if raw_result_action && request_is_multipart(&headers) {
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

    let parsed = match parse_invoke_request(request, &state, &snapshot).await {
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
            snapshot
                .runtime
                .invoke_required_stream(context, request)
                .await
        }
        ParsedInvokeRequest::Json(request) => {
            let response = invoke_admitted_json(
                &state,
                AdmittedInvocation {
                    snapshot,
                    context,
                    identity_proof,
                    permits,
                },
                request,
                agent_access_core::InvocationControl::default(),
            )
            .await;
            return json_invoke_response(response, exports_secrets);
        }
        ParsedInvokeRequest::Multipart(request) => {
            invoke_multipart_after_metadata(&state, &snapshot, context, request).await
        }
    };
    if raw_result_requested {
        return raw_result_response(response, Some(permits))
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

async fn raw_result_response(
    mut response: BrokerResponse<Value>,
    permits: Option<RequestPermits>,
) -> axum::response::Response {
    if response.status >= 400 {
        return envelope_response(response).into_response();
    }
    let Some(stream) = response.stream.take() else {
        return envelope_response(missing_stream_envelope(response)).into_response();
    };
    let metadata = match serde_json::to_vec(&response.envelope) {
        Ok(metadata) => BASE64.encode(metadata),
        Err(_) => return envelope_response(missing_stream_envelope(response)).into_response(),
    };
    let mut headers = HeaderMap::new();
    headers.insert(
        CONTENT_TYPE,
        HeaderValue::from_str(&stream.content_type)
            .unwrap_or_else(|_| HeaderValue::from_static(RAW_RESULT_MIME)),
    );
    headers.insert(
        RESULT_METADATA_HEADER,
        HeaderValue::from_str(&metadata).unwrap_or_else(|_| HeaderValue::from_static("")),
    );
    let body = match stream.source {
        ProviderResultStreamSource::Memory(bytes) => Body::from(bytes),
        ProviderResultStreamSource::Stream(stream) => {
            let Some(stream) = stream.lock().ok().and_then(|mut stream| stream.take()) else {
                return envelope_response(missing_stream_envelope(response)).into_response();
            };
            if let Some(permits) = permits {
                Body::from_stream(stream.map(move |chunk| {
                    let _permits = &permits;
                    chunk
                }))
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

fn missing_stream_envelope(response: BrokerResponse<Value>) -> BrokerResponse<Value> {
    let reason_code = ReasonCode::UpstreamProtocolFailed;
    BrokerResponse {
        retry_after_seconds: None,
        status: reason_code.http_status(),
        envelope: ResponseEnvelope {
            agent_request_id: response.envelope.agent_request_id,
            broker_request_id: response.envelope.broker_request_id,
            decision: agent_access_provider::Decision::Error,
            service: response.envelope.service,
            action: response.envelope.action,
            resource_scopes: response.envelope.resource_scopes,
            reason_code: Some(reason_code.into()),
            reason: Some("provider result stream was not available".to_string()),
            result: None,
            error: Some(agent_access_core::ErrorBody {
                message: "provider result stream was not available".to_string(),
            }),
        },
        stream: None,
    }
}

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
