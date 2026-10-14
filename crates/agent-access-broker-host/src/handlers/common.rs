use crate::ingress::guards::{IngressLimitError, IngressPermit, source_log_address};
use crate::ingress::source::auth_source_key;
use crate::observability;
use crate::state::{AppState, RuntimeSnapshot};
use agent_access_core::{
    BrokerResponse, GovernedOperationContext, IdentityContext, InvocationRateLimited,
    OperationContext, ResponseEnvelope, SourceContext, new_broker_request_id,
    result_retry_after_seconds,
};
use agent_access_provider::{REQUEST_ID_HEADER, ResourceScopes};
use axum::Json;
use axum::http::header::RETRY_AFTER;
use axum::http::{HeaderMap, HeaderValue, StatusCode};
use serde_json::Value;
use std::sync::Arc;

pub(crate) async fn acquire_global_concurrency_guard(
    state: &AppState,
    snapshot: &RuntimeSnapshot,
    agent_request_id: &str,
    service: String,
    action: String,
    source: &SourceContext,
) -> Result<IngressPermit, Box<BrokerResponse<Value>>> {
    let limits = snapshot.runtime.limits();
    let permit = match state
        .reloadable
        .shared_ingress
        .try_global_concurrency(limits.max_concurrent_requests)
    {
        Ok(permit) => permit,
        Err(error) => {
            let broker_request_id = new_broker_request_id();
            observability::record_broker_request_id(&broker_request_id);
            emit_request_limited(
                &error,
                agent_request_id,
                &broker_request_id,
                &service,
                &action,
                Some(source),
                None,
            );
            let error = error.into_provider_error();
            return Err(Box::new(
                snapshot
                    .runtime
                    .admission_limit_error_response(
                        OperationContext {
                            agent_request_id: agent_request_id.to_string(),
                            broker_request_id,
                            identity: agent_access_core::IdentityContext::anonymous(),
                            service: service.clone(),
                            action: action.clone(),
                            source: source.clone(),
                        },
                        error,
                    )
                    .await,
            ));
        }
    };
    Ok(permit)
}

pub(crate) async fn check_auth_source_rate_guard(
    state: &AppState,
    snapshot: &RuntimeSnapshot,
    agent_request_id: &str,
    service: String,
    action: String,
    source: &SourceContext,
) -> Result<(), Box<BrokerResponse<Value>>> {
    let limits = snapshot.runtime.limits();
    let source_key = auth_source_key(source);
    if let Err(error) = state
        .reloadable
        .shared_ingress
        .check_auth_source_rate(&source_key, limits.auth_requests_per_source_per_minute)
    {
        let broker_request_id = new_broker_request_id();
        observability::record_broker_request_id(&broker_request_id);
        emit_request_limited(
            &error,
            agent_request_id,
            &broker_request_id,
            &service,
            &action,
            Some(source),
            None,
        );
        let error = error.into_provider_error();
        return Err(Box::new(
            snapshot
                .runtime
                .admission_limit_error_response(
                    OperationContext {
                        agent_request_id: agent_request_id.to_string(),
                        broker_request_id,
                        identity: agent_access_core::IdentityContext::anonymous(),
                        service,
                        action,
                        source: source.clone(),
                    },
                    error,
                )
                .await,
        ));
    }
    Ok(())
}

/// A resolved caller. Authenticated callers are subject only to concurrency
/// here; service invocations are additionally charged by
/// [`admit_service_invocation`]. Anonymous and unauthenticated callers also
/// spend the authentication budgets.
pub(crate) struct CallerAdmission<'a> {
    pub(crate) identity: &'a IdentityContext,
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
    let CallerAdmission { identity } = caller;
    let limits = snapshot.runtime.limits();
    let principal_permit = match state.reloadable.shared_ingress.try_principal_concurrency(
        &identity.principal,
        limits.max_concurrent_requests_per_principal,
    ) {
        Ok(permit) => permit,
        Err(error) => {
            let broker_request_id = new_broker_request_id();
            observability::record_broker_request_id(&broker_request_id);
            emit_request_limited(
                &error,
                agent_request_id,
                &broker_request_id,
                &service,
                &action,
                None,
                Some(identity),
            );
            let error = error.into_provider_error();
            return Err(Box::new(
                snapshot
                    .runtime
                    .admission_limit_error_response(
                        OperationContext {
                            agent_request_id: agent_request_id.to_string(),
                            broker_request_id,
                            identity: identity.clone(),
                            service: service.clone(),
                            action: action.clone(),
                            source: source.clone(),
                        },
                        error,
                    )
                    .await,
            ));
        }
    };
    if identity.authenticated {
        return Ok(principal_permit);
    }
    let guards = &state.reloadable.shared_ingress;
    let source_key = auth_source_key(source);
    let rate_result = guards
        .check_auth_source_rate(&source_key, limits.auth_requests_per_source_per_minute)
        .and_then(|()| {
            guards.check_auth_principal_rate(
                &identity.principal,
                limits.auth_requests_per_principal_per_minute,
            )
        });
    if let Err(error) = rate_result {
        let broker_request_id = new_broker_request_id();
        observability::record_broker_request_id(&broker_request_id);
        emit_request_limited(
            &error,
            agent_request_id,
            &broker_request_id,
            &service,
            &action,
            Some(source),
            Some(identity),
        );
        let error = error.into_provider_error();
        return Err(Box::new(
            snapshot
                .runtime
                .admission_limit_error_response(
                    OperationContext {
                        agent_request_id: agent_request_id.to_string(),
                        broker_request_id,
                        identity: identity.clone(),
                        service,
                        action,
                        source: source.clone(),
                    },
                    error,
                )
                .await,
        ));
    }
    Ok(principal_permit)
}

/// Charges one service invocation to the caller's `(principal, service)`
/// window. Call once per service-invoking request, after identity resolution
/// and caller admission and before policy evaluation, credential selection,
/// pre-policy lookups, or any upstream call. Unknown services are left to
/// existing validation and never create limiter state.
///
/// On rejection the request is finalized (audited) as `rate_limited` with the
/// structured retry guidance and returned as the error response.
pub(crate) async fn admit_service_invocation(
    state: &AppState,
    snapshot: &RuntimeSnapshot,
    context: GovernedOperationContext,
) -> Result<GovernedOperationContext, Box<BrokerResponse<Value>>> {
    let operation = &context.operation;
    if snapshot
        .runtime
        .service_descriptor(&operation.service)
        .is_none()
    {
        return Ok(context);
    }
    let limit = match snapshot
        .runtime
        .effective_invocation_limit(&operation.identity.principal, &operation.service)
        .await
    {
        Ok(limit) => limit.limit(),
        Err(error) => {
            return Err(Box::new(
                snapshot
                    .runtime
                    .governed_operation_error_response(context, error)
                    .await,
            ));
        }
    };
    match state.reloadable.shared_invocations.try_admit(
        &operation.identity.principal,
        &operation.service,
        limit,
    ) {
        Ok(()) => Ok(context),
        Err(rejection) => {
            emit_invocation_limited(operation, &rejection);
            Err(Box::new(
                snapshot
                    .runtime
                    .governed_admission_limit_error_response(
                        context,
                        rejection.into_provider_error(),
                    )
                    .await,
            ))
        }
    }
}

fn emit_invocation_limited(operation: &OperationContext, rejection: &InvocationRateLimited) {
    let reason_code = agent_access_provider::ReasonCode::RateLimited;
    let decision = agent_access_provider::Decision::Error;
    observability::record_decision(decision.as_str());
    observability::record_reason_code(reason_code.as_str());
    observability::record_status(reason_code.http_status());
    tracing::warn!(
        event = "request_limited",
        agentRequestId = operation.agent_request_id.as_str(),
        brokerRequestId = operation.broker_request_id.as_str(),
        service = operation.service.as_str(),
        action = operation.action.as_str(),
        limitKind = "invocation_rate",
        limitScope = agent_access_core::INVOCATION_LIMIT_SCOPE_PRINCIPAL,
        limit = rejection.limit.requests(),
        windowSeconds = rejection.limit.window_seconds(),
        retryAfterSeconds = rejection.retry_after_seconds,
        source = source_log_address(&operation.source).as_str(),
        principal = operation.identity.principal.as_str(),
        tokenId = identity_token_id(&operation.identity).unwrap_or(""),
        decision = decision.as_str(),
        reasonCode = reason_code.as_str(),
        "http.statusCode" = reason_code.http_status(),
    );
}

/// The broker token ID of the caller's credential, when one was used.
fn identity_token_id(identity: &IdentityContext) -> Option<&str> {
    identity
        .source
        .as_ref()
        .and_then(|source| source.token_id.as_deref())
}

/// `Retry-After` for any broker error response whose `result` carries
/// `retryAfterSeconds`, independent of the reason code.
pub(crate) fn retry_after_header(status: u16, result: Option<&Value>) -> Option<HeaderValue> {
    if status < 400 {
        return None;
    }
    result_retry_after_seconds(result).map(HeaderValue::from)
}

/// Reserved admission envelopes omit result data, but retain their bounded
/// retry guidance as transport metadata.
pub(crate) fn response_retry_after_header(response: &BrokerResponse<Value>) -> Option<HeaderValue> {
    if response.status < 400 {
        return None;
    }
    response
        .retry_after_seconds
        .map(HeaderValue::from)
        .or_else(|| retry_after_header(response.status, response.envelope.result.as_ref()))
}

pub(crate) async fn resolve_identity_blocking(
    snapshot: Arc<RuntimeSnapshot>,
    headers: HeaderMap,
) -> Result<agent_access_core::IdentityContext, agent_access_core::IdentityFailure> {
    // Keep identity resolution in the request's span for log correlation.
    let span = tracing::Span::current();
    tokio::task::spawn_blocking(move || {
        span.in_scope(|| snapshot.runtime.resolve_identity(&headers))
    })
    .await
    .unwrap_or(Err(agent_access_core::IdentityFailure::Invalid))
}

pub(crate) fn request_id_from_headers(
    headers: &HeaderMap,
    service: String,
    action: String,
) -> Result<String, Box<BrokerResponse<Value>>> {
    observability::record_service_action(&service, &action);
    let Some(raw) = headers
        .get(REQUEST_ID_HEADER)
        .and_then(|value| value.to_str().ok())
    else {
        let broker_request_id = new_broker_request_id();
        observability::record_broker_request_id(&broker_request_id);
        observability::record_decision(agent_access_provider::Decision::Deny.as_str());
        observability::record_reason_code(
            agent_access_provider::ReasonCode::RequestIdMissing.as_str(),
        );
        observability::record_status(
            agent_access_provider::ReasonCode::RequestIdMissing.http_status(),
        );
        return Err(Box::new(request_id_error_envelope(
            broker_request_id,
            service,
            action,
            agent_access_provider::ReasonCode::RequestIdMissing,
            "request id is required",
        )));
    };
    let value = raw;
    if value.is_empty()
        || value.len() > 128
        || !value
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || ch == '.' || ch == '_' || ch == '-')
    {
        let broker_request_id = new_broker_request_id();
        observability::record_broker_request_id(&broker_request_id);
        observability::record_decision(agent_access_provider::Decision::Deny.as_str());
        observability::record_reason_code(
            agent_access_provider::ReasonCode::RequestIdInvalid.as_str(),
        );
        observability::record_status(
            agent_access_provider::ReasonCode::RequestIdInvalid.http_status(),
        );
        return Err(Box::new(request_id_error_envelope(
            broker_request_id,
            service,
            action,
            agent_access_provider::ReasonCode::RequestIdInvalid,
            "request id is invalid",
        )));
    }
    observability::record_agent_request_id(value);
    Ok(value.to_string())
}

pub(crate) fn envelope_response(
    response: BrokerResponse<Value>,
) -> (StatusCode, HeaderMap, Json<ResponseEnvelope<Value>>) {
    observability::record_request_ids(
        &response.envelope.agent_request_id,
        &response.envelope.broker_request_id,
    );
    observability::record_service_action(&response.envelope.service, &response.envelope.action);
    observability::record_decision(response.envelope.decision.as_str());
    if let Some(reason_code) = &response.envelope.reason_code {
        observability::record_reason_code(reason_code.as_str());
    }
    observability::record_status(response.status);
    let mut headers = HeaderMap::new();
    if let Some(retry_after) = response_retry_after_header(&response) {
        headers.insert(RETRY_AFTER, retry_after);
    }
    (
        StatusCode::from_u16(response.status).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR),
        headers,
        Json(response.envelope),
    )
}

pub(crate) fn emit_request_limited(
    error: &IngressLimitError,
    agent_request_id: &str,
    broker_request_id: &str,
    service: &str,
    action: &str,
    source: Option<&SourceContext>,
    identity: Option<&IdentityContext>,
) {
    let provider_error = error.provider_error();
    let reason_code = provider_error.reason_code().as_str();
    observability::record_service_action(service, action);
    let principal = identity.map(|identity| identity.principal.as_str());
    if let Some(principal) = principal {
        observability::record_principal(principal);
    }
    observability::record_decision(provider_error.decision().as_str());
    observability::record_reason_code(reason_code);
    observability::record_status(provider_error.reason_code().http_status());
    let source_key = source.map(source_log_address);
    tracing::warn!(
        event = "request_limited",
        agentRequestId = agent_request_id,
        brokerRequestId = broker_request_id,
        service = service,
        action = action,
        limitKind = error.kind().as_str(),
        limit = error.limit(),
        source = source_key.as_deref().unwrap_or(""),
        principal = principal.unwrap_or(""),
        tokenId = identity.and_then(identity_token_id).unwrap_or(""),
        decision = provider_error.decision().as_str(),
        reasonCode = reason_code,
        "http.statusCode" = provider_error.reason_code().http_status(),
    );
}

fn request_id_error_envelope(
    broker_request_id: String,
    service: String,
    action: String,
    reason_code: agent_access_provider::ReasonCode,
    message: &str,
) -> BrokerResponse<Value> {
    BrokerResponse {
        retry_after_seconds: None,
        status: reason_code.http_status(),
        envelope: ResponseEnvelope {
            agent_request_id: String::new(),
            broker_request_id,
            decision: agent_access_provider::Decision::Deny,
            service,
            action,
            resource_scopes: ResourceScopes::new(),
            reason_code: Some(reason_code.into()),
            reason: Some(message.to_string()),
            result: None,
            error: Some(agent_access_core::ErrorBody {
                message: message.to_string(),
            }),
        },
        stream: None,
    }
}

pub(crate) fn input_error_envelope(
    agent_request_id: String,
    broker_request_id: String,
    message: &str,
) -> BrokerResponse<Value> {
    let reason_code = agent_access_provider::ReasonCode::InputInvalid;
    BrokerResponse {
        retry_after_seconds: None,
        status: reason_code.http_status(),
        envelope: ResponseEnvelope {
            agent_request_id,
            broker_request_id,
            decision: agent_access_provider::Decision::Deny,
            service: String::new(),
            action: String::new(),
            resource_scopes: ResourceScopes::new(),
            reason_code: Some(reason_code.into()),
            reason: Some(message.to_string()),
            result: None,
            error: Some(agent_access_core::ErrorBody {
                message: message.to_string(),
            }),
        },
        stream: None,
    }
}

pub(crate) fn discovery_unavailable_envelope(agent_request_id: String) -> BrokerResponse<Value> {
    let message = "local discovery could not complete".to_owned();
    BrokerResponse {
        retry_after_seconds: None,
        status: 503,
        envelope: ResponseEnvelope {
            agent_request_id,
            broker_request_id: new_broker_request_id(),
            decision: agent_access_provider::Decision::Error,
            service: String::new(),
            action: String::new(),
            resource_scopes: ResourceScopes::new(),
            reason_code: None,
            reason: Some(message.clone()),
            result: None,
            error: Some(agent_access_core::ErrorBody { message }),
        },
        stream: None,
    }
}

pub(crate) fn not_found_envelope(
    agent_request_id: String,
    broker_request_id: String,
    service: String,
) -> BrokerResponse<Value> {
    let reason_code = agent_access_provider::ReasonCode::ServiceActionDenied;
    BrokerResponse {
        retry_after_seconds: None,
        status: reason_code.http_status(),
        envelope: ResponseEnvelope {
            agent_request_id,
            broker_request_id,
            decision: agent_access_provider::Decision::Deny,
            service,
            action: String::new(),
            resource_scopes: ResourceScopes::new(),
            reason_code: Some(reason_code.into()),
            reason: Some("service is not visible for this identity".to_string()),
            result: None,
            error: Some(agent_access_core::ErrorBody {
                message: "service is not visible for this identity".to_string(),
            }),
        },
        stream: None,
    }
}
