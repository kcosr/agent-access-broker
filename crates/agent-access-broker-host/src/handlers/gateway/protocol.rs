use super::*;
use agent_access_provider::{
    GatewayBody, GatewayBodyError, GatewayBodyFrame, GatewayForwardPlan, GatewayHookPhase,
    GatewayReplayProfile, GatewayResponseProfile, GatewayStatusMatch,
};
use futures_util::StreamExt;
use std::collections::BTreeSet;

const ROUTE_NOT_FOUND_MESSAGE: &str = "gateway route was not found";

pub(super) fn configured_identity_header(runtime: &BrokerRuntime, name: &str) -> bool {
    runtime
        .config()
        .identity
        .sources
        .iter()
        .any(|source| source.header.eq_ignore_ascii_case(name))
}

pub(super) fn contract_failure() -> ProviderError {
    ProviderError::error(
        ReasonCode::BrokerProviderContractFailed,
        "gateway module violated its host contract",
    )
}

pub(super) fn checked_failure(
    registration: &agent_access_provider::GatewayRegistration,
    phase: GatewayHookPhase,
    error: ProviderError,
) -> ProviderError {
    match registration.check_failure(phase, &error) {
        Ok(()) => error,
        Err(_) => contract_failure(),
    }
}

fn connection_nominated_headers(headers: &HeaderMap) -> BTreeSet<String> {
    headers
        .get_all(axum::http::header::CONNECTION)
        .iter()
        .flat_map(|value| value.as_bytes().split(|byte| *byte == b','))
        .filter_map(|name| axum::http::HeaderName::from_bytes(name.trim_ascii()).ok())
        .map(|name| name.as_str().to_owned())
        .collect()
}

/// Identity carriers never cross the protocol-module request-head boundary.
pub(super) fn protocol_headers(headers: &HeaderMap) -> HeaderMap {
    let nominated = connection_nominated_headers(headers);
    headers
        .iter()
        .filter(|(name, _)| {
            !reserved_request_header(name.as_str()) && !nominated.contains(name.as_str())
        })
        .map(|(name, value)| (name.clone(), value.clone()))
        .collect()
}

/// Imported execution headers are host-owned credential carriers even before
/// policy selects a mode. Neither caller values nor module replacements cross
/// the credential boundary.
pub(super) fn imported_credential_header(
    runtime: &BrokerRuntime,
    service: &str,
    name: &str,
) -> bool {
    runtime
        .imported_catalog()
        .service(service)
        .is_some_and(|record| {
            record.definition.execution_bindings.iter().any(|binding| matches!(
            &binding.delivery,
            agent_access_core::imports::ImportedCredentialDelivery::RawHeader { name: reserved }
                if reserved.eq_ignore_ascii_case(name)
        ))
        })
}

fn classified_head_audit(
    registration: &agent_access_provider::GatewayRegistration,
    audit: Option<&serde_json::Value>,
) -> Result<Option<serde_json::Value>, ProviderError> {
    let Some(audit) = audit else { return Ok(None) };
    let facts = audit.as_object().ok_or_else(contract_failure)?;
    if serde_json::to_vec(audit).map_or(true, |bytes| bytes.len() > 16 * 1024)
        || (registration.audit_key() == "gateway"
            && facts.keys().any(|key| {
                matches!(
                    key.as_str(),
                    "phase"
                        | "message"
                        | "credentialMethod"
                        | "durationMs"
                        | "upstreamStatus"
                        | "transferOutcome"
                        | "kind"
                        | "method"
                        | "upstreamOrigin"
                        | "upstreamPath"
                        | "egressProxy"
                        | "requestBytes"
                        | "responseBytes"
                )
            }))
    {
        return Err(contract_failure());
    }
    Ok(Some(json!({registration.audit_key(): audit})))
}

fn identity_header(name: &str) -> bool {
    name.starts_with("x-aw-")
        || name.starts_with("x-agent-access-")
        || matches!(
            name,
            "x-request-id" | "x-broker-request-id" | "x-reason-code"
        )
}

pub(super) fn reserved_request_header(name: &str) -> bool {
    identity_header(name)
        || name.starts_with("x-forwarded-")
        || name.starts_with("proxy-")
        || matches!(
            name,
            "authorization"
                | "host"
                | "cookie"
                | "set-cookie"
                | "connection"
                | "keep-alive"
                | "transfer-encoding"
                | "te"
                | "upgrade"
                | "forwarded"
                | "x-forwarded-for"
                | "x-forwarded-host"
                | "x-forwarded-proto"
                | "x-real-ip"
                | "true-client-ip"
                | "cf-connecting-ip"
                | "x-client-ip"
                | "via"
        )
}

fn reserved_response_header(name: &str) -> bool {
    reserved_request_header(name)
        || matches!(
            name,
            "www-authenticate" | "trailer" | "location" | "content-location"
        )
}

pub(super) fn classify_gateway_request(
    runtime: &BrokerRuntime,
    matched: &MatchedGateway,
    method: &Method,
    uri: &Uri,
    headers: &HeaderMap,
) -> Result<ClassifiedGatewayRequest, ProviderError> {
    let managed = runtime
        .config()
        .imports
        .gateway_bindings
        .contains_key(&matched.service);
    let unavailable = || {
        ProviderError::deny(
            ReasonCode::GatewayRuleNotFound,
            if managed {
                ROUTE_NOT_FOUND_MESSAGE
            } else {
                "gateway route is unavailable"
            },
        )
    };
    let registration = runtime
        .gateway_registration(&matched.service)
        .ok_or_else(unavailable)?;
    let protocol = runtime
        .gateway_protocol(&matched.service)
        .ok_or_else(unavailable)?;
    let mut headers = protocol_headers(headers);
    let reserved: Vec<_> = headers
        .keys()
        .filter(|name| {
            configured_identity_header(runtime, name.as_str())
                || imported_credential_header(runtime, &matched.service, name.as_str())
        })
        .cloned()
        .collect();
    for name in reserved {
        headers.remove(name);
    }
    let classified = protocol
        .classify(agent_access_provider::host::gateway_request_head(
            method,
            uri.path_and_query().map_or("/", |target| target.as_str()),
            &headers,
        ))
        .map_err(|error| {
            let error = checked_failure(registration, GatewayHookPhase::Classification, error);
            if managed && error.reason_code() == ReasonCode::GatewayRuleNotFound {
                ProviderError::deny(ReasonCode::GatewayRuleNotFound, ROUTE_NOT_FOUND_MESSAGE)
            } else {
                error
            }
        })?;
    let descriptor = runtime
        .service_descriptor(&matched.service)
        .ok_or_else(contract_failure)?;
    let action = descriptor
        .action(classified.action())
        .ok_or_else(contract_failure)?;
    match &action.resource_scope {
        None if !classified.scopes().is_empty() => return Err(contract_failure()),
        Some(scope)
            if classified.scopes().len() != 1
                || classified
                    .scopes()
                    .get(scope)
                    .is_none_or(|values| values.is_empty()) =>
        {
            return Err(contract_failure());
        }
        _ => {}
    }
    if classified
        .scopes()
        .values()
        .flatten()
        .any(|value| value.is_empty() || value.len() > 8192)
    {
        return Err(contract_failure());
    }
    let counted = registration
        .counted(classified.request_kind())
        .ok_or_else(contract_failure)?;
    let head_audit = classified_head_audit(registration, classified.head_audit())?;
    Ok(ClassifiedGatewayRequest {
        service: matched.service.clone(),
        action: classified.action().to_owned(),
        counted,
        method: method.clone(),
        resource_scopes: classified.scopes().clone(),
        request: classified.into_request(),
        registration,
        head_audit,
    })
}

/// The input stream enforces the original body deadline and total wire-byte cap.
/// SDK inspection retains frames; those frames are forwarded without reading or
/// charging the input a second time.
pub(super) fn protocol_body(body: Body, limits: &GatewayForwardLimits) -> GatewayBody {
    let deadline = crate::ingress::request_lifetime::RequestLifetime::current()
        .deadline()
        .map(|value| value.at);
    let max_bytes = limits.request_body_max_bytes;
    let stream = stream::unfold(
        (body, 0usize, false),
        move |(mut body, mut total, done)| async move {
            if done {
                return None;
            }
            let frame = match deadline {
                Some(at) => match tokio::time::timeout_at(at, body.frame()).await {
                    Ok(frame) => frame,
                    Err(_) => return Some((Err(GatewayBodyError::Timeout), (body, total, true))),
                },
                None => body.frame().await,
            };
            let frame = match frame {
                None => return None,
                Some(Err(error)) => {
                    let failure = if body_error_exceeds_limit(&error) {
                        GatewayBodyError::TooLarge
                    } else if body_error_timed_out(&error) {
                        GatewayBodyError::Timeout
                    } else {
                        GatewayBodyError::Read
                    };
                    return Some((Err(failure), (body, total, true)));
                }
                Some(Ok(frame)) => frame,
            };
            let frame = match frame.into_data() {
                Ok(bytes) => {
                    total = total.saturating_add(bytes.len());
                    if total > max_bytes {
                        return Some((Err(GatewayBodyError::TooLarge), (body, total, true)));
                    }
                    GatewayBodyFrame::Data(bytes)
                }
                Err(_) => GatewayBodyFrame::Trailers,
            };
            Some((Ok(frame), (body, total, false)))
        },
    );
    agent_access_provider::host::gateway_body(Box::pin(stream), max_bytes, limits.idle_timeout)
}

pub(super) fn validate_forward_plan(
    gateway: &GatewayConfig,
    original_method: &Method,
    plan: &GatewayForwardPlan,
) -> Result<Url, ProviderError> {
    if agent_access_provider::host::gateway_body_failure(&plan.body).is_some()
        || plan.method != *original_method
        || plan.headers.len() > 128
        || plan
            .headers
            .values()
            .map(|value| value.as_bytes().len())
            .sum::<usize>()
            > 64 * 1024
        || plan.headers.keys().any(|name| {
            reserved_request_header(name.as_str()) || name == TRAILER || name == CONTENT_LENGTH
        })
        || plan.audit.as_ref().is_some_and(|value| {
            serde_json::to_vec(value).map_or(true, |bytes| bytes.len() > 16 * 1024)
        })
        || plan.audit_target.as_ref().is_some_and(|target| {
            target.len() > 8192
                || !target.starts_with('/')
                || target.contains(['?', '#'])
                || target.chars().any(char::is_control)
        })
    {
        return Err(contract_failure());
    }
    validate_response_profile(&plan.response)?;
    if plan.replay == GatewayReplayProfile::BodylessCredentialRecovery
        && !agent_access_provider::host::gateway_body_is_empty_complete(&plan.body)
    {
        return Err(contract_failure());
    }
    gateway_relative_url(gateway, &plan.relative_target)
}

pub(super) fn gateway_relative_url(
    gateway: &GatewayConfig,
    target: &str,
) -> Result<Url, ProviderError> {
    gateway.upstream_url(target)
}

fn validate_response_profile(profile: &GatewayResponseProfile) -> Result<(), ProviderError> {
    if profile.headers.len() > 128 || profile.status_headers.len() > 600 {
        return Err(contract_failure());
    }
    for name in profile.headers.iter().chain(
        profile
            .status_headers
            .iter()
            .flat_map(|entry| &entry.headers),
    ) {
        let name = axum::http::header::HeaderName::from_bytes(name.as_bytes())
            .map_err(|_| contract_failure())?;
        if reserved_response_header(name.as_str()) {
            return Err(contract_failure());
        }
    }
    for entry in &profile.status_headers {
        if entry.headers.len() > 128
            || !match entry.status {
                GatewayStatusMatch::Exact(status) => (100..600).contains(&status),
                GatewayStatusMatch::Class(class) => (1..6).contains(&class),
                GatewayStatusMatch::Default => true,
                _ => false,
            }
        {
            return Err(contract_failure());
        }
    }
    Ok(())
}

pub(super) fn selected_response_headers(
    registration: &agent_access_provider::GatewayRegistration,
    profile: &GatewayResponseProfile,
    status: u16,
    headers: &HeaderMap,
) -> Result<HeaderMap, ProviderError> {
    let nominated = connection_nominated_headers(headers);
    let exact = profile
        .status_headers
        .iter()
        .find(|entry| entry.status == GatewayStatusMatch::Exact(status));
    let selected = exact
        .or_else(|| {
            profile
                .status_headers
                .iter()
                .find(|entry| entry.status == GatewayStatusMatch::Class(status / 100))
        })
        .or_else(|| {
            profile
                .status_headers
                .iter()
                .find(|entry| entry.status == GatewayStatusMatch::Default)
        });
    let allowed: BTreeSet<_> = profile
        .headers
        .iter()
        .chain(selected.into_iter().flat_map(|entry| &entry.headers))
        .map(|name| name.to_ascii_lowercase())
        .collect();
    let mut result = match &profile.validator {
        Some(validator) => validator
            .validate(status, headers)
            .map_err(|error| checked_failure(registration, GatewayHookPhase::Response, error))?,
        None => {
            if allowed.iter().any(|name| {
                !nominated.contains(name.as_str()) && headers.get_all(name).iter().count() > 1
            }) {
                return Err(ProviderError::error(
                    ReasonCode::UpstreamProtocolFailed,
                    "upstream returned ambiguous gateway response headers",
                ));
            }
            headers
                .iter()
                .filter(|(name, _)| allowed.contains(name.as_str()))
                .map(|(name, value)| (name.clone(), value.clone()))
                .collect()
        }
    };
    if result.keys().any(|name| {
        !allowed.contains(name.as_str()) || reserved_response_header(name.as_str()) || {
            // Validators may omit upstream values, but cannot invent,
            // duplicate or reorder them (Git selects the first Content-Type).
            let mut upstream = headers.get_all(name).iter();
            !result
                .get_all(name)
                .iter()
                .all(|selected| upstream.any(|value| value == selected))
        }
    }) {
        return Err(contract_failure());
    }
    if profile.bounded_retry_after {
        result.remove(axum::http::header::RETRY_AFTER);
        if status == 429
            && let Some(wait) = agent_access_provider::UpstreamRetryAfter::from_headers(headers)
        {
            result.insert(
                axum::http::header::RETRY_AFTER,
                HeaderValue::from(wait.seconds()),
            );
        }
    }
    // Validate module-selected values before removing hop-by-hop nominations,
    // so nominations cannot conceal a reserved or invented module output.
    for name in nominated {
        result.remove(name.as_str());
    }
    // Framing comes from the transport's upstream headers and policy, never
    // from a module's selection or validator result.
    result.remove(CONTENT_LENGTH);
    Ok(result)
}

pub(super) fn prepare_protocol_request_body(
    body: GatewayBody,
    discard_trailers: bool,
    limits: &GatewayForwardLimits,
    permits: Option<RequestPermits>,
) -> GatewayPreparedRequestBody {
    if agent_access_provider::host::gateway_body_is_empty_complete(&body) {
        return GatewayPreparedRequestBody::Bytes(Vec::new());
    }
    let failure = Arc::new(AtomicU8::new(REPLAY_FAILURE_NONE));
    let progress = Arc::new(GatewayRequestUploadProgress::new());
    let stream = agent_access_provider::host::gateway_body_stream(body).filter_map(
        move |frame| async move {
            if discard_trailers && matches!(frame, Ok(GatewayBodyFrame::Trailers)) {
                None
            } else {
                Some(frame)
            }
        },
    );
    let stream = Box::pin(stream);
    let state = (
        stream,
        failure.clone(),
        progress.clone(),
        limits.idle_timeout,
        0usize,
        limits.request_body_max_bytes,
        false,
        GatewayUploadOwner {
            progress: progress.clone(),
            _permits: permits,
        },
    );
    let body = reqwest::Body::wrap_stream(stream::unfold(
        state,
        |(mut stream, failure, progress, idle, mut sent, cap, done, mut owner)| async move {
            if done {
                return None;
            }
            let next = match timeout(idle, stream.next()).await {
                Ok(next) => next,
                Err(_) => Some(Err(GatewayBodyError::IdleTimeout)),
            };
            let bytes = match next {
                None => {
                    progress.mark_complete();
                    return None;
                }
                Some(Ok(GatewayBodyFrame::Data(bytes))) => {
                    let next_sent = sent.saturating_add(bytes.len());
                    if next_sent > cap {
                        Err(GatewayBodyError::TooLarge)
                    } else {
                        sent = next_sent;
                        Ok(bytes)
                    }
                }
                Some(Err(error)) => Err(error),
                Some(Ok(_)) => Err(GatewayBodyError::Read),
            };
            let done = bytes.is_err();
            progress.bytes.store(sent as u64, Ordering::Relaxed);
            if done {
                owner._permits.take();
            }
            let bytes = bytes.map_err(|error| {
                progress.finish_audit(Some(match error {
                    GatewayBodyError::TooLarge => ReasonCode::GatewayRequestCapExceeded,
                    GatewayBodyError::Timeout | GatewayBodyError::IdleTimeout => {
                        ReasonCode::UpstreamTimeout
                    }
                    _ => ReasonCode::GatewayRequestBodyDenied,
                }));
                failure.store(
                    match error {
                        GatewayBodyError::TooLarge => REPLAY_FAILURE_CAP_EXCEEDED,
                        GatewayBodyError::Timeout | GatewayBodyError::IdleTimeout => {
                            REPLAY_FAILURE_TIMEOUT
                        }
                        _ => REPLAY_FAILURE_BODY_READ,
                    },
                    Ordering::Relaxed,
                );
                io::Error::other(error)
            });
            progress.bytes.store(sent as u64, Ordering::Relaxed);
            progress.mark_progress();
            Some((
                bytes,
                (stream, failure, progress, idle, sent, cap, done, owner),
            ))
        },
    ));
    GatewayPreparedRequestBody::Stream {
        body,
        failure,
        progress,
    }
}
