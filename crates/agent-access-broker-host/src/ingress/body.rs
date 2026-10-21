//! Transport admission precedes every ordinary body extractor.
use super::guards::{REQUEST_PERMIT, SOURCE_RATE_CHARGED};
use crate::handlers::common::{
    acquire_global_concurrency_guard, check_auth_source_rate_guard, emit_request_limited,
    envelope_response,
};
use crate::state::{AppState, ReloadableState};
use axum::body::{Body, HttpBody};
use axum::extract::{ConnectInfo, DefaultBodyLimit, Request, State};
use axum::http::{Method, StatusCode};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use futures_util::stream;
use http_body_util::{BodyExt, Limited, StreamBody};
use std::cell::RefCell;
use std::error::Error as StdError;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;
use tokio::time::Instant;

const AUTH_BODY_CAP: usize = 16 * 1024;
pub(crate) const JSON_BODY_CAP: usize = 1024 * 1024;
const AUTH_BODY_TIMEOUT: Duration = Duration::from_secs(5);
const CONTROL_BODY_TIMEOUT: Duration = Duration::from_secs(15);

#[derive(Debug)]
pub(crate) struct RequestBodyTimeout;

impl std::fmt::Display for RequestBodyTimeout {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("request body receive deadline exceeded")
    }
}

impl StdError for RequestBodyTimeout {}

pub(crate) fn body_error_timed_out(error: &(dyn StdError + 'static)) -> bool {
    let mut current = Some(error);
    while let Some(error) = current {
        if error.is::<RequestBodyTimeout>() {
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

pub(crate) async fn admit_public_body(
    State(state): State<Arc<ReloadableState>>,
    request: Request,
    next: Next,
) -> Response {
    // MCP has its own pre-extraction transport admission and long-lived session
    // accounting. This exemption is specific to the public listener, never Git
    // repositories whose paths happen to start with /mcp/.
    let path = request.uri().path();
    let probe = matches!(*request.method(), Method::GET | Method::HEAD)
        && matches!(path, "/v1/healthz" | "/v1/readyz");
    let static_asset = matches!(*request.method(), Method::GET | Method::HEAD)
        && request.body().is_end_stream()
        && (path == "/ui" || path.starts_with("/ui/"));
    if probe || static_asset || path == "/mcp" || path.starts_with("/mcp/") {
        return next.run(request).await;
    }
    admit_body(state, request, next, false).await
}

pub(crate) async fn admit_gateway_body(
    State(state): State<Arc<ReloadableState>>,
    request: Request,
    next: Next,
) -> Response {
    admit_body(state, request, next, true).await
}

async fn admit_body(
    state: Arc<ReloadableState>,
    mut request: Request,
    next: Next,
    gateway: bool,
) -> Response {
    let admitted_at = Instant::now();
    let snapshot = state.current();
    let remote = request
        .extensions()
        .get::<ConnectInfo<SocketAddr>>()
        .map(|info| info.0)
        .unwrap_or_else(|| SocketAddr::from(([0, 0, 0, 0], 0)));
    let mut source = snapshot
        .source_resolver
        .source_context(remote, request.headers());
    let mut ids = request
        .headers()
        .get_all(agent_access_provider::REQUEST_ID_HEADER)
        .iter();
    let supplied_id = ids
        .next()
        .and_then(|value| value.to_str().ok())
        .filter(|value| {
            !value.is_empty()
                && value.len() <= 128
                && value
                    .bytes()
                    .all(|ch| ch.is_ascii_alphanumeric() || b"._-".contains(&ch))
        })
        .filter(|_| ids.next().is_none());
    source.agent_request_id_generated = Some(supplied_id.is_none());
    let request_id = supplied_id
        .map(str::to_owned)
        .unwrap_or_else(agent_access_core::new_broker_request_id);
    crate::observability::record_agent_request_id(&request_id);
    let app = AppState {
        reloadable: state.clone(),
    };
    let permit = match acquire_global_concurrency_guard(
        &app,
        &snapshot,
        &request_id,
        "broker".into(),
        "request.admit".into(),
        &source,
    )
    .await
    {
        Ok(permit) => permit,
        Err(response) => {
            return if gateway {
                crate::handlers::gateway::gateway_runtime_response(*response)
            } else {
                envelope_response(*response).into_response()
            };
        }
    };
    let path = request.uri().path();
    let invoke = !gateway && path.starts_with("/v1/invoke/");
    // Invoke and Git handlers authenticate and authorize before consuming any
    // body. Their existing source budget applies to authentication failures.
    // Ordinary control-plane extractors consume before handler authorization.
    // Authenticate before assigning anonymous body capacity, so a slow login
    // behind a NAT cannot occupy authenticated management users' source slots.
    let has_body = !request.body().is_end_stream();
    let ordinary_body = !gateway
        && !invoke
        && (matches!(
            *request.method(),
            Method::POST | Method::PUT | Method::PATCH | Method::DELETE
        ) || has_body);
    let auth = !gateway && path.starts_with("/v1/auth/");
    let password_exchange = matches!(
        path,
        "/v1/auth/local/login" | "/v1/auth/local/password/change"
    );
    let body_identity = if ordinary_body {
        resolve_body_identity(&snapshot, request.headers()).await
    } else {
        None
    };
    let authenticated = body_identity.is_some();
    let anonymous_body =
        ordinary_body && has_body && (!authenticated || path == "/v1/auth/local/login");
    let source_budget_required = ordinary_body && (password_exchange || !authenticated);
    let body_admission = if anonymous_body {
        // Reserve at most a quarter of global capacity for anonymous extraction.
        // A configured global limit of one cannot reserve a separate slot.
        let anonymous_limit = (snapshot.runtime.limits().max_concurrent_requests / 4).max(1);
        state
            .shared_ingress
            .try_anonymous_body_concurrency(anonymous_limit)
            .and_then(|anonymous| {
                state
                    .shared_ingress
                    .try_source_concurrency(
                        &super::source::auth_source_key(&source),
                        snapshot
                            .runtime
                            .limits()
                            .max_concurrent_requests_per_principal,
                    )
                    .map(|source| vec![anonymous, source])
            })
    } else if has_body && let Some(identity) = &body_identity {
        state
            .shared_ingress
            .try_principal_body_concurrency(
                &identity.principal,
                snapshot
                    .runtime
                    .limits()
                    .max_concurrent_requests_per_principal,
            )
            .map(|permit| vec![permit])
    } else {
        Ok(Vec::new())
    };
    let body_permits = match body_admission {
        Ok(permits) => permits,
        Err(error) => {
            let broker_request_id = agent_access_core::new_broker_request_id();
            crate::observability::record_broker_request_id(&broker_request_id);
            emit_request_limited(
                &error,
                &request_id,
                &broker_request_id,
                "broker",
                "request.admit",
                Some(&source),
                body_identity.as_ref(),
            );
            let response = snapshot
                .runtime
                .admission_limit_error_response(
                    agent_access_core::OperationContext {
                        agent_request_id: request_id,
                        broker_request_id,
                        identity: body_identity
                            .unwrap_or_else(agent_access_core::IdentityContext::anonymous),
                        service: "broker".into(),
                        action: "request.admit".into(),
                        source,
                    },
                    error.into_provider_error(),
                )
                .await;
            return envelope_response(response).into_response();
        }
    };
    let route_cap = if auth {
        AUTH_BODY_CAP
    } else if gateway || invoke {
        usize::MAX
    } else {
        JSON_BODY_CAP
    };
    let cap = snapshot
        .runtime
        .max_http_body_bytes()
        .min(state.body_hard_cap)
        .min(route_cap);
    if !gateway {
        DefaultBodyLimit::max(cap).apply(&mut request);
    }
    let idle = snapshot.runtime.streaming_idle_timeout();
    let configured_total = Duration::from_millis(snapshot.runtime.limits().request_body_timeout_ms);
    let total = if auth {
        configured_total.min(AUTH_BODY_TIMEOUT)
    } else if !gateway && !invoke {
        configured_total.min(CONTROL_BODY_TIMEOUT)
    } else {
        configured_total
    };
    let deadline = admitted_at + total;
    let timed_out = Arc::new(AtomicBool::new(false));
    let body_timed_out = timed_out.clone();
    let (parts, body) = request.into_parts();
    let frames = stream::unfold(Some((body, body_permits)), move |state| {
        let timed_out = body_timed_out.clone();
        async move {
            let (mut body, mut body_permits) = state?;
            let frame_deadline = if gateway {
                deadline
            } else {
                deadline.min(Instant::now() + idle)
            };
            if Instant::now() >= deadline {
                timed_out.store(true, Ordering::Relaxed);
                return Some((Err(axum::Error::new(RequestBodyTimeout)), None));
            }
            match tokio::time::timeout_at(frame_deadline, body.frame()).await {
                Ok(Some(frame)) => {
                    if frame.is_err() || body.is_end_stream() {
                        body_permits.clear();
                    }
                    Some((frame, Some((body, body_permits))))
                }
                Ok(None) => None,
                Err(_) => {
                    timed_out.store(true, Ordering::Relaxed);
                    Some((Err(axum::Error::new(RequestBodyTimeout)), None))
                }
            }
        }
    });
    let body = Body::new(StreamBody::new(frames));
    // Matched gateway readers own byte caps and idle timing, including the
    // startup hard cap. Preserve their specific Git error reasons.
    let body = if gateway {
        body
    } else {
        Body::new(Limited::new(body, cap))
    };
    let request = Request::from_parts(parts, body);
    let retained = permit.clone();
    REQUEST_PERMIT
        .scope(
            permit,
            SOURCE_RATE_CHARGED.scope(RefCell::new(None), async move {
                if source_budget_required
                    && let Err(response) = check_auth_source_rate_guard(
                        &app,
                        &snapshot,
                        &request_id,
                        "broker".into(),
                        "request.admit".into(),
                        &source,
                    )
                    .await
                {
                    return envelope_response(*response).into_response();
                }
                let response = next.run(request).await;
                let response = if ordinary_body && timed_out.load(Ordering::Relaxed) {
                    crate::observability::record_status(StatusCode::REQUEST_TIMEOUT.as_u16());
                    (
                        StatusCode::REQUEST_TIMEOUT,
                        "request body receive deadline exceeded",
                    )
                        .into_response()
                } else {
                    response
                };
                let (parts, body) = response.into_parts();
                let frames = stream::unfold((body, retained), |(mut body, permit)| async move {
                    body.frame().await.map(|frame| (frame, (body, permit)))
                });
                Response::from_parts(parts, Body::new(StreamBody::new(frames)))
            }),
        )
        .await
}

async fn resolve_body_identity(
    snapshot: &Arc<crate::state::RuntimeSnapshot>,
    headers: &axum::http::HeaderMap,
) -> Option<agent_access_core::IdentityContext> {
    if !snapshot.runtime.has_configured_identity_header(headers) {
        match crate::handlers::auth::resolve_browser_cookie_identity_without_renewal(
            snapshot.clone(),
            headers.clone(),
        )
        .await
        {
            Ok(Some(session)) => return session.identity.authenticated.then_some(session.identity),
            Err(_) => return None,
            Ok(None) => {}
        }
    }
    crate::handlers::common::resolve_identity_without_renewal(snapshot.clone(), headers.clone())
        .await
        .ok()
        .filter(|identity| identity.authenticated)
}
