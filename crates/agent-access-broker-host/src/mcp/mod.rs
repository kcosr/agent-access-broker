//! Downstream Streamable HTTP MCP. The SDK owns protocol routing; the Broker
//! owns identity, admission, provider execution and all resource authorization.
mod handler;
mod output;
mod sessions;

use crate::{
    handlers::common,
    ingress::guards::{IngressGuards, IngressPermit},
    state::{AppState, ReloadableState, RuntimeSnapshot},
};
use agent_access_core::{
    AttestedIdentityProof, BrokerTokenClass, ExecutionContext, IdentityContext, IdentityFailure,
    IngressAdmission, InvocationControl, mcp::McpView,
};
use axum::{
    Extension,
    body::Body,
    extract::{ConnectInfo, MatchedPath, OriginalUri, State},
    http::{HeaderMap, HeaderValue, Method, Request, StatusCode},
    response::{IntoResponse, Response},
};
use hmac::{Hmac, Mac};
use http_body_util::BodyExt;
use rand::RngCore;
use rmcp::transport::streamable_http_server::{
    StreamableHttpServerConfig, StreamableHttpService,
    session::{SessionId, SessionManager},
};
use serde_json::Value;
use sha2::Sha256;
use std::{
    collections::HashMap,
    net::SocketAddr,
    sync::{
        Arc, Mutex, Weak,
        atomic::{AtomicU8, Ordering},
    },
    time::{Duration, Instant},
};
use tower::ServiceExt;

#[derive(Clone)]
pub(crate) struct Endpoint(Arc<EndpointState>);

/// Constructed by the public router before ordinary principal authentication.
#[derive(Clone)]
pub(crate) struct McpIngress {
    pub(crate) snapshot: Arc<RuntimeSnapshot>,
    pub(crate) admission: IngressAdmission,
}

/// Private authority captured before body intake. It is never serialized or
/// reconstructed from the raw caller credential at later dispatch sites.
#[derive(Clone)]
pub(crate) struct IdentityPin {
    pub(crate) admission: IngressAdmission,
    pub(crate) proof: Option<AttestedIdentityProof>,
    pub(crate) caller_security_epoch: Option<u64>,
}
impl IdentityPin {
    fn revalidate_sync(
        &self,
        state: &ReloadableState,
        snapshot: &RuntimeSnapshot,
        headers: &HeaderMap,
    ) -> Result<IdentityContext, IdentityFailure> {
        let resolve = |current: &RuntimeSnapshot| {
            if let Some(proof) = &self.proof {
                current
                    .runtime
                    .revalidate_admitted_identity(proof, &self.admission)
            } else {
                snapshot
                    .runtime
                    .resolve_admitted_identity(headers, &self.admission)
            }
        };
        if let Some(epoch) = self.caller_security_epoch {
            let stale = if self.admission.is_username() {
                IdentityFailure::AssertionDenied
            } else {
                IdentityFailure::Invalid
            };
            state.with_caller_security(epoch, stale, resolve)
        } else {
            resolve(snapshot)
        }
    }

    pub(crate) async fn revalidate(
        &self,
        state: Arc<ReloadableState>,
        snapshot: Arc<RuntimeSnapshot>,
        headers: HeaderMap,
    ) -> Result<IdentityContext, IdentityFailure> {
        let pin = self.clone();
        tokio::task::spawn_blocking(move || pin.revalidate_sync(&state, &snapshot, &headers))
            .await
            .unwrap_or(Err(IdentityFailure::Unavailable))
    }
}

pub(crate) fn is_mcp_route(request: &Request<Body>) -> bool {
    request
        .extensions()
        .get::<MatchedPath>()
        .is_some_and(|path| matches!(path.as_str(), "/mcp" | "/mcp/{service}"))
}
struct EndpointState {
    state: Arc<ReloadableState>,
    sessions: Arc<sessions::Sessions>,
    control: Arc<IngressGuards>,
    responses: Arc<IngressGuards>,
    key: [u8; 32],
    cleanup: Mutex<Option<tokio::task::JoinHandle<()>>>,
    cancellations: Mutex<HashMap<(String, String), Weak<ExplicitCancellation>>>,
}
#[derive(Clone)]
struct Admitted {
    view: McpView,
    snapshot: Arc<RuntimeSnapshot>,
    http_span: tracing::Span,
    cancellation: Arc<ExplicitCancellation>,
    lifetime: crate::ingress::request_lifetime::RequestLifetime,
    renewal: Arc<crate::membership_renewal::RenewalContext>,
    identity: IdentityContext,
    identity_pin: IdentityPin,
    prepared_discovery: Option<Arc<handler::PreparedDiscovery>>,
    context: ExecutionContext,
    remote: SocketAddr,
    headers: HeaderMap,
    owner: String,
    _permits: Arc<ProtocolPermits>,
    delivery_started: Arc<Mutex<Option<Instant>>>,
    created_sessions: Arc<Mutex<Vec<SessionId>>>,
}
// Only an authenticated cancellation notification can change this signal.
// SDK request tokens also cancel on session teardown, which is not an explicit
// request to stop a previously admitted Broker operation.
#[derive(Default)]
struct ExplicitCancellation {
    token: tokio_util::sync::CancellationToken,
    control: Mutex<Option<InvocationControl>>,
}
impl ExplicitCancellation {
    fn cancel(&self) {
        let control = self.control.lock().unwrap();
        self.token.cancel();
        if let Some(control) = control.as_ref() {
            control.cancel();
        }
    }
    fn attach(&self, control: InvocationControl) {
        let mut attached = self.control.lock().unwrap();
        if self.token.is_cancelled() {
            control.cancel();
        }
        *attached = Some(control);
    }
}
struct ProtocolPermits {
    _global: Arc<IngressPermit>,
    _principal: IngressPermit,
}
tokio::task_local! { static CURRENT_REQUEST: Admitted; }
impl Endpoint {
    /// Closes every open session. A session's protocol worker holds the
    /// broker state until it ends, so the shutdown drain closes them once the
    /// listeners have ended. Closing never cancels admitted operations.
    pub(crate) async fn close_sessions(&self) {
        self.0.sessions.close_all().await;
    }

    pub(crate) fn new(state: Arc<ReloadableState>) -> Self {
        let mut key = [0; 32];
        rand::rngs::OsRng.fill_bytes(&mut key);
        let inner = Arc::new(EndpointState {
            state,
            sessions: sessions::Sessions::new(),
            control: Arc::new(IngressGuards::new()),
            responses: Arc::new(IngressGuards::new()),
            key,
            cleanup: Mutex::new(None),
            cancellations: Mutex::new(HashMap::new()),
        });
        let endpoint = Self(inner);
        endpoint.ensure_cleanup();
        endpoint
    }
    fn ensure_cleanup(&self) {
        let Ok(runtime) = tokio::runtime::Handle::try_current() else {
            return;
        };
        let mut cleanup = self.0.cleanup.lock().unwrap();
        if cleanup.as_ref().is_some_and(|task| !task.is_finished()) {
            return;
        }
        let weak = Arc::downgrade(&self.0);
        *cleanup = Some(runtime.spawn(async move {
            let mut pruning: Option<tokio::task::JoinHandle<()>> = None;
            loop {
                tokio::time::sleep(Duration::from_secs(1)).await;
                let Some(endpoint) = weak.upgrade() else {
                    if let Some(pruning) = pruning {
                        pruning.abort();
                    }
                    break;
                };
                #[cfg(test)]
                if endpoint.state.mcp_cleanup_paused.load(Ordering::SeqCst) {
                    continue;
                }
                let snapshot = endpoint.state.current();
                endpoint.sessions.reap(snapshot.clone()).await;
                #[cfg(test)]
                {
                    endpoint
                        .state
                        .mcp_session_count
                        .store(endpoint.sessions.count().await, Ordering::SeqCst);
                    endpoint.state.mcp_reap_completed.notify_one();
                }
                // Expiry remains responsive when an authoritative proof read
                // stalls. Only one background sweep may be pending at a time.
                if pruning.as_ref().is_none_or(|task| task.is_finished()) {
                    let sessions = endpoint.sessions.clone();
                    let state = endpoint.state.clone();
                    pruning = Some(tokio::spawn(async move {
                        // Unavailable storage does not establish stale proof.
                        let _ = sessions
                            .prune_attested(state.clone(), snapshot, None, None)
                            .await;
                        #[cfg(test)]
                        state.mcp_cleanup_completed.notify_one();
                    }));
                }
            }
        }));
    }
    fn valid_signature(&self, bytes: &[u8], signature: &str) -> bool {
        if signature.len() != 64 || !signature.is_ascii() {
            return false;
        }
        let mut supplied = [0u8; 32];
        for (index, pair) in signature.as_bytes().as_chunks::<2>().0.iter().enumerate() {
            let digit = |value: u8| match value {
                b'0'..=b'9' => Some(value - b'0'),
                b'a'..=b'f' => Some(value - b'a' + 10),
                b'A'..=b'F' => Some(value - b'A' + 10),
                _ => None,
            };
            let (Some(high), Some(low)) = (digit(pair[0]), digit(pair[1])) else {
                return false;
            };
            supplied[index] = (high << 4) | low;
        }
        let mut mac = Hmac::<Sha256>::new_from_slice(&self.0.key).expect("fixed HMAC key");
        mac.update(bytes);
        mac.verify_slice(&supplied).is_ok()
    }
    fn signature(&self, bytes: &[u8]) -> String {
        let mut mac = Hmac::<Sha256>::new_from_slice(&self.0.key).expect("fixed HMAC key");
        mac.update(bytes);
        mac.finalize()
            .into_bytes()
            .iter()
            .map(|v| format!("{v:02x}"))
            .collect()
    }
}

fn failure(status: StatusCode, message: &'static str) -> Response {
    let mut response = (status, axum::Json(serde_json::json!({"error":message}))).into_response();
    response
        .headers_mut()
        .insert("cache-control", HeaderValue::from_static("no-store"));
    if status == StatusCode::UNAUTHORIZED {
        response.headers_mut().insert(
            "www-authenticate",
            HeaderValue::from_static("Bearer realm=\"agent-access-broker\""),
        );
    }
    response
}

pub(crate) fn trailers_failure() -> Response {
    failure(
        StatusCode::BAD_REQUEST,
        "MCP request trailers are not supported",
    )
}

enum PreProtocolFailure {
    Identity(IdentityFailure),
    View,
}
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum PreProtocolPhase {
    Identity,
    View,
    Discovery,
}

async fn identity_failure_response(
    state: &AppState,
    snapshot: Arc<RuntimeSnapshot>,
    headers: &HeaderMap,
    remote: SocketAddr,
    username: bool,
    error: IdentityFailure,
) -> Response {
    if username {
        crate::router::admission_failure_response(state, snapshot, headers, Some(remote), error)
            .await
    } else {
        failure_response(error)
    }
}
fn protocol_failure(
    status: StatusCode,
    id: Value,
    code: i32,
    message: &'static str,
    data: Option<Value>,
) -> Response {
    let mut error = serde_json::json!({"code":code,"message":message});
    if let Some(data) = data {
        error["data"] = data;
    }
    let mut response = (
        status,
        axum::Json(serde_json::json!({"jsonrpc":"2.0","id":id,"error":error})),
    )
        .into_response();
    response
        .headers_mut()
        .insert("cache-control", HeaderValue::from_static("no-store"));
    response
}
#[allow(clippy::result_large_err)] // Transport errors are already concrete HTTP responses.
fn permits(
    guards: &Arc<IngressGuards>,
    principal: &str,
    global: u32,
    per_principal: u32,
) -> Result<ProtocolPermits, Response> {
    let global = guards
        .try_global_concurrency(global)
        .map_err(|_| failure(StatusCode::TOO_MANY_REQUESTS, "MCP capacity exhausted"))?;
    let principal = guards
        .try_principal_concurrency(principal, per_principal)
        .map_err(|_| {
            failure(
                StatusCode::TOO_MANY_REQUESTS,
                "MCP caller capacity exhausted",
            )
        })?;
    Ok(ProtocolPermits {
        _global: Arc::new(global),
        _principal: principal,
    })
}
#[allow(clippy::result_large_err)] // Transport errors are already concrete HTTP responses.
fn security_headers(
    headers: &HeaderMap,
    uri: &axum::http::Uri,
    config: &agent_access_core::McpConfig,
    allow_managed_identity: bool,
    username_mode: bool,
) -> Result<Option<String>, Response> {
    for name in [
        "authorization",
        "host",
        "origin",
        "mcp-session-id",
        "mcp-protocol-version",
        "content-type",
        "content-length",
        "content-encoding",
        "last-event-id",
        agent_access_core::EXECUTION_CONTEXT_HEADER,
    ] {
        if headers.get_all(name).iter().count() > 1 {
            return Err(failure(
                StatusCode::BAD_REQUEST,
                "Duplicate MCP request header",
            ));
        }
    }
    if uri.query().is_some()
        || headers.contains_key("content-encoding")
        || headers.contains_key("last-event-id")
    {
        return Err(failure(
            StatusCode::BAD_REQUEST,
            "Unsupported MCP request encoding or replay",
        ));
    }
    let public = url::Url::parse(config.public_url.as_deref().unwrap_or("")).map_err(|_| {
        failure(
            StatusCode::SERVICE_UNAVAILABLE,
            "MCP endpoint configuration unavailable",
        )
    })?;
    let expected = public[url::Position::BeforeHost..url::Position::AfterPort].to_string();
    let header_host = headers
        .get("host")
        .map(|h| h.to_str())
        .transpose()
        .map_err(|_| failure(StatusCode::BAD_REQUEST, "Invalid MCP Host header"))?;
    let authority = uri.authority().map(|a| a.as_str());
    if let (Some(host), Some(authority)) = (header_host, authority)
        && !host.eq_ignore_ascii_case(authority)
    {
        return Err(failure(
            StatusCode::BAD_REQUEST,
            "Conflicting MCP Host and authority",
        ));
    }
    let host = header_host.or(authority);
    if !host.is_some_and(|h| h.eq_ignore_ascii_case(&expected)) {
        return Err(failure(StatusCode::FORBIDDEN, "MCP host is not allowed"));
    }
    if let Some(origin) = headers.get("origin") {
        let origin = origin
            .to_str()
            .map_err(|_| failure(StatusCode::FORBIDDEN, "MCP origin is not allowed"))?;
        if !config
            .allowed_origins
            .iter()
            .any(|allowed| allowed == origin)
        {
            return Err(failure(StatusCode::FORBIDDEN, "MCP origin is not allowed"));
        }
    }
    if username_mode || (!headers.contains_key("authorization") && allow_managed_identity) {
        return Ok(None);
    }
    let token = agent_access_core::parse_assertion_bearer(headers, "authorization")
        .map_err(|_| failure(StatusCode::UNAUTHORIZED, "Invalid broker bearer identity"))?
        .ok_or_else(|| failure(StatusCode::UNAUTHORIZED, "Broker bearer identity required"))?;
    Ok(Some(token.to_owned()))
}

// Parse the original, undecoded path. Axum's path parameters are intentionally
// not used: percent encodings must never create aliases for a service connection.
fn request_view(request: &Request<Body>) -> Option<McpView> {
    let original = request
        .extensions()
        .get::<OriginalUri>()
        .map(|uri| &uri.0)
        .unwrap_or_else(|| request.uri());
    if original.query().is_some()
        || request.uri().query().is_some()
        || original.path() != request.uri().path()
    {
        return None;
    }
    if original.path() == "/mcp" {
        return Some(McpView::Aggregate);
    }
    let service = original.path().strip_prefix("/mcp/")?;
    agent_access_provider::is_service_name(service).then(|| McpView::Service(service.to_owned()))
}

pub(crate) async fn handle(
    State(state): State<AppState>,
    Extension(endpoint): Extension<Endpoint>,
    ConnectInfo(remote): ConnectInfo<SocketAddr>,
    request: Request<Body>,
) -> Response {
    endpoint.ensure_cleanup();
    let Some(McpIngress {
        snapshot,
        admission: ingress,
    }) = request.extensions().get::<McpIngress>().cloned()
    else {
        return failure(
            StatusCode::SERVICE_UNAVAILABLE,
            "MCP ingress admission unavailable",
        );
    };
    let config = snapshot.runtime.config().mcp.clone();
    if !config.enabled {
        return failure(StatusCode::NOT_FOUND, "MCP endpoint is disabled");
    }
    let Some(view) = request_view(&request) else {
        if ingress.is_username() {
            return crate::router::admission_failure_response(
                &state,
                snapshot,
                request.headers(),
                Some(remote),
                IdentityFailure::AssertionInvalid,
            )
            .await;
        }
        return failure(StatusCode::BAD_REQUEST, "Invalid MCP endpoint path");
    };
    if request.headers().contains_key("trailer") {
        return if ingress.is_username() {
            crate::router::admission_failure_response(
                &state,
                snapshot,
                request.headers(),
                Some(remote),
                IdentityFailure::AssertionInvalid,
            )
            .await
        } else {
            trailers_failure()
        };
    }
    let token = match security_headers(
        request.headers(),
        request.uri(),
        &config,
        !snapshot
            .runtime
            .config()
            .identity
            .trusted_callers
            .is_empty(),
        ingress.is_username(),
    ) {
        Ok(t) => t,
        Err(r) => return r,
    };
    // Bound token validation as well as body intake. Identity resolution uses
    // blocking workers, so the global lease must precede that work.
    let intake_global = match endpoint
        .0
        .control
        .try_global_concurrency(config.max_control_requests)
    {
        Ok(permit) => Arc::new(permit),
        Err(_) => return failure(StatusCode::TOO_MANY_REQUESTS, "MCP capacity exhausted"),
    };
    let source = snapshot
        .source_resolver
        .source_context(remote, request.headers());
    // Explicit Bearer and verified managed-proxy identities are the only MCP
    // authentication paths. Never promote cookies or alternate identity headers.
    let canonical_authorization = token.as_ref().map(|token| {
        HeaderValue::from_str(&format!("Bearer {token}")).expect("validated ASCII token")
    });
    let mut auth_headers = HeaderMap::new();
    if let Some(authorization) = &canonical_authorization {
        auth_headers.insert("authorization", authorization.clone());
    }
    for name in [
        "x-agent-access-caller-authorization",
        "x-aw-identity-token-sha256",
        agent_access_core::USER_HEADER,
        agent_access_core::EXECUTION_CONTEXT_HEADER,
    ] {
        for value in request.headers().get_all(name) {
            auth_headers.append(name, value.clone());
        }
    }
    if ingress.is_direct_username() {
        for value in request.headers().get_all("authorization") {
            auth_headers.append("authorization", value.clone());
        }
    }
    let identity_snapshot = snapshot.clone();
    let identity_ingress = ingress.clone();
    let identity_lease = intake_global.clone();
    let renewal_headers = auth_headers.clone();
    let identity_worker = tokio::task::spawn_blocking(move || {
        // A timed-out response cannot release capacity while blocking token
        // verification is still running.
        let _lease = identity_lease;
        identity_snapshot
            .runtime
            .resolve_admitted_identity_with_proof(&auth_headers, &identity_ingress)
    });
    let resolved = match tokio::time::timeout(
        Duration::from_millis(config.protocol_timeout_ms),
        identity_worker,
    )
    .await
    {
        Ok(Ok(Ok(resolved))) if resolved.identity.authenticated => resolved,
        result => {
            if ingress.is_username() {
                let error = match result {
                    Ok(Ok(Err(error))) => error,
                    _ => IdentityFailure::Unavailable,
                };
                return crate::router::admission_failure_response(
                    &state,
                    snapshot,
                    request.headers(),
                    Some(remote),
                    error,
                )
                .await;
            }
            if let Err(response) = common::check_auth_source_rate_guard(
                &state,
                &snapshot,
                "mcp-auth",
                "mcp".into(),
                "authenticate".into(),
                &source,
            )
            .await
            {
                return common::envelope_response(*response).into_response();
            }
            return failure(
                StatusCode::UNAUTHORIZED,
                "Broker bearer identity is invalid or expired",
            );
        }
    };
    let mut identity = resolved.identity;
    let identity_pin = IdentityPin {
        caller_security_epoch: ingress.caller_id().map(|_| snapshot.caller_security_epoch),
        admission: ingress.clone(),
        proof: resolved.proof,
    };
    // The caller's intake capacity is taken before any renewal wait, so a
    // waiting principal holds its own share rather than the global one.
    let intake_principal = match endpoint.0.control.try_principal_concurrency(
        &identity.principal,
        config.max_control_requests_per_principal,
    ) {
        Ok(permit) => permit,
        Err(_) => {
            return failure(
                StatusCode::TOO_MANY_REQUESTS,
                "MCP caller capacity exhausted",
            );
        }
    };
    // Membership renewal admission, after intake resolution and before
    // protocol handling. After a wait the pin is checked once more: the same
    // credential, or the original proof and caller-security epoch.
    if crate::membership_renewal::admit_membership_renewal(
        &state.reloadable,
        &snapshot,
        resolved.membership_renewal.as_ref(),
        request.headers(),
    )
    .await
        == crate::membership_renewal::RenewalAdmission::Waited
    {
        identity = match identity_pin
            .revalidate(state.reloadable.clone(), snapshot.clone(), renewal_headers)
            .await
        {
            Ok(identity) => identity,
            Err(error) => {
                return identity_failure_response(
                    &state,
                    snapshot,
                    request.headers(),
                    remote,
                    ingress.is_username(),
                    error,
                )
                .await;
            }
        };
    }
    if identity.source.as_ref().is_none_or(|source| {
        let allowed_kind = if ingress.is_username() {
            source.kind == "trusted_user"
        } else if token.is_none() {
            source.kind == "forwarded_identity"
        } else {
            source.token_header.eq_ignore_ascii_case("Authorization")
                && source.token_scheme.eq_ignore_ascii_case("Bearer")
                && matches!(source.kind.as_str(), "static_principals" | "broker_tokens")
        };
        !allowed_kind
            || source
                .token_class
                .as_ref()
                .is_some_and(|class| class != &BrokerTokenClass::AgentInvoke)
    }) {
        return failure(StatusCode::FORBIDDEN, "Broker invocation identity required");
    }
    let context = match ingress.execution_context() {
        Ok(c) => c,
        Err(error) => {
            if ingress.is_username() {
                let error = match error {
                    agent_access_core::ExecutionContextFailure::Required => {
                        IdentityFailure::ExecutionContextRequired
                    }
                    agent_access_core::ExecutionContextFailure::Invalid => {
                        IdentityFailure::ExecutionContextInvalid
                    }
                };
                return crate::router::admission_failure_response(
                    &state,
                    snapshot,
                    request.headers(),
                    Some(remote),
                    error,
                )
                .await;
            }
            return failure(
                StatusCode::BAD_REQUEST,
                "Invalid or missing execution context",
            );
        }
    };
    if snapshot
        .runtime
        .admit_agent_invoke_execution_context(&identity, &context)
        .is_err()
    {
        return failure(StatusCode::FORBIDDEN, "Execution context denied");
    }
    let method = request.method().clone();
    if method != Method::POST && method != Method::DELETE {
        let mut r = failure(StatusCode::METHOD_NOT_ALLOWED, "Use MCP POST or DELETE");
        r.headers_mut()
            .insert("allow", HeaderValue::from_static("POST, DELETE"));
        return r;
    }
    let intake = Arc::new(ProtocolPermits {
        _global: intake_global,
        _principal: intake_principal,
    });
    let (mut parts, body) = request.into_parts();
    // MCP never authenticates through competing configured identity carriers.
    // Keep every subsequent live check on the same selected credential surface.
    for source in &snapshot.runtime.config().identity.sources {
        if !source.header.eq_ignore_ascii_case("authorization") {
            parts.headers.remove(&source.header);
        }
    }
    if ingress.is_username() {
        // The typed admission retains caller authentication. The principal
        // bearer carrier must not be reinterpreted by later request handlers.
        parts.headers.remove("authorization");
    }
    if let Some(authorization) = canonical_authorization {
        parts.headers.insert("authorization", authorization);
    }
    let idle = Duration::from_millis(snapshot.runtime.limits().streaming_idle_timeout_ms);
    let bytes = match tokio::time::timeout(
        Duration::from_millis(config.protocol_timeout_ms),
        read_body(body, config.max_request_bytes, idle),
    )
    .await
    {
        Ok(Ok(b)) => b,
        Ok(Err(BodyReadFailure::Response(r))) => return r,
        Ok(Err(BodyReadFailure::Trailers)) => {
            return if ingress.is_username() {
                crate::router::admission_failure_response(
                    &state,
                    snapshot,
                    &parts.headers,
                    Some(remote),
                    IdentityFailure::AssertionInvalid,
                )
                .await
            } else {
                trailers_failure()
            };
        }
        Err(_) => {
            return failure(
                StatusCode::REQUEST_TIMEOUT,
                "MCP request body deadline exceeded",
            );
        }
    };
    let check_pin = identity_pin.clone();
    let check_state = state.reloadable.clone();
    let check_snapshot = snapshot.clone();
    let check_headers = parts.headers.clone();
    let check_lease = intake.clone();
    identity = match tokio::time::timeout(
        Duration::from_millis(config.protocol_timeout_ms),
        tokio::task::spawn_blocking(move || {
            let _lease = check_lease;
            #[cfg(test)]
            let barrier = check_state.wait_mcp_intake_barrier();
            let result = check_pin.revalidate_sync(&check_state, &check_snapshot, &check_headers);
            drop(_lease);
            #[cfg(test)]
            if let Some(barrier) = barrier {
                barrier.completed.notify_one();
            }
            result
        }),
    )
    .await
    {
        Ok(Ok(Ok(identity))) => identity,
        Ok(Ok(Err(error))) => {
            return identity_failure_response(
                &state,
                snapshot,
                &parts.headers,
                remote,
                ingress.is_username(),
                error,
            )
            .await;
        }
        _ => {
            return identity_failure_response(
                &state,
                snapshot,
                &parts.headers,
                remote,
                ingress.is_username(),
                IdentityFailure::Unavailable,
            )
            .await;
        }
    };
    let message: Value = if method == Method::POST {
        match serde_json::from_slice::<Value>(&bytes) {
            Ok(v) if v.is_object() => v,
            Ok(_) => {
                return protocol_failure(
                    StatusCode::BAD_REQUEST,
                    Value::Null,
                    -32600,
                    "Invalid MCP JSON-RPC message",
                    None,
                );
            }
            Err(_) => {
                return protocol_failure(
                    StatusCode::BAD_REQUEST,
                    Value::Null,
                    -32700,
                    "Invalid MCP JSON",
                    None,
                );
            }
        }
    } else {
        if !bytes.is_empty() {
            return failure(StatusCode::BAD_REQUEST, "DELETE does not accept a body");
        }
        Value::Null
    };
    if let Some(id) = message.get("id")
        && !(id.as_i64().is_some()
            || id.as_u64().is_some()
            || id.as_str().is_some_and(|v| v.len() <= 1024))
    {
        return protocol_failure(
            StatusCode::BAD_REQUEST,
            Value::Null,
            -32600,
            "Invalid MCP request id",
            None,
        );
    }
    let id = message.get("id").cloned().unwrap_or(Value::Null);
    let initialize = message["method"] == "initialize";
    let native = message["method"] == "tools/call"
        && !agent_access_core::mcp::is_helper(message["params"]["name"].as_str().unwrap_or(""));
    if !initialize
        && parts
            .headers
            .get("mcp-protocol-version")
            .is_some_and(|h| h != "2025-11-25")
    {
        return protocol_failure(
            StatusCode::BAD_REQUEST,
            id,
            -32022,
            "Unsupported MCP protocol version",
            Some(serde_json::json!({"supported":["2025-11-25"]})),
        );
    }
    // Reject malformed typed messages without returning SDK serde errors that
    // could contain arbitrary client-supplied fields or secret values.
    if method == Method::POST
        && serde_json::from_slice::<rmcp::model::ClientJsonRpcMessage>(&bytes).is_err()
    {
        let valid_envelope = message["jsonrpc"] == "2.0";
        let known_method = message["method"].as_str().is_some_and(|method| {
            matches!(
                method,
                "initialize"
                    | "ping"
                    | "tools/list"
                    | "tools/call"
                    | "notifications/initialized"
                    | "notifications/cancelled"
            )
        });
        let (code, message) = if !valid_envelope || !message["method"].is_string() {
            (-32600, "Invalid MCP protocol message")
        } else if !known_method {
            (-32601, "MCP method not found")
        } else {
            (-32602, "Invalid MCP method parameters")
        };
        return protocol_failure(StatusCode::BAD_REQUEST, id, code, message, None);
    }
    let request_permits = if native {
        drop(intake);
        let limits = snapshot.runtime.limits();
        match permits(
            &endpoint.0.responses,
            &identity.principal,
            limits.max_concurrent_requests,
            limits.max_concurrent_requests_per_principal,
        ) {
            Ok(p) => Arc::new(p),
            Err(r) => return r,
        }
    } else {
        // Protocol messages and discovery helpers are bounded by the MCP
        // control caps, never by service invocation budgets.
        intake
    };
    if !parts.headers.contains_key("x-agent-access-request-id") {
        parts.headers.insert(
            "x-agent-access-request-id",
            HeaderValue::from_str(&uuid::Uuid::new_v4().to_string()).unwrap(),
        );
    }
    let owner = endpoint.signature(
        &serde_json::to_vec(&(
            identity.source.as_ref().map(|s| (&s.name, &s.token_id)),
            &identity.principal,
            ingress.caller_id(),
            ingress.caller_binding(),
            identity_pin.caller_security_epoch,
            identity_pin
                .proof
                .as_ref()
                .map(AttestedIdentityProof::session_binding),
            &token,
            token.is_none().then(|| {
                parts
                    .headers
                    .get("x-aw-identity-token-sha256")
                    .map(HeaderValue::as_bytes)
            }),
        ))
        .unwrap(),
    );
    let mut admitted = Admitted {
        view,
        snapshot: snapshot.clone(),
        http_span: tracing::Span::current(),
        cancellation: Arc::new(ExplicitCancellation::default()),
        lifetime: crate::ingress::request_lifetime::RequestLifetime::current(),
        renewal: crate::membership_renewal::RenewalContext::current(),
        identity,
        identity_pin,
        prepared_discovery: None,
        context,
        remote,
        headers: parts.headers.clone(),
        owner,
        _permits: request_permits,
        delivery_started: Arc::new(Mutex::new(None)),
        created_sessions: Arc::new(Mutex::new(Vec::new())),
    };
    endpoint.0.sessions.reap(state.reloadable.current()).await;
    if let Some(id) = parts.headers.get("mcp-session-id") {
        let Ok(id) = id.to_str() else {
            return failure(StatusCode::BAD_REQUEST, "Invalid MCP session id");
        };
        if id.len() > 128
            || !endpoint
                .0
                .sessions
                .owned(&SessionId::from(id.to_owned()), &admitted)
                .await
        {
            return failure(
                StatusCode::NOT_FOUND,
                "MCP session unavailable; initialize again",
            );
        }
    } else if !initialize {
        return failure(StatusCode::BAD_REQUEST, "MCP session id required");
    }
    if initialize {
        let pruned = tokio::time::timeout(
            Duration::from_millis(config.protocol_timeout_ms),
            endpoint.0.sessions.prune_attested(
                state.reloadable.clone(),
                state.reloadable.current(),
                Some(&admitted.identity.principal),
                Some(admitted._permits.clone()),
            ),
        )
        .await
        .unwrap_or(Err(IdentityFailure::Unavailable));
        if let Err(error) = pruned {
            return identity_failure_response(
                &state,
                snapshot,
                &parts.headers,
                remote,
                ingress.is_username(),
                error,
            )
            .await;
        }
    }
    if initialize && !endpoint.0.sessions.can_create(&admitted).await {
        return failure(
            StatusCode::TOO_MANY_REQUESTS,
            "MCP session capacity exhausted",
        );
    }
    // Revalidate inside the queued worker, after body intake and session work.
    // Discovery uses the membership returned with this exact proof. An identity
    // transition never becomes an SDK error or a differently mapped principal.
    let mut owned = admitted.clone();
    let owner = state.reloadable.clone();
    let discovery_endpoint = endpoint.clone();
    let discovery_message = message.clone();
    let phase = Arc::new(AtomicU8::new(PreProtocolPhase::Identity as u8));
    let worker_phase = phase.clone();
    #[cfg(test)]
    if !native {
        state.reloadable.wait_mcp_discovery_barrier().await;
    }
    let discovery_started = tokio::time::Instant::now();
    let discovery_deadline = discovery_started + Duration::from_millis(config.protocol_timeout_ms);
    let final_check = tokio::task::spawn_blocking(move || {
        #[cfg(test)]
        owner.wait_mcp_preprotocol_barrier(PreProtocolPhase::Identity);
        owned.identity = owned
            .identity_pin
            .revalidate_sync(&owner, &owned.snapshot, &owned.headers)
            .map_err(PreProtocolFailure::Identity)?;
        if initialize && owned.view.service().is_some() {
            worker_phase.store(PreProtocolPhase::View as u8, Ordering::Release);
            #[cfg(test)]
            owner.wait_mcp_preprotocol_barrier(PreProtocolPhase::View);
            handler::Handler::validate_view(&owned).map_err(|_| PreProtocolFailure::View)?;
        }
        // Prepare discovery inside this same admitted worker. The SDK may
        // queue its callback, but no identity-sensitive discovery is deferred
        // past this boundary and every proof failure keeps its HTTP status.
        worker_phase.store(PreProtocolPhase::Discovery as u8, Ordering::Release);
        #[cfg(test)]
        owner.wait_mcp_preprotocol_barrier(PreProtocolPhase::Discovery);
        owned.prepared_discovery = handler::Handler::new(discovery_endpoint, owned.view.clone())
            .prepare_discovery(&owned, &discovery_message)
            .map(Arc::new);
        Ok::<_, PreProtocolFailure>((owned.identity, owned.prepared_discovery))
    });
    #[cfg(test)]
    let discovery_deadline = {
        let start = state
            .reloadable
            .mcp_preprotocol_timeout_start
            .lock()
            .unwrap()
            .take();
        if let Some(start) = start {
            // The test keeps the worker blocked until it has selected the
            // phase, then starts the production-computed budget. Dropping the
            // sender also releases this wait if the test fails first.
            let _ = start.await;
            tokio::time::Instant::now() + (discovery_deadline - discovery_started)
        } else {
            discovery_deadline
        }
    };
    let final_check = tokio::time::timeout_at(discovery_deadline, final_check).await;
    match final_check {
        Ok(Ok(Ok((identity, discovery)))) => {
            admitted.identity = identity;
            admitted.prepared_discovery = discovery;
        }
        Ok(Ok(Err(PreProtocolFailure::Identity(error)))) => {
            return identity_failure_response(
                &state,
                snapshot,
                &parts.headers,
                remote,
                ingress.is_username(),
                error,
            )
            .await;
        }
        Ok(Ok(Err(PreProtocolFailure::View))) => {
            return failure(StatusCode::NOT_FOUND, "Service MCP view is unavailable");
        }
        result if phase.load(Ordering::Acquire) == PreProtocolPhase::View as u8 => {
            return if result.is_err() {
                failure(
                    StatusCode::REQUEST_TIMEOUT,
                    "MCP view admission deadline exceeded",
                )
            } else {
                failure(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "MCP view admission task failed",
                )
            };
        }
        result if phase.load(Ordering::Acquire) == PreProtocolPhase::Discovery as u8 => {
            return protocol_failure(
                StatusCode::OK,
                id,
                -32603,
                if result.is_err() {
                    "MCP discovery deadline exceeded"
                } else {
                    "MCP discovery task failed"
                },
                None,
            );
        }
        _ => {
            return identity_failure_response(
                &state,
                snapshot,
                &parts.headers,
                remote,
                ingress.is_username(),
                IdentityFailure::Unavailable,
            )
            .await;
        }
    }
    if let Some(handler::PreparedDiscovery::ServiceDetail(service)) =
        admitted.prepared_discovery.as_deref()
    {
        let owned = admitted.clone();
        let detail_state = state.clone();
        let service_name = service.service.clone();
        let service = service.clone();
        let detail = tokio::time::timeout_at(
            discovery_deadline,
            tokio::spawn(async move {
                // A store worker may not be cancelable. Keep the control lease
                // until its result actually returns, even if HTTP timed out.
                let detail = crate::handlers::discovery_limits::service_detail(
                    &detail_state,
                    &owned.snapshot,
                    &owned.identity,
                    service,
                )
                .await;
                drop(owned);
                detail
            }),
        )
        .await;
        let result = match detail {
            Ok(Ok(Ok(detail))) if tokio::time::Instant::now() < discovery_deadline => {
                serde_json::to_value(detail)
                    .ok()
                    .and_then(|value| output::result(value, false, config.max_response_bytes).ok())
                    .unwrap_or_else(|| {
                        output::message(
                            "Discovery result exceeds MCP response limit; use narrower discovery",
                        )
                    })
            }
            Ok(Ok(Err(error))) => {
                let cause = match error {
                    crate::ingress::invocation_limits::InvocationObservationError::RuntimePublished => "runtime_replaced",
                    crate::ingress::invocation_limits::InvocationObservationError::Resolution(_error) => "effective_limit_read",
                };
                tracing::warn!(
                    event = "discovery_unavailable",
                    cause,
                    service = service_name
                );
                return protocol_failure(
                    StatusCode::OK,
                    id,
                    -32603,
                    "MCP discovery task failed",
                    None,
                );
            }
            Ok(Err(_)) => {
                return protocol_failure(
                    StatusCode::OK,
                    id,
                    -32603,
                    "MCP discovery task failed",
                    None,
                );
            }
            _ => {
                return protocol_failure(
                    StatusCode::OK,
                    id,
                    -32603,
                    "MCP discovery deadline exceeded",
                    None,
                );
            }
        };
        admitted.prepared_discovery =
            Some(Arc::new(handler::PreparedDiscovery::Helper(Ok(result))));
    }
    if let Some(session) = parts
        .headers
        .get("mcp-session-id")
        .and_then(|value| value.to_str().ok())
    {
        let mut pending = endpoint.0.cancellations.lock().unwrap();
        pending.retain(|_, weak| weak.strong_count() != 0);
        if native {
            let key = (session.to_owned(), message["id"].to_string());
            if pending.contains_key(&key) {
                return protocol_failure(
                    StatusCode::BAD_REQUEST,
                    message["id"].clone(),
                    -32600,
                    "Native MCP request id is already active",
                    None,
                );
            }
            pending.insert(key, Arc::downgrade(&admitted.cancellation));
        } else if message["method"] == "notifications/cancelled" {
            let key = (
                session.to_owned(),
                message["params"]["requestId"].to_string(),
            );
            if let Some(cancellation) = pending.get(&key).and_then(Weak::upgrade) {
                cancellation.cancel();
            }
        }
    }
    // Notification callbacks run after HTTP 202 and need no Broker request
    // context; do not retain an intake lease in their queued SDK extensions.
    if message.get("id").is_some() {
        parts.extensions.insert(admitted.clone());
    }
    let mut transport = StreamableHttpServerConfig::default().enforce_origin_validation();
    transport.allowed_hosts = vec![
        url::Url::parse(config.public_url.as_deref().unwrap()).unwrap()
            [url::Position::BeforeHost..url::Position::AfterPort]
            .to_owned(),
    ];
    transport.allowed_origins = config.allowed_origins.clone();
    transport.max_request_body_bytes = config.max_request_bytes;
    transport.sse_retry = None;
    transport.sse_keep_alive = Some(Duration::from_secs(10).min(idle / 2));
    let handler_endpoint = endpoint.clone();
    let handler_view = admitted.view.clone();
    let service = StreamableHttpService::new(
        move || {
            Ok(handler::Handler::new(
                handler_endpoint.clone(),
                handler_view.clone(),
            ))
        },
        endpoint.0.sessions.clone(),
        transport,
    );
    let response = tokio::time::timeout(
        Duration::from_millis(config.protocol_timeout_ms),
        CURRENT_REQUEST.scope(
            admitted.clone(),
            service.oneshot(Request::from_parts(parts, Body::from(bytes))),
        ),
    )
    .await;
    let response = match response {
        Ok(Ok(r)) => r.map(Body::new),
        _ => {
            let created = admitted.created_sessions.lock().unwrap().clone();
            for id in created {
                let _ = endpoint.0.sessions.close_session(&id).await;
            }
            return failure(
                StatusCode::REQUEST_TIMEOUT,
                "MCP protocol deadline exceeded",
            );
        }
    };
    if initialize || method == Method::DELETE {
        *admitted.delivery_started.lock().unwrap() = Some(Instant::now());
    }
    let (mut response_parts, body) = response.into_parts();
    response_parts
        .headers
        .insert("cache-control", HeaderValue::from_static("no-store"));
    let delivery = Delivery {
        _lease: admitted._permits.clone(),
        result_ready: admitted.delivery_started.clone(),
        opened: Instant::now(),
        sent: 0,
    };
    let delivery_timeout = Duration::from_millis(config.protocol_timeout_ms);
    let pending_timeout = Duration::from_millis(
        config
            .operation_timeout_ms
            .saturating_add(config.protocol_timeout_ms.saturating_mul(3)),
    );
    let max_response_bytes = config.max_response_bytes;
    let stream = futures_util::stream::unfold(
        (body, delivery),
        move |(mut body, mut delivery)| async move {
            let deadline = match *delivery.result_ready.lock().unwrap() {
                Some(ready) => ready + delivery_timeout,
                None => delivery.opened + pending_timeout,
            };
            let left = deadline.saturating_duration_since(Instant::now());
            if left.is_zero() {
                return None;
            }
            let frame = tokio::time::timeout(left.min(idle), body.frame()).await;
            match frame {
                Ok(Some(Ok(frame))) => match frame.into_data() {
                    Ok(data) if delivery.sent.saturating_add(data.len()) <= max_response_bytes => {
                        delivery.sent += data.len();
                        Some((Ok::<_, std::io::Error>(data), (body, delivery)))
                    }
                    _ => None,
                },
                _ => None,
            }
        },
    );
    Response::from_parts(response_parts, Body::from_stream(stream))
}

/// What delivering one response body needs, and nothing else: no runtime
/// snapshot, so an unread or stalled response cannot keep a generation or
/// its state locks alive. The operation owner holds its own admission and
/// finalizes audit before its result is ready.
struct Delivery {
    /// The MCP capacity lease, which keeps queued or stalled responses
    /// bounded after the operation owner has released its execution permits.
    _lease: Arc<ProtocolPermits>,
    /// When the result was ready; the delivery deadline runs from then.
    result_ready: Arc<Mutex<Option<Instant>>>,
    opened: Instant,
    sent: usize,
}
enum BodyReadFailure {
    Response(Response),
    Trailers,
}

#[allow(clippy::result_large_err)] // Transport errors are already concrete HTTP responses.
async fn read_body(
    mut body: Body,
    limit: usize,
    idle: Duration,
) -> Result<bytes::Bytes, BodyReadFailure> {
    let mut bytes = bytes::BytesMut::new();
    while let Some(frame) = tokio::time::timeout(idle, body.frame())
        .await
        .map_err(|_| {
            BodyReadFailure::Response(failure(StatusCode::REQUEST_TIMEOUT, "MCP body stalled"))
        })?
    {
        let frame = frame.map_err(|_| {
            BodyReadFailure::Response(failure(
                StatusCode::BAD_REQUEST,
                "MCP body could not be read",
            ))
        })?;
        if frame.is_trailers() {
            return Err(BodyReadFailure::Trailers);
        }
        if let Ok(data) = frame.into_data() {
            if data.len() > limit.saturating_sub(bytes.len()) {
                return Err(BodyReadFailure::Response(failure(
                    StatusCode::PAYLOAD_TOO_LARGE,
                    "MCP body exceeds limit",
                )));
            }
            bytes.extend_from_slice(&data);
        }
    }
    Ok(bytes.freeze())
}

fn failure_response(error: agent_access_core::IdentityFailure) -> Response {
    failure(
        StatusCode::from_u16(error.reason_code().http_status()).unwrap(),
        error.message(),
    )
}
