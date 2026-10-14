use crate::handlers::common::{
    CallerAdmission, acquire_caller_guard, acquire_global_concurrency_guard,
    admit_service_invocation, check_auth_source_rate_guard, envelope_response,
    response_retry_after_header,
};
use crate::handlers::data::body_error_exceeds_limit;
use crate::ingress::body::body_error_timed_out;
use crate::ingress::guards::source_log_address;
use crate::ingress::source::auth_source_key;
use crate::observability;
use crate::state::{AppState, RequestPermits, RuntimeSnapshot};
use agent_access_core::{
    BrokerResponse, BrokerRuntime, ExecutionContext, GatewayConfig, GatewayGitConfig,
    GovernedOperationContext, IdentityContext, IdentityFailure, OperationContext,
    PreparedGatewayOperation, REASON_CODE_HEADER, new_broker_request_id,
};
use agent_access_provider::{
    BROKER_REQUEST_ID_HEADER, ExecutionCredential, ProviderError, REQUEST_ID_HEADER, ReasonCode,
    ReasonCodeId, ResourceScopes, StaticCredentialKind, url_allowed_by_patterns,
};
use axum::body::{Body, Bytes};
use axum::extract::{ConnectInfo, State};
use axum::http::header::{
    AUTHORIZATION, CACHE_CONTROL, CONTENT_ENCODING, CONTENT_LENGTH, CONTENT_TYPE, EXPIRES, HOST,
    PRAGMA, TRAILER, WWW_AUTHENTICATE,
};
use axum::http::{HeaderMap, HeaderValue, Method, Request, Response, StatusCode, Uri};
use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64;
use futures_util::{Stream, TryStreamExt, stream};
use http_body_util::BodyExt;
use percent_encoding::percent_decode_str;
use serde_json::json;
use std::collections::VecDeque;
use std::future::Future;
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::pin::Pin;
use std::sync::{
    Arc,
    atomic::{AtomicBool, AtomicU8, AtomicU64, Ordering},
};
use std::time::{Duration, Instant};
use tokio::time::timeout;
use url::Url;
use url::form_urlencoded;

const BASIC_CHALLENGE: &str = r#"Basic realm="Agent Access Broker""#;
const GIT_MAX_PKT_LINE_BYTES: usize = 65_520;
const DEFAULT_RECEIVE_PACK_PREFIX_MAX_BYTES: usize = 1024 * 1024;
const REPLAY_FAILURE_NONE: u8 = 0;
const REPLAY_FAILURE_CAP_EXCEEDED: u8 = 1;
const REPLAY_FAILURE_TIMEOUT: u8 = 2;
const REPLAY_FAILURE_BODY_READ: u8 = 3;

struct MatchedGateway {
    service: String,
    config: GatewayConfig,
}

struct ClassifiedGatewayRequest {
    service: String,
    action: String,
    git_request_kind: GitRequestKind,
    resource_scopes: ResourceScopes,
}

#[derive(Debug)]
struct GatewayClassifyError {
    code: ReasonCode,
    reason: &'static str,
}

impl GatewayClassifyError {
    fn new(code: ReasonCode, reason: &'static str) -> Self {
        Self { code, reason }
    }

    fn rule_not_found(reason: &'static str) -> Self {
        Self::new(ReasonCode::GatewayRuleNotFound, reason)
    }

    fn method_denied(reason: &'static str) -> Self {
        Self::new(ReasonCode::GatewayMethodDenied, reason)
    }

    fn query_denied(reason: &'static str) -> Self {
        Self::new(ReasonCode::GatewayQueryDenied, reason)
    }

    fn git_service_denied(reason: &'static str) -> Self {
        Self::new(ReasonCode::GitServiceDenied, reason)
    }

    fn provider_error(&self) -> ProviderError {
        ProviderError::deny(self.code, self.reason)
    }
}

struct GatewayContext {
    snapshot: Arc<RuntimeSnapshot>,
    agent_request_id: String,
    broker_request_id: String,
    identity: IdentityContext,
    source: agent_access_core::SourceContext,
    execution_context: ExecutionContext,
    permits: RequestPermits,
}

struct GatewayIngressContext {
    admission: agent_access_core::IngressAdmission,
    snapshot: Arc<RuntimeSnapshot>,
    agent_request_id: String,
    broker_request_id: String,
    source: agent_access_core::SourceContext,
    execution_context: ExecutionContext,
}

struct GatewayRequestId {
    value: String,
    generated: bool,
}

#[derive(Clone, Copy)]
pub(crate) struct GatewayForwardLimits {
    pub(crate) request_body_max_bytes: usize,
    pub(crate) response_body_max_bytes: usize,
    pub(crate) idle_timeout: Duration,
}

pub(crate) type GatewayBodyStream =
    Pin<Box<dyn Stream<Item = Result<Bytes, reqwest::Error>> + Send>>;

pub(crate) struct GatewayResponseStreamInput {
    pub(crate) runtime: BrokerRuntime,
    pub(crate) prepared: PreparedGatewayOperation,
    pub(crate) method: Method,
    pub(crate) upstream_url: Url,
    pub(crate) egress_proxy_audit: serde_json::Value,
    pub(crate) upstream_status: u16,
    pub(crate) started: Instant,
    pub(crate) limits: GatewayForwardLimits,
    pub(crate) git_audit: Option<serde_json::Value>,
    pub(crate) body: GatewayBodyStream,
    pub(crate) permits: Option<RequestPermits>,
}

struct GatewayResponseStreamState {
    runtime: BrokerRuntime,
    prepared: Option<PreparedGatewayOperation>,
    method: Method,
    upstream_url: Url,
    egress_proxy_audit: serde_json::Value,
    upstream_status: u16,
    started: Instant,
    limits: GatewayForwardLimits,
    git_audit: Option<serde_json::Value>,
    body: GatewayBodyStream,
    bytes_sent: usize,
    _permits: Option<RequestPermits>,
}

#[derive(Clone)]
struct GitRefUpdate {
    old_id: String,
    new_id: String,
    ref_name: String,
    create: bool,
    delete: bool,
}

struct ReceivePackBody {
    prefix: Bytes,
    replay: Bytes,
    remaining: Body,
    updates: Vec<GitRefUpdate>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum GitRequestKind {
    UploadPackDiscovery,
    UploadPackPost,
    ReceivePackDiscovery,
    ReceivePackPost,
}

impl GitRequestKind {
    fn method(self) -> Method {
        if self.is_pack_post() {
            Method::POST
        } else {
            Method::GET
        }
    }

    fn action(self) -> &'static str {
        match self {
            Self::UploadPackDiscovery | Self::UploadPackPost => "repo.fetch",
            Self::ReceivePackDiscovery | Self::ReceivePackPost => "repo.push",
        }
    }

    fn is_upload_pack_post(self) -> bool {
        matches!(self, Self::UploadPackPost)
    }

    /// `git-upload-pack` and `git-receive-pack` POSTs, the counted invocations.
    fn is_pack_post(self) -> bool {
        matches!(self, Self::UploadPackPost | Self::ReceivePackPost)
    }

    fn is_receive_pack_post(self) -> bool {
        matches!(self, Self::ReceivePackPost)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum GitContentEncoding {
    Gzip,
}

impl GitContentEncoding {
    fn header_value(self) -> &'static str {
        match self {
            Self::Gzip => "gzip",
        }
    }
}

struct GatewayForwardRequest {
    git_request_kind: GitRequestKind,
    headers: HeaderMap,
    body: Body,
    content_encoding: Option<GitContentEncoding>,
    receive_pack: Option<ReceivePackBody>,
}

enum GatewayPreparedRequestBody {
    Bytes(Vec<u8>),
    Stream {
        body: reqwest::Body,
        failure: Arc<AtomicU8>,
        progress: Arc<GatewayRequestUploadProgress>,
    },
}

struct GatewayRequestUploadProgress {
    updates: AtomicU64,
    started: AtomicBool,
    complete: AtomicBool,
}

struct GatewayRequestReplayStreamState {
    initial: VecDeque<Bytes>,
    remaining: Body,
    sent: usize,
    max_bytes: usize,
    idle_timeout: Duration,
    failure: Arc<AtomicU8>,
    progress: Arc<GatewayRequestUploadProgress>,
}

enum GatewaySendError<E> {
    Inner(E),
    RequestUploadIdleTimeout,
    ResponseHeadersIdleTimeout,
}

impl GatewayRequestUploadProgress {
    fn new() -> Self {
        Self {
            updates: AtomicU64::new(0),
            started: AtomicBool::new(false),
            complete: AtomicBool::new(false),
        }
    }

    fn mark_progress(&self) {
        self.started.store(true, Ordering::Relaxed);
        self.updates.fetch_add(1, Ordering::Relaxed);
    }

    fn mark_complete(&self) {
        self.complete.store(true, Ordering::Relaxed);
        self.mark_progress();
    }

    async fn wait_for_send_idle_timeout(
        self: Arc<Self>,
        idle_timeout: Duration,
    ) -> GatewaySendIdleTimeout {
        let mut last_seen = self.updates.load(Ordering::Relaxed);
        loop {
            tokio::time::sleep(idle_timeout).await;
            let current = self.updates.load(Ordering::Relaxed);
            if !self.started.load(Ordering::Relaxed) {
                last_seen = current;
                continue;
            }
            if current == last_seen {
                return if self.complete.load(Ordering::Relaxed) {
                    GatewaySendIdleTimeout::ResponseHeaders
                } else {
                    GatewaySendIdleTimeout::RequestUpload
                };
            }
            last_seen = current;
        }
    }
}

enum GatewaySendIdleTimeout {
    RequestUpload,
    ResponseHeaders,
}

pub(crate) async fn gateway_dispatch(
    State(state): State<AppState>,
    ConnectInfo(remote_addr): ConnectInfo<SocketAddr>,
    request: Request<Body>,
) -> Response<Body> {
    let snapshot = state.reloadable.current();
    let mut source = snapshot
        .source_resolver
        .source_context(remote_addr, request.headers());
    let broker_request_id = new_broker_request_id();
    let agent_request_id = match gateway_request_id(request.headers()) {
        Ok(request_id) => {
            source.agent_request_id_generated = Some(request_id.generated);
            request_id.value
        }
        Err(reason) => {
            return gateway_error_response(
                StatusCode::BAD_REQUEST,
                &broker_request_id,
                Some(ReasonCode::RequestIdInvalid.into()),
                reason,
                false,
            );
        }
    };

    let mut matched_gateway = match match_gateway(&snapshot, &request) {
        Ok(Some(matched_gateway)) => matched_gateway,
        Ok(None) => {
            return gateway_error_response(
                StatusCode::NOT_FOUND,
                &broker_request_id,
                Some(ReasonCode::GatewayHostUnmatched.into()),
                "gateway host is not configured",
                false,
            );
        }
        Err(reason) => {
            return gateway_error_response(
                StatusCode::BAD_REQUEST,
                &broker_request_id,
                Some(ReasonCode::GatewayHostInvalid.into()),
                reason,
                false,
            );
        }
    };

    // Context attestation applies even when this gateway only accepts Basic tokens.
    let admission = snapshot.runtime.admit_ingress(request.headers());
    if let Err(failure) = admission {
        // Unverified ingress cannot supply source forwarding or execution context.
        source.remote = remote_addr.to_string();
        source.proxy_chain.clear();
        if let Some(response) = gateway_preclass_auth_rate_response(
            &state,
            &snapshot,
            &agent_request_id,
            &broker_request_id,
            &source,
            &matched_gateway,
        )
        .await
        {
            return response;
        }
        let response = snapshot
            .runtime
            .ingress_error_response_for_operation(
                OperationContext {
                    agent_request_id,
                    broker_request_id,
                    identity: IdentityContext::anonymous(),
                    service: "broker".into(),
                    action: failure.admission_action().into(),
                    source,
                },
                failure,
            )
            .await;
        return gateway_runtime_response(response);
    }
    let admission = admission.expect("failed caller admission returns above");
    let execution_context = match admission.execution_context() {
        Ok(execution_context) => {
            observability::record_execution_context(&execution_context);
            execution_context
        }
        Err(failure) => {
            if let Some(response) = gateway_preclass_auth_rate_response(
                &state,
                &snapshot,
                &agent_request_id,
                &broker_request_id,
                &source,
                &matched_gateway,
            )
            .await
            {
                return response;
            }

            observability::record_service_action(&matched_gateway.service, "gateway.context");
            let response = snapshot
                .runtime
                .ingress_error_response_for_operation(
                    OperationContext {
                        agent_request_id,
                        broker_request_id,
                        identity: IdentityContext::anonymous(),
                        service: matched_gateway.service,
                        action: "gateway.context".to_string(),
                        source,
                    },
                    match failure {
                        agent_access_core::ExecutionContextFailure::Required => {
                            IdentityFailure::ExecutionContextRequired
                        }
                        agent_access_core::ExecutionContextFailure::Invalid => {
                            IdentityFailure::ExecutionContextInvalid
                        }
                    },
                )
                .await;
            observability::record_decision(response.envelope.decision.as_str());
            if let Some(reason_code) = &response.envelope.reason_code {
                observability::record_reason_code(reason_code.as_str());
            }
            observability::record_status(response.status);
            return gateway_runtime_response(response);
        }
    };

    let classified = match classify_gateway_request(
        &matched_gateway,
        request.method(),
        request.uri(),
        request.headers(),
    ) {
        Ok(classified) => classified,
        Err(error) => {
            if let Some(response) = gateway_preclass_auth_rate_response(
                &state,
                &snapshot,
                &agent_request_id,
                &broker_request_id,
                &source,
                &matched_gateway,
            )
            .await
            {
                return response;
            }

            let response = snapshot
                .runtime
                .governed_operation_error_response(
                    GovernedOperationContext {
                        operation: OperationContext {
                            agent_request_id,
                            broker_request_id,
                            identity: IdentityContext::anonymous(),
                            service: matched_gateway.service,
                            action: "gateway.classify".to_string(),
                            source,
                        },
                        execution_context,
                    },
                    error.provider_error(),
                )
                .await;
            return gateway_runtime_response(response);
        }
    };

    let context = match gateway_context(
        &state,
        GatewayIngressContext {
            admission,
            snapshot,
            agent_request_id,
            broker_request_id,
            source,
            execution_context,
        },
        request.headers(),
        &matched_gateway,
        &classified,
    )
    .await
    {
        Ok(context) => context,
        Err(response) => return *response,
    };

    let headers = request.headers().clone();
    let mut body = Some(request.into_body());
    let GatewayContext {
        snapshot,
        agent_request_id,
        broker_request_id,
        identity,
        source,
        execution_context,
        permits,
    } = context;
    let runtime = snapshot.runtime.clone();
    matched_gateway.config.request_body_max_bytes = Some(
        matched_gateway
            .config
            .request_body_max_bytes
            .unwrap_or(runtime.limits().max_http_body_bytes)
            .min(runtime.limits().max_http_body_bytes)
            .min(state.reloadable.body_hard_cap as u64),
    );
    let limits = gateway_forward_limits(&runtime, &matched_gateway.config);
    let git_request_kind = classified.git_request_kind;
    let operation_context = GovernedOperationContext {
        operation: OperationContext {
            agent_request_id,
            broker_request_id,
            identity,
            service: classified.service,
            action: classified.action,
            source,
        },
        execution_context,
    };
    if let Err(error) = runtime.admit_agent_invoke_token_operation(
        &operation_context.operation.identity,
        &operation_context.operation.service,
        &operation_context.operation.action,
        &operation_context.execution_context,
        &classified.resource_scopes,
    ) {
        let response = runtime
            .reject_gateway_operation_without_credential(
                operation_context.clone(),
                classified.resource_scopes.clone(),
                error,
            )
            .await;
        return gateway_runtime_response(response);
    }
    let content_encoding =
        match validate_git_gateway_representation_headers(&headers, git_request_kind) {
            Ok(content_encoding) => content_encoding,
            Err(error) => {
                let response = runtime
                    .reject_gateway_operation_without_credential(
                        operation_context,
                        classified.resource_scopes,
                        error,
                    )
                    .await;
                return gateway_runtime_response(response);
            }
        };
    let receive_pack = if git_request_kind.is_receive_pack_post() {
        let git = matched_gateway
            .config
            .git
            .as_ref()
            .expect("git_http gateways are validated with git settings");
        match parse_receive_pack_body(
            body.take().expect("request body present"),
            git,
            &headers,
            &limits,
        )
        .await
        {
            Ok(receive_pack) => Some(receive_pack),
            Err(error) => {
                let response = runtime
                    .reject_gateway_operation_without_credential(
                        operation_context,
                        classified.resource_scopes,
                        error,
                    )
                    .await;
                return gateway_runtime_response(response);
            }
        }
    } else {
        None
    };
    let prepared = match runtime
        .prepare_gateway_operation(operation_context, classified.resource_scopes)
        .await
    {
        Ok(prepared) => prepared,
        Err(response) => return gateway_runtime_response(*response),
    };

    forward_prepared_git_http(
        runtime,
        matched_gateway.config,
        GatewayForwardRequest {
            git_request_kind,
            headers,
            body: body.unwrap_or_else(Body::empty),
            content_encoding,
            receive_pack,
        },
        prepared,
        Some(permits),
    )
    .await
}

async fn gateway_context(
    state: &AppState,
    ingress: GatewayIngressContext,
    headers: &HeaderMap,
    matched_gateway: &MatchedGateway,
    classified: &ClassifiedGatewayRequest,
) -> Result<GatewayContext, Box<Response<Body>>> {
    let GatewayIngressContext {
        admission,
        snapshot,
        agent_request_id,
        broker_request_id,
        source,
        execution_context,
    } = ingress;
    let global_permit = acquire_global_concurrency_guard(
        state,
        &snapshot,
        &agent_request_id,
        classified.service.clone(),
        classified.action.clone(),
        &source,
    )
    .await
    .map_err(|response| Box::new(gateway_runtime_response(*response)))?;

    let identity =
        match gateway_basic_identity(&snapshot, headers, matched_gateway, &admission).await {
            Ok(identity) => identity,
            Err(error) => {
                check_auth_source_rate_guard(
                    state,
                    &snapshot,
                    &agent_request_id,
                    classified.service.clone(),
                    classified.action.clone(),
                    &source,
                )
                .await
                .map_err(|response| Box::new(gateway_runtime_response(*response)))?;
                let response = snapshot
                    .runtime
                    .governed_operation_error_response(
                        GovernedOperationContext {
                            operation: OperationContext {
                                agent_request_id,
                                broker_request_id,
                                identity: IdentityContext::anonymous(),
                                service: classified.service.clone(),
                                action: classified.action.clone(),
                                source,
                            },
                            execution_context,
                        },
                        error,
                    )
                    .await;
                return Err(Box::new(gateway_runtime_response_with_basic_challenge(
                    response,
                )));
            }
        };

    let principal_permit = acquire_caller_guard(
        state,
        &snapshot,
        &agent_request_id,
        classified.service.clone(),
        classified.action.clone(),
        &source,
        CallerAdmission {
            identity: &identity,
        },
    )
    .await
    .map_err(|response| Box::new(gateway_runtime_response(*response)))?;

    // Only pack transfers invoke the service; ref discovery is not counted.
    let (identity, source, execution_context) = if classified.git_request_kind.is_pack_post() {
        let context = admit_service_invocation(
            state,
            &snapshot,
            GovernedOperationContext {
                operation: OperationContext {
                    agent_request_id: agent_request_id.clone(),
                    broker_request_id: broker_request_id.clone(),
                    identity,
                    service: classified.service.clone(),
                    action: classified.action.clone(),
                    source,
                },
                execution_context,
            },
        )
        .await
        .map_err(|response| Box::new(gateway_runtime_response(*response)))?;
        (
            context.operation.identity,
            context.operation.source,
            context.execution_context,
        )
    } else {
        (identity, source, execution_context)
    };

    Ok(GatewayContext {
        snapshot,
        agent_request_id,
        broker_request_id,
        identity,
        source,
        execution_context,
        permits: RequestPermits {
            _global: global_permit,
            _principal: principal_permit,
        },
    })
}

async fn gateway_preclass_auth_rate_response(
    state: &AppState,
    snapshot: &RuntimeSnapshot,
    agent_request_id: &str,
    broker_request_id: &str,
    source: &agent_access_core::SourceContext,
    matched_gateway: &MatchedGateway,
) -> Option<Response<Body>> {
    let limit = snapshot
        .runtime
        .limits()
        .auth_requests_per_source_per_minute;
    let error = state
        .reloadable
        .shared_ingress
        .check_auth_source_rate(&auth_source_key(source), limit)
        .err()?;
    let source_address = source_log_address(source);
    let provider_error = error.provider_error().clone();
    let reason_code = provider_error.reason_code();
    let status = reason_code.http_status();
    observability::record_request_ids(agent_request_id, broker_request_id);
    observability::record_service_action(&matched_gateway.service, "gateway.classify");
    observability::record_decision(provider_error.decision().as_str());
    observability::record_reason_code(reason_code.as_str());
    observability::record_status(status);
    tracing::warn!(
        event = "request_limited",
        agentRequestId = agent_request_id,
        brokerRequestId = broker_request_id,
        service = matched_gateway.service.as_str(),
        action = "gateway.classify",
        limitKind = error.kind().as_str(),
        limit = error.limit(),
        source = source_address.as_str(),
        principal = "",
        decision = provider_error.decision().as_str(),
        reasonCode = reason_code.as_str(),
        "http.statusCode" = status,
    );
    let response = snapshot
        .runtime
        .admission_limit_error_response(
            OperationContext {
                agent_request_id: agent_request_id.to_string(),
                broker_request_id: broker_request_id.to_string(),
                identity: IdentityContext::anonymous(),
                service: matched_gateway.service.clone(),
                action: "gateway.classify".to_string(),
                source: source.clone(),
            },
            error.into_provider_error(),
        )
        .await;
    Some(gateway_runtime_response(response))
}

async fn gateway_basic_identity(
    snapshot: &Arc<RuntimeSnapshot>,
    headers: &HeaderMap,
    matched_gateway: &MatchedGateway,
    admission: &agent_access_core::IngressAdmission,
) -> Result<IdentityContext, ProviderError> {
    if !headers.contains_key(AUTHORIZATION)
        && matched_gateway.config.allow_forwarded_identity
        && headers.contains_key("x-aw-identity-token-sha256")
    {
        let runtime = snapshot.runtime.clone();
        let headers = headers.clone();
        let admission = admission.clone();
        return tokio::task::spawn_blocking(move || {
            runtime.resolve_forwarded_identity(&headers, &admission)
        })
        .await
        .unwrap_or(Err(IdentityFailure::Invalid))
        .map_err(|_| {
            ProviderError::deny(
                ReasonCode::GatewayAuthInvalid,
                "gateway identity is invalid",
            )
        });
    }
    let token = match basic_broker_token(headers, matched_gateway) {
        Ok(token) => token,
        Err(error) => return Err(error),
    };
    let runtime = snapshot.runtime.clone();
    let caller_id = admission.caller_id().map(str::to_owned);
    tokio::task::spawn_blocking(move || {
        let mut identity = runtime.resolve_gateway_basic_broker_token(&token)?;
        identity.caller_id = caller_id;
        Ok(identity)
    })
    .await
    .unwrap_or(Err(IdentityFailure::Invalid))
    .map_err(|_| ProviderError::deny(ReasonCode::GatewayAuthInvalid, "gateway auth is invalid"))
}

fn basic_broker_token(
    headers: &HeaderMap,
    matched_gateway: &MatchedGateway,
) -> Result<String, ProviderError> {
    if !matched_gateway
        .config
        .auth_modes
        .iter()
        .any(|mode| mode == "basic_broker_token")
    {
        return Err(ProviderError::deny(
            ReasonCode::GatewayAuthInvalid,
            "gateway basic auth is not enabled",
        ));
    }
    let mut values = headers.get_all(AUTHORIZATION).iter();
    let Some(raw) = values.next() else {
        return Err(ProviderError::deny(
            ReasonCode::GatewayAuthRequired,
            "gateway basic auth is required",
        ));
    };
    if values.next().is_some() {
        return Err(ProviderError::deny(
            ReasonCode::GatewayAuthInvalid,
            "gateway auth is ambiguous",
        ));
    }
    let raw = raw.to_str().map_err(|_| {
        ProviderError::deny(ReasonCode::GatewayAuthInvalid, "gateway auth is invalid")
    })?;
    let Some(encoded) = raw.strip_prefix("Basic ") else {
        return Err(ProviderError::deny(
            ReasonCode::GatewayAuthRequired,
            "gateway basic auth is required",
        ));
    };
    let decoded = BASE64.decode(encoded).map_err(|_| {
        ProviderError::deny(ReasonCode::GatewayAuthInvalid, "gateway auth is invalid")
    })?;
    let decoded = String::from_utf8(decoded).map_err(|_| {
        ProviderError::deny(ReasonCode::GatewayAuthInvalid, "gateway auth is invalid")
    })?;
    let Some((username, token)) = decoded.split_once(':') else {
        return Err(ProviderError::deny(
            ReasonCode::GatewayAuthInvalid,
            "gateway auth is invalid",
        ));
    };
    if username != matched_gateway.config.basic_broker_token_username || token.is_empty() {
        return Err(ProviderError::deny(
            ReasonCode::GatewayAuthInvalid,
            "gateway auth is invalid",
        ));
    }
    Ok(token.to_string())
}

async fn forward_prepared_git_http(
    runtime: BrokerRuntime,
    gateway: GatewayConfig,
    request: GatewayForwardRequest,
    mut prepared: PreparedGatewayOperation,
    permits: Option<RequestPermits>,
) -> Response<Body> {
    let GatewayForwardRequest {
        git_request_kind,
        headers,
        body,
        content_encoding,
        receive_pack,
    } = request;
    let method = git_request_kind.method();
    let upstream_url =
        match gateway_upstream_url(&gateway, git_request_kind, &prepared.resource_scopes) {
            Ok(url) => url,
            Err(error) => {
                let response = runtime
                    .fail_prepared_gateway_operation(prepared, error)
                    .await;
                return gateway_runtime_response(response);
            }
        };
    if !url_allowed_by_patterns(&upstream_url, &gateway.allowed_upstream_hosts) {
        let response = runtime
            .fail_prepared_gateway_operation(
                prepared,
                ProviderError::error(
                    ReasonCode::GatewayUpstreamDenied,
                    "gateway upstream URL is not allowed",
                ),
            )
            .await;
        return gateway_runtime_response(response);
    }

    let limits = gateway_forward_limits(&runtime, &gateway);
    let git_audit = receive_pack
        .as_ref()
        .map(|receive_pack| receive_pack_audit_value(&receive_pack.updates));
    let request_body =
        match prepare_gateway_request_body(&method, &headers, body, receive_pack, &limits).await {
            Ok(request_body) => request_body,
            Err(error) => {
                let response = runtime
                    .fail_prepared_gateway_operation(prepared, error)
                    .await;
                return gateway_runtime_response(response);
            }
        };

    let (client, egress_proxy_audit) =
        match runtime.gateway_http_client(&prepared.service, &gateway) {
            Ok(client) => client,
            Err(_) => {
                let response = runtime
                    .fail_prepared_gateway_operation(
                        prepared,
                        ProviderError::error(
                            ReasonCode::GatewayUpstreamDenied,
                            "gateway upstream client is unavailable",
                        ),
                    )
                    .await;
                return gateway_runtime_response(response);
            }
        };

    let (replay_failure, upload_progress) = match &request_body {
        GatewayPreparedRequestBody::Stream {
            failure, progress, ..
        } => (Some(Arc::clone(failure)), Some(Arc::clone(progress))),
        GatewayPreparedRequestBody::Bytes(_) => (None, None),
    };

    let mut builder = if git_request_kind.is_pack_post() {
        let builder = client.post(upstream_url.clone());
        match request_body {
            GatewayPreparedRequestBody::Bytes(bytes) => builder.body(bytes),
            GatewayPreparedRequestBody::Stream { body, .. } => builder.body(body),
        }
    } else {
        client.get(upstream_url.clone())
    };
    builder = match apply_git_request_headers(builder, &headers, &method, content_encoding) {
        Ok(builder) => builder,
        Err(error) => {
            let response = runtime
                .fail_prepared_gateway_operation(prepared, error)
                .await;
            return gateway_runtime_response(response);
        }
    };
    if gateway.correlation_headers {
        builder = builder
            .header(
                REQUEST_ID_HEADER,
                prepared.correlation.agent_request_id.clone(),
            )
            .header(
                BROKER_REQUEST_ID_HEADER,
                prepared.correlation.broker_request_id.clone(),
            );
    }
    builder = match apply_gateway_credential(builder, &prepared.credential) {
        Ok(builder) => builder,
        Err(error) => {
            let response = runtime
                .fail_prepared_gateway_operation(prepared, error)
                .await;
            return gateway_runtime_response(response);
        }
    };

    if let Err(response) = runtime
        .start_prepared_gateway_operation(
            &mut prepared,
            gateway_forward_audit_with_git(
                &method,
                &upstream_url,
                egress_proxy_audit.clone(),
                0,
                git_audit.clone(),
            ),
        )
        .await
    {
        return gateway_runtime_response(*response);
    }

    let started = Instant::now();
    let upstream_response = match gateway_send_with_upload_watchdog(
        builder.send(),
        upload_progress,
        limits.idle_timeout,
    )
    .await
    {
        Ok(response) => response,
        Err(GatewaySendError::Inner(error)) => {
            let duration_ms = elapsed_millis(started);
            let replay_failure = replay_failure
                .as_ref()
                .map(|failure| failure.load(Ordering::Relaxed))
                .unwrap_or(REPLAY_FAILURE_NONE);
            let response = runtime
                .fail_prepared_gateway_operation(
                    prepared,
                    reqwest_error_to_provider_error(
                        error,
                        &method,
                        &upstream_url,
                        egress_proxy_audit,
                        git_audit,
                        replay_failure,
                    )
                    .with_upstream(None, Some(duration_ms)),
                )
                .await;
            return gateway_runtime_response(response);
        }
        Err(GatewaySendError::RequestUploadIdleTimeout) => {
            let duration_ms = elapsed_millis(started);
            let response = runtime
                .fail_prepared_gateway_operation(
                    prepared,
                    ProviderError::error(
                        ReasonCode::UpstreamTimeout,
                        "gateway upstream request upload timed out",
                    )
                    .with_upstream(None, Some(duration_ms))
                    .with_audit(gateway_forward_audit_with_git(
                        &method,
                        &upstream_url,
                        egress_proxy_audit,
                        0,
                        git_audit,
                    )),
                )
                .await;
            return gateway_runtime_response(response);
        }
        Err(GatewaySendError::ResponseHeadersIdleTimeout) => {
            let duration_ms = elapsed_millis(started);
            let response = runtime
                .fail_prepared_gateway_operation(
                    prepared,
                    ProviderError::error(
                        ReasonCode::UpstreamTimeout,
                        "gateway upstream response headers timed out",
                    )
                    .with_upstream(None, Some(duration_ms))
                    .with_audit(gateway_forward_audit_with_git(
                        &method,
                        &upstream_url,
                        egress_proxy_audit,
                        0,
                        git_audit,
                    )),
                )
                .await;
            return gateway_runtime_response(response);
        }
    };
    let upstream_status = upstream_response.status().as_u16();
    let response_headers = upstream_response.headers().clone();
    if response_content_length_exceeds(&response_headers, limits.response_body_max_bytes) {
        let duration_ms = elapsed_millis(started);
        let response = runtime
            .fail_prepared_gateway_operation(
                prepared,
                ProviderError::error(
                    ReasonCode::GatewayResponseCapExceeded,
                    "gateway upstream response exceeds configured cap",
                )
                .with_upstream(Some(upstream_status), Some(duration_ms))
                .with_audit(gateway_forward_audit_with_git(
                    &method,
                    &upstream_url,
                    egress_proxy_audit,
                    0,
                    git_audit,
                )),
            )
            .await;
        return gateway_runtime_response(response);
    }

    prepared.observe_gateway_response_progress(
        upstream_status,
        gateway_forward_audit_with_git(
            &method,
            &upstream_url,
            egress_proxy_audit.clone(),
            0,
            git_audit.clone(),
        ),
    );
    let broker_request_id = prepared.correlation.broker_request_id.clone();
    let response_body =
        Body::from_stream(gateway_response_body_stream(GatewayResponseStreamInput {
            runtime,
            prepared,
            method: method.clone(),
            upstream_url: upstream_url.clone(),
            egress_proxy_audit,
            upstream_status,
            started,
            limits,
            git_audit,
            body: Box::pin(upstream_response.bytes_stream()),
            permits,
        }));

    gateway_upstream_response(
        upstream_status,
        &broker_request_id,
        &response_headers,
        response_body,
    )
}

async fn gateway_send_with_upload_watchdog<F, T, E>(
    send: F,
    progress: Option<Arc<GatewayRequestUploadProgress>>,
    idle_timeout: Duration,
) -> Result<T, GatewaySendError<E>>
where
    F: Future<Output = Result<T, E>>,
{
    if let Some(progress) = progress {
        tokio::select! {
            result = send => result.map_err(GatewaySendError::Inner),
            timeout = progress.wait_for_send_idle_timeout(idle_timeout) => {
                match timeout {
                    GatewaySendIdleTimeout::RequestUpload => {
                        Err(GatewaySendError::RequestUploadIdleTimeout)
                    }
                    GatewaySendIdleTimeout::ResponseHeaders => {
                        Err(GatewaySendError::ResponseHeadersIdleTimeout)
                    }
                }
            }
        }
    } else {
        match timeout(idle_timeout, send).await {
            Ok(result) => result.map_err(GatewaySendError::Inner),
            Err(_) => Err(GatewaySendError::ResponseHeadersIdleTimeout),
        }
    }
}

fn gateway_upstream_url(
    gateway: &GatewayConfig,
    git_request_kind: GitRequestKind,
    resource_scopes: &ResourceScopes,
) -> Result<Url, ProviderError> {
    let mut url = Url::parse(&gateway.upstream_base_url).map_err(|_| {
        ProviderError::error(
            ReasonCode::GatewayUpstreamDenied,
            "gateway upstream base URL is invalid",
        )
    })?;
    let repository = resource_scopes
        .get("repository")
        .and_then(|repositories| match repositories.as_slice() {
            [repository] if agent_access_provider::is_canonical_repository_path(repository) => {
                Some(repository)
            }
            _ => None,
        })
        .ok_or_else(|| {
            ProviderError::error(
                ReasonCode::GatewayUpstreamDenied,
                "gateway authorized repository is invalid",
            )
        })?;
    // Build from the repository identity already authorized by policy and the
    // classified operation. Both incoming clone URL forms use the same .git
    // upstream path, including subsequent fetch and push POSTs.
    let (suffix, query) = match git_request_kind {
        GitRequestKind::UploadPackDiscovery => ("info/refs", Some("service=git-upload-pack")),
        GitRequestKind::ReceivePackDiscovery => ("info/refs", Some("service=git-receive-pack")),
        GitRequestKind::UploadPackPost => ("git-upload-pack", None),
        GitRequestKind::ReceivePackPost => ("git-receive-pack", None),
    };
    let repository_path = format!("/{repository}.git/{suffix}");
    let base_path = url.path().trim_end_matches('/');
    let upstream_path = if base_path.is_empty() || base_path == "/" {
        repository_path
    } else {
        format!("{base_path}{repository_path}")
    };
    url.set_path(&upstream_path);
    url.set_query(query);
    Ok(url)
}

fn gateway_body_read_error(
    error: &(dyn std::error::Error + 'static),
    receive_pack: bool,
) -> ProviderError {
    if body_error_exceeds_limit(error) {
        ProviderError::deny(
            ReasonCode::GatewayRequestCapExceeded,
            "gateway request body exceeds configured cap",
        )
    } else if body_error_timed_out(error) {
        ProviderError::deny(
            ReasonCode::GatewayRequestBodyDenied,
            "gateway request body read timed out",
        )
    } else if receive_pack {
        ProviderError::deny(
            ReasonCode::GitPktLineMalformed,
            "gateway git receive-pack request body read failed",
        )
    } else {
        ProviderError::deny(
            ReasonCode::GatewayRequestBodyDenied,
            "gateway request body read failed",
        )
    }
}

async fn gateway_request_body_bytes(
    method: &Method,
    headers: &HeaderMap,
    mut body: Body,
    limits: &GatewayForwardLimits,
) -> Result<Vec<u8>, ProviderError> {
    if content_length_exceeds(headers, limits.request_body_max_bytes) {
        return Err(ProviderError::deny(
            ReasonCode::GatewayRequestCapExceeded,
            "gateway request body exceeds configured cap",
        ));
    }
    if method == Method::GET && content_length_value(headers).is_some_and(|length| length > 0) {
        return Err(ProviderError::deny(
            ReasonCode::GatewayRequestBodyDenied,
            "gateway GET requests must not include a body",
        ));
    }
    let mut bytes = Vec::new();
    loop {
        let frame = match timeout(limits.idle_timeout, body.frame()).await {
            Ok(Some(Ok(frame))) => frame,
            Ok(Some(Err(error))) => {
                return Err(gateway_body_read_error(&error, false));
            }
            Ok(None) => break,
            Err(_) => return Err(timeout_error("gateway request body read timed out")),
        };
        let Ok(chunk) = frame.into_data() else {
            continue;
        };
        if method == Method::GET && !chunk.is_empty() {
            return Err(ProviderError::deny(
                ReasonCode::GatewayRequestBodyDenied,
                "gateway GET requests must not include a body",
            ));
        }
        if bytes.len().saturating_add(chunk.len()) > limits.request_body_max_bytes {
            return Err(ProviderError::deny(
                ReasonCode::GatewayRequestCapExceeded,
                "gateway request body exceeds configured cap",
            ));
        }
        bytes.extend_from_slice(&chunk);
    }
    Ok(bytes)
}

async fn prepare_gateway_request_body(
    method: &Method,
    headers: &HeaderMap,
    body: Body,
    receive_pack: Option<ReceivePackBody>,
    limits: &GatewayForwardLimits,
) -> Result<GatewayPreparedRequestBody, ProviderError> {
    if let Some(receive_pack) = receive_pack {
        if content_length_exceeds(headers, limits.request_body_max_bytes) {
            return Err(ProviderError::deny(
                ReasonCode::GatewayRequestCapExceeded,
                "gateway request body exceeds configured cap",
            )
            .with_audit(json!({
                "git": receive_pack_audit_value(&receive_pack.updates),
            })));
        }
        if receive_pack
            .prefix
            .len()
            .saturating_add(receive_pack.replay.len())
            > limits.request_body_max_bytes
        {
            return Err(ProviderError::deny(
                ReasonCode::GatewayRequestCapExceeded,
                "gateway request body exceeds configured cap",
            )
            .with_audit(json!({
                "git": receive_pack_audit_value(&receive_pack.updates),
            })));
        }
        let (body, failure, progress) = gateway_request_replay_body(receive_pack, limits);
        return Ok(GatewayPreparedRequestBody::Stream {
            body,
            failure,
            progress,
        });
    }

    if method == Method::POST {
        if content_length_exceeds(headers, limits.request_body_max_bytes) {
            return Err(ProviderError::deny(
                ReasonCode::GatewayRequestCapExceeded,
                "gateway request body exceeds configured cap",
            ));
        }
        let (body, failure, progress) = gateway_request_stream_body(body, limits);
        return Ok(GatewayPreparedRequestBody::Stream {
            body,
            failure,
            progress,
        });
    }

    gateway_request_body_bytes(method, headers, body, limits)
        .await
        .map(GatewayPreparedRequestBody::Bytes)
}

fn gateway_request_stream_body(
    body: Body,
    limits: &GatewayForwardLimits,
) -> (
    reqwest::Body,
    Arc<AtomicU8>,
    Arc<GatewayRequestUploadProgress>,
) {
    gateway_request_body_stream(VecDeque::new(), body, limits)
}

fn gateway_request_replay_body(
    receive_pack: ReceivePackBody,
    limits: &GatewayForwardLimits,
) -> (
    reqwest::Body,
    Arc<AtomicU8>,
    Arc<GatewayRequestUploadProgress>,
) {
    let mut initial = VecDeque::new();
    if !receive_pack.prefix.is_empty() {
        initial.push_back(receive_pack.prefix);
    }
    if !receive_pack.replay.is_empty() {
        initial.push_back(receive_pack.replay);
    }
    gateway_request_body_stream(initial, receive_pack.remaining, limits)
}

fn gateway_request_body_stream(
    initial: VecDeque<Bytes>,
    remaining: Body,
    limits: &GatewayForwardLimits,
) -> (
    reqwest::Body,
    Arc<AtomicU8>,
    Arc<GatewayRequestUploadProgress>,
) {
    let failure = Arc::new(AtomicU8::new(REPLAY_FAILURE_NONE));
    let progress = Arc::new(GatewayRequestUploadProgress::new());
    let state = GatewayRequestReplayStreamState {
        initial,
        remaining,
        sent: 0,
        max_bytes: limits.request_body_max_bytes,
        idle_timeout: limits.idle_timeout,
        failure: Arc::clone(&failure),
        progress: Arc::clone(&progress),
    };
    let body = reqwest::Body::wrap_stream(stream::unfold(state, |mut state| async move {
        loop {
            if let Some(chunk) = state.initial.pop_front() {
                if state.sent.saturating_add(chunk.len()) > state.max_bytes {
                    state
                        .failure
                        .store(REPLAY_FAILURE_CAP_EXCEEDED, Ordering::Relaxed);
                    return Some((
                        Err(io::Error::other(
                            "gateway request body exceeds configured cap",
                        )),
                        state,
                    ));
                }
                state.sent += chunk.len();
                state.progress.mark_progress();
                return Some((Ok(chunk), state));
            }

            let frame = match timeout(state.idle_timeout, state.remaining.frame()).await {
                Ok(Some(Ok(frame))) => frame,
                Ok(Some(Err(error))) => {
                    let failure = if body_error_exceeds_limit(&error) {
                        REPLAY_FAILURE_CAP_EXCEEDED
                    } else if body_error_timed_out(&error) {
                        REPLAY_FAILURE_TIMEOUT
                    } else {
                        REPLAY_FAILURE_BODY_READ
                    };
                    state.failure.store(failure, Ordering::Relaxed);
                    return Some((
                        Err(io::Error::other("gateway request body stream failed")),
                        state,
                    ));
                }
                Ok(None) => {
                    state.progress.mark_complete();
                    return None;
                }
                Err(_) => {
                    state
                        .failure
                        .store(REPLAY_FAILURE_TIMEOUT, Ordering::Relaxed);
                    return Some((
                        Err(io::Error::new(
                            io::ErrorKind::TimedOut,
                            "gateway request body read timed out",
                        )),
                        state,
                    ));
                }
            };
            let Ok(chunk) = frame.into_data() else {
                continue;
            };
            if chunk.is_empty() {
                continue;
            }
            if state.sent.saturating_add(chunk.len()) > state.max_bytes {
                state
                    .failure
                    .store(REPLAY_FAILURE_CAP_EXCEEDED, Ordering::Relaxed);
                return Some((
                    Err(io::Error::other(
                        "gateway request body exceeds configured cap",
                    )),
                    state,
                ));
            }
            state.sent += chunk.len();
            state.progress.mark_progress();
            return Some((Ok(chunk), state));
        }
    }));
    (body, failure, progress)
}

async fn parse_receive_pack_body(
    mut body: Body,
    git: &GatewayGitConfig,
    headers: &HeaderMap,
    limits: &GatewayForwardLimits,
) -> Result<ReceivePackBody, ProviderError> {
    if content_length_exceeds(headers, limits.request_body_max_bytes) {
        return Err(receive_pack_error(
            ReasonCode::GatewayRequestCapExceeded,
            "gateway request body exceeds configured cap",
            &[],
        ));
    }

    let prefix_cap = receive_pack_prefix_cap(git, limits);
    let mut pending = Vec::new();
    let mut prefix = Vec::new();
    let mut updates = Vec::new();

    loop {
        while pending.len() < 4 {
            read_receive_pack_prefix_frame(
                &mut body,
                &mut pending,
                prefix.len(),
                prefix_cap,
                limits.request_body_max_bytes,
                limits.idle_timeout,
                &updates,
            )
            .await?;
        }

        let length = parse_pkt_line_length(&pending[..4]).map_err(|error| {
            error.with_audit(json!({
                "git": receive_pack_audit_value(&updates),
            }))
        })?;
        match length {
            0 => {
                if updates.is_empty() {
                    return Err(receive_pack_error(
                        ReasonCode::GitPktLineMalformed,
                        "gateway git receive-pack command list is empty",
                        &updates,
                    ));
                }
                if prefix.len().saturating_add(4) > prefix_cap {
                    return Err(receive_pack_error(
                        ReasonCode::GitPrefixCapExceeded,
                        "gateway git receive-pack prefix exceeds configured cap",
                        &updates,
                    ));
                }
                prefix.extend(pending.drain(..4));
                if prefix.len().saturating_add(pending.len()) > limits.request_body_max_bytes {
                    return Err(receive_pack_error(
                        ReasonCode::GatewayRequestCapExceeded,
                        "gateway request body exceeds configured cap",
                        &updates,
                    ));
                }
                return Ok(ReceivePackBody {
                    prefix: Bytes::from(prefix),
                    replay: Bytes::from(pending),
                    remaining: body,
                    updates,
                });
            }
            1 | 2 => {
                return Err(receive_pack_error(
                    ReasonCode::GitPktLineMalformed,
                    "gateway git receive-pack command list uses unsupported pkt-line marker",
                    &updates,
                ));
            }
            3 => {
                return Err(receive_pack_error(
                    ReasonCode::GitPktLineMalformed,
                    "gateway git receive-pack pkt-line length is invalid",
                    &updates,
                ));
            }
            _ if length > GIT_MAX_PKT_LINE_BYTES => {
                return Err(receive_pack_error(
                    ReasonCode::GitPktLineMalformed,
                    "gateway git receive-pack pkt-line exceeds Git maximum length",
                    &updates,
                ));
            }
            _ => {}
        }

        while pending.len() < length {
            read_receive_pack_prefix_frame(
                &mut body,
                &mut pending,
                prefix.len(),
                prefix_cap,
                limits.request_body_max_bytes,
                limits.idle_timeout,
                &updates,
            )
            .await?;
        }

        if prefix.len().saturating_add(length) > prefix_cap {
            return Err(receive_pack_error(
                ReasonCode::GitPrefixCapExceeded,
                "gateway git receive-pack prefix exceeds configured cap",
                &updates,
            ));
        }
        let packet = pending.drain(..length).collect::<Vec<_>>();
        // Shallow clients announce boundary objects before the first update.
        // These packets are part of the bounded prefix, not ref commands.
        if let Some(object) = packet[4..].strip_prefix(b"shallow ") {
            let object = object.strip_suffix(b"\n").unwrap_or(object);
            let valid = std::str::from_utf8(object)
                .is_ok_and(|id| is_git_object_id(id) && !is_zero_object_id(id));
            if !updates.is_empty() || !valid {
                return Err(receive_pack_error(
                    ReasonCode::GitPktLineMalformed,
                    "gateway git receive-pack shallow declaration is malformed or out of order",
                    &updates,
                ));
            }
            prefix.extend_from_slice(&packet);
            continue;
        }
        let parsed =
            parse_receive_pack_command(&packet[4..], updates.is_empty()).map_err(|error| {
                error.with_audit(json!({
                    "git": receive_pack_audit_value(&updates),
                }))
            })?;
        updates.push(parsed.update);
        validate_receive_pack_update(updates.last().expect("just pushed update"), git).map_err(
            |error| {
                error.with_audit(json!({
                    "git": receive_pack_audit_value(&updates),
                }))
            },
        )?;
        validate_receive_pack_capabilities(&parsed.capabilities).map_err(|error| {
            error.with_audit(json!({
                "git": receive_pack_audit_value(&updates),
            }))
        })?;
        prefix.extend_from_slice(&packet);
    }
}

async fn read_receive_pack_prefix_frame(
    body: &mut Body,
    pending: &mut Vec<u8>,
    prefix_len: usize,
    prefix_cap: usize,
    request_cap: usize,
    idle_timeout: Duration,
    updates: &[GitRefUpdate],
) -> Result<(), ProviderError> {
    loop {
        if prefix_len.saturating_add(pending.len()) > prefix_cap {
            return Err(receive_pack_error(
                ReasonCode::GitPrefixCapExceeded,
                "gateway git receive-pack prefix exceeds configured cap",
                updates,
            ));
        }
        let frame = match timeout(idle_timeout, body.frame()).await {
            Ok(Some(Ok(frame))) => frame,
            Ok(Some(Err(error))) => {
                return Err(gateway_body_read_error(&error, true).with_audit(json!({
                    "git": receive_pack_audit_value(updates),
                })));
            }
            Ok(None) => {
                return Err(receive_pack_error(
                    ReasonCode::GitPktLineMalformed,
                    "gateway git receive-pack command list ended before flush",
                    updates,
                ));
            }
            Err(_) => {
                return Err(ProviderError::deny(
                    ReasonCode::GatewayRequestBodyDenied,
                    "gateway git receive-pack request body read timed out",
                )
                .with_audit(json!({
                    "git": receive_pack_audit_value(updates),
                })));
            }
        };
        let Ok(chunk) = frame.into_data() else {
            continue;
        };
        if chunk.is_empty() {
            continue;
        }
        if prefix_len
            .saturating_add(pending.len())
            .saturating_add(chunk.len())
            > request_cap
        {
            return Err(receive_pack_error(
                ReasonCode::GatewayRequestCapExceeded,
                "gateway request body exceeds configured cap",
                updates,
            ));
        }
        pending.extend_from_slice(&chunk);
        if receive_pack_prefix_over_cap_without_flush(pending, prefix_len, prefix_cap) {
            return Err(receive_pack_error(
                ReasonCode::GitPrefixCapExceeded,
                "gateway git receive-pack prefix exceeds configured cap",
                updates,
            ));
        }
        return Ok(());
    }
}

fn receive_pack_prefix_cap(git: &GatewayGitConfig, limits: &GatewayForwardLimits) -> usize {
    git.receive_pack_prefix_max_bytes
        .map(cap_to_usize)
        .unwrap_or(DEFAULT_RECEIVE_PACK_PREFIX_MAX_BYTES)
        .min(limits.request_body_max_bytes)
}

fn receive_pack_prefix_over_cap_without_flush(
    pending: &[u8],
    prefix_len: usize,
    prefix_cap: usize,
) -> bool {
    let mut offset = 0;
    let mut simulated_prefix_len = prefix_len;
    loop {
        let remaining = &pending[offset..];
        if remaining.len() < 4 {
            return simulated_prefix_len.saturating_add(remaining.len()) > prefix_cap;
        }
        let Ok(length) = parse_pkt_line_length(&remaining[..4]) else {
            return false;
        };
        match length {
            0 => return simulated_prefix_len.saturating_add(4) > prefix_cap,
            1..=3 => return false,
            _ if length > GIT_MAX_PKT_LINE_BYTES => return false,
            _ => {}
        }
        if simulated_prefix_len.saturating_add(length) > prefix_cap {
            return true;
        }
        if remaining.len() < length {
            return simulated_prefix_len.saturating_add(remaining.len()) > prefix_cap;
        }
        offset += length;
        simulated_prefix_len += length;
    }
}

struct ParsedReceivePackCommand {
    update: GitRefUpdate,
    capabilities: Vec<String>,
}

fn parse_receive_pack_command(
    payload: &[u8],
    first: bool,
) -> Result<ParsedReceivePackCommand, ProviderError> {
    let text = std::str::from_utf8(payload).map_err(|_| {
        ProviderError::deny(
            ReasonCode::GitPktLineMalformed,
            "gateway git receive-pack command is not valid UTF-8",
        )
    })?;
    let text = text.strip_suffix('\n').unwrap_or(text);
    let (command, capabilities) = if first {
        let (command, capabilities) = text.split_once('\0').ok_or_else(|| {
            ProviderError::deny(
                ReasonCode::GitPktLineMalformed,
                "gateway git receive-pack first command is missing capabilities",
            )
        })?;
        (
            command,
            capabilities
                .split(' ')
                .filter(|capability| !capability.is_empty())
                .map(str::to_string)
                .collect(),
        )
    } else {
        if text.contains('\0') {
            return Err(ProviderError::deny(
                ReasonCode::GitPktLineMalformed,
                "gateway git receive-pack capability suffix is only allowed on the first command",
            ));
        }
        (text, Vec::new())
    };

    let mut fields = command.split(' ');
    let old_id = fields.next().unwrap_or_default();
    let new_id = fields.next().unwrap_or_default();
    let ref_name = fields.next().unwrap_or_default();
    if old_id.is_empty()
        || new_id.is_empty()
        || ref_name.is_empty()
        || fields.next().is_some()
        || !is_git_object_id(old_id)
        || !is_git_object_id(new_id)
        || !is_git_ref_name(ref_name)
    {
        return Err(ProviderError::deny(
            ReasonCode::GitPktLineMalformed,
            "gateway git receive-pack command is malformed",
        ));
    }
    let create = is_zero_object_id(old_id);
    let delete = is_zero_object_id(new_id);
    if create && delete {
        return Err(ProviderError::deny(
            ReasonCode::GitPktLineMalformed,
            "gateway git receive-pack command has no source or target object",
        ));
    }
    Ok(ParsedReceivePackCommand {
        update: GitRefUpdate {
            old_id: old_id.to_string(),
            new_id: new_id.to_string(),
            ref_name: ref_name.to_string(),
            create,
            delete,
        },
        capabilities,
    })
}

fn validate_receive_pack_update(
    update: &GitRefUpdate,
    git: &GatewayGitConfig,
) -> Result<(), ProviderError> {
    if update.ref_name.starts_with("refs/tags/") {
        return Err(ProviderError::deny(
            ReasonCode::GitRefDenied,
            "gateway git receive-pack tag updates are denied",
        ));
    }
    if git.deny_delete_refs && update.delete {
        return Err(ProviderError::deny(
            ReasonCode::GitRefDenied,
            "gateway git receive-pack delete-ref updates are denied",
        ));
    }
    if git
        .deny_ref_patterns
        .iter()
        .any(|pattern| git_ref_matches_pattern(&update.ref_name, pattern))
    {
        return Err(ProviderError::deny(
            ReasonCode::GitRefDenied,
            "gateway git receive-pack ref is denied by policy",
        ));
    }
    Ok(())
}

fn validate_receive_pack_capabilities(capabilities: &[String]) -> Result<(), ProviderError> {
    for capability in capabilities {
        if !is_allowed_receive_pack_capability(capability) {
            return Err(ProviderError::deny(
                ReasonCode::GitCapabilityDenied,
                format!("gateway git receive-pack capability {capability} is denied"),
            ));
        }
    }
    Ok(())
}

fn is_allowed_receive_pack_capability(capability: &str) -> bool {
    matches!(
        capability,
        "report-status"
            | "report-status-v2"
            | "side-band-64k"
            | "quiet"
            | "object-format=sha1"
            | "object-format=sha256"
    ) || capability.starts_with("agent=")
}

fn parse_pkt_line_length(prefix: &[u8]) -> Result<usize, ProviderError> {
    if prefix.len() != 4 || !prefix.iter().all(u8::is_ascii_hexdigit) {
        return Err(ProviderError::deny(
            ReasonCode::GitPktLineMalformed,
            "gateway git receive-pack pkt-line length prefix is malformed",
        ));
    }
    let text = std::str::from_utf8(prefix).map_err(|_| {
        ProviderError::deny(
            ReasonCode::GitPktLineMalformed,
            "gateway git receive-pack pkt-line length prefix is malformed",
        )
    })?;
    usize::from_str_radix(text, 16).map_err(|_| {
        ProviderError::deny(
            ReasonCode::GitPktLineMalformed,
            "gateway git receive-pack pkt-line length prefix is malformed",
        )
    })
}

fn is_git_object_id(value: &str) -> bool {
    matches!(value.len(), 40 | 64) && value.as_bytes().iter().all(u8::is_ascii_hexdigit)
}

fn is_zero_object_id(value: &str) -> bool {
    value.as_bytes().iter().all(|byte| *byte == b'0')
}

fn is_git_ref_name(value: &str) -> bool {
    if value.is_empty()
        || !value.starts_with("refs/")
        || value.contains('\\')
        || value.contains("//")
        || value.contains("..")
        || value.chars().any(char::is_control)
    {
        return false;
    }
    value
        .split('/')
        .all(|segment| !segment.is_empty() && segment != "." && segment != "..")
}

fn git_ref_matches_pattern(ref_name: &str, pattern: &str) -> bool {
    if let Some(prefix) = pattern.strip_suffix("/**") {
        ref_name
            .strip_prefix(prefix)
            .is_some_and(|rest| rest.starts_with('/'))
    } else {
        ref_name == pattern
    }
}

fn receive_pack_error(
    reason_code: ReasonCode,
    message: impl Into<String>,
    updates: &[GitRefUpdate],
) -> ProviderError {
    ProviderError::deny(reason_code, message).with_audit(json!({
        "git": receive_pack_audit_value(updates),
    }))
}

fn receive_pack_audit_value(updates: &[GitRefUpdate]) -> serde_json::Value {
    json!({
        "operation": "receive-pack",
        "updates": updates
            .iter()
            .map(|update| {
                json!({
                    "oldId": update.old_id,
                    "newId": update.new_id,
                    "ref": update.ref_name,
                    "create": update.create,
                    "delete": update.delete,
                })
            })
            .collect::<Vec<_>>(),
    })
}

fn gateway_forward_limits(
    runtime: &BrokerRuntime,
    gateway: &GatewayConfig,
) -> GatewayForwardLimits {
    let limits = runtime.limits();
    GatewayForwardLimits {
        request_body_max_bytes: cap_to_usize(
            gateway
                .request_body_max_bytes
                .unwrap_or(limits.max_http_body_bytes)
                .min(limits.max_http_body_bytes),
        ),
        response_body_max_bytes: cap_to_usize(
            gateway
                .response_body_max_bytes
                .unwrap_or(limits.max_upstream_response_bytes),
        ),
        idle_timeout: Duration::from_millis(
            gateway
                .streaming_idle_timeout_ms
                .unwrap_or(limits.streaming_idle_timeout_ms),
        ),
    }
}

fn cap_to_usize(cap: u64) -> usize {
    usize::try_from(cap).unwrap_or(usize::MAX)
}

fn content_length_exceeds(headers: &HeaderMap, cap: usize) -> bool {
    content_length_value(headers).is_some_and(|length| length > cap as u128)
}

fn content_length_value(headers: &HeaderMap) -> Option<u128> {
    headers
        .get(CONTENT_LENGTH)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.parse::<u128>().ok())
}

fn response_content_length_exceeds(headers: &reqwest::header::HeaderMap, cap: usize) -> bool {
    headers
        .get(reqwest::header::CONTENT_LENGTH)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.parse::<u128>().ok())
        .is_some_and(|length| length > cap as u128)
}

fn timeout_error(message: &'static str) -> ProviderError {
    ProviderError::error(ReasonCode::UpstreamTimeout, message)
}

fn validate_git_gateway_representation_headers(
    headers: &HeaderMap,
    kind: GitRequestKind,
) -> Result<Option<GitContentEncoding>, ProviderError> {
    if headers.contains_key(TRAILER) {
        return Err(gateway_header_denied(
            "Git gateway Trailer header is not allowed",
        ));
    }

    let mut values = headers.get_all(CONTENT_ENCODING).iter();
    let Some(raw) = values.next() else {
        return Ok(None);
    };
    if values.next().is_some() {
        return Err(gateway_header_denied(
            "Git Content-Encoding header is ambiguous",
        ));
    }
    let value = raw
        .to_str()
        .map_err(|_| gateway_header_denied("Git Content-Encoding is invalid"))?
        .trim();
    if !value.eq_ignore_ascii_case("gzip") {
        return Err(gateway_header_denied("Git Content-Encoding is not allowed"));
    }
    if kind.is_upload_pack_post() {
        return Ok(Some(GitContentEncoding::Gzip));
    }
    if kind.is_receive_pack_post() {
        return Err(gateway_header_denied(
            "Git receive-pack Content-Encoding is not supported",
        ));
    }
    Err(gateway_header_denied(
        "Git discovery Content-Encoding is not supported",
    ))
}

fn gateway_header_denied(message: &'static str) -> ProviderError {
    ProviderError::deny(ReasonCode::GatewayHeaderDenied, message)
}

fn apply_git_request_headers(
    mut builder: reqwest::RequestBuilder,
    headers: &HeaderMap,
    method: &Method,
    content_encoding: Option<GitContentEncoding>,
) -> Result<reqwest::RequestBuilder, ProviderError> {
    for name in ["Accept", "User-Agent"] {
        builder = apply_single_request_header(builder, headers, name)?;
    }
    builder = apply_single_request_header(builder, headers, "Git-Protocol")?;
    if method == Method::POST {
        builder = apply_single_request_header(builder, headers, "Content-Type")?;
    }
    if let Some(content_encoding) = content_encoding {
        builder = builder.header(
            reqwest::header::CONTENT_ENCODING,
            content_encoding.header_value(),
        );
    }
    Ok(builder)
}

fn apply_single_request_header(
    builder: reqwest::RequestBuilder,
    headers: &HeaderMap,
    name: &str,
) -> Result<reqwest::RequestBuilder, ProviderError> {
    let mut values = headers.get_all(name).iter();
    let Some(raw) = values.next() else {
        return Ok(builder);
    };
    if values.next().is_some() {
        return Err(ProviderError::deny(
            ReasonCode::GatewayHeaderDenied,
            format!("gateway request header {name} is ambiguous"),
        ));
    }
    let value = raw.to_str().map_err(|_| {
        ProviderError::deny(
            ReasonCode::GatewayHeaderDenied,
            format!("gateway request header {name} is invalid"),
        )
    })?;
    let name = reqwest::header::HeaderName::from_bytes(name.as_bytes()).map_err(|_| {
        ProviderError::deny(
            ReasonCode::GatewayHeaderDenied,
            "gateway request header name is invalid",
        )
    })?;
    Ok(builder.header(name, value))
}

fn apply_gateway_credential(
    builder: reqwest::RequestBuilder,
    credential: &ExecutionCredential,
) -> Result<reqwest::RequestBuilder, ProviderError> {
    match credential.kind() {
        StaticCredentialKind::BearerToken | StaticCredentialKind::BasicApiToken => {
            Ok(credential.authorization().apply(builder))
        }
        _ => Err(ProviderError::deny(
            ReasonCode::CredentialInvalid,
            "the Git gateway does not support this credential kind",
        )),
    }
}

pub(crate) fn gateway_response_body_stream(
    input: GatewayResponseStreamInput,
) -> impl Stream<Item = Result<Bytes, io::Error>> + Send + 'static {
    let state = GatewayResponseStreamState {
        runtime: input.runtime,
        prepared: Some(input.prepared),
        method: input.method,
        upstream_url: input.upstream_url,
        egress_proxy_audit: input.egress_proxy_audit,
        upstream_status: input.upstream_status,
        started: input.started,
        limits: input.limits,
        git_audit: input.git_audit,
        body: input.body,
        bytes_sent: 0,
        _permits: input.permits,
    };
    stream::unfold(state, |mut state| async move {
        let prepared = state.prepared.take()?;
        let next = timeout(state.limits.idle_timeout, state.body.try_next())
            .await
            .map_err(|_| timeout_error("gateway upstream response timed out"))
            .and_then(|result| {
                result.map_err(|_| {
                    ProviderError::error(
                        ReasonCode::UpstreamProtocolFailed,
                        "gateway upstream response stream failed",
                    )
                })
            });
        match next {
            Ok(Some(chunk)) => {
                if state.bytes_sent.saturating_add(chunk.len())
                    > state.limits.response_body_max_bytes
                {
                    let error = ProviderError::error(
                        ReasonCode::GatewayResponseCapExceeded,
                        "gateway upstream response exceeds configured cap",
                    );
                    let (item, state) = fail_gateway_response_stream(state, prepared, error).await;
                    return Some((Err(item), state));
                }
                state.bytes_sent += chunk.len();
                prepared.observe_gateway_response_progress(
                    state.upstream_status,
                    gateway_forward_audit_with_git(
                        &state.method,
                        &state.upstream_url,
                        state.egress_proxy_audit.clone(),
                        state.bytes_sent,
                        state.git_audit.clone(),
                    ),
                );
                state.prepared = Some(prepared);
                Some((Ok(chunk), state))
            }
            Ok(None) => {
                complete_gateway_response_stream(state, prepared).await;
                None
            }
            Err(error) => {
                let (item, state) = fail_gateway_response_stream(state, prepared, error).await;
                Some((Err(item), state))
            }
        }
    })
}

async fn complete_gateway_response_stream(
    state: GatewayResponseStreamState,
    prepared: PreparedGatewayOperation,
) {
    let duration_ms = elapsed_millis(state.started);
    let audit = gateway_forward_audit_with_git(
        &state.method,
        &state.upstream_url,
        state.egress_proxy_audit,
        state.bytes_sent,
        state.git_audit,
    );
    let _ = state
        .runtime
        .complete_prepared_gateway_operation(prepared, state.upstream_status, duration_ms, audit)
        .await;
}

async fn fail_gateway_response_stream(
    mut state: GatewayResponseStreamState,
    prepared: PreparedGatewayOperation,
    error: ProviderError,
) -> (io::Error, GatewayResponseStreamState) {
    let duration_ms = elapsed_millis(state.started);
    let message = error.message.clone();
    let audit = gateway_forward_audit_with_git(
        &state.method,
        &state.upstream_url,
        state.egress_proxy_audit.clone(),
        state.bytes_sent,
        state.git_audit.clone(),
    );
    let _ = state
        .runtime
        .fail_prepared_gateway_operation(
            prepared,
            error
                .with_upstream(Some(state.upstream_status), Some(duration_ms))
                .with_audit(audit),
        )
        .await;
    state.prepared = None;
    (io::Error::other(message), state)
}

fn reqwest_error_to_provider_error(
    error: reqwest::Error,
    method: &Method,
    upstream_url: &Url,
    egress_proxy_audit: serde_json::Value,
    git_audit: Option<serde_json::Value>,
    replay_failure: u8,
) -> ProviderError {
    let replay_error = match replay_failure {
        REPLAY_FAILURE_CAP_EXCEEDED => Some(ProviderError::deny(
            ReasonCode::GatewayRequestCapExceeded,
            "gateway request body exceeds configured cap",
        )),
        REPLAY_FAILURE_TIMEOUT => Some(ProviderError::deny(
            ReasonCode::GatewayRequestBodyDenied,
            "gateway request body read timed out",
        )),
        REPLAY_FAILURE_BODY_READ => Some(ProviderError::deny(
            ReasonCode::GatewayRequestBodyDenied,
            "gateway request body stream failed",
        )),
        _ => None,
    };
    if let Some(error) = replay_error {
        return error.with_audit(gateway_forward_audit_with_git(
            method,
            upstream_url,
            egress_proxy_audit,
            0,
            git_audit,
        ));
    }

    let reason_code = if error.is_timeout() {
        ReasonCode::UpstreamTimeout
    } else if error.is_connect() {
        ReasonCode::UpstreamConnectionFailed
    } else {
        ReasonCode::UpstreamProtocolFailed
    };
    ProviderError::error(reason_code, "gateway upstream request failed").with_audit(
        gateway_forward_audit_with_git(method, upstream_url, egress_proxy_audit, 0, git_audit),
    )
}

fn gateway_forward_audit_with_git(
    method: &Method,
    upstream_url: &Url,
    egress_proxy_audit: serde_json::Value,
    response_bytes: usize,
    git_audit: Option<serde_json::Value>,
) -> serde_json::Value {
    let mut audit = json!({
        "gateway": {
            "kind": "git_http",
            "method": method.as_str(),
            "upstreamOrigin": upstream_origin(upstream_url),
            "upstreamPath": upstream_url.path(),
            "egressProxy": egress_proxy_audit,
            "responseBytes": response_bytes,
        }
    });
    if let Some(git_audit) = git_audit
        && let Some(object) = audit.as_object_mut()
    {
        object.insert("git".to_string(), git_audit);
    }
    audit
}

fn upstream_origin(url: &Url) -> String {
    let host = url.host_str().unwrap_or_default();
    match url.port() {
        Some(port) => format!("{}://{}:{}", url.scheme(), host, port),
        None => format!("{}://{}", url.scheme(), host),
    }
}

fn elapsed_millis(started: Instant) -> u64 {
    u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX)
}

fn gateway_upstream_response(
    upstream_status: u16,
    broker_request_id: &str,
    upstream_headers: &reqwest::header::HeaderMap,
    body: Body,
) -> Response<Body> {
    let mut response = Response::new(body);
    *response.status_mut() =
        StatusCode::from_u16(upstream_status).unwrap_or(StatusCode::BAD_GATEWAY);
    if let Ok(value) = HeaderValue::from_str(broker_request_id) {
        response
            .headers_mut()
            .insert(BROKER_REQUEST_ID_HEADER, value);
    }
    for name in [CONTENT_TYPE] {
        if let Some(value) = upstream_headers
            .get(name.as_str())
            .and_then(|value| value.to_str().ok())
            .and_then(|value| HeaderValue::from_str(value).ok())
        {
            response.headers_mut().insert(name, value);
        }
    }
    // Upstream throttling passes through with its status; its wait is
    // forwarded only as bounded whole seconds, never as the raw value.
    if upstream_status == 429
        && let Some(wait) =
            agent_access_provider::UpstreamRetryAfter::from_headers(upstream_headers)
    {
        response.headers_mut().insert(
            axum::http::header::RETRY_AFTER,
            HeaderValue::from(wait.seconds()),
        );
    }
    prevent_gateway_caching(&mut response);
    response
}

pub(crate) async fn gateway_cache_policy(mut response: Response<Body>) -> Response<Body> {
    prevent_gateway_caching(&mut response);
    response
}

fn prevent_gateway_caching(response: &mut Response<Body>) {
    response
        .headers_mut()
        .insert(CACHE_CONTROL, HeaderValue::from_static("private, no-store"));
    response
        .headers_mut()
        .insert(PRAGMA, HeaderValue::from_static("no-cache"));
    response.headers_mut().remove(EXPIRES);
}

fn gateway_request_id(headers: &HeaderMap) -> Result<GatewayRequestId, &'static str> {
    match headers
        .get(REQUEST_ID_HEADER)
        .and_then(|value| value.to_str().ok())
    {
        Some(value) if request_id_valid(value) => Ok(GatewayRequestId {
            value: value.to_string(),
            generated: false,
        }),
        Some(_) => Err("request id is invalid"),
        None => Ok(GatewayRequestId {
            value: format!("gateway-{}", new_broker_request_id()),
            generated: true,
        }),
    }
}

fn request_id_valid(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || ch == '.' || ch == '_' || ch == '-')
}

fn match_gateway(
    snapshot: &RuntimeSnapshot,
    request: &Request<Body>,
) -> Result<Option<MatchedGateway>, &'static str> {
    let host = effective_gateway_host(request)?;
    for (service, gateway) in &snapshot.runtime.config().gateways {
        if gateway
            .broker_hosts
            .iter()
            .any(|candidate| candidate == &host)
        {
            return Ok(Some(MatchedGateway {
                service: service.clone(),
                config: gateway.clone(),
            }));
        }
    }
    Ok(None)
}

fn effective_gateway_host(request: &Request<Body>) -> Result<String, &'static str> {
    if request.uri().scheme().is_some() {
        return Err("gateway requests must not use absolute-form targets");
    }
    let mut host_values = request.headers().get_all(HOST).iter();
    let raw_host = host_values.next();
    if host_values.next().is_some() {
        return Err("gateway Host header is ambiguous");
    }
    let header_authority = raw_host
        .map(|host| host.to_str().map_err(|_| "gateway Host header is invalid"))
        .transpose()?
        .map(parse_gateway_authority)
        .transpose()?;
    let uri_authority = request
        .uri()
        .authority()
        .map(|authority| parse_gateway_authority(authority.as_str()))
        .transpose()?;

    match (uri_authority, header_authority) {
        (Some(uri_authority), Some(header_authority)) => {
            if uri_authority != header_authority {
                return Err("gateway authority and Host header do not match");
            }
            Ok(uri_authority.host)
        }
        (Some(uri_authority), None) => Ok(uri_authority.host),
        (None, Some(header_authority)) => Ok(header_authority.host),
        (None, None) => Err("gateway Host header or authority is required"),
    }
}

#[derive(Debug, PartialEq, Eq)]
struct GatewayAuthority {
    host: String,
    port: Option<String>,
}

fn parse_gateway_authority(value: &str) -> Result<GatewayAuthority, &'static str> {
    let (host, port) = split_gateway_authority(value)?;
    Ok(GatewayAuthority {
        host: normalize_effective_gateway_host(host)?,
        port: port.map(ToString::to_string),
    })
}

fn split_gateway_authority(value: &str) -> Result<(&str, Option<&str>), &'static str> {
    if value.starts_with('[') || value.contains(']') {
        return Err("gateway authority must be a DNS host");
    }
    if let Some((host, port)) = value.rsplit_once(':') {
        if host.contains(':') || port.is_empty() || !port.bytes().all(|byte| byte.is_ascii_digit())
        {
            return Err("gateway authority is invalid");
        }
        return Ok((host, Some(port)));
    }
    if value.contains(':') {
        return Err("gateway authority is invalid");
    }
    Ok((value, None))
}

fn normalize_effective_gateway_host(value: &str) -> Result<String, &'static str> {
    if value.trim() != value || value.ends_with('.') {
        return Err("gateway host must not have whitespace or a trailing dot");
    }
    let host = value.to_ascii_lowercase();
    if host.is_empty() {
        return Err("gateway Host header is required");
    }
    if host.contains('*')
        || host.contains('{')
        || host.contains('}')
        || host.contains(':')
        || host.contains('/')
        || host.contains('\\')
        || host.contains('@')
    {
        return Err("gateway host must be an exact DNS host");
    }
    if host.parse::<IpAddr>().is_ok() {
        return Err("gateway host must be a DNS host, not an IP literal");
    }
    if host.split('.').any(|label| {
        label.is_empty()
            || label.len() > 63
            || label.starts_with('-')
            || label.ends_with('-')
            || !label
                .bytes()
                .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
    }) {
        return Err("gateway host must be a valid DNS host");
    }
    Ok(host)
}

fn classify_gateway_request(
    matched_gateway: &MatchedGateway,
    method: &Method,
    uri: &Uri,
    headers: &HeaderMap,
) -> Result<ClassifiedGatewayRequest, GatewayClassifyError> {
    if matched_gateway.config.kind != "git_http" {
        return Err(GatewayClassifyError::rule_not_found(
            "gateway kind is not routable",
        ));
    }
    let git = matched_gateway
        .config
        .git
        .as_ref()
        .ok_or_else(|| GatewayClassifyError::rule_not_found("git gateway is not configured"))?;
    let (git_request_kind, repository) = match *method {
        Method::GET => {
            validate_git_protocol_header(headers)?;
            classify_git_discovery(uri, git.allow_fetch, git.allow_push)?
        }
        Method::POST => {
            validate_git_protocol_header(headers)?;
            classify_git_post(uri, headers, git.allow_fetch, git.allow_push)?
        }
        _ => {
            return Err(GatewayClassifyError::method_denied(
                "gateway method is not supported",
            ));
        }
    };
    Ok(ClassifiedGatewayRequest {
        service: matched_gateway.service.clone(),
        action: git_request_kind.action().to_string(),
        git_request_kind,
        resource_scopes: ResourceScopes::from([("repository".to_string(), vec![repository])]),
    })
}

fn classify_git_discovery(
    uri: &Uri,
    allow_fetch: bool,
    allow_push: bool,
) -> Result<(GitRequestKind, String), GatewayClassifyError> {
    let repository = repository_from_suffix(uri.path(), &["info", "refs"])?;
    let mut pairs = form_urlencoded::parse(uri.query().unwrap_or_default().as_bytes());
    let Some((key, value)) = pairs.next() else {
        return Err(GatewayClassifyError::query_denied(
            "git discovery query is required",
        ));
    };
    if pairs.next().is_some() || key != "service" {
        return Err(GatewayClassifyError::query_denied(
            "git discovery query is invalid",
        ));
    }
    match value.as_ref() {
        "git-upload-pack" if allow_fetch => Ok((GitRequestKind::UploadPackDiscovery, repository)),
        "git-receive-pack" if allow_push => Ok((GitRequestKind::ReceivePackDiscovery, repository)),
        _ => Err(GatewayClassifyError::git_service_denied(
            "git discovery service is not allowed",
        )),
    }
}

fn classify_git_post(
    uri: &Uri,
    headers: &HeaderMap,
    allow_fetch: bool,
    allow_push: bool,
) -> Result<(GitRequestKind, String), GatewayClassifyError> {
    if uri.query().is_some() {
        return Err(GatewayClassifyError::query_denied(
            "git POST query is not supported",
        ));
    }
    if let Ok(repository) = repository_from_suffix(uri.path(), &["git-upload-pack"]) {
        if !allow_fetch {
            return Err(GatewayClassifyError::git_service_denied(
                "git fetch is not allowed",
            ));
        }
        validate_git_content_type(headers, "application/x-git-upload-pack-request")?;
        return Ok((GitRequestKind::UploadPackPost, repository));
    }
    if let Ok(repository) = repository_from_suffix(uri.path(), &["git-receive-pack"]) {
        if !allow_push {
            return Err(GatewayClassifyError::git_service_denied(
                "git push is not allowed",
            ));
        }
        validate_git_content_type(headers, "application/x-git-receive-pack-request")?;
        return Ok((GitRequestKind::ReceivePackPost, repository));
    }
    Err(GatewayClassifyError::rule_not_found(
        "git POST route is not allowed",
    ))
}

fn validate_git_protocol_header(headers: &HeaderMap) -> Result<(), GatewayClassifyError> {
    let mut values = headers.get_all("Git-Protocol").iter();
    let Some(raw) = values.next() else {
        return Ok(());
    };
    if values.next().is_some() {
        return Err(GatewayClassifyError::new(
            ReasonCode::GatewayHeaderDenied,
            "Git-Protocol header is ambiguous",
        ));
    }
    let value = raw.to_str().map_err(|_| {
        GatewayClassifyError::new(ReasonCode::GatewayHeaderDenied, "Git-Protocol is invalid")
    })?;
    if value != "version=2" {
        return Err(GatewayClassifyError::new(
            ReasonCode::GatewayHeaderDenied,
            "Git-Protocol is not allowed",
        ));
    }
    Ok(())
}

fn validate_git_content_type(
    headers: &HeaderMap,
    expected: &'static str,
) -> Result<(), GatewayClassifyError> {
    let mut values = headers.get_all(CONTENT_TYPE).iter();
    let Some(raw) = values.next() else {
        return Err(GatewayClassifyError::new(
            ReasonCode::GatewayContentTypeDenied,
            "Git POST content type is required",
        ));
    };
    if values.next().is_some() {
        return Err(GatewayClassifyError::new(
            ReasonCode::GatewayContentTypeDenied,
            "Git POST content type is ambiguous",
        ));
    }
    let value = raw.to_str().map_err(|_| {
        GatewayClassifyError::new(
            ReasonCode::GatewayContentTypeDenied,
            "Git POST content type is invalid",
        )
    })?;
    if !value.eq_ignore_ascii_case(expected) {
        return Err(GatewayClassifyError::new(
            ReasonCode::GatewayContentTypeDenied,
            "Git POST content type is not allowed",
        ));
    }
    Ok(())
}

fn repository_from_suffix(path: &str, suffix: &[&str]) -> Result<String, GatewayClassifyError> {
    let segments = decoded_path_segments(path)?;
    if segments.len() <= suffix.len() {
        return Err(GatewayClassifyError::rule_not_found(
            "repository path is missing",
        ));
    }
    if !segments
        .iter()
        .rev()
        .zip(suffix.iter().rev())
        .take(suffix.len())
        .all(|(segment, expected)| segment == expected)
    {
        return Err(GatewayClassifyError::rule_not_found(
            "gateway route is not supported",
        ));
    }
    let mut repository_segments = segments[..segments.len() - suffix.len()].to_vec();
    if repository_segments[..repository_segments.len().saturating_sub(1)]
        .iter()
        .any(|segment| segment.ends_with(".git"))
    {
        return Err(GatewayClassifyError::rule_not_found(
            "repository path has ambiguous .git segment",
        ));
    }
    let Some(last) = repository_segments.last_mut() else {
        return Err(GatewayClassifyError::rule_not_found(
            "repository path is missing",
        ));
    };
    if let Some(stripped) = last.strip_suffix(".git") {
        *last = stripped.to_string();
    }
    let repository = repository_segments.join("/");
    // Classify with the same canonical grammar policy authorizes, so a path
    // no grant could ever match is rejected here rather than after lookup.
    if !agent_access_provider::is_canonical_repository_path(&repository) {
        return Err(GatewayClassifyError::rule_not_found(
            "repository path is invalid",
        ));
    }
    Ok(repository)
}

fn decoded_path_segments(path: &str) -> Result<Vec<String>, GatewayClassifyError> {
    if !path.starts_with('/') {
        return Err(GatewayClassifyError::rule_not_found(
            "gateway path is invalid",
        ));
    }
    path.split('/')
        .skip(1)
        .map(|segment| {
            let decoded = percent_decode_str(segment)
                .decode_utf8()
                .map_err(|_| GatewayClassifyError::rule_not_found("gateway path is invalid"))?
                .into_owned();
            if decoded.contains('/')
                || decoded.contains('\\')
                || decoded.chars().any(char::is_control)
            {
                return Err(GatewayClassifyError::rule_not_found(
                    "gateway path is invalid",
                ));
            }
            Ok(decoded)
        })
        .collect()
}

pub(crate) fn gateway_runtime_response(
    response: BrokerResponse<serde_json::Value>,
) -> Response<Body> {
    let reason = response.envelope.reason_code.clone();
    let broker_request_id = response.envelope.broker_request_id.clone();
    let retry_after = response_retry_after_header(&response);
    let body = response
        .envelope
        .reason
        .clone()
        .or_else(|| {
            response
                .envelope
                .error
                .as_ref()
                .map(|error| error.message.clone())
        })
        .unwrap_or_else(|| response.envelope.decision.as_str().to_string());
    let (status, _, _) = envelope_response(response);
    with_retry_after(
        gateway_error_response(status, &broker_request_id, reason, &body, false),
        retry_after,
    )
}

fn with_retry_after(
    mut response: Response<Body>,
    retry_after: Option<HeaderValue>,
) -> Response<Body> {
    if let Some(retry_after) = retry_after {
        response
            .headers_mut()
            .insert(axum::http::header::RETRY_AFTER, retry_after);
    }
    response
}

fn gateway_runtime_response_with_basic_challenge(
    response: BrokerResponse<serde_json::Value>,
) -> Response<Body> {
    let reason = response.envelope.reason_code.clone();
    let broker_request_id = response.envelope.broker_request_id.clone();
    let challenge = matches!(
        reason.as_ref().and_then(ReasonCodeId::standard),
        Some(ReasonCode::GatewayAuthRequired | ReasonCode::GatewayAuthInvalid)
    );
    let retry_after = response_retry_after_header(&response);
    let body = response
        .envelope
        .reason
        .clone()
        .or_else(|| {
            response
                .envelope
                .error
                .as_ref()
                .map(|error| error.message.clone())
        })
        .unwrap_or_else(|| response.envelope.decision.as_str().to_string());
    let (status, _, _) = envelope_response(response);
    with_retry_after(
        gateway_error_response(status, &broker_request_id, reason, &body, challenge),
        retry_after,
    )
}

fn gateway_error_response(
    status: StatusCode,
    broker_request_id: &str,
    reason: Option<ReasonCodeId>,
    body: &str,
    basic_challenge: bool,
) -> Response<Body> {
    let mut response = Response::new(Body::from(format!("{body}\n")));
    *response.status_mut() = status;
    if let Ok(value) = HeaderValue::from_str(broker_request_id) {
        response
            .headers_mut()
            .insert(BROKER_REQUEST_ID_HEADER, value);
    }
    if let Some(reason) = &reason
        && let Ok(value) = HeaderValue::from_str(reason.as_str())
    {
        response.headers_mut().insert(REASON_CODE_HEADER, value);
    }
    if basic_challenge {
        response
            .headers_mut()
            .insert(WWW_AUTHENTICATE, HeaderValue::from_static(BASIC_CHALLENGE));
    }
    prevent_gateway_caching(&mut response);
    response
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::router::build_gateway_router;
    use crate::state::ReloadableState;
    use crate::tests::test_temp_dir;
    use agent_access_core::{
        AuditConfig, BrokerConfig, CredentialConfig, CredentialsConfig, DEFAULT_EXECUTION_CONTEXT,
        DeploymentConfig, IdentityConfig, IdentityGroupConfig, IdentitySourceConfig, NetworkConfig,
        PolicyConfig, PolicyGrantConfig, ProvidersConfig, StateLockSet, StaticPrincipalConfig,
    };
    use axum::http::header::{ACCEPT, USER_AGENT};
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use std::collections::BTreeMap;
    use std::path::Path;
    use std::task::Poll;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;
    use tokio::sync::oneshot;
    use tower::ServiceExt;

    #[test]
    fn execution_context_rejection_is_not_a_basic_auth_challenge() {
        let response = gateway_error_response(
            StatusCode::FORBIDDEN,
            "broker-req-context",
            Some(ReasonCode::ExecutionContextRequired.into()),
            "execution context is required",
            false,
        );

        assert_eq!(response.status(), StatusCode::FORBIDDEN);
        assert_eq!(
            response.headers()[REASON_CODE_HEADER],
            ReasonCode::ExecutionContextRequired.as_str()
        );
        assert!(!response.headers().contains_key(WWW_AUTHENTICATE));
    }

    #[test]
    fn gateway_authority_parser_normalizes_case_and_preserves_ports() {
        assert_eq!(
            parse_gateway_authority("GIT.EXAMPLE.TEST:9443").unwrap(),
            GatewayAuthority {
                host: "git.example.test".to_string(),
                port: Some("9443".to_string()),
            }
        );
        assert_eq!(
            parse_gateway_authority("git.example.test").unwrap(),
            GatewayAuthority {
                host: "git.example.test".to_string(),
                port: None,
            }
        );
        assert!(parse_gateway_authority("git.example.test.").is_err());
        assert!(parse_gateway_authority("127.0.0.1").is_err());
        assert!(parse_gateway_authority("[::1]").is_err());
    }

    #[test]
    fn effective_gateway_host_rejects_spoofed_or_ambiguous_authority() {
        let absolute = Request::builder()
            .uri("http://git.example.test/sip/service.git/info/refs")
            .header(HOST, "git.example.test")
            .body(Body::empty())
            .unwrap();
        assert_eq!(
            effective_gateway_host(&absolute).unwrap_err(),
            "gateway requests must not use absolute-form targets"
        );

        let duplicate_host = Request::builder()
            .uri("/sip/service.git/info/refs?service=git-upload-pack")
            .header(HOST, "git.example.test")
            .header(HOST, "git.example.test")
            .body(Body::empty())
            .unwrap();
        assert_eq!(
            effective_gateway_host(&duplicate_host).unwrap_err(),
            "gateway Host header is ambiguous"
        );

        let missing_host = Request::builder()
            .uri("/sip/service.git/info/refs?service=git-upload-pack")
            .body(Body::empty())
            .unwrap();
        assert_eq!(
            effective_gateway_host(&missing_host).unwrap_err(),
            "gateway Host header or authority is required"
        );
    }

    #[test]
    fn gateway_upstream_url_normalizes_clone_bases_for_every_git_operation() {
        for base_path in ["", "/", "/git/root", "/git/root/", "/git/root%20dir/"] {
            let mut gateway = test_gateway_config();
            gateway.upstream_base_url = format!("https://gitlab.example.com{base_path}");
            gateway.git.as_mut().unwrap().allow_push = true;
            let matched = MatchedGateway {
                service: "gitlab_git".to_string(),
                config: gateway,
            };
            for (clone_base, canonical_repository, encoded_repository) in [
                ("team/project", "team/project", "team/project"),
                ("team/project.git", "team/project", "team/project"),
                (
                    "team/subgroup/proj%65ct",
                    "team/subgroup/project",
                    "team/subgroup/project",
                ),
                (
                    "team/subgroup/project%2Egit",
                    "team/subgroup/project",
                    "team/subgroup/project",
                ),
                ("t%C3%A9am/project", "téam/project", "t%C3%A9am/project"),
                // A repository whose actual name ends in .git retains that
                // name; only the transport suffix is removed by classification.
                (
                    "team/project.git.git",
                    "team/project.git",
                    "team/project.git",
                ),
            ] {
                for (method, suffix, query, content_type, expected_kind) in [
                    (
                        Method::GET,
                        "info/refs",
                        "?ser%76ice=git-upload-pack",
                        None,
                        GitRequestKind::UploadPackDiscovery,
                    ),
                    (
                        Method::GET,
                        "info/refs",
                        "?service=git-receive-pack",
                        None,
                        GitRequestKind::ReceivePackDiscovery,
                    ),
                    (
                        Method::POST,
                        "git-upload-pack",
                        "",
                        Some("application/x-git-upload-pack-request"),
                        GitRequestKind::UploadPackPost,
                    ),
                    (
                        Method::POST,
                        "git-receive-pack",
                        "",
                        Some("application/x-git-receive-pack-request"),
                        GitRequestKind::ReceivePackPost,
                    ),
                ] {
                    let uri = format!("/{clone_base}/{suffix}{query}").parse().unwrap();
                    let mut headers = HeaderMap::new();
                    if let Some(content_type) = content_type {
                        headers.insert(CONTENT_TYPE, HeaderValue::from_static(content_type));
                    }
                    let classified =
                        classify_gateway_request(&matched, &method, &uri, &headers).unwrap();
                    assert_eq!(classified.git_request_kind, expected_kind, "{uri}");
                    assert_eq!(classified.git_request_kind.method(), method, "{uri}");
                    assert_eq!(
                        classified.resource_scopes["repository"],
                        [canonical_repository],
                        "{uri}"
                    );
                    let url = gateway_upstream_url(
                        &matched.config,
                        classified.git_request_kind,
                        &classified.resource_scopes,
                    )
                    .unwrap();
                    let canonical_query = query.replace("ser%76ice", "service");
                    assert_eq!(
                        url.as_str(),
                        format!(
                            "https://gitlab.example.com{}/{encoded_repository}.git/{suffix}{canonical_query}",
                            base_path.trim_end_matches('/')
                        ),
                        "{uri}"
                    );
                    assert!(url_allowed_by_patterns(
                        &url,
                        &[format!(
                            "https://gitlab.example.com{}/**",
                            base_path.trim_end_matches('/')
                        )]
                    ));
                }
            }
        }
    }

    #[test]
    fn gateway_upstream_url_requires_one_canonical_authorized_repository() {
        for repositories in [
            vec![],
            vec!["team/project", "other/project"],
            vec!["project"],
            vec!["team/../project"],
            vec!["team/project%2Fother"],
        ] {
            let scopes = ResourceScopes::from([(
                "repository".to_string(),
                repositories.into_iter().map(str::to_string).collect(),
            )]);
            let error = gateway_upstream_url(
                &test_gateway_config(),
                GitRequestKind::UploadPackDiscovery,
                &scopes,
            )
            .unwrap_err();
            assert_eq!(error.reason_code(), ReasonCode::GatewayUpstreamDenied);
        }
        assert!(
            gateway_upstream_url(
                &test_gateway_config(),
                GitRequestKind::UploadPackDiscovery,
                &ResourceScopes::new(),
            )
            .is_err()
        );
    }

    #[test]
    fn gateway_git_url_normalization_keeps_invalid_paths_and_queries_rejected() {
        let mut gateway = test_gateway_config();
        gateway.git.as_mut().unwrap().allow_push = true;
        let matched = MatchedGateway {
            service: "gitlab_git".to_string(),
            config: gateway,
        };
        for repository in [
            "project",
            "team//project",
            "team/.git",
            "team.git/project",
            "team%2Egit/project",
            "team/../project",
            "team/%2E%2E/project",
            "team/project%2Fother",
            "team/project%5Cother",
            "team/project%25other",
            "team/project%3Fother",
            "team/project%23other",
            "team/project%00",
            "team/project%FF",
            "team/project%ZZ",
        ] {
            for service in ["git-upload-pack", "git-receive-pack"] {
                let uri = format!("/{repository}/info/refs?service={service}")
                    .parse()
                    .unwrap();
                assert!(
                    classify_gateway_request(&matched, &Method::GET, &uri, &HeaderMap::new())
                        .is_err(),
                    "{uri}"
                );
                let uri = format!("/{repository}/{service}").parse().unwrap();
                let mut headers = HeaderMap::new();
                headers.insert(
                    CONTENT_TYPE,
                    format!("application/x-{service}-request").parse().unwrap(),
                );
                assert!(
                    classify_gateway_request(&matched, &Method::POST, &uri, &headers).is_err(),
                    "{uri}"
                );
            }
        }
        for query in [
            "",
            "?service=other",
            "?service=git-upload-pack&service=git-receive-pack",
            "?service=git-upload-pack&extra=value",
        ] {
            let uri = format!("/team/project/info/refs{query}").parse().unwrap();
            assert!(
                classify_gateway_request(&matched, &Method::GET, &uri, &HeaderMap::new()).is_err(),
                "{uri}"
            );
        }
        let uri = "/team/project/git-upload-pack?service=git-upload-pack"
            .parse()
            .unwrap();
        let mut headers = HeaderMap::new();
        headers.insert(
            CONTENT_TYPE,
            HeaderValue::from_static("application/x-git-upload-pack-request"),
        );
        let error = classify_gateway_request(&matched, &Method::POST, &uri, &headers)
            .err()
            .unwrap();
        assert_eq!(error.code, ReasonCode::GatewayQueryDenied);
    }

    #[test]
    fn gateway_repository_paths_canonicalize_safe_percent_encoding() {
        let repository =
            repository_from_suffix("/sip%65/service.git/info/refs", &["info", "refs"]).unwrap();
        assert_eq!(repository, "sipe/service");

        let error =
            repository_from_suffix("/sip%2Fservice.git/info/refs", &["info", "refs"]).unwrap_err();
        assert_eq!(error.code, ReasonCode::GatewayRuleNotFound);

        let error =
            repository_from_suffix("/sip%25/service.git/info/refs", &["info", "refs"]).unwrap_err();
        assert_eq!(error.code, ReasonCode::GatewayRuleNotFound);
    }

    #[test]
    fn gateway_repository_paths_follow_the_canonical_repository_grammar() {
        // No grant can match a single-segment path, so classification rejects
        // it before policy lookup instead of denying it later.
        for path in ["/service.git/info/refs", "/12345.git/info/refs"] {
            let error = repository_from_suffix(path, &["info", "refs"]).unwrap_err();
            assert_eq!(error.code, ReasonCode::GatewayRuleNotFound, "{path}");
            assert_eq!(error.reason, "repository path is invalid", "{path}");
        }
        assert_eq!(
            repository_from_suffix("/team/12345.git/info/refs", &["info", "refs"]).unwrap(),
            "team/12345"
        );
    }

    #[test]
    fn gateway_upstream_response_filters_sensitive_headers() {
        let mut upstream_headers = reqwest::header::HeaderMap::new();
        upstream_headers.insert(
            reqwest::header::CONTENT_TYPE,
            reqwest::header::HeaderValue::from_static(
                "application/x-git-upload-pack-advertisement",
            ),
        );
        upstream_headers.insert(
            reqwest::header::WWW_AUTHENTICATE,
            reqwest::header::HeaderValue::from_static("Basic realm=\"upstream\""),
        );
        upstream_headers.insert(
            reqwest::header::SERVER,
            reqwest::header::HeaderValue::from_static("gitlab"),
        );

        upstream_headers.insert(
            CACHE_CONTROL,
            HeaderValue::from_static("public, max-age=3600"),
        );
        upstream_headers.insert(PRAGMA, HeaderValue::from_static("public"));
        upstream_headers.insert(
            EXPIRES,
            HeaderValue::from_static("Thu, 01 Oct 2099 00:00:00 GMT"),
        );
        let response =
            gateway_upstream_response(200, "broker-req-test", &upstream_headers, Body::from("ok"));

        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response.headers()[CONTENT_TYPE],
            "application/x-git-upload-pack-advertisement"
        );
        assert_eq!(
            response.headers()[BROKER_REQUEST_ID_HEADER],
            "broker-req-test"
        );
        assert!(!response.headers().contains_key(WWW_AUTHENTICATE));
        assert!(!response.headers().contains_key("Server"));
        assert_eq!(response.headers()[CACHE_CONTROL], "private, no-store");
        assert_eq!(response.headers()[PRAGMA], "no-cache");
        assert!(!response.headers().contains_key(EXPIRES));
        let denied = gateway_error_response(StatusCode::FORBIDDEN, "denied", None, "denied", false);
        assert_eq!(denied.headers()[CACHE_CONTROL], "private, no-store");
        assert_eq!(denied.headers()[PRAGMA], "no-cache");
    }

    #[test]
    fn gateway_upstream_throttling_forwards_only_a_bounded_retry_after() {
        let date = agent_access_provider::UpstreamRetryAfter::after_seconds(600)
            .at()
            .format("%a, %d %b %Y %H:%M:%S GMT")
            .to_string();
        for (status, retry_after, expected) in [
            (429, Some("30"), Some(30..=30)),
            (429, Some(date.as_str()), Some(598..=601)),
            (429, Some("31536000"), Some(86_400..=86_400)),
            (429, Some("soon"), None),
            (429, None, None),
            (503, Some("30"), None),
        ] {
            let mut upstream_headers = reqwest::header::HeaderMap::new();
            if let Some(value) = retry_after {
                upstream_headers.insert(
                    reqwest::header::RETRY_AFTER,
                    reqwest::header::HeaderValue::from_str(value).unwrap(),
                );
            }
            let response = gateway_upstream_response(
                status,
                "broker-req-test",
                &upstream_headers,
                Body::from("slow down"),
            );
            assert_eq!(response.status().as_u16(), status);
            let forwarded = response
                .headers()
                .get(axum::http::header::RETRY_AFTER)
                .map(|value| value.to_str().unwrap().parse::<u64>().unwrap());
            match expected {
                Some(range) => assert!(
                    forwarded.is_some_and(|seconds| range.contains(&seconds)),
                    "{retry_after:?}: {forwarded:?}"
                ),
                None => assert_eq!(forwarded, None, "{status} {retry_after:?}"),
            }
        }
    }

    #[test]
    fn gateway_outbound_request_filters_inbound_secrets_and_injects_execution_credential() {
        let client = reqwest::Client::new();
        let mut headers = HeaderMap::new();
        headers.insert(
            AUTHORIZATION,
            HeaderValue::from_static("Basic caller-token"),
        );
        headers.insert(HOST, HeaderValue::from_static("git.example.test"));
        headers.insert("Cookie", HeaderValue::from_static("session=secret"));
        headers.insert(
            REQUEST_ID_HEADER,
            HeaderValue::from_static("caller-request-id"),
        );
        headers.insert(
            BROKER_REQUEST_ID_HEADER,
            HeaderValue::from_static("caller-broker-id"),
        );
        headers.insert(
            agent_access_core::EXECUTION_CONTEXT_HEADER,
            HeaderValue::from_static("external"),
        );
        headers.insert("Accept", HeaderValue::from_static("*/*"));
        headers.insert("User-Agent", HeaderValue::from_static("git/2.51"));
        headers.insert("Git-Protocol", HeaderValue::from_static("version=2"));
        headers.insert(
            CONTENT_TYPE,
            HeaderValue::from_static("application/x-git-upload-pack-request"),
        );
        headers.insert(CONTENT_ENCODING, HeaderValue::from_static("GZIP"));

        let builder = client
            .post("https://gitlab.example.com/sip/service.git/git-upload-pack")
            .body(Vec::new());
        let builder = apply_git_request_headers(
            builder,
            &headers,
            &Method::POST,
            Some(GitContentEncoding::Gzip),
        )
        .unwrap();
        let request = apply_gateway_credential(
            builder,
            &agent_access_provider::test_support::bearer_credential("upstream-token"),
        )
        .unwrap()
        .build()
        .unwrap();

        assert_eq!(
            request.headers()[reqwest::header::AUTHORIZATION],
            "Bearer upstream-token"
        );
        assert_eq!(request.headers()[reqwest::header::ACCEPT], "*/*");
        assert_eq!(request.headers()[reqwest::header::USER_AGENT], "git/2.51");
        assert_eq!(request.headers()["Git-Protocol"], "version=2");
        assert_eq!(
            request.headers()[reqwest::header::CONTENT_TYPE],
            "application/x-git-upload-pack-request"
        );
        assert_eq!(request.headers()[reqwest::header::CONTENT_ENCODING], "gzip");
        assert!(!request.headers().contains_key(reqwest::header::COOKIE));
        assert!(!request.headers().contains_key(reqwest::header::HOST));
        assert!(!request.headers().contains_key(REQUEST_ID_HEADER));
        assert!(!request.headers().contains_key(BROKER_REQUEST_ID_HEADER));
        assert!(
            !request
                .headers()
                .contains_key(agent_access_core::EXECUTION_CONTEXT_HEADER)
        );
    }

    #[test]
    fn git_gateway_representation_header_validation_is_action_scoped() {
        let mut upload_pack_headers = HeaderMap::new();
        upload_pack_headers.insert(CONTENT_ENCODING, HeaderValue::from_static(" GZIP "));
        assert_eq!(
            validate_git_gateway_representation_headers(
                &upload_pack_headers,
                GitRequestKind::UploadPackPost,
            )
            .unwrap(),
            Some(GitContentEncoding::Gzip)
        );

        let mut duplicate_encoding = HeaderMap::new();
        duplicate_encoding.append(CONTENT_ENCODING, HeaderValue::from_static("gzip"));
        duplicate_encoding.append(CONTENT_ENCODING, HeaderValue::from_static("gzip"));
        let duplicate_error = validate_git_gateway_representation_headers(
            &duplicate_encoding,
            GitRequestKind::UploadPackPost,
        )
        .unwrap_err();
        assert_eq!(
            duplicate_error.reason_code(),
            ReasonCode::GatewayHeaderDenied
        );

        let mut unsupported_encoding = HeaderMap::new();
        unsupported_encoding.insert(CONTENT_ENCODING, HeaderValue::from_static("br"));
        let unsupported_error = validate_git_gateway_representation_headers(
            &unsupported_encoding,
            GitRequestKind::UploadPackPost,
        )
        .unwrap_err();
        assert_eq!(
            unsupported_error.reason_code(),
            ReasonCode::GatewayHeaderDenied
        );

        let mut comma_encoding = HeaderMap::new();
        comma_encoding.insert(CONTENT_ENCODING, HeaderValue::from_static("gzip, br"));
        let comma_error = validate_git_gateway_representation_headers(
            &comma_encoding,
            GitRequestKind::UploadPackPost,
        )
        .unwrap_err();
        assert_eq!(comma_error.reason_code(), ReasonCode::GatewayHeaderDenied);

        let mut empty_encoding = HeaderMap::new();
        empty_encoding.insert(CONTENT_ENCODING, HeaderValue::from_static(""));
        let empty_error = validate_git_gateway_representation_headers(
            &empty_encoding,
            GitRequestKind::UploadPackPost,
        )
        .unwrap_err();
        assert_eq!(empty_error.reason_code(), ReasonCode::GatewayHeaderDenied);

        let mut receive_pack_headers = HeaderMap::new();
        receive_pack_headers.insert(CONTENT_ENCODING, HeaderValue::from_static("gzip"));
        let receive_pack_error = validate_git_gateway_representation_headers(
            &receive_pack_headers,
            GitRequestKind::ReceivePackPost,
        )
        .unwrap_err();
        assert_eq!(
            receive_pack_error.reason_code(),
            ReasonCode::GatewayHeaderDenied
        );

        let mut discovery_headers = HeaderMap::new();
        discovery_headers.insert(CONTENT_ENCODING, HeaderValue::from_static("gzip"));
        let discovery_error = validate_git_gateway_representation_headers(
            &discovery_headers,
            GitRequestKind::UploadPackDiscovery,
        )
        .unwrap_err();
        assert_eq!(
            discovery_error.reason_code(),
            ReasonCode::GatewayHeaderDenied
        );

        let mut trailer_headers = HeaderMap::new();
        trailer_headers.insert(TRAILER, HeaderValue::from_static("Content-MD5"));
        let trailer_error = validate_git_gateway_representation_headers(
            &trailer_headers,
            GitRequestKind::UploadPackPost,
        )
        .unwrap_err();
        assert_eq!(trailer_error.reason_code(), ReasonCode::GatewayHeaderDenied);
    }

    #[test]
    fn gateway_cap_helpers_detect_declared_overflow() {
        let mut headers = HeaderMap::new();
        headers.insert(CONTENT_LENGTH, HeaderValue::from_static("11"));
        assert!(content_length_exceeds(&headers, 10));
        assert!(!content_length_exceeds(&headers, 11));

        let mut response_headers = reqwest::header::HeaderMap::new();
        response_headers.insert(
            reqwest::header::CONTENT_LENGTH,
            reqwest::header::HeaderValue::from_static("12"),
        );
        assert!(response_content_length_exceeds(&response_headers, 11));
        assert!(!response_content_length_exceeds(&response_headers, 12));
    }

    #[tokio::test]
    async fn gateway_request_body_rejects_get_bodies_and_caps_chunked_bodies() {
        let limits = GatewayForwardLimits {
            request_body_max_bytes: 4,
            response_body_max_bytes: 1024,
            idle_timeout: Duration::from_secs(1),
        };

        let mut headers = HeaderMap::new();
        headers.insert(CONTENT_LENGTH, HeaderValue::from_static("1"));
        let error = gateway_request_body_bytes(&Method::GET, &headers, Body::empty(), &limits)
            .await
            .unwrap_err();
        assert_eq!(error.reason_code(), ReasonCode::GatewayRequestBodyDenied);

        let mut headers = HeaderMap::new();
        headers.insert(CONTENT_LENGTH, HeaderValue::from_static("5"));
        let error = gateway_request_body_bytes(&Method::GET, &headers, Body::empty(), &limits)
            .await
            .unwrap_err();
        assert_eq!(error.reason_code(), ReasonCode::GatewayRequestCapExceeded);

        let mut headers = HeaderMap::new();
        headers.insert(CONTENT_LENGTH, HeaderValue::from_static("0"));
        assert_eq!(
            gateway_request_body_bytes(&Method::GET, &headers, Body::empty(), &limits)
                .await
                .unwrap(),
            Vec::<u8>::new()
        );

        let headers = HeaderMap::new();
        let error = gateway_request_body_bytes(&Method::GET, &headers, Body::from("x"), &limits)
            .await
            .unwrap_err();
        assert_eq!(error.reason_code(), ReasonCode::GatewayRequestBodyDenied);

        let headers = HeaderMap::new();
        let error =
            gateway_request_body_bytes(&Method::POST, &headers, Body::from("too large"), &limits)
                .await
                .unwrap_err();
        assert_eq!(error.reason_code(), ReasonCode::GatewayRequestCapExceeded);
    }

    fn managed_gateway_body_fixture(
        token_action: &str,
        startup_cap: Option<usize>,
        configure: impl FnOnce(&mut BrokerConfig),
    ) -> (Arc<ReloadableState>, String) {
        let temp = test_temp_dir();
        let service_token_path = temp.join("gateway-early-service-token");
        let hash_key_path = temp.join("gateway-early-hash-key");
        let store_path = temp.join("gateway-early-store.sqlite");
        let audit_path = temp.join("gateway-early.audit.jsonl");
        std::fs::write(&service_token_path, "upstream-token").unwrap();
        std::fs::write(&hash_key_path, URL_SAFE_NO_PAD.encode([29_u8; 32])).unwrap();

        let mut config =
            test_forwarding_config(&service_token_path, &service_token_path, &audit_path);
        config.identity = IdentityConfig {
            trusted_callers: Default::default(),
            mode: "required".to_string(),
            authority: "managed".to_string(),
            sources: vec![IdentitySourceConfig {
                name: "broker".to_string(),
                kind: "broker_tokens".to_string(),
                header: "Authorization".to_string(),
                scheme: "Bearer".to_string(),
                principals: vec![],
            }],
            groups: vec![],
        };
        let managed_store_config = agent_access_core::ManagedStoreConfig {
            kind: "sqlite".to_string(),
            path: store_path.display().to_string(),
            require_registered_principal_for_invocation: false,
            auto_migrate: true,
        };
        config.managed_store = Some(managed_store_config.clone());
        config.credential_encryption = Some(agent_access_core::CredentialEncryptionConfig {
            active_key: "fixture".into(),
            keys: vec![agent_access_core::CredentialEncryptionKeyConfig {
                id: "fixture".into(),
                provider: "file".into(),
                env: None,
                path: Some(hash_key_path.display().to_string()),
            }],
        });
        config.broker_tokens = Some(agent_access_core::BrokerTokensConfig {
            hash_key_ref: format!("file:{}", hash_key_path.display()),
            ..Default::default()
        });
        config.policy.grants[0].subjects = vec!["user:gateway-user".to_string()];
        config.policy.grants[0].actions = vec!["repo.push".to_string()];
        config
            .gateways
            .get_mut("gitlab_git")
            .unwrap()
            .git
            .as_mut()
            .unwrap()
            .allow_push = true;

        configure(&mut config);
        let store = agent_access_core::ManagedStore::open(
            &managed_store_config,
            agent_access_core::ManagedStoreOpenMode::Startup,
        )
        .unwrap();
        store
            .create_principal(agent_access_core::PrincipalWriteRequest {
                role: agent_access_core::PrincipalRole::User,
                self_service_enabled: None,
                principal_id: "gateway-user".to_string(),
                kind: "user".to_string(),
                display_name: Some("Gateway User".to_string()),
                email: None,
                external_subject: None,
                created_by: "test".to_string(),
            })
            .unwrap();
        let hasher =
            agent_access_core::BrokerTokenHasher::load(config.broker_tokens.as_ref().unwrap())
                .unwrap();
        let issued = store
            .issue_broker_token(
                &hasher,
                agent_access_core::BrokerTokenIssueRequest {
                    principal_id: "gateway-user".to_string(),
                    name: "gateway body fixture token".to_string(),
                    token_class: agent_access_core::BrokerTokenClass::AgentInvoke,
                    scopes: json!({
                        "allowedServices": ["gitlab_git"],
                        "allowedExecutionContexts": ["default"],
                        "serviceRestrictions": {
                            "gitlab_git": {
                                "actions": [token_action]
                            }
                        }
                    }),
                    expires_at: None,
                    created_by: "test".to_string(),
                },
            )
            .unwrap();
        drop(store);

        let runtime = BrokerRuntime::new(config).unwrap();
        let body_hard_cap = startup_cap.unwrap_or(runtime.max_http_body_bytes());
        let audit_registry = runtime.audit_registry();
        let snapshot = RuntimeSnapshot::new(
            1,
            "sha256:gateway-early-admission-test".to_string(),
            runtime.with_config_generation(1),
            StateLockSet::empty(),
        );
        let state = Arc::new(ReloadableState::from_snapshot(
            std::path::PathBuf::new(),
            std::sync::Arc::new(crate::backend_registry()),
            crate::broker_build_status(),
            snapshot,
            body_hard_cap,
            Duration::from_secs(30),
            Duration::from_secs(30),
            audit_registry,
        ));

        let authorization = format!(
            "Basic {}",
            BASE64.encode(format!("agent-access:{}", issued.token))
        );
        (state, authorization)
    }

    #[tokio::test]
    async fn token_disallowed_receive_pack_does_not_poll_request_body() {
        let (state, authorization) = managed_gateway_body_fixture("repo.fetch", None, |_| {});
        let body_polled = Arc::new(AtomicBool::new(false));
        let body_polled_by_stream = Arc::clone(&body_polled);
        let body = Body::from_stream(stream::poll_fn(move |_| {
            body_polled_by_stream.store(true, Ordering::SeqCst);
            Poll::Ready(Some(Ok::<Bytes, io::Error>(Bytes::from_static(
                b"malformed receive-pack body",
            ))))
        }));
        let response = build_gateway_router(state)
            .oneshot(
                Request::builder()
                    .method(Method::POST)
                    .uri("/sip/service.git/git-receive-pack")
                    .extension(ConnectInfo(
                        "127.0.0.1:41080".parse::<SocketAddr>().unwrap(),
                    ))
                    .header(HOST, "git.example.test")
                    .header(REQUEST_ID_HEADER, "gateway-early-admission")
                    .header(AUTHORIZATION, authorization)
                    .header(CONTENT_TYPE, "application/x-git-receive-pack-request")
                    .body(body)
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::FORBIDDEN);
        assert_eq!(
            response.headers()[REASON_CODE_HEADER],
            ReasonCode::ServiceActionDenied.as_str()
        );
        assert!(
            !body_polled.load(Ordering::SeqCst),
            "token caveat denial must precede receive-pack body parsing"
        );
    }

    async fn gateway_body_response(
        state: Arc<ReloadableState>,
        authorization: String,
        body: Body,
    ) -> Response<Body> {
        build_gateway_router(state)
            .oneshot(
                Request::builder()
                    .method(Method::POST)
                    .uri("/sip/service.git/git-receive-pack")
                    .extension(ConnectInfo(
                        "127.0.0.1:41080".parse::<SocketAddr>().unwrap(),
                    ))
                    .header(HOST, "git.example.test")
                    .header(REQUEST_ID_HEADER, "gateway-body-bounds")
                    .header(AUTHORIZATION, authorization)
                    .header(CONTENT_TYPE, "application/x-git-receive-pack-request")
                    .body(body)
                    .unwrap(),
            )
            .await
            .unwrap()
    }

    #[tokio::test]
    async fn gateway_readers_preserve_wrapped_total_deadline_errors() {
        fn timed_out_body() -> Body {
            Body::from_stream(stream::once(async {
                Err::<Bytes, _>(io::Error::other(crate::ingress::body::RequestBodyTimeout))
            }))
        }
        let limits = gateway_test_limits(1024);
        let error =
            gateway_request_body_bytes(&Method::GET, &HeaderMap::new(), timed_out_body(), &limits)
                .await
                .unwrap_err();
        assert_eq!(error.reason_code(), ReasonCode::GatewayRequestBodyDenied);
        let (body, failure, _) = gateway_request_stream_body(timed_out_body(), &limits);
        assert!(body.collect().await.is_err());
        assert_eq!(failure.load(Ordering::Relaxed), REPLAY_FAILURE_TIMEOUT);
    }

    #[tokio::test]
    async fn gateway_router_streamed_receive_pack_preserves_request_cap_classification() {
        // No Content-Length: exercise the real router and incremental body admission.
        for (runtime_cap, startup_cap, gateway_cap) in [
            (256, 256, Some(256)),
            (256, 512, None),
            (512, 256, Some(512)),
            (512, 512, Some(256)),
        ] {
            let (state, authorization) =
                managed_gateway_body_fixture("repo.push", Some(startup_cap), |config| {
                    config.limits.max_http_body_bytes = runtime_cap;
                    config
                        .gateways
                        .get_mut("gitlab_git")
                        .unwrap()
                        .request_body_max_bytes = gateway_cap;
                });
            let payload = receive_pack_payload(
                RECEIVE_PACK_OLD,
                RECEIVE_PACK_NEW,
                "refs/heads/main",
                Some("report-status"),
                &[b'x'; 256],
            );
            let body = delayed_body(vec![
                (Duration::ZERO, Bytes::copy_from_slice(&payload[..4])),
                (Duration::ZERO, Bytes::copy_from_slice(&payload[4..])),
            ]);
            let response = gateway_body_response(state, authorization, body).await;
            assert_eq!(
                response.status(),
                StatusCode::PAYLOAD_TOO_LARGE,
                "runtime={runtime_cap}, startup={startup_cap}, gateway={gateway_cap:?}"
            );
            assert_eq!(
                response.headers()[REASON_CODE_HEADER],
                ReasonCode::GatewayRequestCapExceeded.as_str()
            );
        }
    }

    #[tokio::test]
    async fn gateway_router_uses_matched_idle_timeout_and_explicit_total_timeout() {
        for total_timeout in [false, true] {
            let (state, authorization) =
                managed_gateway_body_fixture("repo.push", None, |config| {
                    config.limits.streaming_idle_timeout_ms = 10;
                    config.limits.request_body_timeout_ms = if total_timeout { 40 } else { 1_000 };
                    let gateway = config.gateways.get_mut("gitlab_git").unwrap();
                    gateway.streaming_idle_timeout_ms = Some(500);
                    gateway.git.as_mut().unwrap().deny_ref_patterns =
                        vec!["refs/heads/main".into()];
                });
            let payload = receive_pack_payload(
                RECEIVE_PACK_OLD,
                RECEIVE_PACK_NEW,
                "refs/heads/main",
                Some("report-status"),
                b"PACK",
            );
            let response = gateway_body_response(
                state,
                authorization,
                delayed_body(vec![(Duration::from_millis(100), Bytes::from(payload))]),
            )
            .await;
            if total_timeout {
                assert_eq!(response.status(), StatusCode::BAD_REQUEST);
                assert_eq!(
                    response.headers()[REASON_CODE_HEADER],
                    ReasonCode::GatewayRequestBodyDenied.as_str()
                );
                let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
                    .await
                    .unwrap();
                assert!(
                    std::str::from_utf8(&bytes)
                        .unwrap()
                        .contains("request body read timed out")
                );
            } else {
                assert_eq!(response.status(), StatusCode::FORBIDDEN);
                assert_eq!(
                    response.headers()[REASON_CODE_HEADER],
                    ReasonCode::GitRefDenied.as_str()
                );
            }
        }
    }

    #[tokio::test]
    async fn token_namespace_caveat_limits_git_gateway_repository_before_forwarding() {
        let temp = test_temp_dir();
        let service_token_path = temp.join("gateway-namespace-service-token");
        let hash_key_path = temp.join("gateway-namespace-hash-key");
        let store_path = temp.join("gateway-namespace-store.sqlite");
        let audit_path = temp.join("gateway-namespace.audit.jsonl");
        std::fs::write(&service_token_path, "upstream-token").unwrap();
        std::fs::write(&hash_key_path, URL_SAFE_NO_PAD.encode([31_u8; 32])).unwrap();

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let upstream_addr = listener.local_addr().unwrap();
        let upstream = tokio::spawn(async move {
            let (_stream, _) = listener.accept().await.unwrap();
            timeout(Duration::from_millis(100), listener.accept())
                .await
                .is_ok()
        });

        let mut config =
            test_forwarding_config(&service_token_path, &service_token_path, &audit_path);
        config.identity = IdentityConfig {
            trusted_callers: Default::default(),
            mode: "required".to_string(),
            authority: "managed".to_string(),
            sources: vec![IdentitySourceConfig {
                name: "broker".to_string(),
                kind: "broker_tokens".to_string(),
                header: "Authorization".to_string(),
                scheme: "Bearer".to_string(),
                principals: vec![],
            }],
            groups: vec![],
        };
        let managed_store_config = agent_access_core::ManagedStoreConfig {
            kind: "sqlite".to_string(),
            path: store_path.display().to_string(),
            require_registered_principal_for_invocation: false,
            auto_migrate: true,
        };
        config.managed_store = Some(managed_store_config.clone());
        config.credential_encryption = Some(agent_access_core::CredentialEncryptionConfig {
            active_key: "fixture".into(),
            keys: vec![agent_access_core::CredentialEncryptionKeyConfig {
                id: "fixture".into(),
                provider: "file".into(),
                env: None,
                path: Some(hash_key_path.display().to_string()),
            }],
        });
        config.broker_tokens = Some(agent_access_core::BrokerTokensConfig {
            hash_key_ref: format!("file:{}", hash_key_path.display()),
            ..Default::default()
        });
        config.policy.grants[0].subjects = vec!["user:gateway-user".to_string()];
        config.policy.resources.extend([
            gateway_resource(
                "other",
                agent_access_provider::ResourceSelector::Exact {
                    value: "other/tool".to_string(),
                },
            ),
            gateway_resource(
                "sip-namespace",
                agent_access_provider::ResourceSelector::Namespace {
                    value: "sip".to_string(),
                },
            ),
        ]);
        config.policy.grants[0]
            .resources
            .resource_ids
            .push("other".to_string());
        let gateway = config.gateways.get_mut("gitlab_git").unwrap();
        gateway.upstream_base_url = format!("https://{upstream_addr}");
        gateway.allowed_upstream_hosts = vec![format!("https://{upstream_addr}/**")];

        let store = agent_access_core::ManagedStore::open(
            &managed_store_config,
            agent_access_core::ManagedStoreOpenMode::Startup,
        )
        .unwrap();
        store
            .create_principal(agent_access_core::PrincipalWriteRequest {
                role: agent_access_core::PrincipalRole::User,
                self_service_enabled: None,
                principal_id: "gateway-user".to_string(),
                kind: "user".to_string(),
                display_name: Some("Gateway User".to_string()),
                email: None,
                external_subject: None,
                created_by: "test".to_string(),
            })
            .unwrap();
        let hasher =
            agent_access_core::BrokerTokenHasher::load(config.broker_tokens.as_ref().unwrap())
                .unwrap();
        let issued = store
            .issue_broker_token_with_catalog(
                &hasher,
                agent_access_core::BrokerTokenIssueRequest {
                    principal_id: "gateway-user".to_string(),
                    name: "sip namespace gateway token".to_string(),
                    token_class: agent_access_core::BrokerTokenClass::AgentInvoke,
                    scopes: json!({
                        "allowedServices": ["gitlab_git"],
                        "allowedExecutionContexts": ["default"],
                        "serviceRestrictions": {
                            "gitlab_git": {
                                "actions": ["repo.fetch"],
                                "resources": {"resourceIds":["sip-namespace"]}
                            }
                        }
                    }),
                    expires_at: None,
                    created_by: "test".to_string(),
                },
                Some(&agent_access_core::ManagedResourceCatalog {
                    attribute_bindings: Vec::new(),
                    resources: config.policy.resources.clone(),
                    resource_groups: config.policy.resource_groups.clone(),
                }),
            )
            .unwrap();
        drop(store);

        let runtime = BrokerRuntime::new(config).unwrap();
        let body_hard_cap = runtime.max_http_body_bytes();
        let audit_registry = runtime.audit_registry();
        let snapshot = RuntimeSnapshot::new(
            1,
            "sha256:gateway-namespace-admission-test".to_string(),
            runtime.with_config_generation(1),
            StateLockSet::empty(),
        );
        let state = Arc::new(ReloadableState::from_snapshot(
            std::path::PathBuf::new(),
            std::sync::Arc::new(crate::backend_registry()),
            crate::broker_build_status(),
            snapshot,
            body_hard_cap,
            Duration::from_secs(30),
            Duration::from_secs(30),
            audit_registry,
        ));
        let authorization = format!(
            "Basic {}",
            BASE64.encode(format!("agent-access:{}", issued.token))
        );
        let request = |path: &'static str, request_id: &'static str| {
            Request::builder()
                .method(Method::GET)
                .uri(path)
                .extension(ConnectInfo(
                    "127.0.0.1:41081".parse::<SocketAddr>().unwrap(),
                ))
                .header(HOST, "git.example.test")
                .header(REQUEST_ID_HEADER, request_id)
                .header(AUTHORIZATION, authorization.clone())
                .body(Body::empty())
                .unwrap()
        };

        let allowed = build_gateway_router(Arc::clone(&state))
            .oneshot(request(
                "/sip/service.git/info/refs?service=git-upload-pack",
                "gateway-namespace-allowed",
            ))
            .await
            .unwrap();
        assert_eq!(allowed.status(), StatusCode::BAD_GATEWAY);

        let denied = build_gateway_router(state)
            .oneshot(request(
                "/other/tool.git/info/refs?service=git-upload-pack",
                "gateway-namespace-denied",
            ))
            .await
            .unwrap();
        assert_eq!(denied.status(), StatusCode::FORBIDDEN);
        assert_eq!(
            denied.headers()[REASON_CODE_HEADER],
            ReasonCode::ServiceActionDenied.as_str()
        );
        assert!(
            !upstream.await.unwrap(),
            "resource caveat denial must precede upstream forwarding"
        );
    }

    #[tokio::test]
    async fn prepare_gateway_request_body_streams_upload_pack_posts() {
        let limits = GatewayForwardLimits {
            request_body_max_bytes: 4,
            response_body_max_bytes: 1024,
            idle_timeout: Duration::from_secs(1),
        };

        let streamed = prepare_gateway_request_body(
            &Method::POST,
            &HeaderMap::new(),
            Body::from("want"),
            None,
            &limits,
        )
        .await
        .unwrap();
        assert!(matches!(
            streamed,
            GatewayPreparedRequestBody::Stream { .. }
        ));

        let mut headers = HeaderMap::new();
        headers.insert(CONTENT_LENGTH, HeaderValue::from_static("5"));
        let error = match prepare_gateway_request_body(
            &Method::POST,
            &headers,
            Body::from("large"),
            None,
            &limits,
        )
        .await
        {
            Ok(_) => panic!("declared oversized POST body should be rejected"),
            Err(error) => error,
        };
        assert_eq!(error.reason_code(), ReasonCode::GatewayRequestCapExceeded);
    }

    #[tokio::test]
    async fn gateway_send_watchdog_tracks_upload_and_response_header_idle_timeouts() {
        let result = gateway_send_with_upload_watchdog(
            std::future::pending::<Result<(), ()>>(),
            None,
            Duration::from_millis(5),
        )
        .await;
        assert!(matches!(
            result,
            Err(GatewaySendError::ResponseHeadersIdleTimeout)
        ));

        let not_started = Arc::new(GatewayRequestUploadProgress::new());
        let result = tokio::time::timeout(
            Duration::from_millis(20),
            gateway_send_with_upload_watchdog(
                std::future::pending::<Result<(), ()>>(),
                Some(not_started),
                Duration::from_millis(5),
            ),
        )
        .await;
        assert!(result.is_err());

        let progress = Arc::new(GatewayRequestUploadProgress::new());
        progress.mark_progress();
        let result = gateway_send_with_upload_watchdog(
            std::future::pending::<Result<(), ()>>(),
            Some(progress),
            Duration::from_millis(5),
        )
        .await;
        assert!(matches!(
            result,
            Err(GatewaySendError::RequestUploadIdleTimeout)
        ));

        let complete = Arc::new(GatewayRequestUploadProgress::new());
        complete.mark_complete();
        let result = gateway_send_with_upload_watchdog(
            std::future::pending::<Result<(), ()>>(),
            Some(complete),
            Duration::from_millis(5),
        )
        .await;
        assert!(matches!(
            result,
            Err(GatewaySendError::ResponseHeadersIdleTimeout)
        ));
    }

    #[tokio::test]
    async fn gateway_forwarding_maps_streamed_upload_pack_cap_to_413() {
        let temp = test_temp_dir();
        let token_path = temp.join("gateway-upload-cap-token");
        let identity_token_path = temp.join("identity-upload-cap-token");
        let audit_path = temp.join("gateway-upload-cap.audit.jsonl");
        std::fs::write(&token_path, "upstream-token").unwrap();
        std::fs::write(&identity_token_path, "identity-token").unwrap();

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let upstream_addr = listener.local_addr().unwrap();
        let upstream = tokio::spawn(async move {
            let (_stream, _) = listener.accept().await.unwrap();
            tokio::time::sleep(Duration::from_millis(50)).await;
        });

        let runtime = BrokerRuntime::new(test_forwarding_config(
            &token_path,
            &identity_token_path,
            &audit_path,
        ))
        .unwrap();
        let identity = runtime.identity_from_principal_groups(
            "gateway-user".to_string(),
            Some("gateway-user".to_string()),
            vec!["gateway-users".to_string()],
            None,
            None,
        );
        let mut gateway = test_gateway_config();
        gateway.upstream_base_url = format!("http://{upstream_addr}");
        gateway.allowed_upstream_hosts = vec![format!("http://{upstream_addr}/**")];
        gateway.request_body_max_bytes = Some(4);
        let prepared = runtime
            .prepare_gateway_operation(
                test_governed_operation(OperationContext {
                    agent_request_id: "gateway-upload-cap-forward".to_string(),
                    broker_request_id: "broker-upload-cap-forward".to_string(),
                    identity,
                    service: "gitlab_git".to_string(),
                    action: "repo.fetch".to_string(),
                    source: agent_access_core::SourceContext::unknown(),
                }),
                ResourceScopes::from([("repository".to_string(), vec!["sip/service".to_string()])]),
            )
            .await
            .unwrap();
        let mut headers = HeaderMap::new();
        headers.insert(
            CONTENT_TYPE,
            HeaderValue::from_static("application/x-git-upload-pack-request"),
        );

        let response = forward_prepared_git_http(
            runtime.clone(),
            gateway,
            GatewayForwardRequest {
                git_request_kind: GitRequestKind::UploadPackPost,
                headers,
                body: Body::from("large"),
                content_encoding: None,
                receive_pack: None,
            },
            prepared,
            None,
        )
        .await;

        assert_eq!(response.status(), StatusCode::PAYLOAD_TOO_LARGE);
        assert_eq!(
            response.headers()[REASON_CODE_HEADER],
            ReasonCode::GatewayRequestCapExceeded.as_str()
        );
        upstream.await.unwrap();
        drain_gateway_test_audit(&runtime).await;
        let records = audit_records(&audit_path);
        assert!(records.iter().any(|record| {
            record["agentRequestId"] == "gateway-upload-cap-forward"
                && record["decision"] == "deny"
                && record["reasonCode"] == ReasonCode::GatewayRequestCapExceeded.as_str()
                && record["providerAudit"]["gateway"]["phase"] == "failed"
        }));
    }

    #[tokio::test]
    async fn gateway_forwarding_preserves_upload_pack_content_encoding() {
        let temp = test_temp_dir();
        let token_path = temp.join("gateway-upload-encoding-token");
        let identity_token_path = temp.join("identity-upload-encoding-token");
        let audit_path = temp.join("gateway-upload-encoding.audit.jsonl");
        std::fs::write(&token_path, "upstream-token").unwrap();
        std::fs::write(&identity_token_path, "identity-token").unwrap();

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let upstream_addr = listener.local_addr().unwrap();
        let (request_tx, request_rx) = oneshot::channel();
        let upstream = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut request = Vec::new();
            let mut buffer = [0_u8; 1024];
            loop {
                let read = stream.read(&mut buffer).await.unwrap();
                assert_ne!(
                    read, 0,
                    "gateway closed before sending upstream upload-pack request"
                );
                request.extend_from_slice(&buffer[..read]);
                if request.windows(9).any(|window| window == b"gzip-body") {
                    break;
                }
            }
            request_tx.send(request).unwrap();
            stream
                .write_all(
                    b"HTTP/1.1 200 OK\r\nContent-Type: application/x-git-upload-pack-result\r\nContent-Length: 4\r\nConnection: close\r\n\r\n0000",
                )
                .await
                .unwrap();
        });

        let runtime = BrokerRuntime::new(test_forwarding_config(
            &token_path,
            &identity_token_path,
            &audit_path,
        ))
        .unwrap();
        let identity = runtime.identity_from_principal_groups(
            "gateway-user".to_string(),
            Some("gateway-user".to_string()),
            vec!["gateway-users".to_string()],
            None,
            None,
        );
        let mut gateway = test_gateway_config();
        gateway.upstream_base_url = format!("http://{upstream_addr}");
        gateway.allowed_upstream_hosts = vec![format!("http://{upstream_addr}/**")];
        let prepared = runtime
            .prepare_gateway_operation(
                test_governed_operation(OperationContext {
                    agent_request_id: "gateway-upload-encoding-forward".to_string(),
                    broker_request_id: "broker-upload-encoding-forward".to_string(),
                    identity,
                    service: "gitlab_git".to_string(),
                    action: "repo.fetch".to_string(),
                    source: agent_access_core::SourceContext::unknown(),
                }),
                ResourceScopes::from([("repository".to_string(), vec!["sip/service".to_string()])]),
            )
            .await
            .unwrap();
        let mut headers = HeaderMap::new();
        headers.insert(
            CONTENT_TYPE,
            HeaderValue::from_static("application/x-git-upload-pack-request"),
        );

        let response = forward_prepared_git_http(
            runtime.clone(),
            gateway,
            GatewayForwardRequest {
                git_request_kind: GitRequestKind::UploadPackPost,
                headers,
                body: Body::from("gzip-body"),
                content_encoding: Some(GitContentEncoding::Gzip),
                receive_pack: None,
            },
            prepared,
            None,
        )
        .await;

        let upstream_request = request_rx.await.unwrap();
        let upstream_text = String::from_utf8_lossy(&upstream_request);
        assert!(upstream_text.starts_with("POST /sip/service.git/git-upload-pack HTTP/1.1"));
        assert!(upstream_text.contains("authorization: Bearer upstream-token"));
        assert!(upstream_text.contains("content-type: application/x-git-upload-pack-request"));
        assert!(upstream_text.contains("content-encoding: gzip"));
        assert!(
            upstream_request
                .windows(9)
                .any(|window| window == b"gzip-body")
        );
        assert_eq!(response.status(), StatusCode::OK);
        upstream.await.unwrap();
        drain_gateway_test_audit(&runtime).await;
    }

    #[tokio::test]
    async fn receive_pack_parser_accepts_shallow_prefix_and_preserves_wire_bytes() {
        let mut git = test_gateway_config().git.unwrap();
        git.allow_push = true;
        let limits = gateway_test_limits(4096);
        // First packet captured from a standard Git 2.43 shallow push.
        let mut payload = b"0035shallow e56b9448bcf5add52ac4f1944cb0c20d1bf75056\n".to_vec();
        payload.extend(pkt_line(format!("shallow {RECEIVE_PACK_NEW}").as_bytes()));
        payload.extend(receive_pack_payload(
            RECEIVE_PACK_OLD,
            RECEIVE_PACK_NEW,
            "refs/heads/feature",
            Some("report-status-v2 side-band-64k agent=git/2.43.0"),
            b"PACK",
        ));
        let parsed = parse_receive_pack_body(
            Body::from(payload.clone()),
            &git,
            &HeaderMap::new(),
            &limits,
        )
        .await
        .unwrap();
        assert_eq!(&parsed.prefix[..], &payload[..payload.len() - 4]);
        assert_eq!(&parsed.replay[..], b"PACK");
        assert_eq!(parsed.updates.len(), 1);
        assert_eq!(parsed.updates[0].ref_name, "refs/heads/feature");
    }

    #[tokio::test]
    async fn receive_pack_shallow_prefix_preserves_validation_and_limits() {
        let mut git = test_gateway_config().git.unwrap();
        git.allow_push = true;
        git.deny_ref_patterns = vec!["refs/heads/main".to_string()];
        let limits = gateway_test_limits(4096);
        let shallow = pkt_line(format!("shallow {RECEIVE_PACK_OLD}\n").as_bytes());
        for (reference, caps, reason) in [
            ("refs/heads/main", "report-status", ReasonCode::GitRefDenied),
            (
                "refs/heads/feature",
                "push-options",
                ReasonCode::GitCapabilityDenied,
            ),
        ] {
            let mut payload = shallow.clone();
            payload.extend(receive_pack_payload(
                RECEIVE_PACK_OLD,
                RECEIVE_PACK_NEW,
                reference,
                Some(caps),
                b"PACK",
            ));
            let error = expect_receive_pack_error(
                parse_receive_pack_body(Body::from(payload), &git, &HeaderMap::new(), &limits)
                    .await,
            );
            assert_eq!(error.reason_code(), reason);
        }
        for declaration in [
            "shallow bad\n".to_string(),
            format!("shallow {RECEIVE_PACK_ZERO}\n"),
            "shallow ".to_string(),
        ] {
            let mut payload = pkt_line(declaration.as_bytes());
            payload.extend(b"0000");
            let error = expect_receive_pack_error(
                parse_receive_pack_body(Body::from(payload), &git, &HeaderMap::new(), &limits)
                    .await,
            );
            assert_eq!(error.reason_code(), ReasonCode::GitPktLineMalformed);
        }
        let mut empty = shallow.clone();
        empty.extend(b"0000");
        let error = expect_receive_pack_error(
            parse_receive_pack_body(Body::from(empty), &git, &HeaderMap::new(), &limits).await,
        );
        assert_eq!(error.reason_code(), ReasonCode::GitPktLineMalformed);
        let mut late = receive_pack_payload(
            RECEIVE_PACK_OLD,
            RECEIVE_PACK_NEW,
            "refs/heads/feature",
            Some("report-status"),
            b"",
        );
        late.truncate(late.len() - 4);
        late.extend(shallow.clone());
        late.extend(b"0000");
        let error = expect_receive_pack_error(
            parse_receive_pack_body(Body::from(late), &git, &HeaderMap::new(), &limits).await,
        );
        assert_eq!(error.reason_code(), ReasonCode::GitPktLineMalformed);
        git.receive_pack_prefix_max_bytes = Some(shallow.len() as u64);
        let mut too_large = shallow.clone();
        too_large.extend(shallow);
        too_large.extend(b"0000");
        let error = expect_receive_pack_error(
            parse_receive_pack_body(Body::from(too_large), &git, &HeaderMap::new(), &limits).await,
        );
        assert_eq!(error.reason_code(), ReasonCode::GitPrefixCapExceeded);
    }

    #[tokio::test]
    async fn receive_pack_parser_preserves_pack_bytes_after_flush() {
        let mut git = test_gateway_config().git.unwrap();
        git.allow_push = true;
        let limits = gateway_test_limits(1024);
        let payload = receive_pack_payload(
            RECEIVE_PACK_OLD,
            RECEIVE_PACK_NEW,
            "refs/heads/feature",
            Some("report-status side-band-64k agent=broker-test"),
            b"PACK",
        );
        let expected_prefix_len = payload.len() - 4;

        let parsed = parse_receive_pack_body(
            Body::from(payload.clone()),
            &git,
            &HeaderMap::new(),
            &limits,
        )
        .await
        .unwrap();

        assert_eq!(&parsed.prefix[..], &payload[..expected_prefix_len]);
        assert_eq!(&parsed.replay[..], b"PACK");
        assert_eq!(parsed.updates.len(), 1);
        assert_eq!(parsed.updates[0].old_id, RECEIVE_PACK_OLD);
        assert_eq!(parsed.updates[0].new_id, RECEIVE_PACK_NEW);
        assert_eq!(parsed.updates[0].ref_name, "refs/heads/feature");
        assert!(!parsed.updates[0].create);
        assert!(!parsed.updates[0].delete);
    }

    #[tokio::test]
    async fn receive_pack_parser_allows_large_pack_frame_after_flush() {
        let mut git = test_gateway_config().git.unwrap();
        git.allow_push = true;
        git.receive_pack_prefix_max_bytes = Some(128);
        let limits = gateway_test_limits(4096);
        let trailer = vec![b'x'; 2048];
        let payload = receive_pack_payload(
            RECEIVE_PACK_OLD,
            RECEIVE_PACK_NEW,
            "refs/heads/f",
            Some("report-status"),
            &trailer,
        );

        let parsed = parse_receive_pack_body(Body::from(payload), &git, &HeaderMap::new(), &limits)
            .await
            .unwrap();

        assert_eq!(parsed.replay.len(), trailer.len());
        assert_eq!(&parsed.replay[..], &trailer[..]);
    }

    #[tokio::test]
    async fn receive_pack_parser_rejects_replay_over_request_cap_before_credentials() {
        let mut git = test_gateway_config().git.unwrap();
        git.allow_push = true;
        git.receive_pack_prefix_max_bytes = Some(4096);
        let trailer = b"PACK-OVER-CAP";
        let payload = receive_pack_payload(
            RECEIVE_PACK_OLD,
            RECEIVE_PACK_NEW,
            "refs/heads/feature",
            Some("report-status"),
            trailer,
        );
        let prefix_len = payload.len() - trailer.len();
        let limits = gateway_test_limits(prefix_len + 1);

        // Admit the complete command before a later frame crosses the cap.
        // The rejected frame must retain audit for refs already parsed, while
        // oversized frames themselves are rejected before buffering/parsing.
        let command_len = prefix_len - 4;
        let body = delayed_body(vec![
            (
                Duration::ZERO,
                Bytes::copy_from_slice(&payload[..command_len]),
            ),
            (
                Duration::ZERO,
                Bytes::copy_from_slice(&payload[command_len..]),
            ),
        ]);
        let error = expect_receive_pack_error(
            parse_receive_pack_body(body, &git, &HeaderMap::new(), &limits).await,
        );

        assert_eq!(error.reason_code(), ReasonCode::GatewayRequestCapExceeded);
        let audit = error.audit.map(|audit| *audit).unwrap();
        assert_eq!(audit["git"]["updates"][0]["ref"], "refs/heads/feature");
    }

    #[test]
    fn receive_pack_prefix_cap_uses_conservative_default() {
        let mut git = test_gateway_config().git.unwrap();
        git.receive_pack_prefix_max_bytes = None;
        let limits = gateway_test_limits(usize::MAX);

        assert_eq!(
            receive_pack_prefix_cap(&git, &limits),
            DEFAULT_RECEIVE_PACK_PREFIX_MAX_BYTES
        );
    }

    #[tokio::test]
    async fn receive_pack_parser_denies_unknown_capability_with_ref_audit() {
        let mut git = test_gateway_config().git.unwrap();
        git.allow_push = true;
        let limits = gateway_test_limits(1024);

        let error = expect_receive_pack_error(
            parse_receive_pack_body(
                Body::from(receive_pack_payload(
                    RECEIVE_PACK_OLD,
                    RECEIVE_PACK_NEW,
                    "refs/heads/feature",
                    Some("report-status push-options"),
                    b"",
                )),
                &git,
                &HeaderMap::new(),
                &limits,
            )
            .await,
        );

        assert_eq!(error.reason_code(), ReasonCode::GitCapabilityDenied);
        let audit = error.audit.map(|audit| *audit).unwrap();
        assert_eq!(audit["git"]["operation"], "receive-pack");
        assert_eq!(audit["git"]["updates"][0]["ref"], "refs/heads/feature");
    }

    #[tokio::test]
    async fn receive_pack_parser_denies_tag_delete_and_denied_refs() {
        let mut git = test_gateway_config().git.unwrap();
        git.allow_push = true;
        git.deny_ref_patterns = vec!["refs/heads/main".to_string()];
        let limits = gateway_test_limits(1024);

        let tag = expect_receive_pack_error(
            parse_receive_pack_body(
                Body::from(receive_pack_payload(
                    RECEIVE_PACK_OLD,
                    RECEIVE_PACK_NEW,
                    "refs/tags/v1.0.0",
                    Some("report-status"),
                    b"",
                )),
                &git,
                &HeaderMap::new(),
                &limits,
            )
            .await,
        );
        assert_eq!(tag.reason_code(), ReasonCode::GitRefDenied);

        let delete = expect_receive_pack_error(
            parse_receive_pack_body(
                Body::from(receive_pack_payload(
                    RECEIVE_PACK_OLD,
                    RECEIVE_PACK_ZERO,
                    "refs/heads/feature",
                    Some("report-status"),
                    b"",
                )),
                &git,
                &HeaderMap::new(),
                &limits,
            )
            .await,
        );
        assert_eq!(delete.reason_code(), ReasonCode::GitRefDenied);

        let denied = expect_receive_pack_error(
            parse_receive_pack_body(
                Body::from(receive_pack_payload(
                    RECEIVE_PACK_OLD,
                    RECEIVE_PACK_NEW,
                    "refs/heads/main",
                    Some("report-status"),
                    b"",
                )),
                &git,
                &HeaderMap::new(),
                &limits,
            )
            .await,
        );
        assert_eq!(denied.reason_code(), ReasonCode::GitRefDenied);
    }

    #[tokio::test]
    async fn receive_pack_parser_enforces_prefix_cap() {
        let mut git = test_gateway_config().git.unwrap();
        git.allow_push = true;
        git.receive_pack_prefix_max_bytes = Some(16);
        let limits = gateway_test_limits(1024);

        let error = expect_receive_pack_error(
            parse_receive_pack_body(
                Body::from(receive_pack_payload(
                    RECEIVE_PACK_OLD,
                    RECEIVE_PACK_NEW,
                    "refs/heads/feature",
                    Some("report-status"),
                    b"",
                )),
                &git,
                &HeaderMap::new(),
                &limits,
            )
            .await,
        );

        assert_eq!(error.reason_code(), ReasonCode::GitPrefixCapExceeded);
    }

    #[test]
    fn receive_pack_command_parser_rejects_malformed_commands() {
        let bad_old = expect_receive_pack_command_error(parse_receive_pack_command(
            format!("{RECEIVE_PACK_OLD}x {RECEIVE_PACK_NEW} refs/heads/feature\0report-status")
                .as_bytes(),
            true,
        ));
        assert_eq!(bad_old.reason_code(), ReasonCode::GitPktLineMalformed);

        let bad_ref = expect_receive_pack_command_error(parse_receive_pack_command(
            format!("{RECEIVE_PACK_OLD} {RECEIVE_PACK_NEW} ../feature\0report-status").as_bytes(),
            true,
        ));
        assert_eq!(bad_ref.reason_code(), ReasonCode::GitPktLineMalformed);

        let create_delete = expect_receive_pack_command_error(parse_receive_pack_command(
            format!("{RECEIVE_PACK_ZERO} {RECEIVE_PACK_ZERO} refs/heads/feature\0report-status")
                .as_bytes(),
            true,
        ));
        assert_eq!(create_delete.reason_code(), ReasonCode::GitPktLineMalformed);

        let non_first_capability = expect_receive_pack_command_error(parse_receive_pack_command(
            format!("{RECEIVE_PACK_OLD} {RECEIVE_PACK_NEW} refs/heads/feature\0report-status")
                .as_bytes(),
            false,
        ));
        assert_eq!(
            non_first_capability.reason_code(),
            ReasonCode::GitPktLineMalformed
        );

        let non_utf8 = expect_receive_pack_command_error(parse_receive_pack_command(
            &[0xff, 0xfe, 0xfd, 0x00, b'r', b'e', b'p'],
            true,
        ));
        assert_eq!(non_utf8.reason_code(), ReasonCode::GitPktLineMalformed);

        let missing_capabilities = expect_receive_pack_command_error(parse_receive_pack_command(
            format!("{RECEIVE_PACK_OLD} {RECEIVE_PACK_NEW} refs/heads/feature").as_bytes(),
            true,
        ));
        assert_eq!(
            missing_capabilities.reason_code(),
            ReasonCode::GitPktLineMalformed
        );
    }

    #[tokio::test]
    async fn shared_cache_cannot_replay_git_discovery_between_broker_tokens() {
        use rustls::pki_types::{CertificateDer, PrivateKeyDer, pem::PemObject};
        use std::io::{Read, Write};

        // This deliberately identity-blind cache models RFC 9111 storage for this
        // fixture: a successful authenticated GET with explicit public freshness.
        // private/no-store must override public and prevent reuse across callers.
        fn shared_cache_can_store(headers: &HeaderMap) -> bool {
            let directives = headers
                .get_all(CACHE_CONTROL)
                .iter()
                .filter_map(|value| value.to_str().ok())
                .flat_map(|value| value.split(','))
                .map(|value| value.trim().to_ascii_lowercase())
                .collect::<Vec<_>>();
            directives.iter().any(|value| value == "public")
                && directives.iter().any(|value| value == "max-age=3600")
                && !directives
                    .iter()
                    .any(|value| value == "private" || value == "no-store" || value == "no-cache")
        }
        let mut public_headers = HeaderMap::new();
        public_headers.insert(
            CACHE_CONTROL,
            HeaderValue::from_static("public, max-age=3600"),
        );
        assert!(
            shared_cache_can_store(&public_headers),
            "fixture must expose the original cache vulnerability"
        );

        let temp = test_temp_dir();
        let service_token = temp.join("upstream-token");
        let hash_key = temp.join("hash-key");
        let audit_path = temp.join("cache.audit.jsonl");
        std::fs::write(&service_token, "upstream-token").unwrap();
        std::fs::write(&hash_key, URL_SAFE_NO_PAD.encode([39_u8; 32])).unwrap();
        let fixture = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../agent-access-core/tests/fixtures/outbound-tls");
        let certificate = std::fs::read(fixture.join("leaf-a.pem")).unwrap();
        let key = std::fs::read(fixture.join("leaf-a.key")).unwrap();
        let tls = Arc::new(
            rustls::ServerConfig::builder_with_provider(Arc::new(
                rustls::crypto::ring::default_provider(),
            ))
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(
                CertificateDer::pem_slice_iter(&certificate)
                    .collect::<Result<Vec<_>, _>>()
                    .unwrap(),
                PrivateKeyDer::from_pem_slice(&key).unwrap(),
            )
            .unwrap(),
        );
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let upstream_addr = listener.local_addr().unwrap();
        // The accept deadline starts with the first Broker request, not
        // during the store and runtime setup before it. The sender drops if
        // the test fails first; the wait for it is bounded too.
        let (request_started, request_start) = std::sync::mpsc::channel::<()>();
        let upstream = std::thread::spawn(move || {
            if request_start
                .recv_timeout(Duration::from_secs(300))
                .is_err()
            {
                return;
            }
            let deadline = Instant::now() + Duration::from_secs(10);
            let (stream, _) = loop {
                match listener.accept() {
                    Ok(connection) => break connection,
                    Err(error)
                        if error.kind() == io::ErrorKind::WouldBlock
                            && Instant::now() < deadline =>
                    {
                        std::thread::sleep(Duration::from_millis(5))
                    }
                    Err(error) => panic!("upstream accept: {error}"),
                }
            };
            stream
                .set_read_timeout(Some(Duration::from_secs(5)))
                .unwrap();
            stream
                .set_write_timeout(Some(Duration::from_secs(5)))
                .unwrap();
            let mut stream =
                rustls::StreamOwned::new(rustls::ServerConnection::new(tls).unwrap(), stream);
            let mut request = Vec::new();
            let mut byte = [0; 1];
            while !request.ends_with(b"\r\n\r\n") {
                stream.read_exact(&mut byte).unwrap();
                request.extend_from_slice(&byte);
                assert!(request.len() < 16_384);
            }
            assert!(
                String::from_utf8_lossy(&request).contains("authorization: Bearer upstream-token")
            );
            stream.write_all(b"HTTP/1.1 200 OK\r\nContent-Type: application/x-git-upload-pack-advertisement\r\nCache-Control: public, max-age=3600\r\nExpires: Thu, 01 Oct 2099 00:00:00 GMT\r\nContent-Length: 4\r\nConnection: close\r\n\r\n0000").unwrap();
            stream.flush().unwrap();
        });
        let mut config = test_forwarding_config(&service_token, &service_token, &audit_path);
        config.identity = IdentityConfig {
            trusted_callers: Default::default(),
            mode: "required".into(),
            authority: "managed".into(),
            sources: vec![IdentitySourceConfig {
                name: "broker".into(),
                kind: "broker_tokens".into(),
                header: "Authorization".into(),
                scheme: "Bearer".into(),
                principals: vec![],
            }],
            groups: vec![],
        };
        let store_config = agent_access_core::ManagedStoreConfig {
            kind: "sqlite".into(),
            path: temp.join("store.sqlite").display().to_string(),
            require_registered_principal_for_invocation: false,
            auto_migrate: true,
        };
        config.managed_store = Some(store_config.clone());
        config.credential_encryption = Some(agent_access_core::CredentialEncryptionConfig {
            active_key: "fixture".into(),
            keys: vec![agent_access_core::CredentialEncryptionKeyConfig {
                id: "fixture".into(),
                provider: "file".into(),
                env: None,
                path: Some(hash_key.display().to_string()),
            }],
        });
        config.broker_tokens = Some(agent_access_core::BrokerTokensConfig {
            hash_key_ref: format!("file:{}", hash_key.display()),
            ..Default::default()
        });
        config.network.outbound_tls = agent_access_core::OutboundTlsConfig {
            trust: agent_access_core::OutboundTlsTrustMode::Custom,
            ca_certificate: Some(fixture.join("ca-a.pem")),
        };
        config.policy.grants[0].subjects = vec!["user:gateway-user".into()];
        let gateway = config.gateways.get_mut("gitlab_git").unwrap();
        gateway.upstream_base_url = format!("https://{upstream_addr}");
        gateway.allowed_upstream_hosts = vec![format!("https://{upstream_addr}/**")];
        let store = agent_access_core::ManagedStore::open(
            &store_config,
            agent_access_core::ManagedStoreOpenMode::Startup,
        )
        .unwrap();
        let hasher =
            agent_access_core::BrokerTokenHasher::load(config.broker_tokens.as_ref().unwrap())
                .unwrap();
        let mut tokens = Vec::new();
        for principal in ["gateway-user", "denied-user"] {
            store
                .create_principal(agent_access_core::PrincipalWriteRequest {
                    role: agent_access_core::PrincipalRole::User,
                    self_service_enabled: None,
                    principal_id: principal.into(),
                    kind: "user".into(),
                    display_name: None,
                    email: None,
                    external_subject: None,
                    created_by: "test".into(),
                })
                .unwrap();
            tokens.push(store.issue_broker_token(&hasher, agent_access_core::BrokerTokenIssueRequest { principal_id: principal.into(), name: "cache test".into(), token_class: agent_access_core::BrokerTokenClass::AgentInvoke, scopes: json!({"allowedServices":["gitlab_git"], "allowedExecutionContexts":["default"]}), expires_at: None, created_by: "test".into() }).unwrap().token);
        }
        drop(store);
        let runtime = BrokerRuntime::new(config).unwrap();
        let body_hard_cap = runtime.max_http_body_bytes();
        let audit_registry = runtime.audit_registry();
        let snapshot = RuntimeSnapshot::new(
            1,
            "sha256:cache-test".into(),
            runtime.clone().with_config_generation(1),
            StateLockSet::empty(),
        );
        let state = Arc::new(ReloadableState::from_snapshot(
            std::path::PathBuf::new(),
            Arc::new(crate::backend_registry()),
            crate::broker_build_status(),
            snapshot,
            body_hard_cap,
            Duration::from_secs(30),
            Duration::from_secs(30),
            audit_registry,
        ));
        let router = build_gateway_router(state);
        let mut cache: Option<(StatusCode, HeaderMap, Bytes)> = None;
        let mut broker_calls = 0;
        for (index, token) in tokens.iter().enumerate() {
            let (status, headers, body) = if let Some(cached) = &cache {
                cached.clone()
            } else {
                broker_calls += 1;
                if index == 0 {
                    request_started.send(()).unwrap();
                }
                let response = router
                    .clone()
                    .oneshot(
                        Request::builder()
                            .method(Method::GET)
                            .uri("/sip/service.git/info/refs?service=git-upload-pack")
                            .extension(ConnectInfo(
                                "127.0.0.1:41081".parse::<SocketAddr>().unwrap(),
                            ))
                            .header(HOST, "git.example.test")
                            .header(
                                AUTHORIZATION,
                                format!("Basic {}", BASE64.encode(format!("agent-access:{token}"))),
                            )
                            .body(Body::empty())
                            .unwrap(),
                    )
                    .await
                    .unwrap();
                let status = response.status();
                let headers = response.headers().clone();
                let body = axum::body::to_bytes(response.into_body(), 4096)
                    .await
                    .unwrap();
                if status == StatusCode::OK && shared_cache_can_store(&headers) {
                    cache = Some((status, headers.clone(), body.clone()));
                }
                (status, headers, body)
            };
            assert_eq!(headers[CACHE_CONTROL], "private, no-store");
            assert_eq!(headers[PRAGMA], "no-cache");
            assert!(!headers.contains_key(EXPIRES));
            if index == 0 {
                assert_eq!(status, StatusCode::OK, "{}", String::from_utf8_lossy(&body));
                assert_eq!(&body[..], b"0000");
            } else {
                assert_eq!(status, StatusCode::FORBIDDEN);
                assert_ne!(&body[..], b"0000");
            }
        }
        assert_eq!(
            broker_calls, 2,
            "each caller must reach broker authorization"
        );
        assert!(cache.is_none());
        upstream.join().unwrap();
        drain_gateway_test_audit(&runtime).await;
    }

    #[tokio::test]
    async fn gateway_forwarding_sanitizes_headers_and_audits_before_upstream_response() {
        let temp = test_temp_dir();
        let token_path = temp.join("gateway-token");
        let identity_token_path = temp.join("identity-token");
        let audit_path = temp.join("gateway-forward.audit.jsonl");
        std::fs::write(&token_path, "upstream-token").unwrap();
        std::fs::write(&identity_token_path, "identity-token").unwrap();

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let upstream_addr = listener.local_addr().unwrap();
        let (request_tx, request_rx) = oneshot::channel();
        let (release_tx, release_rx) = oneshot::channel();
        let upstream = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut request = Vec::new();
            let mut buffer = [0_u8; 1024];
            loop {
                let read = stream.read(&mut buffer).await.unwrap();
                assert_ne!(read, 0, "gateway closed before sending upstream request");
                request.extend_from_slice(&buffer[..read]);
                if request.windows(4).any(|window| window == b"\r\n\r\n") {
                    break;
                }
            }
            request_tx
                .send(String::from_utf8_lossy(&request).into_owned())
                .unwrap();
            release_rx.await.unwrap();
            stream
                .write_all(
                    b"HTTP/1.1 200 OK\r\nContent-Type: application/x-git-upload-pack-advertisement\r\nServer: hidden\r\nContent-Length: 4\r\nConnection: close\r\n\r\n0000",
                )
                .await
                .unwrap();
        });

        let runtime = BrokerRuntime::new(test_forwarding_config(
            &token_path,
            &identity_token_path,
            &audit_path,
        ))
        .unwrap();
        let identity = runtime.identity_from_principal_groups(
            "gateway-user".to_string(),
            Some("gateway-user".to_string()),
            vec!["gateway-users".to_string()],
            None,
            None,
        );
        let mut gateway = test_gateway_config();
        gateway.upstream_base_url = format!("http://{upstream_addr}");
        gateway.allowed_upstream_hosts = vec![format!("http://{upstream_addr}/**")];
        let prepared = runtime
            .prepare_gateway_operation(
                test_governed_operation(OperationContext {
                    agent_request_id: "gateway-forward".to_string(),
                    broker_request_id: "broker-forward".to_string(),
                    identity,
                    service: "gitlab_git".to_string(),
                    action: "repo.fetch".to_string(),
                    source: agent_access_core::SourceContext::unknown(),
                }),
                ResourceScopes::from([("repository".to_string(), vec!["sip/service".to_string()])]),
            )
            .await
            .unwrap();

        let mut headers = HeaderMap::new();
        headers.insert(
            AUTHORIZATION,
            HeaderValue::from_static("Basic caller-token"),
        );
        headers.insert(HOST, HeaderValue::from_static("git.example.test"));
        headers.insert("Cookie", HeaderValue::from_static("session=secret"));
        headers.insert(ACCEPT, HeaderValue::from_static("*/*"));
        headers.insert(USER_AGENT, HeaderValue::from_static("git/2.51"));
        headers.insert("Git-Protocol", HeaderValue::from_static("version=2"));

        let runtime_for_forward = runtime.clone();
        let forward = tokio::spawn(async move {
            forward_prepared_git_http(
                runtime_for_forward,
                gateway,
                GatewayForwardRequest {
                    git_request_kind: GitRequestKind::UploadPackDiscovery,
                    headers,
                    body: Body::empty(),
                    content_encoding: None,
                    receive_pack: None,
                },
                prepared,
                None,
            )
            .await
        });

        let upstream_request = request_rx.await.unwrap();
        assert!(
            upstream_request
                .starts_with("GET /sip/service.git/info/refs?service=git-upload-pack HTTP/1.1")
        );
        assert!(upstream_request.contains("authorization: Bearer upstream-token"));
        assert!(!upstream_request.contains("Basic caller-token"));
        assert!(!upstream_request.to_ascii_lowercase().contains("cookie:"));
        assert!(!upstream_request.contains("git.example.test"));
        assert!(upstream_request.contains("git-protocol: version=2"));

        let started_records = audit_records(&audit_path);
        let request_records = started_records
            .iter()
            .filter(|record| record["agentRequestId"] == "gateway-forward")
            .collect::<Vec<_>>();
        assert_eq!(request_records.len(), 1);
        assert_eq!(
            request_records[0]["providerAudit"]["gateway"]["phase"],
            "started"
        );
        assert_eq!(request_records[0]["decision"], "allow");

        release_tx.send(()).unwrap();
        let response = forward.await.unwrap();
        upstream.await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response.headers()[CONTENT_TYPE],
            "application/x-git-upload-pack-advertisement"
        );
        assert!(!response.headers().contains_key("Server"));
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        assert_eq!(&body[..], b"0000");

        drain_gateway_test_audit(&runtime).await;
        let records = audit_records(&audit_path);
        let request_records = records
            .iter()
            .filter(|record| record["agentRequestId"] == "gateway-forward")
            .collect::<Vec<_>>();
        assert_eq!(request_records.len(), 2);
        assert!(request_records.iter().any(|record| {
            record["providerAudit"]["gateway"]["phase"] == "started"
                && record["providerAudit"]["gateway"]["responseBytes"] == 0
        }));
        assert!(request_records.iter().any(|record| {
            record["upstreamStatus"] == 200
                && record["providerAudit"]["gateway"]["phase"] == "completed"
                && record["providerAudit"]["gateway"]["method"] == "GET"
                && record["providerAudit"]["gateway"]["responseBytes"] == 4
        }));
    }

    #[tokio::test]
    async fn gateway_streaming_response_outlives_global_request_timeout_while_data_flows() {
        let temp = test_temp_dir();
        let token_path = temp.join("gateway-timeout-token");
        let identity_token_path = temp.join("identity-timeout-token");
        let audit_path = temp.join("gateway-timeout.audit.jsonl");
        std::fs::write(&token_path, "upstream-token").unwrap();
        std::fs::write(&identity_token_path, "identity-token").unwrap();

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let upstream_addr = listener.local_addr().unwrap();
        let upstream = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            read_http_request_headers(&mut stream).await;
            stream
                .write_all(
                    b"HTTP/1.1 200 OK\r\nContent-Type: application/x-git-upload-pack-advertisement\r\nContent-Length: 4\r\nConnection: close\r\n\r\n",
                )
                .await
                .unwrap();
            tokio::time::sleep(Duration::from_millis(50)).await;
            stream.write_all(b"0000").await.unwrap();
        });

        let mut config = test_forwarding_config(&token_path, &identity_token_path, &audit_path);
        config.limits.request_timeout_ms = 10;
        let runtime = BrokerRuntime::new(config).unwrap();
        let identity = runtime.identity_from_principal_groups(
            "gateway-user".to_string(),
            Some("gateway-user".to_string()),
            vec!["gateway-users".to_string()],
            None,
            None,
        );
        let mut gateway = test_gateway_config();
        gateway.upstream_base_url = format!("http://{upstream_addr}");
        gateway.allowed_upstream_hosts = vec![format!("http://{upstream_addr}/**")];
        gateway.streaming_idle_timeout_ms = Some(1_000);
        let prepared = runtime
            .prepare_gateway_operation(
                test_governed_operation(OperationContext {
                    agent_request_id: "gateway-timeout-forward".to_string(),
                    broker_request_id: "broker-timeout-forward".to_string(),
                    identity,
                    service: "gitlab_git".to_string(),
                    action: "repo.fetch".to_string(),
                    source: agent_access_core::SourceContext::unknown(),
                }),
                ResourceScopes::from([("repository".to_string(), vec!["sip/service".to_string()])]),
            )
            .await
            .unwrap();

        let response = forward_prepared_git_http(
            runtime.clone(),
            gateway,
            GatewayForwardRequest {
                git_request_kind: GitRequestKind::UploadPackDiscovery,
                headers: HeaderMap::new(),
                body: Body::empty(),
                content_encoding: None,
                receive_pack: None,
            },
            prepared,
            None,
        )
        .await;

        assert_eq!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        assert_eq!(&body[..], b"0000");
        upstream.await.unwrap();
    }

    #[tokio::test]
    async fn gateway_forwarding_holds_permits_until_response_body_finishes() {
        let temp = test_temp_dir();
        let token_path = temp.join("gateway-permit-token");
        let identity_token_path = temp.join("identity-permit-token");
        let audit_path = temp.join("gateway-permit.audit.jsonl");
        std::fs::write(&token_path, "upstream-token").unwrap();
        std::fs::write(&identity_token_path, "identity-token").unwrap();

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let upstream_addr = listener.local_addr().unwrap();
        let (release_tx, release_rx) = oneshot::channel();
        let upstream = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            read_http_request_headers(&mut stream).await;
            stream
                .write_all(
                    b"HTTP/1.1 200 OK\r\nContent-Type: application/x-git-upload-pack-advertisement\r\nContent-Length: 4\r\nConnection: close\r\n\r\n",
                )
                .await
                .unwrap();
            release_rx.await.unwrap();
            stream.write_all(b"0000").await.unwrap();
        });

        let runtime = BrokerRuntime::new(test_forwarding_config(
            &token_path,
            &identity_token_path,
            &audit_path,
        ))
        .unwrap();
        let identity = runtime.identity_from_principal_groups(
            "gateway-user".to_string(),
            Some("gateway-user".to_string()),
            vec!["gateway-users".to_string()],
            None,
            None,
        );
        let mut gateway = test_gateway_config();
        gateway.upstream_base_url = format!("http://{upstream_addr}");
        gateway.allowed_upstream_hosts = vec![format!("http://{upstream_addr}/**")];
        let prepared = runtime
            .prepare_gateway_operation(
                test_governed_operation(OperationContext {
                    agent_request_id: "gateway-permit-forward".to_string(),
                    broker_request_id: "broker-permit-forward".to_string(),
                    identity,
                    service: "gitlab_git".to_string(),
                    action: "repo.fetch".to_string(),
                    source: agent_access_core::SourceContext::unknown(),
                }),
                ResourceScopes::from([("repository".to_string(), vec!["sip/service".to_string()])]),
            )
            .await
            .unwrap();
        let guards = Arc::new(crate::ingress::guards::IngressGuards::new());
        let global_permit = guards.try_global_concurrency(1).unwrap();
        let principal_permit = guards.try_principal_concurrency("gateway-user", 1).unwrap();

        let response = forward_prepared_git_http(
            runtime.clone(),
            gateway,
            GatewayForwardRequest {
                git_request_kind: GitRequestKind::UploadPackDiscovery,
                headers: HeaderMap::new(),
                body: Body::empty(),
                content_encoding: None,
                receive_pack: None,
            },
            prepared,
            Some(RequestPermits {
                _global: global_permit,
                _principal: principal_permit,
            }),
        )
        .await;
        assert_eq!(response.status(), StatusCode::OK);
        assert!(guards.try_global_concurrency(1).is_err());
        assert!(guards.try_principal_concurrency("gateway-user", 1).is_err());

        release_tx.send(()).unwrap();
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        assert_eq!(&body[..], b"0000");
        drop(guards.try_global_concurrency(1).unwrap());
        drop(guards.try_principal_concurrency("gateway-user", 1).unwrap());
        upstream.await.unwrap();
    }

    #[tokio::test]
    async fn gateway_upstream_429_passes_through_and_is_audited_as_upstream_rate_limited() {
        let temp = test_temp_dir();
        let token_path = temp.join("gateway-429-token");
        let identity_token_path = temp.join("identity-429-token");
        let audit_path = temp.join("gateway-429.audit.jsonl");
        std::fs::write(&token_path, "upstream-token").unwrap();
        std::fs::write(&identity_token_path, "identity-token").unwrap();

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let upstream_addr = listener.local_addr().unwrap();
        let upstream = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            read_http_request_headers(&mut stream).await;
            stream
                .write_all(
                    b"HTTP/1.1 429 Too Many Requests\r\nContent-Type: text/plain\r\nRetry-After: 30\r\nContent-Length: 10\r\nConnection: close\r\n\r\nslow down\n",
                )
                .await
                .unwrap();
        });

        let runtime = BrokerRuntime::new(test_forwarding_config(
            &token_path,
            &identity_token_path,
            &audit_path,
        ))
        .unwrap();
        let identity = runtime.identity_from_principal_groups(
            "gateway-user".to_string(),
            Some("gateway-user".to_string()),
            vec!["gateway-users".to_string()],
            None,
            None,
        );
        let mut gateway = test_gateway_config();
        gateway.upstream_base_url = format!("http://{upstream_addr}");
        gateway.allowed_upstream_hosts = vec![format!("http://{upstream_addr}/**")];
        let prepared = runtime
            .prepare_gateway_operation(
                test_governed_operation(OperationContext {
                    agent_request_id: "gateway-upstream-429".to_string(),
                    broker_request_id: "broker-upstream-429".to_string(),
                    identity,
                    service: "gitlab_git".to_string(),
                    action: "repo.fetch".to_string(),
                    source: agent_access_core::SourceContext::unknown(),
                }),
                ResourceScopes::from([("repository".to_string(), vec!["sip/service".to_string()])]),
            )
            .await
            .unwrap();

        let response = forward_prepared_git_http(
            runtime.clone(),
            gateway,
            GatewayForwardRequest {
                git_request_kind: GitRequestKind::UploadPackDiscovery,
                headers: HeaderMap::new(),
                body: Body::empty(),
                content_encoding: None,
                receive_pack: None,
            },
            prepared,
            None,
        )
        .await;
        // The Git client sees the upstream throttling unchanged, with a
        // bounded whole-second Retry-After.
        assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);
        assert_eq!(response.headers()[axum::http::header::RETRY_AFTER], "30");
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        assert_eq!(&body[..], b"slow down\n");
        upstream.await.unwrap();

        drain_gateway_test_audit(&runtime).await;
        let records = audit_records(&audit_path);
        let terminal = records
            .iter()
            .filter(|record| record["agentRequestId"] == "gateway-upstream-429")
            .find(|record| record["providerAudit"]["gateway"]["phase"] != "started")
            .unwrap();
        assert_eq!(terminal["decision"], "error");
        assert_eq!(terminal["reasonCode"], "upstream_rate_limited");
        assert_eq!(terminal["upstreamStatus"], 429);
        assert_eq!(terminal["providerAudit"]["gateway"]["phase"], "failed");
        assert_eq!(terminal["providerAudit"]["gateway"]["responseBytes"], 10);
    }

    #[tokio::test]
    async fn gateway_streaming_response_cap_applies_without_content_length() {
        let temp = test_temp_dir();
        let token_path = temp.join("gateway-cap-token");
        let identity_token_path = temp.join("identity-cap-token");
        let audit_path = temp.join("gateway-cap.audit.jsonl");
        std::fs::write(&token_path, "upstream-token").unwrap();
        std::fs::write(&identity_token_path, "identity-token").unwrap();

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let upstream_addr = listener.local_addr().unwrap();
        let upstream = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            read_http_request_headers(&mut stream).await;
            stream
                .write_all(
                    b"HTTP/1.1 200 OK\r\nContent-Type: application/x-git-upload-pack-advertisement\r\nConnection: close\r\n\r\n0000",
                )
                .await
                .unwrap();
        });

        let runtime = BrokerRuntime::new(test_forwarding_config(
            &token_path,
            &identity_token_path,
            &audit_path,
        ))
        .unwrap();
        let identity = runtime.identity_from_principal_groups(
            "gateway-user".to_string(),
            Some("gateway-user".to_string()),
            vec!["gateway-users".to_string()],
            None,
            None,
        );
        let mut gateway = test_gateway_config();
        gateway.upstream_base_url = format!("http://{upstream_addr}");
        gateway.allowed_upstream_hosts = vec![format!("http://{upstream_addr}/**")];
        gateway.response_body_max_bytes = Some(3);
        let prepared = runtime
            .prepare_gateway_operation(
                test_governed_operation(OperationContext {
                    agent_request_id: "gateway-cap-forward".to_string(),
                    broker_request_id: "broker-cap-forward".to_string(),
                    identity,
                    service: "gitlab_git".to_string(),
                    action: "repo.fetch".to_string(),
                    source: agent_access_core::SourceContext::unknown(),
                }),
                ResourceScopes::from([("repository".to_string(), vec!["sip/service".to_string()])]),
            )
            .await
            .unwrap();

        let response = forward_prepared_git_http(
            runtime.clone(),
            gateway,
            GatewayForwardRequest {
                git_request_kind: GitRequestKind::UploadPackDiscovery,
                headers: HeaderMap::new(),
                body: Body::empty(),
                content_encoding: None,
                receive_pack: None,
            },
            prepared,
            None,
        )
        .await;

        assert_eq!(response.status(), StatusCode::OK);
        assert!(
            axum::body::to_bytes(response.into_body(), usize::MAX)
                .await
                .is_err()
        );
        upstream.await.unwrap();

        drain_gateway_test_audit(&runtime).await;
        let records = audit_records(&audit_path);
        assert!(records.iter().any(|record| {
            record["agentRequestId"] == "gateway-cap-forward"
                && record["decision"] == "error"
                && record["reasonCode"] == ReasonCode::GatewayResponseCapExceeded.as_str()
                && record["providerAudit"]["gateway"]["phase"] == "failed"
        }));
    }

    #[tokio::test]
    async fn gateway_forwarding_streams_receive_pack_after_prefix_authorization() {
        let temp = test_temp_dir();
        let token_path = temp.join("gateway-push-token");
        let identity_token_path = temp.join("identity-push-token");
        let audit_path = temp.join("gateway-push-forward.audit.jsonl");
        std::fs::write(&token_path, "upstream-token").unwrap();
        std::fs::write(&identity_token_path, "identity-token").unwrap();

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let upstream_addr = listener.local_addr().unwrap();
        let (request_tx, request_rx) = oneshot::channel();
        let (release_tx, release_rx) = oneshot::channel();
        let upstream = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut request = Vec::new();
            let mut buffer = [0_u8; 1024];
            loop {
                let read = stream.read(&mut buffer).await.unwrap();
                assert_ne!(
                    read, 0,
                    "gateway closed before sending upstream push request"
                );
                request.extend_from_slice(&buffer[..read]);
                if request.windows(4).any(|window| window == b"PACK") {
                    break;
                }
            }
            request_tx.send(request).unwrap();
            release_rx.await.unwrap();
            stream
                .write_all(
                    b"HTTP/1.1 200 OK\r\nContent-Type: application/x-git-receive-pack-result\r\nContent-Length: 4\r\nConnection: close\r\n\r\n0000",
                )
                .await
                .unwrap();
        });

        let mut config = test_forwarding_config(&token_path, &identity_token_path, &audit_path);
        config.policy.grants[0].actions = vec!["repo.push".to_string()];
        config
            .gateways
            .get_mut("gitlab_git")
            .unwrap()
            .git
            .as_mut()
            .unwrap()
            .allow_push = true;
        let runtime = BrokerRuntime::new(config).unwrap();
        let identity = runtime.identity_from_principal_groups(
            "gateway-user".to_string(),
            Some("gateway-user".to_string()),
            vec!["gateway-users".to_string()],
            None,
            None,
        );
        let mut gateway = test_gateway_config();
        gateway.upstream_base_url = format!("http://{upstream_addr}");
        gateway.allowed_upstream_hosts = vec![format!("http://{upstream_addr}/**")];
        gateway.git.as_mut().unwrap().allow_push = true;
        let prepared = runtime
            .prepare_gateway_operation(
                test_governed_operation(OperationContext {
                    agent_request_id: "gateway-push-forward".to_string(),
                    broker_request_id: "broker-push-forward".to_string(),
                    identity,
                    service: "gitlab_git".to_string(),
                    action: "repo.push".to_string(),
                    source: agent_access_core::SourceContext::unknown(),
                }),
                ResourceScopes::from([("repository".to_string(), vec!["sip/service".to_string()])]),
            )
            .await
            .unwrap();

        let mut headers = HeaderMap::new();
        headers.insert(
            AUTHORIZATION,
            HeaderValue::from_static("Basic caller-token"),
        );
        headers.insert(HOST, HeaderValue::from_static("git.example.test"));
        headers.insert(
            CONTENT_TYPE,
            HeaderValue::from_static("application/x-git-receive-pack-request"),
        );
        headers.insert(ACCEPT, HeaderValue::from_static("*/*"));
        headers.insert(USER_AGENT, HeaderValue::from_static("git/2.51"));
        let payload = receive_pack_payload(
            RECEIVE_PACK_OLD,
            RECEIVE_PACK_NEW,
            "refs/heads/feature",
            Some("report-status side-band-64k agent=broker-test"),
            b"PACK",
        );
        let limits = gateway_forward_limits(&runtime, &gateway);
        let receive_pack = parse_receive_pack_body(
            Body::from(payload),
            gateway.git.as_ref().unwrap(),
            &headers,
            &limits,
        )
        .await
        .unwrap();

        let runtime_for_forward = runtime.clone();
        let forward = tokio::spawn(async move {
            forward_prepared_git_http(
                runtime_for_forward,
                gateway,
                GatewayForwardRequest {
                    git_request_kind: GitRequestKind::ReceivePackPost,
                    headers,
                    body: Body::empty(),
                    content_encoding: None,
                    receive_pack: Some(receive_pack),
                },
                prepared,
                None,
            )
            .await
        });

        let upstream_request = request_rx.await.unwrap();
        let upstream_text = String::from_utf8_lossy(&upstream_request);
        assert!(upstream_text.starts_with("POST /sip/service.git/git-receive-pack HTTP/1.1"));
        assert!(upstream_text.contains("authorization: Bearer upstream-token"));
        assert!(upstream_text.contains("content-type: application/x-git-receive-pack-request"));
        assert!(!upstream_text.contains("Basic caller-token"));
        assert!(upstream_text.contains("refs/heads/feature"));
        assert!(upstream_request.windows(4).any(|window| window == b"PACK"));

        let started_records = audit_records(&audit_path);
        assert!(started_records.iter().any(|record| {
            record["agentRequestId"] == "gateway-push-forward"
                && record["providerAudit"]["gateway"]["phase"] == "started"
                && record["providerAudit"]["git"]["updates"][0]["ref"] == "refs/heads/feature"
        }));

        release_tx.send(()).unwrap();
        let response = forward.await.unwrap();
        upstream.await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        assert_eq!(&body[..], b"0000");

        drain_gateway_test_audit(&runtime).await;
        let records = audit_records(&audit_path);
        assert!(records.iter().any(|record| {
            record["agentRequestId"] == "gateway-push-forward"
                && record["upstreamStatus"] == 200
                && record["providerAudit"]["gateway"]["phase"] == "completed"
                && record["providerAudit"]["gateway"]["method"] == "POST"
                && record["providerAudit"]["git"]["updates"][0]["ref"] == "refs/heads/feature"
        }));
    }

    #[tokio::test]
    async fn gateway_forwarding_receive_pack_upload_outlives_idle_timeout_while_data_flows() {
        let temp = test_temp_dir();
        let token_path = temp.join("gateway-slow-push-token");
        let identity_token_path = temp.join("identity-slow-push-token");
        let audit_path = temp.join("gateway-slow-push-forward.audit.jsonl");
        std::fs::write(&token_path, "upstream-token").unwrap();
        std::fs::write(&identity_token_path, "identity-token").unwrap();

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let upstream_addr = listener.local_addr().unwrap();
        let (elapsed_tx, elapsed_rx) = oneshot::channel();
        let upstream = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let started = Instant::now();
            let mut request = read_http_request_headers(&mut stream).await;
            let mut buffer = [0_u8; 1024];
            while !request
                .windows(b"PACK-4".len())
                .any(|window| window == b"PACK-4")
            {
                let read = stream.read(&mut buffer).await.unwrap();
                assert_ne!(
                    read, 0,
                    "gateway closed before streaming the complete push request"
                );
                request.extend_from_slice(&buffer[..read]);
            }
            elapsed_tx.send(started.elapsed()).unwrap();
            stream
                .write_all(
                    b"HTTP/1.1 200 OK\r\nContent-Type: application/x-git-receive-pack-result\r\nContent-Length: 4\r\nConnection: close\r\n\r\n0000",
                )
                .await
                .unwrap();
        });

        let mut config = test_forwarding_config(&token_path, &identity_token_path, &audit_path);
        config.policy.grants[0].actions = vec!["repo.push".to_string()];
        config
            .gateways
            .get_mut("gitlab_git")
            .unwrap()
            .git
            .as_mut()
            .unwrap()
            .allow_push = true;
        let runtime = BrokerRuntime::new(config).unwrap();
        let identity = runtime.identity_from_principal_groups(
            "gateway-user".to_string(),
            Some("gateway-user".to_string()),
            vec!["gateway-users".to_string()],
            None,
            None,
        );
        let mut gateway = test_gateway_config();
        gateway.upstream_base_url = format!("http://{upstream_addr}");
        gateway.allowed_upstream_hosts = vec![format!("http://{upstream_addr}/**")];
        gateway.streaming_idle_timeout_ms = Some(80);
        gateway.git.as_mut().unwrap().allow_push = true;
        let prepared = runtime
            .prepare_gateway_operation(
                test_governed_operation(OperationContext {
                    agent_request_id: "gateway-slow-push-forward".to_string(),
                    broker_request_id: "broker-slow-push-forward".to_string(),
                    identity,
                    service: "gitlab_git".to_string(),
                    action: "repo.push".to_string(),
                    source: agent_access_core::SourceContext::unknown(),
                }),
                ResourceScopes::from([("repository".to_string(), vec!["sip/service".to_string()])]),
            )
            .await
            .unwrap();

        let mut headers = HeaderMap::new();
        headers.insert(
            CONTENT_TYPE,
            HeaderValue::from_static("application/x-git-receive-pack-request"),
        );
        let prefix = receive_pack_payload(
            RECEIVE_PACK_OLD,
            RECEIVE_PACK_NEW,
            "refs/heads/feature",
            Some("report-status side-band-64k"),
            b"",
        );
        let body = delayed_body(vec![
            (Duration::ZERO, Bytes::from(prefix)),
            (Duration::from_millis(30), Bytes::from_static(b"PACK-1")),
            (Duration::from_millis(30), Bytes::from_static(b"PACK-2")),
            (Duration::from_millis(30), Bytes::from_static(b"PACK-3")),
            (Duration::from_millis(30), Bytes::from_static(b"PACK-4")),
        ]);
        let limits = gateway_forward_limits(&runtime, &gateway);
        let receive_pack =
            parse_receive_pack_body(body, gateway.git.as_ref().unwrap(), &headers, &limits)
                .await
                .unwrap();

        let response = forward_prepared_git_http(
            runtime.clone(),
            gateway,
            GatewayForwardRequest {
                git_request_kind: GitRequestKind::ReceivePackPost,
                headers,
                body: Body::empty(),
                content_encoding: None,
                receive_pack: Some(receive_pack),
            },
            prepared,
            None,
        )
        .await;

        let elapsed_before_response = elapsed_rx.await.unwrap();
        assert!(
            elapsed_before_response >= Duration::from_millis(100),
            "test upload completed too quickly to exceed the idle interval: {elapsed_before_response:?}"
        );
        upstream.await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        assert_eq!(&body[..], b"0000");

        drain_gateway_test_audit(&runtime).await;
        let records = audit_records(&audit_path);
        assert!(records.iter().any(|record| {
            record["agentRequestId"] == "gateway-slow-push-forward"
                && record["upstreamStatus"] == 200
                && record["providerAudit"]["gateway"]["phase"] == "completed"
                && record["providerAudit"]["gateway"]["method"] == "POST"
        }));
    }

    const RECEIVE_PACK_OLD: &str = "1111111111111111111111111111111111111111";
    const RECEIVE_PACK_NEW: &str = "2222222222222222222222222222222222222222";
    const RECEIVE_PACK_ZERO: &str = "0000000000000000000000000000000000000000";

    fn gateway_test_limits(request_body_max_bytes: usize) -> GatewayForwardLimits {
        GatewayForwardLimits {
            request_body_max_bytes,
            response_body_max_bytes: 1024,
            idle_timeout: Duration::from_secs(1),
        }
    }

    fn receive_pack_payload(
        old_id: &str,
        new_id: &str,
        ref_name: &str,
        capabilities: Option<&str>,
        trailer: &[u8],
    ) -> Vec<u8> {
        let mut command = format!("{old_id} {new_id} {ref_name}");
        if let Some(capabilities) = capabilities {
            command.push('\0');
            command.push_str(capabilities);
        }
        let mut payload = pkt_line(command.as_bytes());
        payload.extend_from_slice(b"0000");
        payload.extend_from_slice(trailer);
        payload
    }

    fn delayed_body(chunks: Vec<(Duration, Bytes)>) -> Body {
        Body::from_stream(stream::unfold(
            VecDeque::from(chunks),
            |mut chunks| async move {
                let (delay, chunk) = chunks.pop_front()?;
                if !delay.is_zero() {
                    tokio::time::sleep(delay).await;
                }
                Some((Ok::<Bytes, io::Error>(chunk), chunks))
            },
        ))
    }

    fn pkt_line(payload: &[u8]) -> Vec<u8> {
        let mut packet = format!("{:04x}", payload.len() + 4).into_bytes();
        packet.extend_from_slice(payload);
        packet
    }

    async fn read_http_request_headers(stream: &mut tokio::net::TcpStream) -> Vec<u8> {
        let mut request = Vec::new();
        let mut buffer = [0_u8; 1024];
        loop {
            let read = stream.read(&mut buffer).await.unwrap();
            assert_ne!(read, 0, "gateway closed before sending upstream request");
            request.extend_from_slice(&buffer[..read]);
            if request.windows(4).any(|window| window == b"\r\n\r\n") {
                return request;
            }
        }
    }

    fn expect_receive_pack_error(result: Result<ReceivePackBody, ProviderError>) -> ProviderError {
        match result {
            Ok(_) => panic!("expected receive-pack parse error"),
            Err(error) => error,
        }
    }

    fn expect_receive_pack_command_error(
        result: Result<ParsedReceivePackCommand, ProviderError>,
    ) -> ProviderError {
        match result {
            Ok(_) => panic!("expected receive-pack command parse error"),
            Err(error) => error,
        }
    }

    fn test_gateway_config() -> GatewayConfig {
        GatewayConfig {
            allow_forwarded_identity: false,
            kind: "git_http".to_string(),
            display_name: "GitLab Git".to_string(),
            broker_hosts: vec!["git.example.test".to_string()],
            upstream_base_url: "https://gitlab.example.com/git/root".to_string(),
            allowed_upstream_hosts: vec!["https://gitlab.example.com/git/root/**".to_string()],
            egress_proxy: None,
            auth_modes: vec!["basic_broker_token".to_string()],
            basic_broker_token_username: "agent-access".to_string(),
            credential_modes: vec!["service".to_string()],
            redirect_policy: "none".to_string(),
            request_body_max_bytes: Some(1024),
            response_body_max_bytes: Some(1024),
            streaming_idle_timeout_ms: Some(30_000),
            correlation_headers: true,
            git: Some(agent_access_core::GatewayGitConfig {
                allow_fetch: true,
                allow_push: false,
                deny_ref_patterns: vec![],
                deny_delete_refs: true,
                receive_pack_prefix_max_bytes: Some(65_536),
            }),
        }
    }

    fn test_governed_operation(operation: OperationContext) -> GovernedOperationContext {
        GovernedOperationContext {
            operation,
            execution_context: ExecutionContext::new(DEFAULT_EXECUTION_CONTEXT)
                .expect("default execution context is valid"),
        }
    }

    fn gateway_resource(
        id: &str,
        selector: agent_access_provider::ResourceSelector,
    ) -> agent_access_core::ResourceDefinition {
        agent_access_core::ResourceDefinition {
            id: id.to_string(),
            display_name: None,
            resource_type: agent_access_provider::GIT_REPOSITORY_RESOURCE.id().clone(),
            selector,
            allowed_execution_contexts: vec!["default".to_string()],
            enabled: true,
        }
    }

    fn test_forwarding_config(
        token_path: &Path,
        identity_token_path: &Path,
        audit_path: &Path,
    ) -> BrokerConfig {
        BrokerConfig {
            imports: Default::default(),
            oauth: Default::default(),
            deployment: DeploymentConfig::default(),
            network: NetworkConfig::default(),
            execution_context: None,
            identity: IdentityConfig {
                trusted_callers: Default::default(),
                mode: "anonymous".to_string(),
                authority: "toml".to_string(),
                sources: vec![IdentitySourceConfig {
                    name: "static".to_string(),
                    kind: "static_principals".to_string(),
                    header: "Authorization".to_string(),
                    scheme: "Bearer".to_string(),
                    principals: vec![StaticPrincipalConfig {
                        principal: "gateway-user".to_string(),
                        token_refs: vec![format!("file:{}", identity_token_path.display())],
                    }],
                }],
                groups: vec![IdentityGroupConfig {
                    id: "gateway-users".to_string(),
                    status: "active".to_string(),
                    members: vec!["gateway-user".to_string()],
                }],
            },
            credentials: CredentialsConfig {
                imported_modes: Default::default(),
                service: BTreeMap::from([(
                    "gitlab_git".to_string(),
                    CredentialConfig {
                        kind: "bearer_token".to_string(),
                        username_ref: None,
                        token_ref: Some(format!("file:{}", token_path.display())),
                        provider: None,
                        path: None,
                        read_only: None,
                        credential_name: None,
                        profile: None,
                    },
                )]),
                per_user: BTreeMap::new(),
                lookup: BTreeMap::new(),
            },
            managed_store: None,
            credential_encryption: None,
            management: agent_access_core::ManagementConfig::default(),
            broker_tokens: None,
            browser_auth: agent_access_core::BrowserAuthConfig::default(),
            portal: agent_access_core::PortalConfig::default(),
            mcp: Default::default(),
            policy: PolicyConfig {
                authority: "toml".to_string(),
                default_decision: "deny".to_string(),
                resources: vec![gateway_resource(
                    "sip-service",
                    agent_access_provider::ResourceSelector::Exact {
                        value: "sip/service".to_string(),
                    },
                )],
                resource_groups: vec![],
                grants: vec![PolicyGrantConfig {
                    subjects: vec!["group:gateway-users".to_string()],
                    service: "gitlab_git".to_string(),
                    actions: vec!["repo.fetch".to_string()],
                    resources: agent_access_core::ResourceSelection {
                        resource_ids: vec!["sip-service".to_string()],
                        resource_group_ids: vec![],
                    },
                    credential_mode: "service".to_string(),
                    priority: None,
                    execution_contexts: None,
                }],
            },
            attribution: Default::default(),
            providers: ProvidersConfig::default(),
            gateways: BTreeMap::from([("gitlab_git".to_string(), test_gateway_config())]),
            limits: agent_access_core::LimitsConfig::new(
                audit_path
                    .parent()
                    .unwrap()
                    .join("upload-spool")
                    .display()
                    .to_string(),
            ),
            audit: Some(AuditConfig::new(
                agent_access_core::AuditStoreType::Jsonl,
                audit_path.display().to_string(),
            )),
        }
    }

    async fn drain_gateway_test_audit(runtime: &BrokerRuntime) {
        // JSONL retention enumerates the audit directory before draining
        // terminal writes. Shared filesystems can stall that cleanup without
        // changing any gateway response or streaming idle deadline.
        let started = Instant::now();
        runtime
            .shutdown_audit(Duration::from_secs(5))
            .await
            .unwrap_or_else(|error| {
                panic!(
                    "audit shutdown failed after {:?}: {error}",
                    started.elapsed()
                )
            });
    }

    fn audit_records(path: &Path) -> Vec<serde_json::Value> {
        agent_access_core::test_support::read_audit_records(
            agent_access_core::AuditStoreType::Jsonl,
            path,
        )
    }
}
