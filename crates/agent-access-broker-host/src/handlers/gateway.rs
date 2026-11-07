mod protocol;
use crate::handlers::common::{
    CallerAdmission, PendingIdentity, acquire_caller_guard, acquire_global_concurrency_guard,
    admit_service_invocation, emit_request_limited, envelope_response, response_retry_after_header,
};
use crate::handlers::data::body_error_exceeds_limit;
use crate::ingress::body::body_error_timed_out;
use crate::ingress::guards::source_log_address;
use crate::ingress::source::auth_source_key;
use crate::observability;
use crate::state::{AppState, RequestPermits, RuntimeSnapshot};
use agent_access_core::{
    BrokerResponse, BrokerRuntime, ExecutionContext, GatewayConfig, GatewayRequestBodyAudit,
    GovernedOperationContext, IdentityContext, IdentityFailure, OperationContext,
    PreparedGatewayOperation, REASON_CODE_HEADER, new_broker_request_id,
};
use agent_access_provider::{
    BROKER_REQUEST_ID_HEADER, ProviderError, REQUEST_ID_HEADER, ReasonCode, ReasonCodeId,
    ResourceScopes,
};
use axum::body::{Body, Bytes};
use axum::extract::{ConnectInfo, State};
use axum::http::header::{
    AUTHORIZATION, CACHE_CONTROL, CONTENT_LENGTH, CONTENT_TYPE, EXPIRES, HOST, PRAGMA, TRAILER,
    WWW_AUTHENTICATE,
};
use axum::http::{HeaderMap, HeaderValue, Method, Request, Response, StatusCode, Uri};
use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64;
use futures_util::{Stream, TryStreamExt, stream};
use http_body_util::BodyExt;
use protocol::*;
use serde_json::json;
use std::future::Future;
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::pin::Pin;
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicBool, AtomicU8, AtomicU64, Ordering},
};
use std::time::{Duration, Instant};
use tokio::time::timeout;
use url::Url;

const BASIC_CHALLENGE: &str = r#"Basic realm="Agent Access Broker""#;
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
    counted: bool,
    method: Method,
    resource_scopes: ResourceScopes,
    request: Box<dyn agent_access_provider::GatewayRequest>,
    registration: &'static agent_access_provider::GatewayRegistration,
}

struct GatewayAdmission {
    service: String,
    action: String,
    counted: bool,
}

type GatewayIdentityRecheck =
    Pin<Box<dyn Future<Output = Result<IdentityContext, ProviderError>> + Send>>;

struct GatewayContext {
    snapshot: Arc<RuntimeSnapshot>,
    agent_request_id: String,
    broker_request_id: String,
    identity: IdentityContext,
    source: agent_access_core::SourceContext,
    execution_context: ExecutionContext,
    permits: RequestPermits,
    rate_admission: Option<agent_access_core::InvocationAdmissionAudit>,
    dispatch_identity: GatewayIdentityRecheck,
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
    pub(crate) protocol_audit: GatewayAuditDetails,
    pub(crate) body: GatewayBodyStream,
    pub(crate) permits: Option<RequestPermits>,
    pub(crate) expected_body_bytes: Option<usize>,
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
    protocol_audit: GatewayAuditDetails,
    body: GatewayBodyStream,
    bytes_sent: usize,
    expected_body_bytes: Option<usize>,
    _permits: Option<RequestPermits>,
}

enum GatewayPreparedRequestBody {
    Bytes(Vec<u8>),
    Stream {
        body: reqwest::Body,
        failure: Arc<AtomicU8>,
        progress: Arc<GatewayRequestUploadProgress>,
    },
}

struct GatewayForwardOwnership {
    permits: Option<RequestPermits>,
    disposal: Option<GatewayDisposalAudit>,
    dispatch_identity: Option<GatewayIdentityRecheck>,
    #[cfg(test)]
    reloadable: Option<Arc<crate::state::ReloadableState>>,
}

/// The last connection disposal owner releases this audit lease, whether the
/// original body ended, was discarded, or was stopped at its bounded deadline.
#[derive(Clone, Default)]
struct GatewayDisposalAudit(Arc<GatewayDisposalAuditInner>);

#[derive(Default)]
struct GatewayDisposalAuditInner(Mutex<Option<GatewayRequestBodyAudit>>);

impl Drop for GatewayDisposalAuditInner {
    fn drop(&mut self) {
        if let Some(audit) = self.0.get_mut().unwrap().take() {
            audit.complete(None);
        }
    }
}

struct GatewayUploadOwner {
    progress: Arc<GatewayRequestUploadProgress>,
    _permits: Option<RequestPermits>,
}

impl Drop for GatewayUploadOwner {
    fn drop(&mut self) {
        self.progress
            .finish_audit(Some(ReasonCode::GatewayRequestBodyDenied));
    }
}

struct GatewayRequestUploadProgress {
    updates: AtomicU64,
    started: AtomicBool,
    complete: AtomicBool,
    bytes: Arc<AtomicU64>,
    audit: Mutex<Option<GatewayRequestBodyAudit>>,
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
            bytes: Arc::new(AtomicU64::new(0)),
            audit: Mutex::new(None),
        }
    }

    fn mark_progress(&self) {
        self.started.store(true, Ordering::Relaxed);
        self.updates.fetch_add(1, Ordering::Relaxed);
    }

    fn mark_complete(&self) {
        self.complete.store(true, Ordering::Relaxed);
        self.mark_progress();
        self.finish_audit(None);
    }

    fn finish_audit(&self, failure: Option<ReasonCode>) {
        if let Some(audit) = self.audit.lock().unwrap().take() {
            let bytes = Some(self.bytes.load(Ordering::Relaxed));
            match failure {
                Some(reason) => audit.fail(reason, bytes),
                None => audit.complete(bytes),
            }
        }
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

    let matched_gateway = match match_gateway(&snapshot, &request) {
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
        &snapshot.runtime,
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
                        admission: None,
                        operation: OperationContext {
                            agent_request_id,
                            broker_request_id,
                            identity: IdentityContext::anonymous(),
                            service: matched_gateway.service.clone(),
                            action: "gateway.classify".to_string(),
                            source,
                        },
                        execution_context,
                    },
                    if snapshot
                        .runtime
                        .config()
                        .imports
                        .gateway_bindings
                        .contains_key(&matched_gateway.service)
                    {
                        error.with_audit(json!({"gateway": {
                            "kind": matched_gateway.config.kind,
                            "method": observability::bounded_http_method(request.method()),
                        }}))
                    } else {
                        error
                    },
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
        GatewayAdmission {
            service: classified.service.clone(),
            action: classified.action.clone(),
            counted: classified.counted,
        },
    )
    .await
    {
        Ok(context) => context,
        Err(response) => return *response,
    };
    // Refusals before admission, including authentication, concurrency, rate
    // and queue limits, never read the body. A later refusal or upstream
    // failure can leave it unread, as for a push refused after its command
    // prefix; the connection lingers so the client reads the response. The
    // remainder is only discarded, never parsed or forwarded. Lingering keeps
    // the admitted request's permits, so it stays within the global and
    // per-principal concurrency limits.
    let (request, unread) = crate::ingress::lingering_close::track(request);
    let permits = context.permits.clone();
    let disposal = GatewayDisposalAudit::default();
    let response = gateway_dispatch_admitted(
        &state,
        request,
        matched_gateway,
        classified,
        context,
        disposal.clone(),
    )
    .await;
    unread.linger_gateway(response, (permits, disposal))
}

async fn gateway_dispatch_admitted(
    state: &AppState,
    request: Request<Body>,
    mut matched_gateway: MatchedGateway,
    classified: ClassifiedGatewayRequest,
    context: GatewayContext,
    disposal: GatewayDisposalAudit,
) -> Response<Body> {
    let GatewayContext {
        snapshot,
        agent_request_id,
        broker_request_id,
        identity,
        source,
        execution_context,
        permits,
        rate_admission,
        dispatch_identity,
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
    let operation_context = GovernedOperationContext {
        admission: rate_admission,
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
        return gateway_runtime_response(
            runtime
                .reject_gateway_operation_without_credential(
                    operation_context,
                    classified.resource_scopes,
                    error,
                )
                .await,
        );
    }
    let body = protocol_body(request.into_body(), &limits);
    let plan = match classified.request.preflight(body).await {
        Ok(plan) => plan,
        Err(error) => {
            return gateway_runtime_response(
                runtime
                    .reject_gateway_operation_without_credential(
                        operation_context,
                        classified.resource_scopes,
                        checked_failure(
                            classified.registration,
                            agent_access_provider::GatewayHookPhase::Preflight,
                            error,
                        ),
                    )
                    .await,
            );
        }
    };
    let upstream_url =
        match validate_forward_plan(&matched_gateway.config, &classified.method, &plan).and_then(
            |url| {
                if plan.headers.keys().any(|name| {
                    imported_credential_header(&runtime, &matched_gateway.service, name.as_str())
                }) {
                    Err(contract_failure())
                } else {
                    Ok(url)
                }
            },
        ) {
            Ok(url) => url,
            Err(error) => {
                return gateway_runtime_response(
                    runtime
                        .reject_gateway_operation_without_credential(
                            operation_context,
                            classified.resource_scopes,
                            error,
                        )
                        .await,
                );
            }
        };
    let prepared = match runtime
        .prepare_gateway_operation(operation_context, classified.resource_scopes)
        .await
    {
        Ok(prepared) => prepared,
        Err(response) => return gateway_runtime_response(*response),
    };
    #[cfg(test)]
    state
        .reloadable
        .wait_gateway_dispatch_barrier(crate::state::GatewayDispatchPhase::AfterPrepare)
        .await;
    forward_prepared_gateway(
        runtime,
        matched_gateway.config,
        classified.registration,
        upstream_url,
        plan,
        prepared,
        GatewayForwardOwnership {
            permits: Some(permits),
            disposal: Some(disposal),
            dispatch_identity: Some(dispatch_identity),
            #[cfg(test)]
            reloadable: Some(state.reloadable.clone()),
        },
    )
    .await
}

async fn gateway_context(
    state: &AppState,
    ingress: GatewayIngressContext,
    headers: &HeaderMap,
    matched_gateway: &MatchedGateway,
    classified: GatewayAdmission,
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

    let failure_context = || GovernedOperationContext {
        admission: None,
        operation: OperationContext {
            agent_request_id: agent_request_id.clone(),
            broker_request_id: broker_request_id.clone(),
            identity: IdentityContext::anonymous(),
            service: classified.service.clone(),
            action: classified.action.clone(),
            source: source.clone(),
        },
        execution_context: execution_context.clone(),
    };
    let (pending, recheck, dispatch_identity) =
        match gateway_identity(state, &snapshot, headers, matched_gateway, &admission).await {
            Ok(pending) => pending,
            Err(error) => {
                return Err(Box::new(gateway_runtime_response_with_challenges(
                    gateway_identity_failure(state, &snapshot, failure_context(), error).await,
                    &matched_gateway.config,
                )));
            }
        };
    // A membership renewal wait holds the caller's capacity.
    let principal_permit = acquire_caller_guard(
        state,
        &snapshot,
        &agent_request_id,
        classified.service.clone(),
        classified.action.clone(),
        &source,
        CallerAdmission {
            identity: pending.value(),
        },
    )
    .await
    .map_err(|response| Box::new(gateway_runtime_response(*response)))?;
    let identity = match pending.admit(state, &snapshot, headers).await {
        Ok(identity) => identity,
        Err(error) => {
            return Err(Box::new(gateway_runtime_response_with_basic_challenge(
                gateway_identity_failure(state, &snapshot, failure_context(), error).await,
            )));
        }
    };

    // Only pack transfers invoke the service; ref discovery is not counted.
    let permits = RequestPermits {
        _global: global_permit,
        _principal: principal_permit,
    };
    let (identity, source, execution_context, permits, rate_admission) = if classified.counted {
        let recheck_snapshot = snapshot.clone();
        let recheck_state = state.clone();
        let deadline = crate::ingress::request_lifetime::RequestLifetime::current().deadline();
        let revalidate: crate::admission::AdmissionRevalidation =
            Box::new(move |context, guard| {
                Box::pin(async move {
                    let recheck = crate::admission::identity_work(guard, recheck);
                    let result = match deadline {
                        Some(deadline) => match tokio::time::timeout_at(deadline.at, recheck).await
                        {
                            Ok(result) if tokio::time::Instant::now() < deadline.at => result
                                .unwrap_or_else(|_| {
                                    Err(gateway_identity_invalid(IdentityFailure::Invalid))
                                }),
                            _ => Err(ProviderError::deny(
                                ReasonCode::GatewayRequestBodyDenied,
                                "gateway request body read timed out",
                            )),
                        },
                        None => recheck.await.unwrap_or_else(|_| {
                            Err(gateway_identity_invalid(IdentityFailure::Invalid))
                        }),
                    }
                    .and_then(|identity| {
                        if identity.principal == context.operation.identity.principal {
                            Ok(identity)
                        } else {
                            Err(gateway_identity_invalid(IdentityFailure::Invalid))
                        }
                    });
                    match result {
                        Ok(identity) => Ok(identity),
                        Err(error)
                            if error.reason_code().standard()
                                != Some(ReasonCode::GatewayRequestBodyDenied) =>
                        {
                            Err(Box::new(
                                gateway_identity_failure(
                                    &recheck_state,
                                    &recheck_snapshot,
                                    context,
                                    error,
                                )
                                .await,
                            ))
                        }
                        Err(error) => Err(Box::new(
                            recheck_snapshot
                                .runtime
                                .governed_operation_error_response(context, error)
                                .await,
                        )),
                    }
                })
            });
        let (context, permits) = admit_service_invocation(
            state,
            &snapshot,
            GovernedOperationContext {
                admission: None,
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
            permits,
            revalidate,
            crate::admission::AdmissionSurface::Git,
        )
        .await
        .map_err(|response| {
            Box::new(gateway_runtime_response_with_challenges(
                *response,
                &matched_gateway.config,
            ))
        })?;
        (
            context.operation.identity,
            context.operation.source,
            context.execution_context,
            permits,
            context.admission,
        )
    } else {
        (identity, source, execution_context, permits, None)
    };

    Ok(GatewayContext {
        snapshot,
        agent_request_id,
        broker_request_id,
        identity,
        source,
        execution_context,
        permits,
        rate_admission,
        dispatch_identity,
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

/// A Git request's identity failure: the source's authentication budget is
/// charged and the failure is audited anonymously. Keep rate admission evidence
/// when a previously admitted identity failed its post-wait revalidation.
async fn gateway_identity_failure(
    state: &AppState,
    snapshot: &RuntimeSnapshot,
    mut context: GovernedOperationContext,
    error: ProviderError,
) -> BrokerResponse<serde_json::Value> {
    context.operation.identity = IdentityContext::anonymous();
    if let Err(error) = state.reloadable.shared_ingress.check_auth_source_rate(
        &auth_source_key(&context.operation.source),
        snapshot
            .runtime
            .limits()
            .auth_requests_per_source_per_minute,
    ) {
        emit_request_limited(
            &error,
            &context.operation.agent_request_id,
            &context.operation.broker_request_id,
            &context.operation.service,
            &context.operation.action,
            Some(&context.operation.source),
            None,
        );
        return snapshot
            .runtime
            .governed_admission_limit_error_response(context, error.into_provider_error())
            .await;
    }
    snapshot
        .runtime
        .governed_operation_error_response(context, error)
        .await
}

fn gateway_identity_invalid(_: IdentityFailure) -> ProviderError {
    ProviderError::deny(
        ReasonCode::GatewayAuthInvalid,
        "gateway identity is invalid",
    )
}

/// The Git request's identity for membership renewal admission: a
/// forwarded identity, or a Basic broker token. After a wait the forwarded
/// identity revalidates its original proof and caller-security epoch, and
/// the Basic token is resolved again.
async fn gateway_identity(
    state: &AppState,
    snapshot: &Arc<RuntimeSnapshot>,
    headers: &HeaderMap,
    matched_gateway: &MatchedGateway,
    admission: &agent_access_core::IngressAdmission,
) -> Result<
    (
        PendingIdentity<IdentityContext, ProviderError>,
        GatewayIdentityRecheck,
        GatewayIdentityRecheck,
    ),
    ProviderError,
> {
    if !headers.contains_key(AUTHORIZATION)
        && matched_gateway.config.allow_forwarded_identity
        && headers.contains_key("x-aw-identity-token-sha256")
    {
        let runtime = snapshot.runtime.clone();
        let forwarded = admission.clone();
        let resolved = tokio::task::spawn_blocking(move || {
            runtime.resolve_forwarded_identity_with_proof(&forwarded)
        })
        .await
        .unwrap_or(Err(IdentityFailure::Invalid))
        .map_err(gateway_identity_invalid)?;
        let pin = crate::mcp::IdentityPin {
            caller_security_epoch: admission
                .caller_id()
                .map(|_| snapshot.caller_security_epoch),
            admission: admission.clone(),
            proof: resolved.proof,
        };
        let resolve = move || {
            let pin = pin.clone();
            let reloadable = state.reloadable.clone();
            let current = snapshot.clone();
            let credential = headers.clone();
            async move { pin.revalidate(reloadable, current, credential).await }
        };
        let renewal_recheck = resolve();
        let rate_recheck = resolve();
        let dispatch_recheck = resolve();
        return Ok((
            PendingIdentity::new(
                resolved.identity,
                resolved.membership_renewal,
                renewal_recheck,
            )
            .map_err(gateway_identity_invalid),
            Box::pin(async move { rate_recheck.await.map_err(gateway_identity_invalid) }),
            Box::pin(async move { dispatch_recheck.await.map_err(gateway_identity_invalid) }),
        ));
    }
    let token = basic_broker_token(headers, matched_gateway)?;
    let resolve = |token: String| {
        // Resolution records the token's last use: the blocking worker holds
        // the snapshot, and with it the state locks, until that write returns.
        let snapshot = Arc::clone(snapshot);
        let caller_id = admission.caller_id().map(str::to_owned);
        async move {
            tokio::task::spawn_blocking(move || {
                let mut resolved = snapshot
                    .runtime
                    .resolve_gateway_basic_broker_token(&token)?;
                resolved.identity.caller_id = caller_id;
                Ok(resolved)
            })
            .await
            .unwrap_or(Err(IdentityFailure::Invalid))
            .map_err(|_| {
                ProviderError::deny(ReasonCode::GatewayAuthInvalid, "gateway auth is invalid")
            })
        }
    };
    let resolved = resolve(token.clone()).await?;
    let recheck = resolve(token.clone());
    let rate_recheck = resolve(token.clone());
    let dispatch_recheck = resolve(token);
    Ok((
        PendingIdentity::new(resolved.identity, resolved.membership_renewal, async move {
            recheck.await.map(|resolved| resolved.identity)
        }),
        Box::pin(async move { rate_recheck.await.map(|resolved| resolved.identity) }),
        Box::pin(async move { dispatch_recheck.await.map(|resolved| resolved.identity) }),
    ))
}

fn basic_broker_token(
    headers: &HeaderMap,
    matched_gateway: &MatchedGateway,
) -> Result<String, ProviderError> {
    let mut values = headers.get_all(AUTHORIZATION).iter();
    let Some(raw) = values.next() else {
        return Err(ProviderError::deny(
            ReasonCode::GatewayAuthRequired,
            "gateway authentication is required",
        ));
    };
    if values.next().is_some() {
        return Err(ProviderError::deny(
            ReasonCode::GatewayAuthInvalid,
            "gateway auth is ambiguous",
        ));
    }
    let invalid = || ProviderError::deny(ReasonCode::GatewayAuthInvalid, "gateway auth is invalid");
    let raw = raw.to_str().map_err(|_| invalid())?;
    let (scheme, encoded) = raw.split_once(' ').ok_or_else(invalid)?;
    if scheme.eq_ignore_ascii_case("Bearer") {
        if !matched_gateway
            .config
            .auth_modes
            .iter()
            .any(|mode| mode == "bearer_broker_token")
            || encoded.is_empty()
            || encoded.bytes().any(|byte| byte.is_ascii_whitespace())
        {
            return Err(invalid());
        }
        return Ok(encoded.to_owned());
    }
    if !scheme.eq_ignore_ascii_case("Basic")
        || !matched_gateway
            .config
            .auth_modes
            .iter()
            .any(|mode| mode == "basic_broker_token")
    {
        return Err(invalid());
    }
    let decoded =
        String::from_utf8(BASE64.decode(encoded).map_err(|_| invalid())?).map_err(|_| invalid())?;
    let (username, token) = decoded.split_once(':').ok_or_else(invalid)?;
    if username != matched_gateway.config.basic_broker_token_username || token.is_empty() {
        return Err(invalid());
    }
    Ok(token.to_owned())
}

async fn forward_prepared_gateway(
    runtime: BrokerRuntime,
    gateway: GatewayConfig,
    registration: &'static agent_access_provider::GatewayRegistration,
    upstream_url: Url,
    plan: agent_access_provider::GatewayForwardPlan,
    mut prepared: PreparedGatewayOperation,
    ownership: GatewayForwardOwnership,
) -> Response<Body> {
    let GatewayForwardOwnership {
        permits,
        disposal,
        dispatch_identity,
        #[cfg(test)]
        reloadable,
    } = ownership;
    let method = plan.method.clone();
    let limits = gateway_forward_limits(&runtime, &gateway);
    let request_body = prepare_protocol_request_body(plan.body, &limits, permits.clone());
    let protocol_audit = GatewayAuditDetails {
        kind: gateway.kind.clone(),
        key: registration.audit_key().to_owned(),
        facts: plan.audit,
        path: plan
            .audit_target
            .unwrap_or_else(|| upstream_url.path().to_owned()),
        request_bytes: match &request_body {
            GatewayPreparedRequestBody::Bytes(bytes) => {
                Arc::new(AtomicU64::new(bytes.len() as u64))
            }
            GatewayPreparedRequestBody::Stream { progress, .. } => progress.bytes.clone(),
        },
    };
    let (client, egress_proxy_audit) =
        match runtime.gateway_http_client(&prepared.service, &gateway) {
            Ok(client) => client,
            Err(_) => {
                return gateway_runtime_response(
                    runtime
                        .fail_prepared_gateway_operation(
                            prepared,
                            ProviderError::error(
                                ReasonCode::GatewayUpstreamDenied,
                                "gateway upstream client is unavailable",
                            ),
                        )
                        .await,
                );
            }
        };
    let (replay_failure, upload_progress) = match &request_body {
        GatewayPreparedRequestBody::Stream {
            failure, progress, ..
        } => (Some(failure.clone()), Some(progress.clone())),
        GatewayPreparedRequestBody::Bytes(_) => (None, None),
    };
    let mut builder = client
        .request(method.clone(), upstream_url.clone())
        .headers(plan.headers);
    builder = match request_body {
        GatewayPreparedRequestBody::Bytes(bytes) if bytes.is_empty() => builder,
        GatewayPreparedRequestBody::Bytes(bytes) => builder.body(bytes),
        GatewayPreparedRequestBody::Stream { body, .. } => builder.body(body),
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
    // No request is resubmitted from method/replayability alone. The transport
    // disables implicit protocol retries. This explicit exception requires the
    // linked module's bodyless profile, which validate_forward_plan checked.
    let discovery_retry = (plan.replay
        == agent_access_provider::GatewayReplayProfile::BodylessCredentialRecovery)
        .then(|| builder.try_clone())
        .flatten();
    let presentation = match prepared.upstream_presentation(&gateway).await {
        Ok(presentation) => presentation,
        Err(error) => {
            return gateway_runtime_response(
                runtime
                    .fail_prepared_gateway_operation(prepared, error)
                    .await,
            );
        }
    };
    if let Some(authorization) = presentation.authorization() {
        builder = agent_access_provider::host::authorize_host_request(builder, authorization);
    }
    let attempt_audit = GatewayAttemptAudit {
        method: &method,
        upstream_url: &upstream_url,
        egress_proxy: &egress_proxy_audit,
        protocol: &protocol_audit,
    };
    if let Err(response) = runtime
        .start_prepared_gateway_operation(&mut prepared, attempt_audit.value())
        .await
    {
        return gateway_runtime_response(*response);
    }
    #[cfg(test)]
    if let Some(state) = reloadable {
        state
            .wait_gateway_dispatch_barrier(crate::state::GatewayDispatchPhase::BeforeSend)
            .await;
    }
    // Generated gateways must keep the original identity and generation through
    // every await above. Never select replacement credentials or remap a proof.
    if runtime
        .imported_catalog()
        .service(&prepared.service)
        .is_some()
        && let Some(recheck) = dispatch_identity
    {
        let result = recheck.await.and_then(|identity| {
            if identity == prepared.identity {
                Ok(())
            } else {
                Err(gateway_identity_invalid(IdentityFailure::Invalid))
            }
        });
        if let Err(error) = result {
            return gateway_runtime_response(
                runtime
                    .fail_prepared_gateway_operation(
                        prepared,
                        error.with_audit(attempt_audit.value()),
                    )
                    .await,
            );
        }
    }
    if let Err(error) = prepared.validate_imported_dispatch() {
        return gateway_runtime_response(
            runtime
                .fail_prepared_gateway_operation(prepared, error.with_audit(attempt_audit.value()))
                .await,
        );
    }
    if let Some(progress) = &upload_progress {
        *progress.audit.lock().unwrap() = prepared.retain_gateway_request_body();
        if let Some(disposal) = &disposal {
            *disposal.0.0.lock().unwrap() = prepared.retain_gateway_request_body();
        }
    }
    let started = Instant::now();
    let mut upstream_response = match send_gateway_upstream(
        builder,
        upload_progress,
        replay_failure.as_deref(),
        limits.idle_timeout,
        &attempt_audit,
        started,
    )
    .await
    {
        Ok(response) => response,
        Err(error) => {
            return gateway_runtime_response(
                runtime
                    .fail_prepared_gateway_operation(prepared, error)
                    .await,
            );
        }
    };
    if upstream_response.status() == reqwest::StatusCode::UNAUTHORIZED
        && presentation.is_delegated()
    {
        drop(upstream_response);
        let outcome = match discovery_retry {
            Some(retry) => {
                retry_bodyless_gateway(
                    &prepared,
                    &gateway,
                    retry,
                    limits.idle_timeout,
                    &attempt_audit,
                    started,
                )
                .await
            }
            None => Err(prepared
                .reject_upstream_presentation(
                    &presentation,
                    agent_access_core::GatewayUpstreamRejection::NotReplayed,
                )
                .with_upstream(Some(401), Some(elapsed_millis(started)))
                .with_audit(attempt_audit.value())),
        };
        upstream_response = match outcome {
            Ok(response) => response,
            Err(error) => {
                return gateway_runtime_response(
                    runtime
                        .fail_prepared_gateway_operation(prepared, error)
                        .await,
                );
            }
        };
    }
    let status = upstream_response.status().as_u16();
    let headers = upstream_response.headers().clone();
    let body_forbidden = method == Method::HEAD || status == 204 || status == 304;
    let expected_body_bytes = if body_forbidden {
        Some(0)
    } else {
        content_length_value(&headers).and_then(|length| usize::try_from(length).ok())
    };
    let response_error = if plan.response.translate_unauthorized && status == 401 {
        Some(ProviderError::error(
            ReasonCode::UpstreamUnauthorized,
            "gateway upstream authentication failed",
        ))
    } else if plan.response.reject_redirects && (300..400).contains(&status) && status != 304 {
        Some(ProviderError::error(
            ReasonCode::UpstreamProtocolFailed,
            "gateway upstream redirect is not permitted",
        ))
    } else if !body_forbidden
        && response_content_length_exceeds(&headers, limits.response_body_max_bytes)
    {
        Some(ProviderError::error(
            ReasonCode::GatewayResponseCapExceeded,
            "gateway upstream response exceeds configured cap",
        ))
    } else {
        None
    };
    if let Some(error) = response_error {
        return gateway_runtime_response(
            runtime
                .fail_prepared_gateway_operation(
                    prepared,
                    error
                        .with_upstream(Some(status), Some(elapsed_millis(started)))
                        .with_audit(attempt_audit.value()),
                )
                .await,
        );
    }
    let response_headers =
        match selected_response_headers(registration, &plan.response, status, &headers) {
            Ok(headers) => headers,
            Err(error) => {
                return gateway_runtime_response(
                    runtime
                        .fail_prepared_gateway_operation(
                            prepared,
                            error
                                .with_upstream(Some(status), Some(elapsed_millis(started)))
                                .with_audit(attempt_audit.value()),
                        )
                        .await,
                );
            }
        };
    prepared.observe_gateway_response_progress(status, attempt_audit.value());
    let broker_request_id = prepared.correlation.broker_request_id.clone();
    let body = if expected_body_bytes == Some(0) {
        // Hyper need not poll HEAD/204/304/zero-length bodies. Complete before
        // giving it an empty body; unread-request disposal retains its permits.
        let _ = runtime
            .complete_prepared_gateway_operation(
                prepared,
                status,
                elapsed_millis(started),
                attempt_audit.value(),
            )
            .await;
        drop(upstream_response);
        drop(permits);
        Body::empty()
    } else {
        Body::from_stream(gateway_response_body_stream(GatewayResponseStreamInput {
            runtime,
            prepared,
            method,
            upstream_url,
            egress_proxy_audit,
            upstream_status: status,
            started,
            limits,
            protocol_audit,
            body: Box::pin(upstream_response.bytes_stream()),
            permits,
            expected_body_bytes,
        }))
    };
    let mut response =
        gateway_upstream_response(status, &broker_request_id, &response_headers, body);
    if plan.response.preserve_content_length
        && status != 204
        && let Some(length) = headers.get(CONTENT_LENGTH)
    {
        response
            .headers_mut()
            .insert(CONTENT_LENGTH, length.clone());
    }
    response
}

/// The facts every gateway audit value of one forwarded request repeats.
struct GatewayAttemptAudit<'a> {
    method: &'a Method,
    upstream_url: &'a Url,
    egress_proxy: &'a serde_json::Value,
    protocol: &'a GatewayAuditDetails,
}

impl GatewayAttemptAudit<'_> {
    /// The gateway audit value before any response bytes.
    fn value(&self) -> serde_json::Value {
        gateway_forward_audit(
            self.method,
            self.upstream_url,
            self.egress_proxy.clone(),
            0,
            self.protocol.clone(),
        )
    }
}

/// Sends one upstream attempt, failing as the operation's error when no
/// response headers arrive.
async fn send_gateway_upstream(
    builder: reqwest::RequestBuilder,
    upload_progress: Option<Arc<GatewayRequestUploadProgress>>,
    replay_failure: Option<&AtomicU8>,
    idle_timeout: Duration,
    audit: &GatewayAttemptAudit<'_>,
    started: Instant,
) -> Result<reqwest::Response, ProviderError> {
    let timed_out = |message: &'static str| {
        ProviderError::error(ReasonCode::UpstreamTimeout, message)
            .with_upstream(None, Some(elapsed_millis(started)))
            .with_audit(audit.value())
    };
    match gateway_send_with_upload_watchdog(builder.send(), upload_progress, idle_timeout).await {
        Ok(response) => Ok(response),
        Err(GatewaySendError::Inner(error)) => {
            let duration_ms = elapsed_millis(started);
            let replay_failure = replay_failure
                .map(|failure| failure.load(Ordering::Relaxed))
                .unwrap_or(REPLAY_FAILURE_NONE);
            Err(reqwest_error_to_provider_error(
                error,
                audit.method,
                audit.upstream_url,
                audit.egress_proxy.clone(),
                audit.protocol.clone(),
                replay_failure,
            )
            .with_upstream(None, Some(duration_ms)))
        }
        Err(GatewaySendError::RequestUploadIdleTimeout) => {
            Err(timed_out("gateway upstream request upload timed out"))
        }
        Err(GatewaySendError::ResponseHeadersIdleTimeout) => {
            Err(timed_out("gateway upstream response headers timed out"))
        }
    }
}

/// Ref discovery's one recovery after the upstream answered its OAuth access
/// with 401: the access is replaced, reusing a successor another request
/// already obtained, and the request is sent once more. A second 401 rejects
/// the replacement too and fails the request.
async fn retry_bodyless_gateway(
    prepared: &PreparedGatewayOperation,
    gateway: &GatewayConfig,
    retry: reqwest::RequestBuilder,
    idle_timeout: Duration,
    audit: &GatewayAttemptAudit<'_>,
    started: Instant,
) -> Result<reqwest::Response, ProviderError> {
    let rejected = |error: ProviderError| {
        error
            .with_upstream(Some(401), Some(elapsed_millis(started)))
            .with_audit(audit.value())
    };
    let presentation = prepared
        .recover_upstream_presentation(gateway)
        .await
        .map_err(rejected)?;
    let retry = match presentation.authorization() {
        Some(authorization) => {
            agent_access_provider::host::authorize_host_request(retry, authorization)
        }
        None => return Err(contract_failure()),
    };
    let response = send_gateway_upstream(retry, None, None, idle_timeout, audit, started).await?;
    if response.status() == reqwest::StatusCode::UNAUTHORIZED {
        return Err(rejected(prepared.reject_upstream_presentation(
            &presentation,
            agent_access_core::GatewayUpstreamRejection::AfterRecovery,
        )));
    }
    Ok(response)
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

#[cfg(test)]
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
        protocol_audit: input.protocol_audit,
        body: input.body,
        bytes_sent: 0,
        expected_body_bytes: input.expected_body_bytes,
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
                if state
                    .expected_body_bytes
                    .is_some_and(|expected| state.bytes_sent.saturating_add(chunk.len()) > expected)
                {
                    let error = ProviderError::error(
                        ReasonCode::UpstreamProtocolFailed,
                        "gateway upstream response length is invalid",
                    );
                    let (item, state) = fail_gateway_response_stream(state, prepared, error).await;
                    return Some((Err(item), state));
                }
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
                    gateway_forward_audit(
                        &state.method,
                        &state.upstream_url,
                        state.egress_proxy_audit.clone(),
                        state.bytes_sent,
                        state.protocol_audit.clone(),
                    ),
                );
                if state.expected_body_bytes == Some(state.bytes_sent) {
                    // The HTTP framing layer may stop polling immediately after
                    // this chunk. Finalize before yielding the last promised byte.
                    let audit = gateway_forward_audit(
                        &state.method,
                        &state.upstream_url,
                        state.egress_proxy_audit.clone(),
                        state.bytes_sent,
                        state.protocol_audit.clone(),
                    );
                    let _ = state
                        .runtime
                        .complete_prepared_gateway_operation(
                            prepared,
                            state.upstream_status,
                            elapsed_millis(state.started),
                            audit,
                        )
                        .await;
                    // Framing may prevent another body poll. This response no
                    // longer owns retained bytes or upstream execution capacity.
                    state._permits.take();
                } else {
                    state.prepared = Some(prepared);
                }
                Some((Ok(chunk), state))
            }
            Ok(None) => {
                if state
                    .expected_body_bytes
                    .is_some_and(|expected| state.bytes_sent != expected)
                {
                    let error = ProviderError::error(
                        ReasonCode::UpstreamProtocolFailed,
                        "gateway upstream response was truncated",
                    );
                    let (item, state) = fail_gateway_response_stream(state, prepared, error).await;
                    return Some((Err(item), state));
                }
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
    let audit = gateway_forward_audit(
        &state.method,
        &state.upstream_url,
        state.egress_proxy_audit,
        state.bytes_sent,
        state.protocol_audit,
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
    let audit = gateway_forward_audit(
        &state.method,
        &state.upstream_url,
        state.egress_proxy_audit.clone(),
        state.bytes_sent,
        state.protocol_audit.clone(),
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
    protocol_audit: GatewayAuditDetails,
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
        return error.with_audit(gateway_forward_audit(
            method,
            upstream_url,
            egress_proxy_audit,
            0,
            protocol_audit,
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
        gateway_forward_audit(method, upstream_url, egress_proxy_audit, 0, protocol_audit),
    )
}

#[derive(Clone)]
pub(crate) struct GatewayAuditDetails {
    pub(crate) kind: String,
    pub(crate) key: String,
    pub(crate) facts: Option<serde_json::Value>,
    pub(crate) path: String,
    pub(crate) request_bytes: Arc<AtomicU64>,
}

fn gateway_forward_audit(
    method: &Method,
    upstream_url: &Url,
    egress_proxy_audit: serde_json::Value,
    response_bytes: usize,
    protocol_audit: GatewayAuditDetails,
) -> serde_json::Value {
    let mut gateway = if protocol_audit.key == "gateway" {
        protocol_audit
            .facts
            .clone()
            .and_then(|facts| facts.as_object().cloned())
            .unwrap_or_default()
    } else {
        serde_json::Map::new()
    };
    gateway.retain(|key, _| {
        !matches!(
            key.as_str(),
            "phase"
                | "message"
                | "credentialMethod"
                | "durationMs"
                | "upstreamStatus"
                | "transferOutcome"
        )
    });
    for (key, value) in [
        ("kind", json!(protocol_audit.kind)),
        ("method", json!(method.as_str())),
        ("upstreamOrigin", json!(upstream_origin(upstream_url))),
        ("upstreamPath", json!(protocol_audit.path)),
        ("egressProxy", egress_proxy_audit),
        ("responseBytes", json!(response_bytes)),
    ] {
        gateway.insert(key.to_owned(), value);
    }
    if protocol_audit.key == "gateway" {
        gateway.insert(
            "requestBytes".into(),
            json!(protocol_audit.request_bytes.load(Ordering::Relaxed)),
        );
    }
    let mut audit = json!({"gateway": gateway});
    if protocol_audit.key != "gateway"
        && let Some(facts) = protocol_audit.facts
    {
        audit[&protocol_audit.key] = facts;
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
    for (name, value) in upstream_headers {
        response.headers_mut().append(name.clone(), value.clone());
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
    for (service, gateway) in snapshot.runtime.gateway_configs() {
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

fn gateway_runtime_response_with_challenges(
    response: BrokerResponse<serde_json::Value>,
    gateway: &GatewayConfig,
) -> Response<Body> {
    let mut response = gateway_runtime_response_with_basic_challenge(response);
    if response.headers().contains_key(WWW_AUTHENTICATE) {
        if !gateway
            .auth_modes
            .iter()
            .any(|mode| mode == "basic_broker_token")
        {
            response.headers_mut().remove(WWW_AUTHENTICATE);
        }
        if gateway
            .auth_modes
            .iter()
            .any(|mode| mode == "bearer_broker_token")
        {
            response.headers_mut().append(
                WWW_AUTHENTICATE,
                HeaderValue::from_static(r#"Bearer realm="Agent Access Broker""#),
            );
        }
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

/// A gateway failure as Git sees it: the status, and the reason as a
/// `text/plain` line, which Git shows as `remote:` output when ref discovery
/// fails.
fn gateway_error_response(
    status: StatusCode,
    broker_request_id: &str,
    reason: Option<ReasonCodeId>,
    body: &str,
    basic_challenge: bool,
) -> Response<Body> {
    let mut response = Response::new(Body::from(format!("{body}\n")));
    *response.status_mut() = status;
    response.headers_mut().insert(
        CONTENT_TYPE,
        HeaderValue::from_static("text/plain; charset=utf-8"),
    );
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
mod contract_tests;
#[cfg(test)]
mod tests;
