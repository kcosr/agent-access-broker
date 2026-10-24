//! Pending rate-admission ownership. No owner in this module runs provider work.
use crate::ingress::invocation_limits::{AdmissionCancellation, AdmissionCancellationReason};
use crate::state::{AppState, RequestPermits, RuntimeSnapshot};
use agent_access_core::{BrokerResponse, GovernedOperationContext};
use futures_util::future::BoxFuture;
use serde_json::Value;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::sync::Notify;
use tokio_util::sync::CancellationToken;
use tracing::Instrument;

#[derive(Clone, Copy)]
pub(crate) enum AdmissionSurface {
    RestInvoke,
    Git,
    HttpMcp,
}

pub(crate) type AdmissionRevalidation = Box<
    dyn FnOnce(
            GovernedOperationContext,
            IdentityWorkGuard,
        ) -> BoxFuture<
            'static,
            Result<agent_access_core::IdentityContext, Box<BrokerResponse<Value>>>,
        > + Send,
>;

#[derive(Default)]
pub(crate) struct AdmissionRegistry {
    state: Mutex<RegistryState>,
    changed: Notify,
}

#[derive(Default)]
struct RegistryState {
    closing: bool,
    owners: usize,
}

#[derive(Clone)]
pub(crate) struct Registration {
    _lease: Arc<RegistrationLease>,
}

struct RegistrationLease(Arc<AdmissionRegistry>);

impl Drop for RegistrationLease {
    fn drop(&mut self) {
        self.0.state.lock().unwrap().owners -= 1;
        self.0.changed.notify_waiters();
    }
}

impl AdmissionRegistry {
    pub(crate) fn register(self: &Arc<Self>) -> Option<Registration> {
        let mut state = self.state.lock().unwrap();
        if state.closing {
            return None;
        }
        state.owners += 1;
        Some(Registration {
            _lease: Arc::new(RegistrationLease(self.clone())),
        })
    }

    pub(crate) fn close(&self) {
        self.state.lock().unwrap().closing = true;
    }

    pub(crate) async fn drain(&self, budget: Duration) -> usize {
        self.close();
        let empty = async {
            loop {
                let changed = self.changed.notified();
                tokio::pin!(changed);
                changed.as_mut().enable();
                if self.state.lock().unwrap().owners == 0 {
                    return;
                }
                changed.await;
            }
        };
        let _ = tokio::time::timeout(budget, empty).await;
        let unfinished = self.state.lock().unwrap().owners;
        if unfinished != 0 {
            tracing::error!(event = "admission_shutdown_unfinalized", count = unfinished);
        }
        unfinished
    }
}

/// A bounded identity read can outlive its deadline response, but keeps the
/// original request's leases and drain registration until the read ends.
pub(crate) struct IdentityWorkGuard {
    _permits: RequestPermits,
    _registration: Registration,
}

pub(crate) fn identity_work<T: Send + 'static>(
    guard: IdentityWorkGuard,
    future: impl std::future::Future<Output = T> + Send + 'static,
) -> tokio::task::JoinHandle<T> {
    tokio::spawn(
        async move {
            let _guard = guard;
            future.await
        }
        .instrument(tracing::Span::current()),
    )
}

/// The result receiver can disappear independently of the transport middleware
/// (including direct handler callers). Its guard never owns a request permit.
pub(crate) struct OwnerCancellation {
    pub(crate) parent: Arc<dyn AdmissionCancellation>,
    pub(crate) receiver_gone: CancellationToken,
}

impl AdmissionCancellation for OwnerCancellation {
    fn reason(&self) -> Option<AdmissionCancellationReason> {
        self.parent.reason().or_else(|| {
            self.receiver_gone
                .is_cancelled()
                .then_some(AdmissionCancellationReason::OwnerAbandoned)
        })
    }

    fn cancelled(&self) -> BoxFuture<'_, AdmissionCancellationReason> {
        Box::pin(async move {
            tokio::select! {
                biased;
                reason = self.parent.cancelled() => reason,
                _ = self.receiver_gone.cancelled() => AdmissionCancellationReason::OwnerAbandoned,
            }
        })
    }
}

/// Used only when the host owns proof that no invocation has been handed off.
pub(crate) fn undispatched_error(message: &str) -> agent_access_provider::ProviderError {
    let evidence = serde_json::json!({"executionState":"not_dispatched","retrySafe":true});
    agent_access_provider::ProviderError::error(
        agent_access_provider::ReasonCode::OperationCancelled,
        message,
    )
    .with_result(evidence.clone())
    .with_audit(evidence)
}

/// Transfers admission and its terminal audit to a tracked owner. The receiver
/// acknowledges a successful grant before taking finalization responsibility.
pub(crate) async fn admit(
    state: &AppState,
    snapshot: &Arc<RuntimeSnapshot>,
    mut context: GovernedOperationContext,
    permits: RequestPermits,
    revalidate: AdmissionRevalidation,
    surface: AdmissionSurface,
) -> Result<(GovernedOperationContext, RequestPermits), Box<BrokerResponse<Value>>> {
    use crate::ingress::invocation_limits::{InvocationAdmissionError, InvocationAdmissionRequest};
    let Some(registration) = state.reloadable.admission_owners.register() else {
        context.admission = Some(agent_access_core::InvocationAdmissionAudit::cancelled(
            false, 0,
        ));
        return Err(Box::new(
            snapshot
                .runtime
                .governed_operation_error_response(
                    context,
                    undispatched_error("broker shut down before rate admission"),
                )
                .await,
        ));
    };
    let epoch = match state
        .reloadable
        .shared_invocations
        .runtime_epoch(|| Arc::ptr_eq(&state.reloadable.current(), snapshot))
    {
        Ok(epoch) => epoch,
        Err(removal) => {
            context.admission = Some(agent_access_core::InvocationAdmissionAudit::cancelled(
                false, 0,
            ));
            let failed = context.clone();
            let snapshot = snapshot.clone();
            let (send, receive) = tokio::sync::oneshot::channel();
            tokio::spawn(
                async move {
                    let _registration = registration;
                    let _permits = permits;
                    let response = snapshot
                        .runtime
                        .governed_operation_error_response(context, removal.into_provider_error())
                        .await;
                    let _ = send.send(response);
                }
                .instrument(tracing::Span::current()),
            );
            return Err(Box::new(
                receive
                    .await
                    .unwrap_or_else(|_| supervisor_failure(&failed)),
            ));
        }
    };
    let lifetime = crate::ingress::request_lifetime::RequestLifetime::current();
    let receiver_gone = CancellationToken::new();
    let _receiver_guard = receiver_gone.clone().drop_guard();
    let cancellation = Arc::new(OwnerCancellation {
        parent: lifetime.cancellation(),
        receiver_gone,
    });
    let resolver_snapshot = snapshot.clone();
    let principal = context.operation.identity.principal.clone();
    let service = context.operation.service.clone();
    let resolver_principal = principal.clone();
    let resolver_service = service.clone();
    let resolver_permits = permits.clone();
    let resolver_registration = registration.clone();
    let request = InvocationAdmissionRequest {
        epoch,
        principal,
        max_wait: snapshot
            .runtime
            .configured_invocation_limits()
            .max_wait(&service),
        service,
        hard_deadline: lifetime.deadline(),
        cancellation,
        resolve_limit: Arc::new(move || {
            let snapshot = resolver_snapshot.clone();
            let principal = resolver_principal.clone();
            let service = resolver_service.clone();
            let permits = resolver_permits.clone();
            let registration = resolver_registration.clone();
            Box::pin(async move {
                let _permits = permits;
                let _registration = registration;
                snapshot
                    .runtime
                    .effective_invocation_limit(&principal, &service)
                    .await
                    .map(|effective| effective.limit())
            })
        }),
    };
    let owner_snapshot = snapshot.clone();
    let limiter = state.reloadable.shared_invocations.clone();
    let failed_context = context.clone();
    let (send, receive) = tokio::sync::oneshot::channel();
    let (accepted, acknowledgement) = tokio::sync::oneshot::channel();
    tokio::spawn(
        async move {
            let _registration = registration;
            let mut context = context;
            match limiter.admit(request).await {
                Ok(grant) => {
                    context.admission =
                        Some(agent_access_core::InvocationAdmissionAudit::admitted(
                            grant.waited,
                            grant.waited_milliseconds,
                        ));
                    let identity_guard = IdentityWorkGuard {
                        _permits: permits.clone(),
                        _registration: _registration.clone(),
                    };
                    match revalidate(context.clone(), identity_guard).await {
                        Ok(identity) => context.operation.identity = identity,
                        Err(response) => {
                            let _ = send.send(Err(response));
                            return;
                        }
                    }
                    // Keep a proof copy until the response waiter acknowledges the
                    // handoff. Sending alone does not prove its future still exists.
                    let proof = context.clone();
                    let retained_permits = Arc::new(permits);
                    let handed = send.send(Ok((context, retained_permits.clone()))).is_ok();
                    if !handed || acknowledgement.await.is_err() {
                        owner_snapshot
                            .runtime
                            .governed_operation_error_response(
                                proof,
                                undispatched_error("request abandoned before invocation handoff"),
                            )
                            .await;
                    }
                }
                Err(error) => {
                    let response = match error {
                        InvocationAdmissionError::RateLimited(rejection) => {
                            context.admission =
                                Some(agent_access_core::InvocationAdmissionAudit::rejected(
                                    rejection.was_queued,
                                    rejection.waited_milliseconds,
                                ));
                            crate::handlers::common::emit_invocation_limited(
                                &context.operation,
                                &rejection,
                            );
                            owner_snapshot
                                .runtime
                                .governed_admission_limit_error_response(
                                    context,
                                    rejection.into_provider_error(),
                                )
                                .await
                        }
                        InvocationAdmissionError::Cancelled(removal) => {
                            context.admission =
                                Some(agent_access_core::InvocationAdmissionAudit::cancelled(
                                    removal.waited(),
                                    removal.waited_milliseconds(),
                                ));
                            owner_snapshot
                                .runtime
                                .governed_operation_error_response(
                                    context,
                                    removal.into_provider_error(),
                                )
                                .await
                        }
                        InvocationAdmissionError::Deadline(kind) => {
                            context.admission = Some(
                                agent_access_core::InvocationAdmissionAudit::rejected(false, 0),
                            );
                            owner_snapshot
                                .runtime
                                .governed_operation_error_response(
                                    context,
                                    unresolved_deadline_error(surface, kind),
                                )
                                .await
                        }
                        InvocationAdmissionError::Resolution {
                            error,
                            waited,
                            waited_milliseconds,
                        } => {
                            context.admission =
                                Some(agent_access_core::InvocationAdmissionAudit::rejected(
                                    waited,
                                    waited_milliseconds,
                                ));
                            owner_snapshot
                                .runtime
                                .governed_operation_error_response(context, error)
                                .await
                        }
                    };
                    let _ = send.send(Err(Box::new(response)));
                    drop(permits);
                }
            }
        }
        .instrument(tracing::Span::current()),
    );
    match receive.await {
        Ok(Ok((context, permits))) => {
            let _ = accepted.send(());
            // The owner may still hold its acknowledgement proof. Clone leases
            // rather than wait for that task to be rescheduled.
            Ok((
                context,
                RequestPermits {
                    _global: permits._global.clone(),
                    _principal: permits._principal.clone(),
                },
            ))
        }
        Ok(Err(response)) => Err(response),
        Err(_) => Err(Box::new(supervisor_failure(&failed_context))),
    }
}

fn unresolved_deadline_error(
    surface: AdmissionSurface,
    kind: agent_access_core::InvocationDeadlineKind,
) -> agent_access_provider::ProviderError {
    use agent_access_provider::{ProviderError, ReasonCode};
    let error = match surface {
        AdmissionSurface::RestInvoke => ProviderError::deny(
            ReasonCode::BodyMalformed,
            "request body receive deadline exceeded",
        ),
        AdmissionSurface::Git => ProviderError::deny(
            ReasonCode::GatewayRequestBodyDenied,
            "gateway request body read timed out",
        ),
        AdmissionSurface::HttpMcp => ProviderError::error(
            ReasonCode::OperationTimeout,
            "operation deadline exceeded before rate settings resolved",
        ),
    };
    let evidence = serde_json::json!({"executionState":"not_dispatched", "retrySafe":true, "deadlineKind":kind});
    error.with_result(evidence.clone()).with_audit(evidence)
}

fn supervisor_failure(context: &GovernedOperationContext) -> BrokerResponse<Value> {
    let message = "admission finalization failed; outcome must be reconciled";
    BrokerResponse {
        retry_after_seconds: None,
        status: agent_access_provider::ReasonCode::AuditUnavailable.http_status(),
        envelope: agent_access_core::ResponseEnvelope {
            agent_request_id: context.operation.agent_request_id.clone(),
            broker_request_id: context.operation.broker_request_id.clone(),
            decision: agent_access_provider::Decision::Error,
            service: context.operation.service.clone(),
            action: context.operation.action.clone(),
            resource_scopes: agent_access_provider::ResourceScopes::new(),
            reason_code: Some(agent_access_provider::ReasonCode::AuditUnavailable.into()),
            reason: Some(message.into()),
            result: Some(serde_json::json!({"executionState":"not_dispatched","retrySafe":false})),
            error: Some(agent_access_core::ErrorBody {
                message: message.into(),
            }),
        },
        stream: None,
    }
}
