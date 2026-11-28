//! `POST /v1/access-keys/resolve`: a trusted caller asks whose access key a
//! value is. The route has its own admission: the caller's credential is
//! checked before any of the body is read, every request runs in a pool of
//! this route's own, and the requests no stored key answers for are counted
//! in rates of this route's own, so it neither spends the sign-in budgets
//! nor takes shared, anonymous-body or per-principal capacity, and it never
//! waits for a membership renewal.
//!
//! No payer (a caller entry, or a peer address that presents no configured
//! caller's credential) holds more of the pool at once than
//! `limits.max_concurrent_access_key_resolutions_per_caller`, so one caller
//! that stalls cannot keep the others out.
//!
//! A lookup for a stored key, whatever the key's state, is bounded by the
//! pool alone: no rate ever refuses it. The rate of a caller counts what
//! the Broker cannot tie to a stored key: a well-formed key that no store
//! holds, a malformed request (one abandoned while its body was being read
//! is one), and a lookup that failed. Beyond the rate the answer is 429.
//! Resolution identifies a key; the resolving service logs its own decisions.
//! This route writes no audit records, including on refusal or failure.
use crate::handlers::auth::valid_request_id;
use crate::handlers::common::{emit_request_limited, envelope_response};
use crate::ingress::guards::{IngressGuards, IngressLimitError, IngressPermit};
use crate::ingress::source::auth_source_key;
use crate::state::{AppState, RuntimeSnapshot};
use agent_access_core::{
    ACCESS_KEY_RESOLUTION_MAX_ANSWER_BYTES, AccessKeyResolution, BrokerResponse, BrokerRuntime,
    IdentityContext, LimitsConfig, ManagedStoreError, OperationContext, SourceContext,
    is_access_key, new_broker_request_id,
};
use agent_access_provider::{ProviderError, REQUEST_ID_HEADER, ReasonCode};
use axum::extract::{ConnectInfo, Request, State};
use axum::http::header::{CACHE_CONTROL, CONTENT_TYPE};
use axum::http::{HeaderMap, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use http_body_util::{BodyExt, Limited};
use serde::Deserialize;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

const ACCESS_KEY_RESOLVE: &str = "access_keys.resolve";

pub(crate) const RESOLVE_PATH: &str = "/v1/access-keys/resolve";
/// The largest request body.
const REQUEST_BODY_CAP: usize = 4 * 1024;
/// The longest a request has from the start of its body, unless
/// `limits.request_body_timeout_ms` is shorter: the whole body must arrive
/// by then.
const REQUEST_DEADLINE: Duration = Duration::from_secs(5);

/// The request body: a JSON object with exactly the member `key`. Only an
/// object is one; an array of the same values is not.
struct ResolveRequest {
    key: String,
}

impl<'de> Deserialize<'de> for ResolveRequest {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct Object;

        impl<'de> serde::de::Visitor<'de> for Object {
            type Value = ResolveRequest;

            fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                formatter.write_str("an object with exactly the member key")
            }

            fn visit_map<A: serde::de::MapAccess<'de>>(
                self,
                mut map: A,
            ) -> Result<Self::Value, A::Error> {
                use serde::de::Error;
                let mut key = None;
                while let Some(member) = map.next_key::<String>()? {
                    if member != "key" {
                        return Err(A::Error::unknown_field(&member, &["key"]));
                    }
                    if key.is_some() {
                        return Err(A::Error::duplicate_field("key"));
                    }
                    key = Some(map.next_value::<String>()?);
                }
                key.map(|key| ResolveRequest { key })
                    .ok_or_else(|| A::Error::missing_field("key"))
            }
        }

        deserializer.deserialize_map(Object)
    }
}

/// Whose rate counts a request that no stored key answers for.
#[derive(Clone)]
enum Payer {
    /// A caller with the capability: its entry's window, at the rate of
    /// `limits.access_key_resolutions_per_caller_per_minute`.
    Resolver(String),
    /// A configured caller that lacks the capability: its entry's window,
    /// at the small number an unauthenticated source has.
    WithoutCapability(String),
    /// No configured caller's credential: the window of the peer address,
    /// which belongs to this route, at
    /// `limits.auth_requests_per_source_per_minute`.
    Unauthenticated(String),
}

/// What one payer is held to: the count of its requests that no stored key
/// answers for, which the request or the lookup it started can make, and
/// its places in the pool.
#[derive(Clone)]
struct Charge {
    guards: Arc<IngressGuards>,
    payer: Payer,
    per_caller: u32,
    unauthenticated: u32,
    /// The most of the pool the payer may hold at once.
    share: u32,
}

impl Charge {
    fn new(state: &AppState, limits: &LimitsConfig, payer: Payer) -> Self {
        Self {
            guards: state.reloadable.access_key_resolution_ingress.clone(),
            payer,
            per_caller: limits.access_key_resolutions_per_caller_per_minute,
            unauthenticated: limits.auth_requests_per_source_per_minute,
            share: limits.max_concurrent_access_key_resolutions_per_caller,
        }
    }

    /// One of the payer's places in the pool; `Err` when it holds its share.
    fn place(&self) -> Result<IngressPermit, IngressLimitError> {
        match &self.payer {
            Payer::Resolver(caller) | Payer::WithoutCapability(caller) => self
                .guards
                .try_access_key_resolution_caller_share(caller, self.share),
            Payer::Unauthenticated(source) => self
                .guards
                .try_access_key_resolution_source_share(source, self.share),
        }
    }

    /// Counts one request; `Err` when the payer's window is spent, and the
    /// request is then answered 429 and not audited. Nothing here is shared
    /// with any other route.
    fn apply(&self) -> Result<(), IngressLimitError> {
        match &self.payer {
            Payer::Resolver(caller) => self
                .guards
                .check_auth_principal_rate(caller, self.per_caller),
            Payer::WithoutCapability(caller) => self
                .guards
                .check_auth_principal_rate(caller, self.unauthenticated),
            Payer::Unauthenticated(source) => self
                .guards
                .check_own_source_rate(source, self.unauthenticated),
        }
    }
}

/// A request's capacity: one of its payer's places and a slot of the pool.
/// Whatever must outlive the request holds a clone.
#[derive(Clone)]
struct Slot {
    _place: IngressPermit,
    _pool: IngressPermit,
}

/// Counts a request that goes away while its body is being read. Nobody is
/// left to answer, and the request is still one that no stored
/// key answers for: without the count, a caller could hold slots with
/// bodies it never sends, leave before the deadline and spend no rate.
struct ChargeIfAbandoned(Option<Charge>);

impl ChargeIfAbandoned {
    /// The body has been read, or has failed or run out of time: what
    /// follows answers the request and counts it where it must be.
    fn body_read(mut self) {
        self.0 = None;
    }
}

impl Drop for ChargeIfAbandoned {
    fn drop(&mut self) {
        if let Some(charge) = self.0.take() {
            // Beyond the rate there is nothing more to refuse.
            let _ = charge.apply();
        }
    }
}

/// One request to the route.
struct Resolution {
    snapshot: Arc<RuntimeSnapshot>,
    request_id: String,
    broker_request_id: String,
    source: SourceContext,
    /// The configured caller whose credential the request presented. `None`
    /// when it presented none, or one that is no configured caller's.
    caller: Option<String>,
    charge: Charge,
}

impl Resolution {
    fn operation(&self) -> OperationContext {
        OperationContext {
            agent_request_id: self.request_id.clone(),
            broker_request_id: self.broker_request_id.clone(),
            identity: IdentityContext {
                caller_id: self.caller.clone(),
                ..IdentityContext::anonymous()
            },
            service: "broker".to_string(),
            action: ACCESS_KEY_RESOLVE.to_string(),
            source: self.source.clone(),
        }
    }

    /// A slot of this route's pool, which every request to the route runs
    /// in and which alone bounds a lookup for a stored key, taken within
    /// the payer's share of that pool. Nothing is awaited to take it.
    fn slot(&self) -> Result<Slot, IngressLimitError> {
        let place = self.charge.place()?;
        let pool = self.charge.guards.try_global_concurrency(
            self.snapshot
                .runtime
                .limits()
                .max_concurrent_access_key_resolutions,
        )?;
        Ok(Slot {
            _place: place,
            _pool: pool,
        })
    }

    /// A refusal of a request that names no stored key. Count it against
    /// its payer's rate first, then return the reason's status or 429.
    fn refuse(&self, reason: ReasonCode, message: &str) -> Response {
        match self.charge.apply() {
            Ok(()) => self.failed(ProviderError::deny(reason, message)),
            Err(error) => self.limited(error),
        }
    }

    fn unavailable(&self, reason: ReasonCode, message: &str) -> Response {
        self.failed(ProviderError::error(reason, message))
    }

    fn failed(&self, error: ProviderError) -> Response {
        failure_response(BrokerRuntime::access_key_resolution_error_response(
            self.operation(),
            error,
        ))
    }

    /// The answer to a request the pool or a rate turned away: 429, logged,
    /// and never audited, so that no flood of refusals reaches the audit
    /// trail.
    fn limited(&self, error: IngressLimitError) -> Response {
        let operation = self.operation();
        emit_request_limited(
            &error,
            &operation.agent_request_id,
            &operation.broker_request_id,
            &operation.service,
            &operation.action,
            Some(&operation.source),
            None,
        );
        let response = BrokerRuntime::access_key_resolution_limit_response(
            operation,
            error.into_provider_error(),
        );
        no_store(envelope_response(response).into_response())
    }
}

/// The request ID a caller supplied: `Ok(None)` when it supplied none, and
/// `Err` when what it supplied is not one ID of the accepted form: two
/// headers, bytes that are not text, or a value outside the grammar.
fn supplied_request_id(headers: &HeaderMap) -> Result<Option<String>, ()> {
    let mut values = headers.get_all(REQUEST_ID_HEADER).iter();
    let Some(first) = values.next() else {
        return Ok(None);
    };
    match first.to_str() {
        Ok(value) if values.next().is_none() && valid_request_id(value) => {
            Ok(Some(value.to_string()))
        }
        _ => Err(()),
    }
}

fn no_store(mut response: Response) -> Response {
    response
        .headers_mut()
        .insert(CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response
}

/// The answer to any method but POST on the route's path: the same bare 405
/// for every such request.
pub(crate) fn method_not_allowed() -> Response {
    no_store(
        (
            StatusCode::METHOD_NOT_ALLOWED,
            [(axum::http::header::ALLOW, HeaderValue::from_static("POST"))],
        )
            .into_response(),
    )
}

fn answer(body: Vec<u8>) -> Response {
    no_store(
        (
            StatusCode::OK,
            [(CONTENT_TYPE, HeaderValue::from_static("application/json"))],
            body,
        )
            .into_response(),
    )
}

/// Keep ordinary failure telemetry without coupling a lookup to the audit store.
fn failure_response(response: BrokerResponse<serde_json::Value>) -> Response {
    macro_rules! log_failure {
        ($level:expr) => {
            tracing::event!(
                $level,
                event = "access_key_resolution_failed",
                agentRequestId = response.envelope.agent_request_id.as_str(),
                brokerRequestId = response.envelope.broker_request_id.as_str(),
                action = response.envelope.action.as_str(),
                reasonCode = response
                    .envelope
                    .reason_code
                    .as_ref()
                    .map(agent_access_provider::ReasonCodeId::as_str),
                "http.statusCode" = response.status,
            );
        };
    }
    if response.envelope.decision == agent_access_provider::Decision::Error {
        log_failure!(tracing::Level::ERROR);
    } else {
        log_failure!(tracing::Level::INFO);
    }
    no_store(envelope_response(response).into_response())
}

pub(crate) async fn resolve(
    State(state): State<AppState>,
    ConnectInfo(remote): ConnectInfo<SocketAddr>,
    request: Request,
) -> Response {
    let (parts, body) = request.into_parts();
    let headers = parts.headers;
    let snapshot = state.reloadable.current();
    let limits = snapshot.runtime.limits().clone();
    // The caller's credential, before any of the body is read.
    let caller = match snapshot
        .runtime
        .authenticate_access_key_resolution_caller(&headers)
    {
        Ok(caller) => caller,
        Err(refusal) => {
            // A refused caller is refused by this route, within this route's
            // capacity: it takes nothing from the shared pool and spends none
            // of its source's sign-in budget. It is counted in a window of
            // this route at the small number an unauthenticated source has:
            // a caller that lacks only the capability as that caller, and
            // any other request as its peer address. Beyond that number
            // nothing is audited.
            crate::observability::record_execution_context_failure(
                refusal.failure.reason_code().as_str(),
            );
            let (request_id, source) =
                crate::router::admission_failure_correlation(&headers, Some(remote));
            let payer = match &refusal.caller {
                Some(caller) => Payer::WithoutCapability(caller.clone()),
                None => Payer::Unauthenticated(auth_source_key(&source)),
            };
            let refused = Resolution {
                charge: Charge::new(&state, &limits, payer),
                snapshot,
                request_id,
                broker_request_id: new_broker_request_id(),
                source,
                caller: refusal.caller,
            };
            let _permit = match refused.slot() {
                Ok(permit) => permit,
                Err(error) => return refused.limited(error),
            };
            if let Err(error) = refused.charge.apply() {
                return refused.limited(error);
            }
            return crate::router::admission_response_headers(failure_response(
                BrokerRuntime::access_key_resolution_caller_error_response(
                    refused.operation(),
                    refusal.failure,
                ),
            ));
        }
    };
    crate::observability::record_operation(ACCESS_KEY_RESOLVE);
    let broker_request_id = new_broker_request_id();
    crate::observability::record_broker_request_id(&broker_request_id);
    // A request need carry no ID. One that carries an invalid one is
    // refused below, inside the route's admission, under a generated ID.
    let supplied = supplied_request_id(&headers);
    let request_id = match &supplied {
        Ok(Some(supplied)) => supplied.clone(),
        Ok(None) | Err(()) => new_broker_request_id(),
    };
    crate::observability::record_agent_request_id(&request_id);
    let mut source = snapshot.source_resolver.source_context(remote, &headers);
    source.agent_request_id_generated = Some(!matches!(supplied, Ok(Some(_))));
    let resolution = Resolution {
        charge: Charge::new(&state, &limits, Payer::Resolver(caller.clone())),
        source,
        snapshot,
        request_id,
        broker_request_id,
        caller: Some(caller),
    };
    // The route's pool, before anything is awaited: every answer below
    // is given within it.
    let permit = match resolution.slot() {
        Ok(permit) => permit,
        Err(error) => return resolution.limited(error),
    };
    if supplied.is_err() {
        return resolution.refuse(ReasonCode::RequestIdInvalid, "request id is invalid");
    }
    // The caller speaks for itself only: no header under which this
    // configuration accepts or asserts an identity belongs on the request.
    if let Some(header) = resolution
        .snapshot
        .runtime
        .access_key_resolution_forbidden_header(&headers)
    {
        return resolution.refuse(
            ReasonCode::InputInvalid,
            &format!("the {header} header is not accepted on access key resolution"),
        );
    }
    // The request's body must arrive by its deadline.
    let deadline = tokio::time::Instant::now()
        + REQUEST_DEADLINE.min(Duration::from_millis(limits.request_body_timeout_ms.max(1)));
    // A request that goes away during the read is counted as it goes.
    let abandoned = ChargeIfAbandoned(Some(resolution.charge.clone()));
    let read =
        tokio::time::timeout_at(deadline, Limited::new(body, REQUEST_BODY_CAP).collect()).await;
    abandoned.body_read();
    let body = match read {
        Ok(Ok(body)) => body.to_bytes(),
        Ok(Err(_)) => {
            return resolution.refuse(
                ReasonCode::BodyMalformed,
                "request body is unreadable or larger than 4096 bytes",
            );
        }
        Err(_) => {
            return resolution.refuse(
                ReasonCode::BodyMalformed,
                "request body receive deadline exceeded",
            );
        }
    };
    let token = match serde_json::from_slice::<ResolveRequest>(&body) {
        Ok(request) if is_access_key(&request.key) => request.key,
        Ok(_) => {
            return resolution.refuse(ReasonCode::InputInvalid, "key is not an access key");
        }
        Err(_) => {
            return resolution.refuse(
                ReasonCode::BodyMalformed,
                "request body must be a JSON object with exactly the member key",
            );
        }
    };
    let runtime = resolution.snapshot.runtime.clone();
    // The lookup runs in a blocking task that outlives a cancelled request,
    // so it holds the route's capacity itself until it returns.
    let lookup_permit = permit.clone();
    let charge = resolution.charge.clone();
    #[cfg(test)]
    let barrier = state
        .reloadable
        .access_key_resolution_store_barrier
        .lock()
        .unwrap()
        .clone();
    let looked_up = resolution
        .snapshot
        .managed_store_call(move |_| {
            #[cfg(test)]
            if let Some(barrier) = &barrier {
                barrier.wait();
            }
            // One keyed hash and one indexed read tell whether a store
            // holds the key. A key that none holds is read no further and
            // nothing is written for it here.
            let resolved = runtime.resolve_access_key(&token);
            // A key no store holds, and a lookup that failed, is a request
            // no stored key answers for. The lookup counts it itself,
            // inside the pool, so that the count does not depend on the
            // request still being there. A stored key is never counted.
            let charged = match &resolved {
                Ok(AccessKeyResolution::Inactive(inactive)) if inactive.key_id.is_none() => {
                    charge.apply()
                }
                Err(_) => charge.apply(),
                Ok(_) => Ok(()),
            };
            drop(lookup_permit);
            #[cfg(test)]
            if let Some(barrier) = &barrier {
                barrier.completed.notify_one();
            }
            Ok((resolved, charged))
        })
        .await;
    let (resolved, charged) = match looked_up {
        Ok(outcome) => outcome,
        // The lookup did not run, so it counted nothing.
        Err(error) => (Err(error), resolution.charge.apply()),
    };
    if let Err(error) = charged {
        return resolution.limited(error);
    }
    let resolved = match resolved {
        Ok(resolved) => resolved,
        Err(
            ManagedStoreError::EncryptionKeyMissing(_) | ManagedStoreError::EncryptionKeyInvalid(_),
        ) => {
            return resolution.unavailable(
                ReasonCode::EncryptionKeyMissing,
                "broker token hash key is unavailable",
            );
        }
        Err(_) => {
            return resolution.unavailable(
                ReasonCode::ManagedStoreUnavailable,
                "managed store is unavailable",
            );
        }
    };
    let answer_cap = ACCESS_KEY_RESOLUTION_MAX_ANSWER_BYTES;
    #[cfg(test)]
    let answer_cap = state
        .reloadable
        .access_key_resolution_answer_cap
        .lock()
        .unwrap()
        .unwrap_or(answer_cap);
    match crate::bounded_json::serialize(&resolved, answer_cap) {
        Ok(body) => answer(body),
        // No part of an answer that does not fit is given. The largest
        // supported active or inactive answer fits within this bound.
        Err(_) => resolution.unavailable(
            ReasonCode::BrokerAccessKeyAnswerTooLarge,
            "the resolution answer exceeds its size limit",
        ),
    }
}
