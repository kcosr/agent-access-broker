//! Outbound HTTP to an upstream service under the broker's common rules:
//! clients the host constructs (outbound TLS trust, the selected egress route,
//! the requested time profile and no automatic redirects), allowlisted
//! destinations, correlation headers and credentials only toward the
//! service's own origin, and one trace event per upstream request.
//!
//! Backends own their protocol (URLs, authentication scheme, status and body
//! handling); they build clients and send requests through this module.
use crate::authorization::{AuthorizationPosition, attach};
use crate::correlation::apply_current_correlation_headers;
use crate::host::{ClientTransportSpec, UpstreamClientFactory};
use crate::trace::{checked_trace_reason, emit_upstream_request_completed_for};
use crate::{
    EgressDeclaration, EgressRoute, ProviderBuildError, ProviderReason, ReasonCode,
    UpstreamAuthorization, UpstreamTrace, current_provider_action, same_origin,
    url_allowed_by_patterns,
};
use futures_util::TryStreamExt;
use reqwest::{Method, RequestBuilder, Response};
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use thiserror::Error;
use tokio::sync::watch;
use url::Url;

/// How a client bounds time and retries. Every profile uses the broker's
/// outbound TLS trust and the host's egress route, and never follows redirects
/// on its own.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClientProfile {
    /// Each request must complete within `ProviderLimits::request_timeout_ms`.
    Request,
    /// The ordinary request deadline, with every automatic HTTP retry disabled,
    /// including reqwest's default retries of protocol-level negative acknowledgments.
    SingleAttempt,
    /// No whole-request deadline: the caller bounds streamed response bodies
    /// chunk by chunk with its idle timeout.
    Stream,
    /// Only connecting is bounded by `request_timeout_ms`; the request body is
    /// bounded by upload progress (see [`UpstreamClient::send_upload`]).
    Upload,
    /// Explicit bounds for single-attempt callers whose own deadlines are
    /// shorter than the operator's request timeout. Automatic HTTP retries are
    /// disabled, including protocol-level negative acknowledgments.
    Bounded { total: Duration, connect: Duration },
}

/// What a backend declares about one upstream client, which
/// [`UpstreamClient::build`] reads.
#[non_exhaustive]
pub struct UpstreamClientSpec<'a> {
    label: &'a str,
    provider: &'static str,
    base: &'a Url,
    egress: EgressDeclaration<'a>,
    allowed_upstream_hosts: &'a [String],
    profile: ClientProfile,
    status_reasons: &'static [(u16, ReasonCode)],
}

impl<'a> UpstreamClientSpec<'a> {
    /// A client for the service at `base`:
    ///
    /// - `label` is the configuration path naming the client in
    ///   diagnostics, such as `providers.jira.egress_proxy`;
    /// - `provider` is recorded on trace events;
    /// - `base`'s origin is the only one that receives correlation headers
    ///   and credentials;
    /// - `egress` is the route the client needs, which the host selects and
    ///   may deny;
    /// - every request, including each redirect hop, must match one of
    ///   `allowed_upstream_hosts`;
    /// - `profile` bounds time and retries.
    ///
    /// Its traces record no reason for an unclassified status until
    /// [`Self::with_status_reasons`] declares some.
    pub fn new(
        label: &'a str,
        provider: &'static str,
        base: &'a Url,
        egress: EgressDeclaration<'a>,
        allowed_upstream_hosts: &'a [String],
        profile: ClientProfile,
    ) -> Self {
        Self {
            label,
            provider,
            base,
            egress,
            allowed_upstream_hosts,
            profile,
            status_reasons: &[],
        }
    }

    /// Reason codes a trace records for these statuses when the caller
    /// classifies the response with none, such as 409 for a version conflict.
    pub fn with_status_reasons(mut self, status_reasons: &'static [(u16, ReasonCode)]) -> Self {
        self.status_reasons = status_reasons;
        self
    }
}

/// Why an upstream request produced no usable response.
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum UpstreamError {
    #[error("upstream URL is not allowlisted")]
    NotAllowed,
    /// The request never reached the upstream: it could not be built, it
    /// carried credentials to another origin than the service's, or no
    /// connection was established. Nothing upstream acted on it.
    #[error("upstream request was not sent: {detail}")]
    NotSent { timed_out: bool, detail: String },
    #[error("upstream request timed out")]
    Timeout,
    #[error("upstream request failed: {0}")]
    Transport(String),
    #[error("upstream redirect is invalid")]
    Redirect,
}

impl UpstreamError {
    /// The reason code a trace or error records for this failure.
    pub fn reason_code(&self) -> ReasonCode {
        match self {
            Self::Timeout
            | Self::NotSent {
                timed_out: true, ..
            } => ReasonCode::UpstreamTimeout,
            Self::Transport(_) | Self::NotSent { .. } => ReasonCode::UpstreamConnectionFailed,
            Self::NotAllowed | Self::Redirect => ReasonCode::UpstreamProtocolFailed,
        }
    }
}

/// Names one upstream request in its trace event, and carries the
/// credentials the client presents on it.
#[non_exhaustive]
#[derive(Debug, Clone, Copy)]
pub struct UpstreamCall<'a> {
    pub operation: &'a str,
    /// 1 for the first request; redirect hops and retries count up.
    pub attempt: u32,
    authorizations: &'a [UpstreamAuthorization],
}

impl<'a> UpstreamCall<'a> {
    /// The first attempt of `operation`, presenting no credential.
    pub fn new(operation: &'a str) -> Self {
        Self {
            operation,
            attempt: 1,
            authorizations: &[],
        }
    }

    /// A later attempt: 1 is the first request, and redirect hops and
    /// retries count up.
    pub fn with_attempt(mut self, attempt: u32) -> Self {
        self.attempt = attempt;
        self
    }

    /// The request presents `authorization`. The client adds its header to
    /// the request it builds from the provider's, immediately before
    /// dispatch: in place of a header of the same name the provider set, or
    /// otherwise right after the client's correlation headers, before the
    /// provider's own headers. A request to another origin than the client's
    /// base fails as [`UpstreamError::NotSent`] instead of carrying it.
    /// Replaces any authorization set before.
    pub fn with_authorization(self, authorization: &'a UpstreamAuthorization) -> Self {
        self.with_authorizations(std::slice::from_ref(authorization))
    }

    /// The request presents every authorization in `authorizations`, added in
    /// order as [`Self::with_authorization`] adds one, such as an API key and
    /// a separate transport token. Replaces any authorization set before.
    pub fn with_authorizations(mut self, authorizations: &'a [UpstreamAuthorization]) -> Self {
        self.authorizations = authorizations;
        self
    }
}

/// Last time an upload body made progress.
pub type UploadProgress = watch::Receiver<tokio::time::Instant>;

/// How [`UpstreamClient::get_following_redirects`] walks a redirect chain.
#[non_exhaustive]
pub struct RedirectRules<'a> {
    max_redirects: u32,
    deadline: Duration,
    correlate_other_origins: bool,
    vet: &'a (dyn Fn(&Url) -> bool + Sync),
    decorate: &'a (dyn Fn(RequestBuilder) -> RequestBuilder + Sync),
    authorization: Option<&'a UpstreamAuthorization>,
}

impl<'a> RedirectRules<'a> {
    /// Follows at most `max_redirects` redirects after the first request
    /// (one more is an error) and waits at most `deadline` for each hop's
    /// response headers.
    ///
    /// Hops to other origins carry no correlation headers, no hop carries a
    /// credential, every hop is sent as built, and the chain needs only the
    /// allowlist and the absence of embedded credentials, until the builders
    /// below change that.
    pub fn new(max_redirects: u32, deadline: Duration) -> Self {
        Self {
            max_redirects,
            deadline,
            correlate_other_origins: false,
            vet: &accept_every_hop,
            decorate: &undecorated_hop,
            authorization: None,
        }
    }

    /// Hops on the service's own origin present `authorization`. The client
    /// adds its header after the hop's decoration, immediately before
    /// dispatch; hops to other origins never carry it.
    pub fn with_authorization(mut self, authorization: &'a UpstreamAuthorization) -> Self {
        self.authorization = Some(authorization);
        self
    }

    /// Hops to other origins also carry the invocation's correlation
    /// headers. Hops to the service's own origin always do.
    pub fn correlating_other_origins(mut self) -> Self {
        self.correlate_other_origins = true;
        self
    }

    /// An additional backend check each URL in the chain must pass, on top
    /// of the allowlist and the absence of embedded credentials.
    pub fn with_vet(mut self, vet: &'a (dyn Fn(&Url) -> bool + Sync)) -> Self {
        self.vet = vet;
        self
    }

    /// Headers every hop carries. A credential-bearing header (see
    /// [`UpstreamClient::request`]) makes a hop to another origin fail as
    /// [`UpstreamError::NotSent`]; authorize hops with
    /// [`Self::with_authorization`] instead.
    pub fn with_decorate(
        mut self,
        decorate: &'a (dyn Fn(RequestBuilder) -> RequestBuilder + Sync),
    ) -> Self {
        self.decorate = decorate;
        self
    }
}

fn accept_every_hop(_: &Url) -> bool {
    true
}

fn undecorated_hop(request: RequestBuilder) -> RequestBuilder {
    request
}

/// An HTTP client for one upstream service.
#[derive(Clone)]
pub struct UpstreamClient {
    client: reqwest::Client,
    route: EgressRoute,
    provider: &'static str,
    base: Url,
    allowed_upstream_hosts: Arc<[String]>,
    status_reasons: &'static [(u16, ReasonCode)],
}

impl std::fmt::Debug for UpstreamClient {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("UpstreamClient")
            .field("provider", &self.provider)
            .field("base", &self.base.as_str())
            .field("route", &self.route)
            .finish_non_exhaustive()
    }
}

impl UpstreamClient {
    /// Builds a client through the host's factory, which applies the
    /// profile, TLS trust and route.
    pub fn build(
        spec: UpstreamClientSpec<'_>,
        clients: &dyn UpstreamClientFactory,
    ) -> Result<Self, ProviderBuildError> {
        let (client, route) = clients
            .build_client(&ClientTransportSpec::new(
                spec.label,
                spec.provider,
                spec.base,
                spec.egress,
                spec.profile,
            ))
            .map_err(|error| ProviderBuildError::client(spec.label, error))?
            .into_parts();
        Ok(Self {
            client,
            route,
            provider: spec.provider,
            base: spec.base.clone(),
            allowed_upstream_hosts: spec.allowed_upstream_hosts.into(),
            status_reasons: spec.status_reasons,
        })
    }

    pub fn base(&self) -> &Url {
        &self.base
    }

    /// The route the host selected, for audit.
    pub fn egress_route(&self) -> &EgressRoute {
        &self.route
    }

    /// Starts a request. Requests to the service's own origin carry the
    /// invocation's correlation headers; requests elsewhere carry none.
    ///
    /// Credentials stay on the service's origin: every send method refuses,
    /// before sending, a request to another origin that carries an
    /// `Authorization`, `Proxy-Authorization` or `Cookie` header or any
    /// header value marked sensitive, with [`UpstreamError::NotSent`]. Lent
    /// credentials are not added here: hand their
    /// [`UpstreamAuthorization`] to the send method
    /// ([`UpstreamCall::with_authorization`]), which adds the sensitive header
    /// to the request it builds. Mark any other credential-bearing header
    /// sensitive (`HeaderValue::set_sensitive`) so the client keeps it there
    /// too.
    pub fn request(&self, method: Method, url: Url) -> RequestBuilder {
        let trusted = same_origin(&url, &self.base);
        let request = self.client.request(method, url);
        if trusted {
            apply_current_correlation_headers(request)
        } else {
            request
        }
    }

    /// Sends a request bounded by the client's profile, presenting the
    /// credentials `call` carries ([`UpstreamCall::with_authorization`]). The
    /// response carries a pending trace that [`complete_upstream_trace`]
    /// records once the caller has classified the response; dropping the
    /// response records it with its status alone.
    pub async fn send(
        &self,
        request: RequestBuilder,
        call: UpstreamCall<'_>,
    ) -> Result<Response, UpstreamError> {
        self.send_bounded(request, None, call, AuthorizationPosition::AfterCorrelation)
            .await
    }

    /// [`Self::send`] with a deadline for the response headers, for clients
    /// whose profile sets none.
    pub async fn send_with_deadline(
        &self,
        request: RequestBuilder,
        deadline: Duration,
        call: UpstreamCall<'_>,
    ) -> Result<Response, UpstreamError> {
        self.send_bounded(
            request,
            Some(deadline),
            call,
            AuthorizationPosition::AfterCorrelation,
        )
        .await
    }

    /// Sends a request whose body is a streamed upload. The upload fails
    /// once `progress` has not advanced for `idle_timeout`, and once the body
    /// is sent the response headers must follow within `idle_timeout`.
    /// Without progress reporting this is [`Self::send`].
    pub async fn send_upload(
        &self,
        request: RequestBuilder,
        progress: Option<UploadProgress>,
        idle_timeout: Duration,
        call: UpstreamCall<'_>,
    ) -> Result<Response, UpstreamError> {
        let Some(mut progress) = progress else {
            return self.send(request, call).await;
        };
        let (request, trace) =
            self.prepare(request, call, AuthorizationPosition::AfterCorrelation)?;
        let mut send = Box::pin(self.client.execute(request));
        loop {
            let deadline = *progress.borrow_and_update() + idle_timeout;
            tokio::select! {
                // Progress wins a tie with the timer, and the timer branch
                // rechecks it: progress may be recorded without a
                // notification having been observed yet.
                biased;
                response = &mut send => return trace.finish(response),
                changed = progress.changed() => {
                    if changed.is_err() {
                        let response = tokio::time::timeout(idle_timeout, send).await;
                        return match response {
                            Ok(response) => trace.finish(response),
                            Err(_) => Err(trace.fail(UpstreamError::Timeout)),
                        };
                    }
                }
                _ = tokio::time::sleep_until(deadline) => {
                    if *progress.borrow() + idle_timeout <= tokio::time::Instant::now() {
                        return Err(trace.fail(UpstreamError::Timeout));
                    }
                }
            }
        }
    }

    /// GETs `url`, following redirects by hand under `rules`. Every hop must
    /// be allowlisted, carry no embedded credentials, and pass `rules.vet`;
    /// only hops on the service's own origin present the rules'
    /// authorization.
    /// Each redirect hop records its own trace; the final response carries a
    /// pending one.
    pub async fn get_following_redirects(
        &self,
        url: Url,
        rules: RedirectRules<'_>,
        operation: &str,
    ) -> Result<Response, UpstreamError> {
        let mut url = url;
        for hop in 0..=rules.max_redirects {
            if !self.redirect_target_allowed(&url, &rules) {
                return Err(UpstreamError::Redirect);
            }
            let trusted = same_origin(&url, &self.base);
            let request = self.client.get(url.clone());
            let request = if trusted || rules.correlate_other_origins {
                apply_current_correlation_headers(request)
            } else {
                request
            };
            let request = (rules.decorate)(request);
            let call = UpstreamCall::new(operation).with_attempt(hop + 1);
            let call = match rules.authorization {
                Some(authorization) if trusted => call.with_authorization(authorization),
                _ => call,
            };
            let mut response = self
                .send_bounded(
                    request,
                    Some(rules.deadline),
                    call,
                    AuthorizationPosition::End,
                )
                .await?;
            if !response.status().is_redirection() {
                return Ok(response);
            }
            let next = (hop < rules.max_redirects)
                .then(|| redirect_location(&response, &url))
                .flatten()
                .filter(|next| self.redirect_target_allowed(next, &rules));
            let Some(next) = next else {
                complete_upstream_trace(
                    &mut response,
                    Some(ReasonCode::UpstreamProtocolFailed.into()),
                );
                return Err(UpstreamError::Redirect);
            };
            complete_upstream_trace(&mut response, None);
            url = next;
        }
        Err(UpstreamError::Redirect)
    }

    fn redirect_target_allowed(&self, url: &Url, rules: &RedirectRules<'_>) -> bool {
        url.username().is_empty()
            && url.password().is_none()
            && url_allowed_by_patterns(url, &self.allowed_upstream_hosts)
            && (rules.vet)(url)
    }

    async fn send_bounded(
        &self,
        request: RequestBuilder,
        deadline: Option<Duration>,
        call: UpstreamCall<'_>,
        position: AuthorizationPosition,
    ) -> Result<Response, UpstreamError> {
        let (request, trace) = self.prepare(request, call, position)?;
        let send = self.client.execute(request);
        let response = match deadline {
            Some(deadline) => match tokio::time::timeout(deadline, send).await {
                Ok(response) => response,
                Err(_) => return Err(trace.fail(UpstreamError::Timeout)),
            },
            None => send.await,
        };
        trace.finish(response)
    }

    /// Builds the provider's request and adds the call's authorizations at
    /// `position`. The credential exists only in the built request, which
    /// the client then checks and dispatches itself; the provider never holds
    /// it.
    fn prepare(
        &self,
        request: RequestBuilder,
        call: UpstreamCall<'_>,
        position: AuthorizationPosition,
    ) -> Result<(reqwest::Request, TraceEvent), UpstreamError> {
        let (client, request) = request.build_split();
        let request = request.and_then(|mut request| {
            match attach(request.headers_mut(), call.authorizations, position) {
                Ok(()) => Ok(request),
                // Fail exactly as reqwest's own builder fails on such a value.
                Err(unrepresentable) => unrepresentable
                    .apply_to_builder(RequestBuilder::from_parts(client, request))
                    .build(),
            }
        });
        let request = match request {
            Ok(request) => request,
            Err(error) => {
                // The request never left, but the attempt is still traced.
                // Its method is not recoverable from a failed builder.
                let origin = error.url().unwrap_or(&self.base).origin();
                let trace = self.trace(call, origin.ascii_serialization(), "unknown");
                return Err(trace.fail(UpstreamError::NotSent {
                    timed_out: false,
                    detail: error.without_url().to_string(),
                }));
            }
        };
        if !url_allowed_by_patterns(request.url(), &self.allowed_upstream_hosts) {
            return Err(UpstreamError::NotAllowed);
        }
        let trace = self.trace(
            call,
            request.url().origin().ascii_serialization(),
            request.method().as_str(),
        );
        if !same_origin(request.url(), &self.base) && carries_credentials(request.headers()) {
            return Err(trace.fail(UpstreamError::NotSent {
                timed_out: false,
                detail: "credentials are sent only to the service origin".to_string(),
            }));
        }
        Ok((request, trace))
    }

    fn trace(&self, call: UpstreamCall<'_>, origin: String, method: &str) -> TraceEvent {
        let (service, action) = current_provider_action().unwrap_or_default();
        TraceEvent {
            status_reasons: self.status_reasons,
            service,
            action,
            hook: crate::correlation::current_hook_context(),
            span: tracing::Span::current(),
            provider: self.provider,
            operation: call.operation.to_string(),
            origin,
            method: method.to_string(),
            status: None,
            attempt: call.attempt,
            egress_proxy_mode: self.route.mode(),
            started: Instant::now(),
        }
    }
}

/// Whether a request carries credentials: an `Authorization`,
/// `Proxy-Authorization` or `Cookie` header, or any header value marked
/// sensitive, as a presented [`UpstreamAuthorization`], `basic_auth`,
/// `bearer_auth` and credentials embedded in the URL produce.
fn carries_credentials(headers: &reqwest::header::HeaderMap) -> bool {
    use reqwest::header::{AUTHORIZATION, COOKIE, PROXY_AUTHORIZATION};
    headers.iter().any(|(name, value)| {
        value.is_sensitive() || [AUTHORIZATION, PROXY_AUTHORIZATION, COOKIE].contains(name)
    })
}

/// A body streaming the file at `path`, with its upload progress.
pub async fn file_upload_body(path: &Path) -> std::io::Result<(reqwest::Body, UploadProgress)> {
    let file = tokio::fs::File::open(path).await?;
    let (progress_tx, progress) = watch::channel(tokio::time::Instant::now());
    let stream = tokio_util::io::ReaderStream::new(file).inspect_ok(move |_| {
        let _ = progress_tx.send(tokio::time::Instant::now());
    });
    Ok((reqwest::Body::wrap_stream(stream), progress))
}

/// Why [`read_bounded_body`] returned no body. The caller maps each case to
/// its own outcome.
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum BodyReadError {
    /// The declared `Content-Length`, or the bytes read, exceed the cap.
    #[error("upstream response body exceeds the byte cap")]
    TooLarge,
    /// No chunk arrived within the idle timeout.
    #[error("upstream response body stalled")]
    IdleTimeout,
    /// Reading the body failed. `timed_out` is set when the client's own
    /// deadline expired while reading.
    #[error("upstream response body could not be read: {detail}")]
    Transport { timed_out: bool, detail: String },
}

/// Reads `response`'s whole body into memory: a declared `Content-Length`
/// over `byte_cap` fails before reading, and so does reading more than
/// `byte_cap` bytes. With an `idle_timeout`, each chunk must arrive within it.
pub async fn read_bounded_body(
    mut response: Response,
    byte_cap: u64,
    idle_timeout: Option<Duration>,
) -> Result<Vec<u8>, BodyReadError> {
    if response
        .content_length()
        .is_some_and(|length| length > byte_cap)
    {
        return Err(BodyReadError::TooLarge);
    }
    let mut body = Vec::new();
    loop {
        let chunk = match idle_timeout {
            Some(idle_timeout) => tokio::time::timeout(idle_timeout, response.chunk())
                .await
                .map_err(|_| BodyReadError::IdleTimeout)?,
            None => response.chunk().await,
        }
        .map_err(|error| BodyReadError::Transport {
            timed_out: error.is_timeout(),
            detail: error.without_url().to_string(),
        })?;
        let Some(chunk) = chunk else {
            return Ok(body);
        };
        if (body.len() as u64).saturating_add(chunk.len() as u64) > byte_cap {
            return Err(BodyReadError::TooLarge);
        }
        body.extend_from_slice(&chunk);
    }
}

/// Records the trace [`UpstreamClient`] attached to `response`, with the
/// reason the caller classified it with. Later calls do nothing.
pub fn complete_upstream_trace(response: &mut Response, reason_code: Option<ProviderReason>) {
    if let Some(pending) = take_upstream_trace(response) {
        pending.complete(reason_code);
    }
}

/// Detaches the trace [`UpstreamClient`] attached to `response`, so the
/// caller can consume the body and record the outcome afterwards.
pub fn take_upstream_trace(response: &mut Response) -> Option<PendingUpstreamTrace> {
    response.extensions_mut().remove::<PendingUpstreamTrace>()
}

fn redirect_location(response: &Response, base: &Url) -> Option<Url> {
    let location = response
        .headers()
        .get(reqwest::header::LOCATION)?
        .to_str()
        .ok()?;
    base.join(location).ok()
}

/// One request's trace. It keeps the invocation, provider hook and span that
/// sent the request, so a trace recorded after the invocation's scope ended,
/// or while another invocation runs, is still attributed to and checked
/// against its own.
struct TraceEvent {
    status_reasons: &'static [(u16, ReasonCode)],
    service: String,
    action: String,
    hook: Option<crate::contract::HookContext>,
    span: tracing::Span,
    provider: &'static str,
    operation: String,
    origin: String,
    method: String,
    status: Option<u16>,
    attempt: u32,
    egress_proxy_mode: &'static str,
    started: Instant,
}

impl TraceEvent {
    /// Records the trace with the provider's classification, or the one its
    /// client declared for the status; both are checked against the hook
    /// that sent the request.
    fn emit(&self, reason_code: Option<ProviderReason>) {
        let reason_code = reason_code
            .or_else(|| {
                let status = self.status?;
                self.status_reasons
                    .iter()
                    .find(|(code, _)| *code == status)
                    .map(|(_, reason)| ProviderReason::from(*reason))
            })
            .map(|reason| {
                checked_trace_reason(reason, &self.service, &self.action, self.hook.as_ref())
            });
        self.emit_classified(reason_code);
    }

    /// Records the trace with a classification this crate made itself, such
    /// as a transport failure's.
    fn emit_classified(&self, reason_code: Option<ProviderReason>) {
        let trace = UpstreamTrace::new(
            self.provider,
            UpstreamCall::new(&self.operation).with_attempt(self.attempt),
            &self.origin,
            &self.method,
            self.egress_proxy_mode,
            self.started.elapsed().as_millis() as u64,
        )
        .with_status(self.status)
        .with_reason_code(reason_code);
        self.span.in_scope(|| {
            emit_upstream_request_completed_for(trace, &self.service, &self.action);
        });
    }

    fn finish(mut self, response: reqwest::Result<Response>) -> Result<Response, UpstreamError> {
        match response {
            Ok(mut response) => {
                self.status = Some(response.status().as_u16());
                response
                    .extensions_mut()
                    .insert(PendingUpstreamTrace(Arc::new(PendingTraceState {
                        operation: self.operation.clone(),
                        event: Mutex::new(Some(self)),
                    })));
                Ok(response)
            }
            Err(error) => {
                // A connect failure, even a connect timeout, means the request
                // never reached the upstream.
                let error = if error.is_connect() {
                    UpstreamError::NotSent {
                        timed_out: error.is_timeout(),
                        detail: error.without_url().to_string(),
                    }
                } else if error.is_timeout() {
                    UpstreamError::Timeout
                } else {
                    UpstreamError::Transport(error.without_url().to_string())
                };
                Err(self.fail(error))
            }
        }
    }

    fn fail(self, error: UpstreamError) -> UpstreamError {
        self.emit_classified(Some(error.reason_code().into()));
        error
    }
}

/// A trace waiting for the caller to classify its response, carried in the
/// response's extensions until [`take_upstream_trace`] detaches it. The event
/// is recorded once: by [`Self::complete`], or with the response status alone
/// when the last copy is dropped.
#[derive(Clone)]
pub struct PendingUpstreamTrace(Arc<PendingTraceState>);

impl PendingUpstreamTrace {
    /// The operation the request was sent for.
    pub fn operation(&self) -> &str {
        &self.0.operation
    }

    pub fn complete(self, reason_code: Option<ProviderReason>) {
        if let Some(event) = self.0.event.lock().ok().and_then(|mut event| event.take()) {
            event.emit(reason_code);
        }
    }
}

impl std::fmt::Debug for PendingUpstreamTrace {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("PendingUpstreamTrace")
            .field("operation", &self.0.operation)
            .finish_non_exhaustive()
    }
}

struct PendingTraceState {
    operation: String,
    event: Mutex<Option<TraceEvent>>,
}

impl Drop for PendingTraceState {
    fn drop(&mut self) {
        if let Some(event) = self.event.get_mut().ok().and_then(Option::take) {
            event.emit(None);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::host::with_correlation_context;
    use crate::{CorrelationContext, REQUEST_ID_HEADER};
    use wiremock::matchers::{header, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    fn client(base: &str, allowed: &[String], profile: ClientProfile) -> UpstreamClient {
        UpstreamClient::build(
            UpstreamClientSpec::new(
                "providers.example",
                "example",
                &Url::parse(base).unwrap(),
                EgressDeclaration::Ordinary(None),
                allowed,
                profile,
            )
            .with_status_reasons(&[(409, ReasonCode::VersionConflict)]),
            &crate::test_support::TestHost::default(),
        )
        .unwrap()
    }

    fn allow(servers: &[&MockServer]) -> Vec<String> {
        servers
            .iter()
            .map(|server| format!("{}/**", server.uri()))
            .collect()
    }

    /// The service's bearer token as the SDK presents it.
    static SERVICE_SECRET: std::sync::LazyLock<UpstreamAuthorization> =
        std::sync::LazyLock::new(|| {
            crate::test_support::bearer_credential("service-secret").authorization()
        });

    fn rules<'a>(max_redirects: u32, vet: &'a (dyn Fn(&Url) -> bool + Sync)) -> RedirectRules<'a> {
        RedirectRules::new(max_redirects, Duration::from_secs(5))
            .with_authorization(&SERVICE_SECRET)
            .with_vet(vet)
            .with_decorate(&|request| request.header("X-Every-Hop", "yes"))
    }

    #[tokio::test]
    async fn correlation_headers_reach_only_the_service_origin() {
        let service = MockServer::start().await;
        let elsewhere = MockServer::start().await;
        for server in [&service, &elsewhere] {
            Mock::given(method("GET"))
                .respond_with(ResponseTemplate::new(200))
                .mount(server)
                .await;
        }
        let client = client(
            &service.uri(),
            &allow(&[&service, &elsewhere]),
            ClientProfile::Request,
        );
        with_correlation_context(CorrelationContext::for_tests(), async {
            for server in [&service, &elsewhere] {
                let url = Url::parse(&format!("{}/item", server.uri())).unwrap();
                client
                    .send(
                        client.request(Method::GET, url),
                        UpstreamCall::new("item.view"),
                    )
                    .await
                    .unwrap();
            }
        })
        .await;
        let service_request = &service.received_requests().await.unwrap()[0];
        assert_eq!(
            service_request.headers[REQUEST_ID_HEADER],
            "test-agent-request-id"
        );
        let other_request = &elsewhere.received_requests().await.unwrap()[0];
        assert!(!other_request.headers.contains_key(REQUEST_ID_HEADER));
    }

    #[tokio::test]
    async fn requests_outside_the_allowlist_are_never_sent() {
        let service = MockServer::start().await;
        let elsewhere = MockServer::start().await;
        let client = client(&service.uri(), &allow(&[&service]), ClientProfile::Request);
        let url = Url::parse(&format!("{}/item", elsewhere.uri())).unwrap();
        let error = client
            .send(
                client.request(Method::GET, url),
                UpstreamCall::new("item.view"),
            )
            .await
            .unwrap_err();
        assert_eq!(error, UpstreamError::NotAllowed);
        assert!(elsewhere.received_requests().await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn redirects_are_authorized_only_on_the_service_origin() {
        let service = MockServer::start().await;
        let storage = MockServer::start().await;
        Mock::given(path("/download"))
            .respond_with(
                ResponseTemplate::new(302)
                    .insert_header("Location", format!("{}/blob", storage.uri())),
            )
            .mount(&service)
            .await;
        Mock::given(path("/blob"))
            .and(header("X-Every-Hop", "yes"))
            .respond_with(ResponseTemplate::new(200).set_body_string("bytes"))
            .mount(&storage)
            .await;
        let client = client(
            &service.uri(),
            &allow(&[&service, &storage]),
            ClientProfile::Stream,
        );
        let url = Url::parse(&format!("{}/download", service.uri())).unwrap();
        for correlate_other_origins in [false, true] {
            let response = with_correlation_context(
                CorrelationContext::for_tests(),
                client.get_following_redirects(
                    url.clone(),
                    RedirectRules {
                        correlate_other_origins,
                        ..rules(3, &|_| true)
                    },
                    "item.download",
                ),
            )
            .await
            .unwrap();
            assert_eq!(response.text().await.unwrap(), "bytes");
        }
        for first in service.received_requests().await.unwrap() {
            assert_eq!(first.headers["authorization"], "Bearer service-secret");
            assert_eq!(first.headers[REQUEST_ID_HEADER], "test-agent-request-id");
        }
        let hops = storage.received_requests().await.unwrap();
        assert!(
            hops.iter()
                .all(|hop| !hop.headers.contains_key("authorization"))
        );
        assert!(!hops[0].headers.contains_key(REQUEST_ID_HEADER));
        assert_eq!(hops[1].headers[REQUEST_ID_HEADER], "test-agent-request-id");
    }

    /// Credentials reach only the service's origin: a request carrying them
    /// anywhere else is refused before it is sent, while the same request
    /// without them, such as a media or artifact download, still goes out.
    #[tokio::test(flavor = "current_thread")]
    async fn credentials_never_leave_the_service_origin() {
        let service = MockServer::start().await;
        let elsewhere = MockServer::start().await;
        for server in [&service, &elsewhere] {
            Mock::given(method("GET"))
                .respond_with(ResponseTemplate::new(200))
                .mount(server)
                .await;
        }
        let client = client(
            &service.uri(),
            &allow(&[&service, &elsewhere]),
            ClientProfile::Request,
        );
        let item = |server: &MockServer| Url::parse(&format!("{}/item", server.uri())).unwrap();
        let mut api_key = reqwest::header::HeaderValue::from_static("service-secret");
        api_key.set_sensitive(true);
        type Authorize = Box<dyn Fn(RequestBuilder) -> RequestBuilder>;
        let credentials: Vec<(&str, Authorize)> = vec![
            ("bearer", Box::new(|r| r.bearer_auth("service-secret"))),
            (
                "basic",
                Box::new(|r| r.basic_auth("user", Some("service-secret"))),
            ),
            (
                "raw authorization",
                Box::new(|r| r.header("authorization", "Token service-secret")),
            ),
            (
                "proxy authorization",
                Box::new(|r| r.header("proxy-authorization", "Basic c2VjcmV0")),
            ),
            (
                "cookie",
                Box::new(|r| r.header("cookie", "session=service-secret")),
            ),
            (
                "sensitive header",
                Box::new(move |r| r.header("x-api-key", api_key.clone())),
            ),
        ];
        // Lent credentials the client presents itself.
        let authorizations = [
            (
                "static credential",
                crate::test_support::basic_credential("user", "service-secret").authorization(),
            ),
            (
                "placed api key",
                crate::test_support::bearer_credential("service-secret")
                    .authorization_as(&crate::CredentialPlacement::header(
                        reqwest::header::HeaderName::from_static("x-api-key"),
                    ))
                    .unwrap(),
            ),
            (
                "delegated access",
                crate::DelegatedAccess::new(
                    "service-secret",
                    "https://service.example.test/",
                    "https://service.example.test/",
                    "v1",
                    i64::MAX,
                )
                .authorization(),
            ),
        ];
        let capture = crate::test_support::install_trace_capture().start();
        for (name, authorize) in &credentials {
            let error = capture
                .run(client.send(
                    authorize(client.request(Method::GET, item(&elsewhere))),
                    UpstreamCall::new("item.view"),
                ))
                .await
                .unwrap_err();
            assert!(
                matches!(
                    error,
                    UpstreamError::NotSent {
                        timed_out: false,
                        ..
                    }
                ),
                "{name}: {error:?}"
            );
            assert_eq!(error.reason_code(), ReasonCode::UpstreamConnectionFailed);
            client
                .send(
                    authorize(client.request(Method::GET, item(&service))),
                    UpstreamCall::new("item.view"),
                )
                .await
                .unwrap_or_else(|error| panic!("{name}: {error:?}"));
        }
        for (name, authorization) in &authorizations {
            let call = UpstreamCall::new("item.view").with_authorization(authorization);
            let error = capture
                .run(client.send(client.request(Method::GET, item(&elsewhere)), call))
                .await
                .unwrap_err();
            assert!(
                matches!(
                    error,
                    UpstreamError::NotSent {
                        timed_out: false,
                        ..
                    }
                ),
                "{name}: {error:?}"
            );
            client
                .send(client.request(Method::GET, item(&service)), call)
                .await
                .unwrap_or_else(|error| panic!("{name}: {error:?}"));
        }
        // Credentials embedded in the URL become an Authorization header.
        let mut embedded = item(&elsewhere);
        embedded.set_username("user").unwrap();
        embedded.set_password(Some("service-secret")).unwrap();
        let error = client
            .send(
                client.request(Method::GET, embedded),
                UpstreamCall::new("item.view"),
            )
            .await
            .unwrap_err();
        assert!(matches!(error, UpstreamError::NotSent { .. }), "{error:?}");
        // The refusals are traced as unsent attempts to the other origin.
        let events = capture.take_upstream_requests();
        assert_eq!(
            events.len(),
            credentials.len() + authorizations.len(),
            "{events:?}"
        );
        assert!(events.iter().all(|event| {
            event["upstreamOrigin"] == elsewhere.uri()
                && event["reasonCode"] == "upstream_connection_failed"
        }));
        assert!(elsewhere.received_requests().await.unwrap().is_empty());

        // Without credentials, another allowlisted origin is reachable.
        client
            .send(
                client
                    .request(Method::GET, item(&elsewhere))
                    .header("accept", "application/octet-stream"),
                UpstreamCall::new("item.download"),
            )
            .await
            .unwrap();
        let received = elsewhere.received_requests().await.unwrap();
        assert_eq!(received.len(), 1);
        assert!(!received[0].headers.contains_key("authorization"));
        let authorized = service.received_requests().await.unwrap();
        assert_eq!(authorized.len(), credentials.len() + authorizations.len());
        assert_eq!(
            authorized[0].headers["authorization"],
            "Bearer service-secret"
        );
        // The client presented each lent credential on the service origin.
        let presented = &authorized[credentials.len()..];
        assert_eq!(
            presented[0].headers["authorization"],
            "Basic dXNlcjpzZXJ2aWNlLXNlY3JldA=="
        );
        assert_eq!(presented[1].headers["x-api-key"], "service-secret");
        assert_eq!(
            presented[2].headers["authorization"],
            "Bearer service-secret"
        );
    }

    /// A redirect hop to another origin cannot carry credentials through
    /// `with_decorate`; `authorize` keeps them on the service's origin.
    #[tokio::test]
    async fn redirect_hops_cannot_decorate_other_origins_with_credentials() {
        let service = MockServer::start().await;
        let storage = MockServer::start().await;
        Mock::given(path("/download"))
            .respond_with(
                ResponseTemplate::new(302)
                    .insert_header("Location", format!("{}/blob", storage.uri())),
            )
            .mount(&service)
            .await;
        Mock::given(path("/blob"))
            .respond_with(ResponseTemplate::new(200).set_body_string("bytes"))
            .mount(&storage)
            .await;
        let client = client(
            &service.uri(),
            &allow(&[&service, &storage]),
            ClientProfile::Stream,
        );
        let url = Url::parse(&format!("{}/download", service.uri())).unwrap();
        let error = client
            .get_following_redirects(
                url,
                RedirectRules::new(3, Duration::from_secs(5))
                    .with_decorate(&|request| request.bearer_auth("service-secret")),
                "item.download",
            )
            .await
            .unwrap_err();
        assert!(matches!(error, UpstreamError::NotSent { .. }), "{error:?}");
        assert_eq!(service.received_requests().await.unwrap().len(), 1);
        assert!(storage.received_requests().await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn redirect_chains_fail_closed() {
        let service = MockServer::start().await;
        let outside = MockServer::start().await;
        let service_uri = service.uri();
        for (route, location) in [
            ("/outside", format!("{}/blob", outside.uri())),
            ("/loop", format!("{service_uri}/loop")),
            (
                "/userinfo",
                service_uri.replace("http://", "http://user:pass@") + "/blob",
            ),
            ("/vetted", format!("{service_uri}/forbidden")),
        ] {
            Mock::given(path(route))
                .respond_with(ResponseTemplate::new(302).insert_header("Location", location))
                .mount(&service)
                .await;
        }
        let client = client(&service_uri, &allow(&[&service]), ClientProfile::Stream);
        let vet = |url: &Url| !url.path().starts_with("/forbidden");
        for route in ["/outside", "/loop", "/userinfo", "/vetted"] {
            let url = Url::parse(&format!("{service_uri}{route}")).unwrap();
            let error = client
                .get_following_redirects(url, rules(2, &vet), "item.download")
                .await
                .unwrap_err();
            assert_eq!(error, UpstreamError::Redirect, "{route}");
        }
        assert!(outside.received_requests().await.unwrap().is_empty());
        let loops = service
            .received_requests()
            .await
            .unwrap()
            .iter()
            .filter(|request| request.url.path() == "/loop")
            .count();
        assert_eq!(loops, 3);
    }

    #[tokio::test]
    async fn stalled_uploads_time_out() {
        let service = MockServer::start().await;
        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(200))
            .mount(&service)
            .await;
        let client = client(&service.uri(), &allow(&[&service]), ClientProfile::Upload);
        let (_progress_tx, progress) = watch::channel(tokio::time::Instant::now());
        let stalled = futures_util::stream::pending::<Result<bytes::Bytes, std::io::Error>>();
        let request = client
            .request(
                Method::POST,
                Url::parse(&format!("{}/upload", service.uri())).unwrap(),
            )
            .body(reqwest::Body::wrap_stream(stalled));
        let started = Instant::now();
        let error = client
            .send_upload(
                request,
                Some(progress),
                Duration::from_millis(200),
                UpstreamCall::new("item.upload"),
            )
            .await
            .unwrap_err();
        assert_eq!(error, UpstreamError::Timeout);
        assert!(started.elapsed() < Duration::from_secs(5));
    }

    #[tokio::test(flavor = "current_thread", start_paused = true)]
    async fn upload_progress_recorded_at_the_deadline_extends_it() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let base = format!("http://{}", listener.local_addr().unwrap());
        let _accepted = tokio::spawn(async move {
            // Accept and hold the connection without reading the body.
            let (_socket, _) = listener.accept().await.unwrap();
            std::future::pending::<()>().await;
        });
        let client = client(&base, &[format!("{base}/**")], ClientProfile::Upload);
        let idle = Duration::from_secs(10);
        let started = tokio::time::Instant::now();
        let (progress_tx, progress) = watch::channel(started);
        let recorder = tokio::spawn(async move {
            tokio::time::sleep(idle / 2).await;
            // Progress lands without a notification yet being observed.
            progress_tx.send_if_modified(|last| {
                *last = tokio::time::Instant::now();
                false
            });
            std::future::pending::<()>().await;
        });
        let stalled = futures_util::stream::pending::<Result<bytes::Bytes, std::io::Error>>();
        let request = client
            .request(Method::POST, Url::parse(&format!("{base}/upload")).unwrap())
            .body(reqwest::Body::wrap_stream(stalled));
        let error = client
            .send_upload(
                request,
                Some(progress),
                idle,
                UpstreamCall::new("item.upload"),
            )
            .await
            .unwrap_err();
        assert_eq!(error, UpstreamError::Timeout);
        assert_eq!(started.elapsed(), idle / 2 + idle);
        recorder.abort();
    }

    /// A server answering one request with `response`, then holding the
    /// connection open or closing it.
    fn raw_server(response: &'static [u8], hold: bool) -> String {
        use std::io::{Read, Write};
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        std::thread::spawn(move || {
            let (mut socket, _) = listener.accept().unwrap();
            let mut request = Vec::new();
            let mut buffer = [0_u8; 1024];
            while !request.windows(4).any(|window| window == b"\r\n\r\n") {
                match socket.read(&mut buffer) {
                    Ok(0) | Err(_) => return,
                    Ok(read) => request.extend_from_slice(&buffer[..read]),
                }
            }
            socket.write_all(response).unwrap();
            socket.flush().unwrap();
            if hold {
                std::thread::sleep(Duration::from_secs(30));
            }
            let _ = socket.shutdown(std::net::Shutdown::Both);
        });
        format!("http://{address}/body")
    }

    #[tokio::test]
    async fn bounded_body_reads_stop_at_the_cap_and_type_their_failures() {
        let server = MockServer::start().await;
        Mock::given(path("/body"))
            .respond_with(ResponseTemplate::new(200).set_body_string("12345678"))
            .mount(&server)
            .await;
        let fetch = |url: String| async move {
            reqwest::Client::builder()
                .no_proxy()
                .build()
                .unwrap()
                .get(url)
                .send()
                .await
                .unwrap()
        };
        let declared = format!("{}/body", server.uri());
        assert_eq!(
            read_bounded_body(fetch(declared.clone()).await, 8, None)
                .await
                .unwrap(),
            b"12345678"
        );
        // Over the cap by its declared length, and by the bytes read.
        assert_eq!(
            read_bounded_body(fetch(declared).await, 4, None).await,
            Err(BodyReadError::TooLarge)
        );
        let chunked = raw_server(
            b"HTTP/1.1 200 OK\r\ntransfer-encoding: chunked\r\n\r\n8\r\n12345678\r\n0\r\n\r\n",
            false,
        );
        assert_eq!(
            read_bounded_body(fetch(chunked).await, 4, None).await,
            Err(BodyReadError::TooLarge)
        );
        let truncated = b"HTTP/1.1 200 OK\r\ncontent-length: 10\r\n\r\nab";
        let stalled = raw_server(truncated, true);
        assert_eq!(
            read_bounded_body(fetch(stalled).await, 1024, Some(Duration::from_millis(100))).await,
            Err(BodyReadError::IdleTimeout)
        );
        let closed = raw_server(truncated, false);
        let error = read_bounded_body(fetch(closed).await, 1024, Some(Duration::from_secs(10)))
            .await
            .unwrap_err();
        assert!(
            matches!(
                error,
                BodyReadError::Transport {
                    timed_out: false,
                    ..
                }
            ),
            "{error:?}"
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn declared_status_reasons_classify_unclassified_responses() {
        let service = MockServer::start().await;
        Mock::given(method("PUT"))
            .respond_with(ResponseTemplate::new(409))
            .mount(&service)
            .await;
        let client = client(&service.uri(), &allow(&[&service]), ClientProfile::Request);
        let capture = crate::test_support::install_trace_capture().start();
        let url = Url::parse(&format!("{}/page", service.uri())).unwrap();
        for reason in [None, Some(ReasonCode::UpstreamProtocolFailed.into())] {
            let mut response = capture
                .run(crate::test_support::in_invocation_hook(
                    "example",
                    "page.update",
                    client.send(
                        client.request(Method::PUT, url.clone()),
                        UpstreamCall::new("page.update"),
                    ),
                ))
                .await
                .unwrap();
            capture.in_scope(|| complete_upstream_trace(&mut response, reason));
        }
        let events = capture.take_upstream_requests();
        assert_eq!(events[0]["reasonCode"], "version_conflict");
        assert_eq!(events[1]["reasonCode"], "upstream_protocol_failed");
    }

    #[tokio::test(flavor = "current_thread")]
    async fn requests_that_cannot_be_built_are_traced_as_failures() {
        let service = MockServer::start().await;
        let client = client(&service.uri(), &allow(&[&service]), ClientProfile::Request);
        let capture = crate::test_support::install_trace_capture().start();
        let request = client
            .request(
                Method::GET,
                Url::parse(&format!("{}/item", service.uri())).unwrap(),
            )
            .bearer_auth("token\r\ninjected: header");
        let error = capture
            .run(client.send(request, UpstreamCall::new("item.view")))
            .await
            .unwrap_err();
        assert!(
            matches!(
                error,
                UpstreamError::NotSent {
                    timed_out: false,
                    ..
                }
            ),
            "{error:?}"
        );
        let events = capture.take_upstream_requests();
        assert_eq!(events.len(), 1, "{events:?}");
        assert_eq!(events[0]["upstreamOperation"], "item.view");
        assert_eq!(events[0]["reasonCode"], "upstream_connection_failed");
        assert_eq!(events[0]["upstreamOrigin"], service.uri());
        assert!(service.received_requests().await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn refused_connections_are_not_sent() {
        // Bound without a listener, the port refuses connections, and no
        // other socket can take it meanwhile.
        let reserved = tokio::net::TcpSocket::new_v4().unwrap();
        reserved.bind("127.0.0.1:0".parse().unwrap()).unwrap();
        let base = format!("http://{}", reserved.local_addr().unwrap());
        let client = client(&base, &[format!("{base}/**")], ClientProfile::Request);
        let error = client
            .send(
                client.request(Method::GET, Url::parse(&format!("{base}/item")).unwrap()),
                UpstreamCall::new("item.view"),
            )
            .await
            .unwrap_err();
        assert!(
            matches!(
                error,
                UpstreamError::NotSent {
                    timed_out: false,
                    ..
                }
            ),
            "{error:?}"
        );
        assert_eq!(error.reason_code(), ReasonCode::UpstreamConnectionFailed);
    }

    #[tokio::test]
    async fn bounded_clients_apply_their_own_total_timeout() {
        let service = MockServer::start().await;
        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(200).set_delay(Duration::from_secs(5)))
            .mount(&service)
            .await;
        let client = client(
            &service.uri(),
            &allow(&[&service]),
            ClientProfile::Bounded {
                total: Duration::from_millis(200),
                connect: Duration::from_secs(1),
            },
        );
        let started = Instant::now();
        let error = client
            .send(
                client.request(
                    Method::GET,
                    Url::parse(&format!("{}/slow", service.uri())).unwrap(),
                ),
                UpstreamCall::new("item.view"),
            )
            .await
            .unwrap_err();
        assert_eq!(error, UpstreamError::Timeout);
        assert!(started.elapsed() < Duration::from_secs(4));
    }

    #[tokio::test(flavor = "current_thread")]
    async fn deferred_traces_keep_their_invocation() {
        let service = MockServer::start().await;
        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(200))
            .mount(&service)
            .await;
        let client = client(&service.uri(), &allow(&[&service]), ClientProfile::Request);
        let capture = crate::test_support::install_trace_capture().start();
        let url = Url::parse(&format!("{}/item", service.uri())).unwrap();
        let send = || async {
            client
                .send(
                    client.request(Method::GET, url.clone()),
                    UpstreamCall::new("item.view"),
                )
                .await
                .unwrap()
        };
        let in_scope = |action: &'static str| {
            crate::host::with_provider_context(
                crate::CorrelationContext::for_tests(),
                "example".to_string(),
                action.to_string(),
                send(),
            )
        };

        capture
            .run(async {
                let outlived = in_scope("item.view").await;
                drop(outlived);
                let retained = in_scope("item.view").await;
                let extensions = retained.extensions().clone();
                crate::host::with_provider_context(
                    crate::CorrelationContext::for_tests(),
                    "other".to_string(),
                    "other.action".to_string(),
                    async move {
                        drop(retained);
                        drop(extensions);
                    },
                )
                .await;
            })
            .await;

        let events = capture.take_upstream_requests();
        assert_eq!(events.len(), 2, "{events:?}");
        for event in &events {
            assert_eq!(event["service"], "example");
            assert_eq!(event["action"], "item.view");
        }
    }

    #[tokio::test(flavor = "current_thread")]
    async fn each_request_is_traced_once_with_the_callers_classification() {
        let service = MockServer::start().await;
        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(502))
            .mount(&service)
            .await;
        let client = client(&service.uri(), &allow(&[&service]), ClientProfile::Request);
        let capture = crate::test_support::install_trace_capture().start();
        let url = Url::parse(&format!("{}/item", service.uri())).unwrap();

        capture
            .run(crate::test_support::in_invocation_hook(
                "example",
                "item.view",
                async {
                    let mut classified = client
                        .send(
                            client.request(Method::GET, url.clone()),
                            UpstreamCall::new("item.view"),
                        )
                        .await
                        .unwrap();
                    complete_upstream_trace(
                        &mut classified,
                        Some(ReasonCode::UpstreamFailed.into()),
                    );
                    complete_upstream_trace(
                        &mut classified,
                        Some(ReasonCode::UpstreamTimeout.into()),
                    );
                    drop(classified);
                    let dropped = client
                        .send(
                            client.request(Method::GET, url),
                            UpstreamCall::new("item.list"),
                        )
                        .await
                        .unwrap();
                    drop(dropped);

                    let mut detached = client
                        .send(
                            client.request(
                                Method::GET,
                                Url::parse(&format!("{}/item", service.uri())).unwrap(),
                            ),
                            UpstreamCall::new("item.update"),
                        )
                        .await
                        .unwrap();
                    let trace = take_upstream_trace(&mut detached).unwrap();
                    assert_eq!(trace.operation(), "item.update");
                    drop(detached);
                    trace.complete(Some(ReasonCode::UpstreamProtocolFailed.into()));
                },
            ))
            .await;

        let events = capture.take_upstream_requests();
        assert_eq!(events.len(), 3, "{events:?}");
        assert_eq!(events[0]["upstreamOperation"], "item.view");
        assert_eq!(events[0]["reasonCode"], "upstream_failed");
        assert_eq!(events[0]["http.statusCode"], 502);
        assert_eq!(events[1]["upstreamOperation"], "item.list");
        assert_eq!(events[1]["provider"], "example");
        assert_eq!(events[2]["upstreamOperation"], "item.update");
        assert_eq!(events[2]["reasonCode"], "upstream_protocol_failed");
    }

    static ITEM_LOCKED: crate::ProviderReasonDefinition = crate::ProviderReasonDefinition::deny(
        "example_item_locked",
        crate::ProviderFailureStatus::Conflict,
    );
    static ITEM_REASONS: [&crate::ProviderReasonDefinition; 1] = [&ITEM_LOCKED];
    static OTHER_LOCKED: crate::ProviderReasonDefinition = crate::ProviderReasonDefinition::deny(
        "other_item_locked",
        crate::ProviderFailureStatus::Conflict,
    );

    /// Classifications are checked against the hook that sent the request,
    /// captured at send time: its phase, its backend's domain reasons and its
    /// service. A rejected or unattributable one is recorded as
    /// `broker_provider_contract_failed`; the transport's own classification
    /// is not the provider's and needs no hook.
    #[tokio::test]
    async fn trace_classifications_are_checked_against_the_sending_hook() {
        use crate::HookPhase;
        use crate::host::{hook_context, with_hook_context};
        let service = MockServer::start().await;
        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(409))
            .mount(&service)
            .await;
        let client = client(&service.uri(), &allow(&[&service]), ClientProfile::Request);
        let url = Url::parse(&format!("{}/item", service.uri())).unwrap();
        let capture = crate::test_support::install_trace_capture().start();
        let send = || {
            client.send(
                client.request(Method::GET, url.clone()),
                UpstreamCall::new("item.view"),
            )
        };
        let cases: Vec<(
            Option<crate::contract::HookContext>,
            Option<ProviderReason>,
            &str,
        )> = vec![
            (
                Some(hook_context(
                    "example",
                    "item.view",
                    HookPhase::Invocation,
                    &ITEM_REASONS,
                )),
                Some((&ITEM_LOCKED).into()),
                "example_item_locked",
            ),
            (
                Some(hook_context(
                    "example",
                    "item.view",
                    HookPhase::Invocation,
                    &ITEM_REASONS,
                )),
                Some((&OTHER_LOCKED).into()),
                "broker_provider_contract_failed",
            ),
            (
                Some(hook_context(
                    "example",
                    "item.view",
                    HookPhase::Invocation,
                    &[],
                )),
                Some(ReasonCode::RateLimited.into()),
                "broker_provider_contract_failed",
            ),
            (
                Some(hook_context(
                    "example",
                    "item.view",
                    HookPhase::CredentialVerification,
                    &[],
                )),
                Some(ReasonCode::MutationVerificationFailed.into()),
                "broker_provider_contract_failed",
            ),
            (
                Some(hook_context(
                    "example",
                    "item.view",
                    HookPhase::Invocation,
                    &[],
                )),
                Some(ReasonCode::MutationVerificationFailed.into()),
                "mutation_verification_failed",
            ),
            (
                None,
                Some(ReasonCode::UpstreamFailed.into()),
                "broker_provider_contract_failed",
            ),
            // The client's declared status reason (409) is the provider's
            // classification too, so it needs a hook.
            (None, None, "broker_provider_contract_failed"),
        ];
        for (hook, reason, expected) in cases {
            let mut response = match hook {
                Some(hook) => capture.run(with_hook_context(hook, send())).await,
                None => capture.run(send()).await,
            }
            .unwrap();
            capture.in_scope(|| complete_upstream_trace(&mut response, reason));
            let events = capture.take_upstream_requests();
            assert_eq!(events.len(), 1, "{events:?}");
            assert_eq!(events[0]["reasonCode"], expected, "{reason:?}");
        }

        // A hook nested under another service's provider action cannot
        // attribute the trace consistently.
        let mut response = capture
            .run(with_hook_context(
                hook_context("example", "item.view", HookPhase::Invocation, &[]),
                crate::host::with_provider_context(
                    crate::CorrelationContext::for_tests(),
                    "other".to_owned(),
                    "item.view".to_owned(),
                    send(),
                ),
            ))
            .await
            .unwrap();
        capture.in_scope(|| {
            complete_upstream_trace(&mut response, Some(ReasonCode::UpstreamFailed.into()))
        });
        let events = capture.take_upstream_requests();
        assert_eq!(events[0]["reasonCode"], "broker_provider_contract_failed");

        // The provider's classification made after its hook returned is
        // still checked against that hook, which the trace captured.
        let mut response = capture
            .run(with_hook_context(
                hook_context("example", "item.view", HookPhase::Invocation, &ITEM_REASONS),
                send(),
            ))
            .await
            .unwrap();
        capture.in_scope(|| complete_upstream_trace(&mut response, Some((&ITEM_LOCKED).into())));
        let events = capture.take_upstream_requests();
        assert_eq!(events[0]["reasonCode"], "example_item_locked");

        // A transport failure's classification is the client's own. Bound
        // without a listener, the port refuses connections, and no other
        // socket can take it meanwhile.
        let reserved = tokio::net::TcpSocket::new_v4().unwrap();
        reserved.bind("127.0.0.1:0".parse().unwrap()).unwrap();
        let base = format!("http://{}", reserved.local_addr().unwrap());
        let unreachable =
            super::tests::client(&base, &[format!("{base}/**")], ClientProfile::Request);
        let _ = capture
            .run(unreachable.send(
                unreachable.request(Method::GET, Url::parse(&format!("{base}/item")).unwrap()),
                UpstreamCall::new("item.view"),
            ))
            .await
            .unwrap_err();
        let events = capture.take_upstream_requests();
        assert_eq!(events[0]["reasonCode"], "upstream_connection_failed");
    }
}
