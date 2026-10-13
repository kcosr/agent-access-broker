//! Outbound HTTP to an upstream service under the broker's common rules:
//! clients the host constructs (outbound TLS trust, the selected egress route,
//! the requested time profile and no automatic redirects), allowlisted
//! destinations, correlation headers and credentials only toward the
//! service's own origin, and one trace event per upstream request.
//!
//! Backends own their protocol (URLs, authentication scheme, status and body
//! handling); they build clients and send requests through this module.
use crate::host::{ClientTransportSpec, UpstreamClientFactory};
use crate::{
    EgressDeclaration, EgressRoute, ProviderBuildError, ReasonCode, UpstreamTrace,
    apply_current_correlation_headers, current_provider_action,
    emit_upstream_request_completed_for, same_origin, url_allowed_by_patterns,
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

/// What a backend declares about one upstream client.
pub struct UpstreamClientSpec<'a> {
    /// Configuration path naming the client in diagnostics, such as
    /// `providers.jira.egress_proxy`.
    pub label: &'a str,
    /// The `provider` recorded on trace events.
    pub provider: &'static str,
    /// The service's base URL. Its origin is the only one that receives
    /// correlation headers and credentials.
    pub base: &'a Url,
    /// The route the client needs; the host selects and may deny it.
    pub egress: EgressDeclaration<'a>,
    /// URL patterns every request, including each redirect hop, must match.
    pub allowed_upstream_hosts: &'a [String],
    pub profile: ClientProfile,
    /// Reason codes a trace records for these statuses when the caller
    /// classifies the response with none, such as 409 for a version conflict.
    pub status_reasons: &'static [(u16, ReasonCode)],
}

/// Why an upstream request produced no usable response.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum UpstreamError {
    #[error("upstream URL is not allowlisted")]
    NotAllowed,
    /// The request never reached the upstream: it could not be built, or no
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

/// Names one upstream request in its trace event.
#[derive(Debug, Clone, Copy)]
pub struct UpstreamCall<'a> {
    pub operation: &'a str,
    /// 1 for the first request; redirect hops and retries count up.
    pub attempt: u32,
}

impl<'a> UpstreamCall<'a> {
    pub fn new(operation: &'a str) -> Self {
        Self {
            operation,
            attempt: 1,
        }
    }
}

/// Last time an upload body made progress.
pub type UploadProgress = watch::Receiver<tokio::time::Instant>;

/// How [`UpstreamClient::get_following_redirects`] walks a redirect chain.
pub struct RedirectRules<'a> {
    /// Redirects followed after the first request; one more is an error.
    pub max_redirects: u32,
    /// Deadline for each hop's response headers.
    pub deadline: Duration,
    /// Whether hops to other origins carry the invocation's correlation
    /// headers. Hops to the service's own origin always do.
    pub correlate_other_origins: bool,
    /// Additional backend checks each URL in the chain must pass, on top of
    /// the allowlist and the absence of embedded credentials.
    pub vet: &'a (dyn Fn(&Url) -> bool + Sync),
    /// Headers every hop carries.
    pub decorate: &'a (dyn Fn(RequestBuilder) -> RequestBuilder + Sync),
    /// Credentials, applied only to hops on the service's own origin.
    pub authorize: &'a (dyn Fn(RequestBuilder) -> RequestBuilder + Sync),
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
    pub fn request(&self, method: Method, url: Url) -> RequestBuilder {
        let trusted = same_origin(&url, &self.base);
        let request = self.client.request(method, url);
        if trusted {
            apply_current_correlation_headers(request)
        } else {
            request
        }
    }

    /// Sends a request bounded by the client's profile. The response carries
    /// a pending trace that [`complete_upstream_trace`] records once the
    /// caller has classified the response; dropping the response records it
    /// with its status alone.
    pub async fn send(
        &self,
        request: RequestBuilder,
        call: UpstreamCall<'_>,
    ) -> Result<Response, UpstreamError> {
        self.send_bounded(request, None, call).await
    }

    /// [`Self::send`] with a deadline for the response headers, for clients
    /// whose profile sets none.
    pub async fn send_with_deadline(
        &self,
        request: RequestBuilder,
        deadline: Duration,
        call: UpstreamCall<'_>,
    ) -> Result<Response, UpstreamError> {
        self.send_bounded(request, Some(deadline), call).await
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
        let (request, trace) = self.prepare(request, call)?;
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
    /// only hops on the service's own origin are authorized.
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
            let request = if trusted {
                (rules.authorize)(request)
            } else {
                request
            };
            let mut response = self
                .send_with_deadline(
                    request,
                    rules.deadline,
                    UpstreamCall {
                        operation,
                        attempt: hop + 1,
                    },
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
                complete_upstream_trace(&mut response, Some(ReasonCode::UpstreamProtocolFailed));
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
    ) -> Result<Response, UpstreamError> {
        let (request, trace) = self.prepare(request, call)?;
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

    fn prepare(
        &self,
        request: RequestBuilder,
        call: UpstreamCall<'_>,
    ) -> Result<(reqwest::Request, TraceEvent), UpstreamError> {
        let request = match request.build() {
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
        Ok((request, trace))
    }

    fn trace(&self, call: UpstreamCall<'_>, origin: String, method: &str) -> TraceEvent {
        let (service, action) = current_provider_action().unwrap_or_default();
        TraceEvent {
            status_reasons: self.status_reasons,
            service,
            action,
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

/// A body streaming the file at `path`, with its upload progress.
pub async fn file_upload_body(path: &Path) -> std::io::Result<(reqwest::Body, UploadProgress)> {
    let file = tokio::fs::File::open(path).await?;
    let (progress_tx, progress) = watch::channel(tokio::time::Instant::now());
    let stream = tokio_util::io::ReaderStream::new(file).inspect_ok(move |_| {
        let _ = progress_tx.send(tokio::time::Instant::now());
    });
    Ok((reqwest::Body::wrap_stream(stream), progress))
}

/// Records the trace [`UpstreamClient`] attached to `response`, with the
/// reason code the caller classified it with. Later calls do nothing.
pub fn complete_upstream_trace(response: &mut Response, reason_code: Option<ReasonCode>) {
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

/// One request's trace. It keeps the invocation and span that sent the
/// request, so a trace recorded after the invocation's scope ended, or while
/// another invocation runs, is still attributed to its own.
struct TraceEvent {
    status_reasons: &'static [(u16, ReasonCode)],
    service: String,
    action: String,
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
    fn emit(&self, reason_code: Option<ReasonCode>) {
        let reason_code = reason_code.or_else(|| {
            let status = self.status?;
            self.status_reasons
                .iter()
                .find(|(code, _)| *code == status)
                .map(|(_, reason)| *reason)
        });
        let trace = UpstreamTrace {
            provider: self.provider,
            upstream_operation: &self.operation,
            upstream_origin: &self.origin,
            method: &self.method,
            status: self.status,
            duration_ms: self.started.elapsed().as_millis() as u64,
            attempt: self.attempt,
            egress_proxy_mode: self.egress_proxy_mode,
            reason_code,
            path_template: None,
        };
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
        self.emit(Some(error.reason_code()));
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

    pub fn complete(self, reason_code: Option<ReasonCode>) {
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
    use crate::{CorrelationContext, REQUEST_ID_HEADER, with_correlation_context};
    use wiremock::matchers::{header, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    fn client(base: &str, allowed: &[String], profile: ClientProfile) -> UpstreamClient {
        UpstreamClient::build(
            UpstreamClientSpec {
                label: "providers.example",
                provider: "example",
                base: &Url::parse(base).unwrap(),
                egress: EgressDeclaration::Ordinary(None),
                allowed_upstream_hosts: allowed,
                profile,
                status_reasons: &[(409, ReasonCode::VersionConflict)],
            },
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

    fn rules<'a>(max_redirects: u32, vet: &'a (dyn Fn(&Url) -> bool + Sync)) -> RedirectRules<'a> {
        RedirectRules {
            max_redirects,
            deadline: Duration::from_secs(5),
            correlate_other_origins: false,
            vet,
            decorate: &|request| request.header("X-Every-Hop", "yes"),
            authorize: &|request| request.bearer_auth("service-secret"),
        }
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
        for reason in [None, Some(ReasonCode::UpstreamProtocolFailed)] {
            let mut response = capture
                .run(client.send(
                    client.request(Method::PUT, url.clone()),
                    UpstreamCall::new("page.update"),
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
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let base = format!("http://{}", listener.local_addr().unwrap());
        drop(listener);
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
            crate::with_provider_context(
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
                crate::with_provider_context(
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
            .run(async {
                let mut classified = client
                    .send(
                        client.request(Method::GET, url.clone()),
                        UpstreamCall::new("item.view"),
                    )
                    .await
                    .unwrap();
                complete_upstream_trace(&mut classified, Some(ReasonCode::UpstreamFailed));
                complete_upstream_trace(&mut classified, Some(ReasonCode::UpstreamTimeout));
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
                trace.complete(Some(ReasonCode::UpstreamProtocolFailed));
            })
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
}
