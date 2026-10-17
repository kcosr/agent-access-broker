use agent_access_core::ExecutionContext;
use axum::body::Body;
use axum::extract::{ConnectInfo, MatchedPath};
use axum::http::{Request, Response};
use futures_util::future::BoxFuture;
use std::net::SocketAddr;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Instant;
use tower::{Layer, Service};
use tracing::{Instrument, Level, Span, field, span};

#[derive(Debug, Clone, Copy)]
pub(crate) enum ListenerKind {
    Public,
    Gateway,
}

impl ListenerKind {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::Public => "public",
            Self::Gateway => "gateway",
        }
    }
}

#[derive(Clone)]
pub(crate) struct RequestTracingLayer {
    listener: ListenerKind,
    /// The broker's effective node ID, which reload never changes.
    node_id: Arc<str>,
}

impl RequestTracingLayer {
    pub(crate) fn new(listener: ListenerKind, node_id: &str) -> Self {
        Self {
            listener,
            node_id: Arc::from(node_id),
        }
    }
}

impl<S> Layer<S> for RequestTracingLayer {
    type Service = RequestTracingService<S>;

    fn layer(&self, inner: S) -> Self::Service {
        RequestTracingService {
            inner,
            listener: self.listener,
            node_id: Arc::clone(&self.node_id),
        }
    }
}

#[derive(Clone)]
pub(crate) struct RequestTracingService<S> {
    inner: S,
    listener: ListenerKind,
    node_id: Arc<str>,
}

impl<S> Service<Request<Body>> for RequestTracingService<S>
where
    S: Service<Request<Body>, Response = Response<Body>> + Send + 'static,
    S::Future: Send + 'static,
    S::Error: Send + 'static,
{
    type Response = Response<Body>;
    type Error = S::Error;
    type Future = BoxFuture<'static, Result<Self::Response, Self::Error>>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, request: Request<Body>) -> Self::Future {
        let started = Instant::now();
        let method = request.method().clone();
        let route = request
            .extensions()
            .get::<MatchedPath>()
            .map(|matched| matched.as_str().to_string());
        let path = sanitized_path(request.uri().path(), route.as_deref());
        let peer = request
            .extensions()
            .get::<ConnectInfo<SocketAddr>>()
            .map(|ConnectInfo(addr)| *addr);
        let span = span!(
            Level::INFO,
            "http.request",
            nodeId = &*self.node_id,
            listener = self.listener.as_str(),
            "http.method" = %method,
            "http.route" = field::Empty,
            "http.path" = field::Empty,
            "network.peer.ip" = field::Empty,
            "network.peer.port" = field::Empty,
            agentRequestId = field::Empty,
            brokerRequestId = field::Empty,
            service = field::Empty,
            action = field::Empty,
            operation = field::Empty,
            principal = field::Empty,
            executionContext = field::Empty,
            executionContextFailure = field::Empty,
            decision = field::Empty,
            reasonCode = field::Empty,
            configGeneration = field::Empty,
            "http.statusCode" = field::Empty,
            "broker.statusCode" = field::Empty,
            durationMs = field::Empty,
        );
        if let Some(route) = route {
            span.record("http.route", route.as_str());
        }
        if let Some(path) = path {
            span.record("http.path", path.as_str());
        }
        if let Some(peer) = peer {
            let ip = peer.ip().to_string();
            span.record("network.peer.ip", ip.as_str());
            span.record("network.peer.port", peer.port());
        }

        let future = self.inner.call(request).instrument(span.clone());
        Box::pin(
            async move {
                let response = future.await?;
                record_status(response.status().as_u16());
                record_duration_ms(elapsed_ms(started));
                Ok(response)
            }
            .instrument(span),
        )
    }
}

fn sanitized_path(path: &str, route: Option<&str>) -> Option<String> {
    if matches!(path, "/v1/healthz" | "/v1/readyz") {
        return Some(path.to_string());
    }
    if let Some(route) = route
        && !route.contains('{')
    {
        return Some(route.to_string());
    }
    None
}

pub(crate) fn record_agent_request_id(agent_request_id: &str) {
    if agent_request_id.is_empty() {
        return;
    }
    Span::current().record("agentRequestId", agent_request_id);
}

pub(crate) fn record_broker_request_id(broker_request_id: &str) {
    if broker_request_id.is_empty() {
        return;
    }
    Span::current().record("brokerRequestId", broker_request_id);
}

pub(crate) fn record_request_ids(agent_request_id: &str, broker_request_id: &str) {
    record_agent_request_id(agent_request_id);
    record_broker_request_id(broker_request_id);
}

pub(crate) fn record_service_action(service: &str, action: &str) {
    let span = Span::current();
    if !service.is_empty() {
        span.record("service", service);
    }
    if !action.is_empty() {
        span.record("action", action);
    }
}

pub(crate) fn record_operation(operation: &str) {
    Span::current().record("operation", operation);
}

pub(crate) fn record_principal(principal: &str) {
    Span::current().record("principal", principal);
}

pub(crate) fn record_execution_context(execution_context: &ExecutionContext) {
    Span::current().record("executionContext", execution_context.as_str());
}

pub(crate) fn record_execution_context_failure(failure: &str) {
    Span::current().record("executionContextFailure", failure);
}

pub(crate) fn record_decision(decision: &str) {
    Span::current().record("decision", decision);
}

pub(crate) fn record_reason_code(reason_code: &str) {
    Span::current().record("reasonCode", reason_code);
}

pub(crate) fn record_status(status: u16) {
    Span::current().record("http.statusCode", status);
}

pub(crate) fn record_duration_ms(duration_ms: u64) {
    Span::current().record("durationMs", duration_ms);
}

pub(crate) fn elapsed_ms(started: Instant) -> u64 {
    started.elapsed().as_millis().try_into().unwrap_or(u64::MAX)
}

#[cfg(test)]
pub(crate) fn tracing_capture_test_lock() -> &'static tokio::sync::Mutex<()> {
    static LOCK: std::sync::OnceLock<tokio::sync::Mutex<()>> = std::sync::OnceLock::new();
    LOCK.get_or_init(|| tokio::sync::Mutex::new(()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::Router;
    use axum::http::{Method, StatusCode};
    use axum::routing::post;
    use std::collections::BTreeMap;
    use std::sync::{Arc, Mutex};
    use tower::ServiceExt;
    use tracing::field::{Field, Visit};
    use tracing::{Event, Id, Subscriber};
    use tracing_subscriber::layer::Context;
    use tracing_subscriber::prelude::*;
    use tracing_subscriber::registry::LookupSpan;

    #[test]
    fn request_span_records_route_and_omits_sensitive_concrete_path() {
        let _capture_guard = tracing_capture_test_lock().blocking_lock();
        // With only one scoped dispatcher, tracing's callsite fast path asks
        // whichever thread first registers a callsite for its current subscriber.
        // Concurrent broker tests have no scoped subscriber and could cache
        // Interest::never for http.request after our cache rebuild. Retaining a
        // second dispatcher makes registration consider all live subscribers.
        let _registration_guard =
            tracing::Dispatch::new(tracing::subscriber::NoSubscriber::default());
        let captured = CapturedSpans::default();
        let subscriber = tracing_subscriber::registry().with(CaptureLayer {
            spans: captured.clone(),
        });
        let _guard = tracing::subscriber::set_default(subscriber);
        tracing_core::callsite::rebuild_interest_cache();

        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
            .block_on(async {
                let service = Router::new()
                    .route(
                        "/v1/invoke/{service}/{action}",
                        post(|| async {
                            record_execution_context(
                                &ExecutionContext::new("external").expect("valid test context"),
                            );
                            record_execution_context_failure("unknown");
                            StatusCode::NO_CONTENT
                        }),
                    )
                    .layer(RequestTracingLayer::new(ListenerKind::Public, "node-test"));
                let request = Request::builder()
                    .method(Method::POST)
                    .uri("/v1/invoke/sensitive-service/secret-action?token=secret")
                    .extension(ConnectInfo(
                        "127.0.0.1:41234".parse::<SocketAddr>().unwrap(),
                    ))
                    .body(Body::empty())
                    .unwrap();
                service.oneshot(request).await.unwrap();
            });

        let spans = captured.take();
        let span = spans
            .iter()
            .find(|span| span.get("name").is_some_and(|name| name == "http.request"))
            .expect("http.request span is captured");
        assert_eq!(span.get("listener").map(String::as_str), Some("public"));
        assert_eq!(span.get("nodeId").map(String::as_str), Some("node-test"));
        assert_eq!(span.get("http.method").map(String::as_str), Some("POST"));
        assert_eq!(
            span.get("http.route").map(String::as_str),
            Some("/v1/invoke/{service}/{action}")
        );
        assert!(span.get("http.path").is_none());
        assert_eq!(
            span.get("network.peer.ip").map(String::as_str),
            Some("127.0.0.1")
        );
        assert_eq!(
            span.get("network.peer.port").map(String::as_str),
            Some("41234")
        );
        assert_eq!(span.get("http.statusCode").map(String::as_str), Some("204"));
        assert_eq!(
            span.get("executionContext").map(String::as_str),
            Some("external")
        );
        assert_eq!(
            span.get("executionContextFailure").map(String::as_str),
            Some("unknown")
        );
        assert!(span.get("durationMs").is_some());
    }

    #[test]
    fn request_span_records_fixed_health_path_and_no_metrics_route_is_fixed() {
        assert_eq!(
            sanitized_path("/v1/healthz", Some("/v1/healthz")).as_deref(),
            Some("/v1/healthz")
        );
        assert_eq!(
            sanitized_path("/v1/readyz", Some("/v1/readyz")).as_deref(),
            Some("/v1/readyz")
        );
        assert!(sanitized_path("/metrics", None).is_none());
        assert!(sanitized_path("/v1/credentials/connections/fake", None).is_none());
    }

    #[derive(Clone, Default)]
    struct CapturedSpans {
        spans: Arc<Mutex<Vec<BTreeMap<String, String>>>>,
    }

    impl CapturedSpans {
        fn push(&self, span: BTreeMap<String, String>) {
            self.spans.lock().unwrap().push(span);
        }

        fn take(&self) -> Vec<BTreeMap<String, String>> {
            std::mem::take(&mut *self.spans.lock().unwrap())
        }
    }

    struct CaptureLayer {
        spans: CapturedSpans,
    }

    impl<S> tracing_subscriber::Layer<S> for CaptureLayer
    where
        S: Subscriber + for<'a> LookupSpan<'a>,
    {
        fn on_new_span(&self, attrs: &tracing::span::Attributes<'_>, id: &Id, ctx: Context<'_, S>) {
            let Some(span) = ctx.span(id) else {
                return;
            };
            let mut fields = BTreeMap::new();
            fields.insert("name".to_string(), attrs.metadata().name().to_string());
            attrs.record(&mut StringVisitor(&mut fields));
            span.extensions_mut().insert(fields);
        }

        fn on_record(&self, id: &Id, values: &tracing::span::Record<'_>, ctx: Context<'_, S>) {
            let Some(span) = ctx.span(id) else {
                return;
            };
            let mut extensions = span.extensions_mut();
            if let Some(fields) = extensions.get_mut::<BTreeMap<String, String>>() {
                values.record(&mut StringVisitor(fields));
            }
        }

        fn on_event(&self, _event: &Event<'_>, _ctx: Context<'_, S>) {}

        fn on_close(&self, id: Id, ctx: Context<'_, S>) {
            let Some(span) = ctx.span(&id) else {
                return;
            };
            let extensions = span.extensions();
            if let Some(fields) = extensions.get::<BTreeMap<String, String>>() {
                self.spans.push(fields.clone());
            }
        }
    }

    struct StringVisitor<'a>(&'a mut BTreeMap<String, String>);

    impl Visit for StringVisitor<'_> {
        fn record_str(&mut self, field: &Field, value: &str) {
            self.0.insert(field.name().to_string(), value.to_string());
        }

        fn record_debug(&mut self, field: &Field, value: &dyn std::fmt::Debug) {
            self.0
                .insert(field.name().to_string(), format!("{value:?}"));
        }

        fn record_i64(&mut self, field: &Field, value: i64) {
            self.0.insert(field.name().to_string(), value.to_string());
        }

        fn record_u64(&mut self, field: &Field, value: u64) {
            self.0.insert(field.name().to_string(), value.to_string());
        }

        fn record_bool(&mut self, field: &Field, value: bool) {
            self.0.insert(field.name().to_string(), value.to_string());
        }
    }
}
