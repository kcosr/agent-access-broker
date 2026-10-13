//! Scoped capture of `tracing` events for tests.
//!
//! # Design
//!
//! `tracing` caches, per callsite, whether any dispatcher is interested in it.
//! The cache is computed when a thread first reaches the callsite, from the
//! dispatchers registered at that moment; while only one is registered, it is
//! computed from that thread's default alone. A per-test dispatcher installed
//! with `set_default` or `WithSubscriber` therefore loses events whenever a
//! concurrently running test reaches a callsite first: the callsite is cached
//! as uninteresting for the whole process.
//!
//! Captures instead share one process-wide dispatcher, which a test installs
//! explicitly with [`install_trace_capture`] as the binary's global default.
//! Every callsite reached afterwards is evaluated against it, and installation
//! re-evaluates the callsites reached before. Nothing is installed implicitly.
//!
//! Each capture is scoped by a root span, not by thread or dispatcher.
//! [`TraceCaptureDispatcher::start`] creates the span with its own event sink,
//! and the dispatcher records an event into the sink of the innermost capture
//! span enclosing it. Events outside every capture are discarded. A capture
//! therefore follows its work across `.await` points, across the worker
//! threads of a multi-threaded runtime, and onto spawned tasks that carry the
//! span: [`InvocationScope`](crate::InvocationScope) carries the current span
//! for owned provider work, and `tracing::Instrument::in_current_span` does so
//! for any other future. Concurrent captures never see each other's events.
//! Work that leaves the span behind, such as an uninstrumented
//! `tokio::spawn`, a `spawn_blocking` closure or a plain thread, is not
//! captured.
use serde_json::Value;
use std::sync::{Arc, Mutex, OnceLock, PoisonError};
use tracing::field::{Field, Visit};
use tracing::instrument::Instrumented;
use tracing::{Dispatch, Event, Instrument, Span, Subscriber};
use tracing_subscriber::layer::{Context, SubscriberExt};
use tracing_subscriber::registry::{LookupSpan, Registry};

/// The process-wide dispatcher that records events into scoped captures.
pub struct TraceCaptureDispatcher {
    dispatch: Dispatch,
}

/// Installs the process-wide [`TraceCaptureDispatcher`] as this process's
/// global default `tracing` dispatcher on the first call, and returns it.
///
/// Call it in every test that captures events; later calls return the
/// installed dispatcher. A test binary that uses it must not install another
/// global subscriber. Events outside a capture are discarded, so installing it
/// does not change what uncaptured tests observe.
///
/// # Panics
///
/// If a different global default dispatcher is already installed, because
/// captures could then never observe an event.
pub fn install_trace_capture() -> &'static TraceCaptureDispatcher {
    static INSTALLED: OnceLock<TraceCaptureDispatcher> = OnceLock::new();
    INSTALLED.get_or_init(|| {
        // While two dispatchers are registered, a thread reaching a callsite
        // for the first time evaluates it against every registered dispatcher
        // under tracing's registry lock, instead of against its own default,
        // which is the no-op dispatcher until the global default is set.
        let _registration = Dispatch::new(tracing::subscriber::NoSubscriber::default());
        let dispatch = Dispatch::new(tracing_subscriber::registry().with(CaptureLayer));
        tracing::dispatcher::set_global_default(dispatch.clone()).expect(
            "trace capture needs to be the global tracing dispatcher of this test binary, \
             but another global dispatcher is already installed",
        );
        // Re-evaluate the callsites that were reached before installation.
        tracing::callsite::rebuild_interest_cache();
        TraceCaptureDispatcher { dispatch }
    })
}

impl TraceCaptureDispatcher {
    /// Starts a capture with an empty event sink. It records the events
    /// emitted inside [`TraceCapture::run`], [`TraceCapture::in_scope`], or
    /// any other work carrying [`TraceCapture::span`].
    pub fn start(&self) -> TraceCapture {
        let span = tracing::dispatcher::with_default(
            &self.dispatch,
            || tracing::info_span!(parent: None, "trace_capture"),
        );
        let id = span
            .id()
            .expect("the trace capture dispatcher enables every span");
        let sink = CaptureSink::default();
        self.dispatch
            .downcast_ref::<Registry>()
            .and_then(|registry| registry.span(&id))
            .expect("the capture span is in the trace capture registry")
            .extensions_mut()
            .insert(sink.clone());
        TraceCapture { span, sink }
    }
}

/// One test's capture of the `tracing` events emitted within its span.
pub struct TraceCapture {
    span: Span,
    sink: CaptureSink,
}

impl TraceCapture {
    /// The capture's root span. Work entered into it, or into a span created
    /// beneath it, is captured.
    pub fn span(&self) -> &Span {
        &self.span
    }

    /// Instruments `future` with the capture span, so its events are captured
    /// wherever it is polled.
    pub fn run<F: std::future::Future>(&self, future: F) -> Instrumented<F> {
        future.instrument(self.span.clone())
    }

    /// Runs `work` synchronously inside the capture span.
    pub fn in_scope<T>(&self, work: impl FnOnce() -> T) -> T {
        self.span.in_scope(work)
    }

    /// Takes the captured events in emission order, leaving the capture
    /// recording into an empty sink. Each event is a JSON object of its fields
    /// plus its `level`.
    pub fn take_events(&self) -> Vec<Value> {
        std::mem::take(&mut *self.sink.lock())
    }

    /// Takes every captured event, as [`Self::take_events`] does, and returns
    /// the `upstream_request_completed` trace events among them.
    pub fn take_upstream_requests(&self) -> Vec<Value> {
        self.take_events()
            .into_iter()
            .filter(|event| event["event"] == "upstream_request_completed")
            .collect()
    }
}

#[derive(Clone, Default)]
struct CaptureSink(Arc<Mutex<Vec<Value>>>);

impl CaptureSink {
    fn lock(&self) -> std::sync::MutexGuard<'_, Vec<Value>> {
        self.0.lock().unwrap_or_else(PoisonError::into_inner)
    }

    fn record(&self, event: &Event<'_>) {
        let mut fields = Fields(serde_json::Map::new());
        fields.0.insert(
            "level".to_string(),
            Value::from(event.metadata().level().as_str()),
        );
        event.record(&mut fields);
        self.lock().push(Value::Object(fields.0));
    }
}

/// Records each event into the sink of the innermost capture span enclosing
/// it.
struct CaptureLayer;

impl<S> tracing_subscriber::Layer<S> for CaptureLayer
where
    S: Subscriber + for<'lookup> LookupSpan<'lookup>,
{
    fn on_event(&self, event: &Event<'_>, context: Context<'_, S>) {
        let sink = context.event_scope(event).and_then(|scope| {
            scope
                .into_iter()
                .find_map(|span| span.extensions().get::<CaptureSink>().cloned())
        });
        if let Some(sink) = sink {
            sink.record(event);
        }
    }
}

struct Fields(serde_json::Map<String, Value>);

impl Visit for Fields {
    fn record_str(&mut self, field: &Field, value: &str) {
        self.0.insert(field.name().to_string(), Value::from(value));
    }

    fn record_bool(&mut self, field: &Field, value: bool) {
        self.0.insert(field.name().to_string(), Value::from(value));
    }

    fn record_i64(&mut self, field: &Field, value: i64) {
        self.0.insert(field.name().to_string(), Value::from(value));
    }

    fn record_u64(&mut self, field: &Field, value: u64) {
        self.0.insert(field.name().to_string(), Value::from(value));
    }

    fn record_f64(&mut self, field: &Field, value: f64) {
        self.0.insert(field.name().to_string(), Value::from(value));
    }

    fn record_debug(&mut self, field: &Field, value: &dyn std::fmt::Debug) {
        self.0
            .insert(field.name().to_string(), Value::from(format!("{value:?}")));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{CorrelationContext, InvocationScope, with_provider_context};

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn captures_follow_their_own_work_only() {
        let first = install_trace_capture().start();
        let second = install_trace_capture().start();
        let first_work = first.run(async {
            tracing::info!(event = "first", count = 1_u64, ok = true);
            // Owned work on another task keeps the capture through the
            // invocation scope.
            with_provider_context(
                CorrelationContext::for_tests(),
                "example".into(),
                "item.view".into(),
                async {
                    let scope = InvocationScope::current();
                    tokio::spawn(scope.run(async { tracing::warn!(event = "owned") }))
                        .await
                        .unwrap();
                },
            )
            .await;
            // A plain spawn leaves the span behind.
            tokio::spawn(async { tracing::info!(event = "detached") })
                .await
                .unwrap();
        });
        let second_work = second.run(async { tracing::info!(event = "second") });
        tokio::join!(first_work, second_work);
        tracing::info!(event = "outside");
        second.in_scope(|| tracing::error!(event = "second.sync"));

        let first_events = first.take_events();
        let names: Vec<_> = first_events.iter().map(|event| &event["event"]).collect();
        assert_eq!(names, ["first", "owned"], "{first_events:?}");
        assert_eq!(first_events[0]["level"], "INFO");
        assert_eq!(first_events[0]["count"], 1);
        assert_eq!(first_events[0]["ok"], true);
        assert_eq!(first_events[1]["level"], "WARN");
        assert!(first.take_events().is_empty());

        let second_events = second.take_events();
        let names: Vec<_> = second_events.iter().map(|event| &event["event"]).collect();
        assert_eq!(names, ["second", "second.sync"], "{second_events:?}");
    }

    #[test]
    fn installation_is_idempotent() {
        assert!(std::ptr::eq(
            install_trace_capture(),
            install_trace_capture()
        ));
    }
}
