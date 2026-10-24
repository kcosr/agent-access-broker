//! Transport ownership of a request that has not yet passed rate admission.
//!
//! A response body can outlive its handler, notably for HTTP MCP. Its owner
//! therefore moves from the handler future into that body. The signals here
//! only cancel pending admission; they never cancel an admitted operation.
use super::invocation_limits::{
    AdmissionCancellation, AdmissionCancellationReason, AdmissionDeadline,
};
use agent_access_core::InvocationDeadlineKind;
use axum::body::{Body, Bytes, HttpBody};
use axum::extract::Request;
use axum::middleware::Next;
use axum::response::Response;
use futures_util::future::BoxFuture;
use hyper::body::{Frame, SizeHint};
use std::future::Future;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use tokio::time::Instant;
use tokio_util::sync::CancellationToken;

tokio::task_local! {
    static REQUEST_LIFETIME: RequestLifetime;
}

/// The lifetime of a Hyper connection, without any runtime or permit owner.
#[derive(Clone, Default)]
pub(crate) struct ConnectionClosed(CancellationToken);

impl ConnectionClosed {
    pub(crate) fn token(&self) -> &CancellationToken {
        &self.0
    }
}

/// A cloneable admission context. Clones observe abandonment but do not keep
/// transport ownership alive; only `RequestOwner` does that.
#[derive(Clone)]
pub(crate) struct RequestLifetime {
    shared: Arc<RequestState>,
    explicit: Option<CancellationToken>,
    waiter_abandoned: Option<CancellationToken>,
    operation_deadline: Option<Instant>,
    initial_admission_deadline: Option<Instant>,
}

struct RequestState {
    abandoned: CancellationToken,
    body_deadline: Mutex<Option<Instant>>,
    initial_admission_complete: AtomicBool,
    initial_admission_changed: tokio::sync::Notify,
}

impl Default for RequestLifetime {
    fn default() -> Self {
        Self::new(CancellationToken::new())
    }
}

impl RequestLifetime {
    fn new(abandoned: CancellationToken) -> Self {
        Self {
            shared: Arc::new(RequestState {
                abandoned,
                body_deadline: Mutex::new(None),
                initial_admission_complete: AtomicBool::new(false),
                initial_admission_changed: tokio::sync::Notify::new(),
            }),
            explicit: None,
            waiter_abandoned: None,
            operation_deadline: None,
            initial_admission_deadline: None,
        }
    }

    /// Capture before spawning work: Tokio task-local state is not inherited.
    pub(crate) fn current() -> Self {
        REQUEST_LIFETIME.try_with(Clone::clone).unwrap_or_default()
    }

    pub(crate) async fn scope<F: Future>(&self, future: F) -> F::Output {
        REQUEST_LIFETIME.scope(self.clone(), future).await
    }

    pub(crate) fn with_operation(&self, deadline: Instant, explicit: CancellationToken) -> Self {
        let mut scoped = self.clone();
        scoped.operation_deadline = Some(
            scoped
                .operation_deadline
                .map_or(deadline, |existing| existing.min(deadline)),
        );
        scoped.explicit = Some(explicit);
        scoped
    }

    pub(crate) fn with_initial_admission_deadline(&self, deadline: Instant) -> Self {
        let mut scoped = self.clone();
        scoped.initial_admission_deadline = Some(deadline);
        scoped
    }

    /// An SDK waiter can disappear before its transport body is dropped.
    /// This signal is local to that pending-admission handoff.
    pub(crate) fn with_abandonment(&self, abandoned: CancellationToken) -> Self {
        let mut scoped = self.clone();
        scoped.waiter_abandoned = Some(abandoned);
        scoped
    }

    pub(crate) fn initial_admission_deadline(&self) -> Option<Instant> {
        self.initial_admission_deadline.map(|initial| {
            self.deadline()
                .map_or(initial, |request| initial.min(request.at))
        })
    }

    /// The protocol timeout ends before deliberate rate waiting starts.
    pub(crate) fn complete_initial_admission(&self) {
        self.shared
            .initial_admission_complete
            .store(true, Ordering::Release);
        self.shared.initial_admission_changed.notify_waiters();
    }

    pub(crate) fn initial_admission_is_complete(&self) -> bool {
        self.shared
            .initial_admission_complete
            .load(Ordering::Acquire)
    }

    pub(crate) async fn initial_admission_complete(&self) {
        loop {
            let changed = self.shared.initial_admission_changed.notified();
            tokio::pin!(changed);
            changed.as_mut().enable();
            if self.initial_admission_is_complete() {
                return;
            }
            changed.await;
        }
    }

    /// The original ingress body deadline is not restarted by a rate wait.
    pub(crate) fn set_body_deadline(&self, deadline: Instant) {
        let mut existing = self.shared.body_deadline.lock().unwrap();
        *existing = Some(existing.map_or(deadline, |old| old.min(deadline)));
    }

    pub(crate) fn deadline(&self) -> Option<AdmissionDeadline> {
        let body = self
            .shared
            .body_deadline
            .lock()
            .unwrap()
            .map(|at| AdmissionDeadline {
                at,
                kind: InvocationDeadlineKind::Body,
            });
        let operation = self.operation_deadline.map(|at| AdmissionDeadline {
            at,
            kind: InvocationDeadlineKind::Operation,
        });
        match (body, operation) {
            (Some(body), Some(operation)) if body.at <= operation.at => Some(body),
            (_, Some(operation)) => Some(operation),
            (body, None) => body,
        }
    }

    pub(crate) fn cancellation(&self) -> Arc<dyn AdmissionCancellation> {
        Arc::new(self.clone())
    }
}

impl AdmissionCancellation for RequestLifetime {
    fn reason(&self) -> Option<AdmissionCancellationReason> {
        if self
            .explicit
            .as_ref()
            .is_some_and(CancellationToken::is_cancelled)
        {
            Some(AdmissionCancellationReason::ExplicitCancellation)
        } else if self.shared.abandoned.is_cancelled()
            || self
                .waiter_abandoned
                .as_ref()
                .is_some_and(CancellationToken::is_cancelled)
        {
            Some(AdmissionCancellationReason::OwnerAbandoned)
        } else {
            None
        }
    }

    fn cancelled(&self) -> BoxFuture<'_, AdmissionCancellationReason> {
        Box::pin(async move {
            tokio::select! {
                biased;
                () = async {
                    match &self.explicit {
                        Some(explicit) => explicit.cancelled().await,
                        None => std::future::pending().await,
                    }
                } => AdmissionCancellationReason::ExplicitCancellation,
                () = self.shared.abandoned.cancelled() => AdmissionCancellationReason::OwnerAbandoned,
                () = async {
                    match &self.waiter_abandoned {
                        Some(abandoned) => abandoned.cancelled().await,
                        None => std::future::pending().await,
                    }
                } => AdmissionCancellationReason::OwnerAbandoned,
            }
        })
    }
}

struct RequestOwner(CancellationToken);

impl Drop for RequestOwner {
    fn drop(&mut self) {
        self.0.cancel();
    }
}

/// Applies to each HTTP request, not to the connection or the MCP session.
/// Its guard follows a streaming response, so opening SSE is not abandonment.
pub(crate) async fn scope_request_lifetime(mut request: Request, next: Next) -> Response {
    let abandoned = request
        .extensions()
        .get::<ConnectionClosed>()
        .map_or_else(CancellationToken::new, |connection| {
            connection.0.child_token()
        });
    let lifetime = RequestLifetime::new(abandoned.clone());
    let owner = RequestOwner(abandoned);
    request.extensions_mut().insert(lifetime.clone());
    let response = lifetime.scope(next.run(request)).await;
    let (parts, body) = response.into_parts();
    Response::from_parts(
        parts,
        Body::new(OwnedResponseBody {
            body,
            owner: Some(owner),
        }),
    )
}

struct OwnedResponseBody {
    body: Body,
    owner: Option<RequestOwner>,
}

impl HttpBody for OwnedResponseBody {
    type Data = Bytes;
    type Error = axum::Error;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        let frame = Pin::new(&mut self.body).poll_frame(cx);
        if matches!(frame, Poll::Ready(None | Some(Err(_)))) {
            self.owner.take();
        }
        frame
    }

    fn is_end_stream(&self) -> bool {
        self.body.is_end_stream()
    }

    fn size_hint(&self) -> SizeHint {
        self.body.size_hint()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{Extension, Router, middleware, routing::get};
    use http_body_util::BodyExt;
    use std::time::Duration;
    use tokio::sync::mpsc;
    use tower::ServiceExt;

    type Captures = mpsc::UnboundedSender<RequestLifetime>;

    async fn waiting(Extension(captures): Extension<Captures>) -> Response {
        captures.send(RequestLifetime::current()).unwrap();
        std::future::pending().await
    }

    async fn streaming(Extension(captures): Extension<Captures>) -> Response {
        captures.send(RequestLifetime::current()).unwrap();
        Response::new(Body::from_stream(futures_util::stream::pending::<
            Result<Bytes, std::io::Error>,
        >()))
    }

    fn router(captures: Captures) -> Router {
        Router::new()
            .route("/wait", get(waiting))
            .route("/stream", get(streaming))
            .layer(Extension(captures))
            .layer(middleware::from_fn(scope_request_lifetime))
    }

    fn request(path: &str, connection: Option<&ConnectionClosed>) -> Request {
        let mut request = Request::builder().uri(path).body(Body::empty()).unwrap();
        if let Some(connection) = connection {
            request.extensions_mut().insert(connection.clone());
        }
        request
    }

    #[tokio::test]
    async fn dropping_handler_future_cancels_pending_admission() {
        let (send, mut receive) = mpsc::unbounded_channel();
        let task = tokio::spawn(router(send).oneshot(request("/wait", None)));
        let lifetime = receive.recv().await.unwrap();
        assert_eq!(lifetime.reason(), None);
        task.abort();
        let _ = task.await;
        assert_eq!(
            tokio::time::timeout(Duration::from_secs(1), lifetime.cancelled())
                .await
                .unwrap(),
            AdmissionCancellationReason::OwnerAbandoned,
        );
    }

    #[tokio::test]
    async fn opening_stream_transfers_owner_and_body_drop_cancels_only_that_request() {
        let (send, mut receive) = mpsc::unbounded_channel();
        let app = router(send);
        let connection = ConnectionClosed::default();
        let first = app
            .clone()
            .oneshot(request("/stream", Some(&connection)))
            .await
            .unwrap();
        let first_lifetime = receive.recv().await.unwrap();
        let second = app
            .oneshot(request("/stream", Some(&connection)))
            .await
            .unwrap();
        let second_lifetime = receive.recv().await.unwrap();
        // Both handlers finished normally; neither opened response is abandoned.
        assert_eq!(first_lifetime.reason(), None);
        assert_eq!(second_lifetime.reason(), None);
        drop(first);
        assert_eq!(
            first_lifetime.reason(),
            Some(AdmissionCancellationReason::OwnerAbandoned)
        );
        assert_eq!(second_lifetime.reason(), None);
        assert!(!connection.token().is_cancelled());
        connection.token().cancel();
        assert_eq!(
            second_lifetime.reason(),
            Some(AdmissionCancellationReason::OwnerAbandoned)
        );
        drop(second);
    }

    #[tokio::test]
    async fn completed_or_failed_body_releases_owner_and_preserves_payload() {
        let lifetime = RequestLifetime::default();
        let mut body = OwnedResponseBody {
            body: Body::from("hello"),
            owner: Some(RequestOwner(lifetime.shared.abandoned.clone())),
        };
        assert_eq!(body.size_hint().exact(), Some(5));
        assert_eq!(
            body.frame().await.unwrap().unwrap().into_data().unwrap(),
            "hello"
        );
        assert_eq!(lifetime.reason(), None);
        assert!(body.frame().await.is_none());
        assert_eq!(
            lifetime.reason(),
            Some(AdmissionCancellationReason::OwnerAbandoned)
        );

        let failed = RequestLifetime::default();
        let mut body = OwnedResponseBody {
            body: Body::from_stream(futures_util::stream::once(async {
                Err::<Bytes, _>(std::io::Error::other("response interrupted"))
            })),
            owner: Some(RequestOwner(failed.shared.abandoned.clone())),
        };
        assert!(body.frame().await.unwrap().is_err());
        assert_eq!(
            failed.reason(),
            Some(AdmissionCancellationReason::OwnerAbandoned)
        );
    }

    #[tokio::test]
    async fn explicit_and_waiter_cancellation_preserve_distinct_causes() {
        let base = RequestLifetime::default();
        let explicit = CancellationToken::new();
        let waiter = CancellationToken::new();
        let lifetime = base
            .with_operation(Instant::now() + Duration::from_secs(60), explicit.clone())
            .with_abandonment(waiter.clone());
        waiter.cancel();
        assert_eq!(
            lifetime.cancelled().await,
            AdmissionCancellationReason::OwnerAbandoned
        );
        assert_eq!(base.reason(), None);
        explicit.cancel();
        assert_eq!(
            lifetime.reason(),
            Some(AdmissionCancellationReason::ExplicitCancellation)
        );
        assert_eq!(
            lifetime.cancelled().await,
            AdmissionCancellationReason::ExplicitCancellation
        );
        assert_eq!(base.reason(), None);
    }

    #[tokio::test]
    async fn captured_context_preserves_original_deadlines_across_task_handoff() {
        let base = RequestLifetime::default();
        let now = Instant::now();
        let body_deadline = now + Duration::from_secs(12);
        base.set_body_deadline(body_deadline);
        // A later intake wrapper must never extend the original bound.
        base.set_body_deadline(now + Duration::from_secs(30));
        let lifetime = base
            .with_operation(now + Duration::from_secs(20), CancellationToken::new())
            .with_initial_admission_deadline(now + Duration::from_secs(5));
        tokio::spawn(async move {
            lifetime
                .scope(async {
                    let current = RequestLifetime::current();
                    let deadline = current.deadline().unwrap();
                    assert_eq!(deadline.at, body_deadline);
                    assert_eq!(deadline.kind, InvocationDeadlineKind::Body);
                    assert_eq!(
                        current.initial_admission_deadline(),
                        Some(now + Duration::from_secs(5))
                    );
                })
                .await;
        })
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn initial_phase_completion_crosses_task_handoff_without_lost_wakeup() {
        let lifetime = RequestLifetime::default();
        let owner = lifetime.clone();
        let waiting = tokio::spawn(async move { owner.initial_admission_complete().await });
        lifetime.complete_initial_admission();
        tokio::time::timeout(Duration::from_secs(1), waiting)
            .await
            .unwrap()
            .unwrap();
        assert!(lifetime.initial_admission_is_complete());
        // A waiter arriving after the notification observes the durable marker.
        tokio::time::timeout(
            Duration::from_secs(1),
            lifetime.initial_admission_complete(),
        )
        .await
        .unwrap();
    }
}
