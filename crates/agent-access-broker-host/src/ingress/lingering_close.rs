//! Lingering close for an admitted request answered while its body is still
//! unread: an invocation, typically an upload refused after its metadata
//! part, or a Git pack POST, typically a push refused after its command
//! prefix or one whose upstream request failed before the whole pack was
//! forwarded.
//!
//! When a handler drops an unfinished HTTP/1 request body, Hyper discards only
//! the bytes it has already buffered and then closes the connection. The
//! client is usually still sending, so the kernel answers with a reset, which
//! can fail the client's write or destroy the response before the client reads
//! it. Instead, the Broker keeps discarding the remaining body while the
//! response is delivered, up to [`LINGER_MAX_BYTES`] and for at most
//! [`LINGER_TIMEOUT`], and never past the request's own deadline or the
//! ingress body cap, which keep applying to the body read here. A body that
//! ends within those bounds leaves the connection reusable; otherwise Hyper
//! closes it as before. A body that already failed, for example past the
//! ingress cap or receive deadline, is not read again.
//!
//! The discarding task holds the admitted request's concurrency permits, so a
//! lingering connection still counts against the global and per-principal
//! limits until it is done. It runs among its server's connection tasks:
//! graceful shutdown waits for it and forced shutdown cancels it.
//!
//! The remainder is only read and dropped, never parsed or forwarded.
//! Refusals before admission, including authentication, rate and queue
//! limits, never reach this: their bodies stay unread.
use super::request_lifetime::RequestLifetime;
use crate::http_server::ConnectionTasks;
use axum::body::{Body, Bytes, HttpBody};
use axum::extract::Request;
use axum::http::{Version, header::EXPECT};
use axum::response::Response;
use http_body_util::BodyExt;
use hyper::body::{Frame, SizeHint};
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::time::Duration;
use tokio::time::Instant;

/// The request-body allowance discarded after the response. Enough for the
/// remainder of a typical refused upload; larger remainders still close.
/// Discarding stops once the allowance is used up. A received frame is read
/// whole, so the frame that crosses the allowance is the last one read and the
/// total exceeds it by less than that frame.
pub(crate) const LINGER_MAX_BYTES: u64 = 8 * 1024 * 1024;
/// The longest the connection keeps discarding after the response.
pub(crate) const LINGER_TIMEOUT: Duration = Duration::from_secs(5);

/// The connection's handle on a request body its handler may leave unread.
pub(crate) struct UnreadBody {
    left: Arc<Mutex<Option<LeftBody>>>,
    tasks: Option<ConnectionTasks>,
    expects_continue: bool,
}

struct LeftBody {
    body: Body,
    polled: bool,
}

/// Wraps `request`'s body so that a handler that drops it unfinished leaves it
/// to the returned handle. Only an HTTP/1 connection's server lingers: an
/// HTTP/2 stream refuses its remaining body with a stream reset of its own.
pub(crate) fn track(request: Request) -> (Request, UnreadBody) {
    let tasks = matches!(
        request.version(),
        Version::HTTP_09 | Version::HTTP_10 | Version::HTTP_11
    )
    .then(|| request.extensions().get::<ConnectionTasks>().cloned())
    .flatten();
    let expects_continue = request
        .headers()
        .get(EXPECT)
        .is_some_and(|value| value.as_bytes().eq_ignore_ascii_case(b"100-continue"));
    let left = Arc::new(Mutex::new(None));
    let (parts, body) = request.into_parts();
    let body = Body::new(TrackedBody {
        body: Some(body),
        polled: false,
        left: left.clone(),
    });
    (
        Request::from_parts(parts, body),
        UnreadBody {
            left,
            tasks,
            expects_continue,
        },
    )
}

impl UnreadBody {
    /// Returns `response` unchanged. If the handler left the body unfinished,
    /// the connection discards the rest, within the bounds above, while the
    /// response is sent, and `permits`, the admitted request's concurrency
    /// permits, are released only once that ends; otherwise they are released
    /// now. A client that asked to continue and was answered before any body
    /// was read has not sent the body, so nothing waits for it.
    pub(crate) fn linger<P: Send + 'static>(self, response: Response, permits: P) -> Response {
        let left = self.left.lock().unwrap().take();
        if let (Some(left), Some(tasks)) = (left, self.tasks)
            && (left.polled || !self.expects_continue)
        {
            let deadline = linger_deadline(
                Instant::now(),
                RequestLifetime::current()
                    .deadline()
                    .map(|deadline| deadline.at),
            );
            tasks.spawn(async move {
                discard(left.body, deadline).await;
                drop(permits);
            });
        }
        response
    }
}

/// The lingering period never outlives the request's own deadline.
fn linger_deadline(now: Instant, request_deadline: Option<Instant>) -> Instant {
    let linger = now + LINGER_TIMEOUT;
    request_deadline.map_or(linger, |deadline| deadline.min(linger))
}

/// Reads and drops `body` until it ends or fails, the [`LINGER_MAX_BYTES`]
/// allowance is used up, or `deadline` passes. No frame is polled once the
/// allowance is used up.
async fn discard(mut body: Body, deadline: Instant) {
    let mut allowance = LINGER_MAX_BYTES;
    let _ = tokio::time::timeout_at(deadline, async {
        while allowance > 0 {
            let Some(Ok(frame)) = body.frame().await else {
                break;
            };
            let read = frame.data_ref().map_or(0, |data| data.len() as u64);
            allowance = allowance.saturating_sub(read);
        }
    })
    .await;
}

/// A request body that hands itself back to its [`UnreadBody`] when dropped
/// before it ended or failed.
struct TrackedBody {
    body: Option<Body>,
    polled: bool,
    left: Arc<Mutex<Option<LeftBody>>>,
}

impl HttpBody for TrackedBody {
    type Data = Bytes;
    type Error = axum::Error;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        let this = &mut *self;
        let Some(body) = this.body.as_mut() else {
            return Poll::Ready(None);
        };
        this.polled = true;
        let frame = Pin::new(body).poll_frame(cx);
        if matches!(frame, Poll::Ready(None | Some(Err(_)))) {
            this.body = None;
        }
        frame
    }

    fn is_end_stream(&self) -> bool {
        self.body.as_ref().is_none_or(HttpBody::is_end_stream)
    }

    fn size_hint(&self) -> SizeHint {
        self.body
            .as_ref()
            .map_or_else(|| SizeHint::with_exact(0), HttpBody::size_hint)
    }
}

impl Drop for TrackedBody {
    fn drop(&mut self) {
        if let Some(body) = self.body.take()
            && !body.is_end_stream()
        {
            *self.left.lock().unwrap() = Some(LeftBody {
                body,
                polled: self.polled,
            });
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::Method;
    use futures_util::stream;
    use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
    use tokio_util::task::TaskTracker;

    /// An endless body of `frame`-byte frames counting the bytes it yields.
    fn endless_body(frame: usize) -> (Body, Arc<AtomicU64>) {
        let yielded = Arc::new(AtomicU64::new(0));
        let counter = yielded.clone();
        let body = Body::from_stream(stream::repeat_with(move || {
            counter.fetch_add(frame as u64, Ordering::SeqCst);
            Ok::<_, std::io::Error>(Bytes::from(vec![0_u8; frame]))
        }));
        (body, yielded)
    }

    /// A body of `frames` one-byte frames counting the polls it receives.
    fn counted_body(frames: usize) -> (Body, Arc<AtomicUsize>) {
        let polls = Arc::new(AtomicUsize::new(0));
        let counter = polls.clone();
        let mut left = frames;
        let body = Body::from_stream(stream::poll_fn(move |_| {
            counter.fetch_add(1, Ordering::SeqCst);
            Poll::Ready((left > 0).then(|| {
                left -= 1;
                Ok::<_, std::io::Error>(Bytes::from_static(b"x"))
            }))
        }));
        (body, polls)
    }

    fn builder(tasks: &ConnectionTasks) -> axum::http::request::Builder {
        Request::builder()
            .method(Method::POST)
            .uri("/v1/invoke/fake/echo")
            .extension(tasks.clone())
    }

    async fn settle(tracker: &TaskTracker) {
        tracker.close();
        tokio::time::timeout(LINGER_TIMEOUT * 2, tracker.wait())
            .await
            .expect("lingering is bounded");
        tracker.reopen();
    }

    /// Reads the first frame of `request`'s body and drops it unfinished, as a
    /// handler refusing an upload after its metadata part does.
    async fn refuse_after_first_frame(request: Request) {
        let mut body = request.into_body();
        body.frame().await.unwrap().unwrap();
    }

    /// Stands in for the admitted request's permits: held while it has clones.
    fn permits() -> Arc<()> {
        Arc::new(())
    }

    fn held(permits: &Arc<()>) -> bool {
        Arc::strong_count(permits) > 1
    }

    #[tokio::test]
    async fn an_unfinished_body_is_discarded_after_the_response_holding_the_permits() {
        let tracker = TaskTracker::new();
        let tasks = ConnectionTasks::tracked_by(tracker.clone());
        // The first frame, then whatever the client sends later.
        let (sender, receiver) = tokio::sync::mpsc::unbounded_channel::<Bytes>();
        sender.send(Bytes::from_static(b"metadata")).unwrap();
        let read = Arc::new(AtomicUsize::new(0));
        let counter = read.clone();
        let body = Body::from_stream(stream::unfold(receiver, move |mut receiver| {
            let counter = counter.clone();
            async move {
                let frame = receiver.recv().await;
                counter.fetch_add(1, Ordering::SeqCst);
                frame.map(|frame| (Ok::<_, std::io::Error>(frame), receiver))
            }
        }));
        let (request, unread) = track(builder(&tasks).body(body).unwrap());
        refuse_after_first_frame(request).await;
        let permits = permits();
        let response = unread.linger(Response::new(Body::from("refused")), permits.clone());
        assert_eq!(
            axum::body::to_bytes(response.into_body(), 64)
                .await
                .unwrap(),
            "refused"
        );
        // The rest has not arrived: the connection still waits for it.
        tokio::task::yield_now().await;
        assert!(held(&permits));
        for _ in 0..100 {
            sender.send(Bytes::from_static(b"x")).unwrap();
        }
        drop(sender);
        settle(&tracker).await;
        // The first frame, every remaining frame and the end of the body.
        assert_eq!(read.load(Ordering::SeqCst), 102);
        assert!(!held(&permits));
    }

    #[tokio::test]
    async fn finished_failed_unpolled_continue_and_http2_bodies_do_not_linger() {
        let tracker = TaskTracker::new();
        let tasks = ConnectionTasks::tracked_by(tracker.clone());
        let permits = permits();

        // A body read to its end leaves nothing behind.
        let (body, polls) = counted_body(2);
        let (request, unread) = track(builder(&tasks).body(body).unwrap());
        axum::body::to_bytes(request.into_body(), 64).await.unwrap();
        unread.linger(Response::new(Body::empty()), permits.clone());
        assert!(!held(&permits));
        settle(&tracker).await;
        assert_eq!(polls.load(Ordering::SeqCst), 3);

        // A failed body, such as one over the ingress cap or past its receive
        // deadline, is not read again.
        let polled = Arc::new(AtomicUsize::new(0));
        let counter = polled.clone();
        let failing = Body::from_stream(stream::poll_fn(move |_| {
            counter.fetch_add(1, Ordering::SeqCst);
            Poll::Ready(Some(Err::<Bytes, _>(std::io::Error::other("over the cap"))))
        }));
        let (request, unread) = track(builder(&tasks).body(failing).unwrap());
        assert!(request.into_body().frame().await.unwrap().is_err());
        unread.linger(Response::new(Body::empty()), permits.clone());
        assert!(!held(&permits));
        settle(&tracker).await;
        assert_eq!(polled.load(Ordering::SeqCst), 1);

        // A client that expects 100 Continue and was answered before any body
        // was read has not sent it.
        let (body, polls) = counted_body(2);
        let (request, unread) = track(
            builder(&tasks)
                .header(EXPECT, "100-Continue")
                .body(body)
                .unwrap(),
        );
        drop(request);
        unread.linger(Response::new(Body::empty()), permits.clone());
        assert!(!held(&permits));
        settle(&tracker).await;
        assert_eq!(polls.load(Ordering::SeqCst), 0);

        // Once its body was read, it is sending, and its remainder is discarded.
        let (body, polls) = counted_body(2);
        let (request, unread) = track(
            builder(&tasks)
                .header(EXPECT, "100-continue")
                .body(body)
                .unwrap(),
        );
        refuse_after_first_frame(request).await;
        unread.linger(Response::new(Body::empty()), permits.clone());
        settle(&tracker).await;
        assert_eq!(polls.load(Ordering::SeqCst), 3);
        assert!(!held(&permits));

        // HTTP/2 refuses a stream's remaining body itself.
        let (body, polls) = counted_body(2);
        let (request, unread) = track(builder(&tasks).version(Version::HTTP_2).body(body).unwrap());
        refuse_after_first_frame(request).await;
        unread.linger(Response::new(Body::empty()), permits.clone());
        assert!(!held(&permits));
        settle(&tracker).await;
        assert_eq!(polls.load(Ordering::SeqCst), 1);

        // Without a connection, as for a router driven in process, there is
        // nothing to keep open.
        let (body, polls) = counted_body(2);
        let (request, unread) = track(Request::builder().body(body).unwrap());
        refuse_after_first_frame(request).await;
        unread.linger(Response::new(Body::empty()), permits.clone());
        assert!(!held(&permits));
        tokio::task::yield_now().await;
        assert_eq!(polls.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn discarding_stops_once_the_allowance_is_used_up() {
        // Frames that divide the allowance: no frame is read past it.
        let (body, yielded) = endless_body(64 * 1024);
        tokio::time::timeout(
            LINGER_TIMEOUT,
            discard(body, Instant::now() + LINGER_TIMEOUT),
        )
        .await
        .expect("an endless body stops at the allowance, not the deadline");
        assert_eq!(yielded.load(Ordering::SeqCst), LINGER_MAX_BYTES);
    }

    #[tokio::test]
    async fn the_frame_crossing_the_allowance_is_the_last_one_read() {
        // Three-MiB frames: the third crosses 8 MiB, is read whole, and ends it.
        let frame = 3 * 1024 * 1024;
        let (body, yielded) = endless_body(frame);
        tokio::time::timeout(
            LINGER_TIMEOUT,
            discard(body, Instant::now() + LINGER_TIMEOUT),
        )
        .await
        .expect("an endless body stops at the allowance, not the deadline");
        let read = yielded.load(Ordering::SeqCst);
        assert_eq!(read, 3 * frame as u64);
        assert!(read > LINGER_MAX_BYTES && read < LINGER_MAX_BYTES + frame as u64);
    }

    #[tokio::test(start_paused = true)]
    async fn discarding_stops_at_the_linger_timeout_or_the_earlier_request_deadline() {
        let started = Instant::now();
        let stalled = || Body::from_stream(stream::pending::<Result<Bytes, std::io::Error>>());
        discard(stalled(), linger_deadline(started, None)).await;
        assert_between(started.elapsed(), LINGER_TIMEOUT);

        let started = Instant::now();
        let request_deadline = started + Duration::from_secs(1);
        assert_eq!(
            linger_deadline(started, Some(request_deadline)),
            request_deadline
        );
        assert_eq!(
            linger_deadline(started, Some(started + LINGER_TIMEOUT * 2)),
            started + LINGER_TIMEOUT
        );
        discard(stalled(), linger_deadline(started, Some(request_deadline))).await;
        assert_between(started.elapsed(), Duration::from_secs(1));
    }

    /// The paused clock advances to the timer's millisecond tick.
    fn assert_between(elapsed: Duration, expected: Duration) {
        assert!(
            elapsed >= expected && elapsed < expected + Duration::from_millis(2),
            "{elapsed:?}"
        );
    }
}
