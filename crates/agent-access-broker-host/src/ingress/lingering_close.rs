//! Lingering close for an admitted request answered while its body is still
//! unread: an invocation, typically an upload refused after its metadata
//! part, or a Git pack POST, typically a push refused after its command
//! prefix or one whose upstream request failed or answered before the whole
//! pack was forwarded.
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
//! The body can still be held when the response is ready, for example by an
//! upstream request that answered early or failed and has not yet let go of
//! the pack it was sending. After an unsuccessful response, the connection
//! then waits, within the same deadline, for the body to be handed over when
//! that holder drops it unfinished, and discards the rest in the time left. A
//! body that ends while held releases the wait at once. At the deadline, a
//! body still held is stopped: its holder's read fails, at once if the holder
//! is waiting for a frame the client may never send, so it reads and forwards
//! nothing more and drops the body, which is then dropped unread, and the
//! connection closes as before. A successful response leaves a held body
//! to its holder, as for an upstream that answers before it has read the whole
//! pack: the exchange is still in progress, and its response keeps the
//! permits, as the Git gateway's forwarded response does until it ends.
//!
//! The waiting and discarding task holds the admitted request's concurrency
//! permits, so a lingering connection still counts against the global and
//! per-principal limits until it is done, and never past the lingering
//! deadline. It runs among its server's connection tasks: graceful shutdown
//! waits for it and forced shutdown cancels it.
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
use futures_util::task::AtomicWaker;
use http_body_util::BodyExt;
use hyper::body::{Frame, SizeHint};
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::time::Duration;
use tokio::sync::oneshot;
use tokio::time::Instant;

/// The request-body allowance discarded after the response. Enough for the
/// remainder of a typical refused upload; larger remainders still close.
/// Discarding stops once the allowance is used up. A received frame is read
/// whole, so the frame that crosses the allowance is the last one read and the
/// total exceeds it by less than that frame.
pub(crate) const LINGER_MAX_BYTES: u64 = 8 * 1024 * 1024;
/// The longest the connection keeps waiting for and discarding the body after
/// the response.
pub(crate) const LINGER_TIMEOUT: Duration = Duration::from_secs(5);

/// The connection's handle on a request body its handler may leave unread.
pub(crate) struct UnreadBody {
    shared: Arc<Shared>,
    tasks: Option<ConnectionTasks>,
    expects_continue: bool,
}

/// What a tracked body and its handle share.
struct Shared {
    slot: Mutex<Slot>,
    /// Lingering for a held body ended: its next read fails.
    expired: AtomicBool,
    /// The task of a holder waiting for the body's next frame.
    reader: AtomicWaker,
}

impl Shared {
    /// Stops a body still held at the deadline: the holder's read fails, and a
    /// body handed over from now on is dropped unread. A holder waiting for a
    /// frame is woken to read the failure, so it gives the body up without
    /// waiting for a frame the client may never send.
    fn expire(&self) {
        self.expired.store(true, Ordering::Release);
        *self.slot.lock().unwrap() = Slot::Done;
        self.reader.wake();
    }
}

/// The error a held body's next read returns once lingering for its
/// unsuccessful response has ended.
#[derive(Debug)]
struct LingerExpired;

impl std::fmt::Display for LingerExpired {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("request body abandoned after an unsuccessful response")
    }
}

impl std::error::Error for LingerExpired {}

/// Where a tracked body stands, shared by the body and its handle.
enum Slot {
    /// Owned by the handler, or by whatever it passed the body to, such as an
    /// upstream request still sending it.
    Held,
    /// Dropped unfinished before the response was ready.
    Left(LeftBody),
    /// Held when the response was ready: dropping it unfinished hands it to
    /// the connection task waiting on the receiver.
    Awaited(oneshot::Sender<LeftBody>),
    /// Ended, failed or handed over: nothing is left for the handle.
    Done,
}

struct LeftBody {
    body: Body,
    polled: bool,
}

impl LeftBody {
    /// A client that asked to continue and whose body was never read has not
    /// sent it, so there is nothing to discard.
    fn sent(&self, expects_continue: bool) -> bool {
        self.polled || !expects_continue
    }
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
    let shared = Arc::new(Shared {
        slot: Mutex::new(Slot::Held),
        expired: AtomicBool::new(false),
        reader: AtomicWaker::new(),
    });
    let (parts, body) = request.into_parts();
    let body = Body::new(TrackedBody {
        body: Some(body),
        polled: false,
        shared: shared.clone(),
    });
    (
        Request::from_parts(parts, body),
        UnreadBody {
            shared,
            tasks,
            expects_continue,
        },
    )
}

impl UnreadBody {
    /// Returns `response` unchanged. If the handler left the body unfinished,
    /// the connection discards the rest, within the bounds above, while the
    /// response is sent, and `permits`, the admitted request's concurrency
    /// permits, are released only once that ends. If the body is still held
    /// and `response` is unsuccessful, the connection waits for it, within the
    /// same deadline, and the permits are released once the body ends, is
    /// discarded or is stopped at the deadline. Otherwise they are released
    /// now. A client that asked to continue and was answered before any body
    /// was read has not sent the body, so nothing is discarded for it.
    pub(crate) fn linger<P: Send + 'static>(self, response: Response, permits: P) -> Response {
        let unsuccessful = !(response.status().is_success() || response.status().is_redirection());
        let mut slot = self.shared.slot.lock().unwrap();
        let state = std::mem::replace(&mut *slot, Slot::Done);
        let Some(tasks) = self.tasks else {
            return response;
        };
        let deadline = || {
            linger_deadline(
                Instant::now(),
                RequestLifetime::current()
                    .deadline()
                    .map(|deadline| deadline.at),
            )
        };
        let expects_continue = self.expects_continue;
        match state {
            Slot::Left(left) if left.sent(expects_continue) => {
                drop(slot);
                let deadline = deadline();
                tasks.spawn(async move {
                    discard(left.body, deadline).await;
                    drop(permits);
                });
            }
            Slot::Held if unsuccessful => {
                let (sender, handed_over) = oneshot::channel();
                *slot = Slot::Awaited(sender);
                drop(slot);
                let deadline = deadline();
                let shared = self.shared.clone();
                tasks.spawn(async move {
                    // The holder drops the sender without a body when the
                    // body ends; one it still holds at the deadline is
                    // stopped before the permits are released.
                    match tokio::time::timeout_at(deadline, handed_over).await {
                        Ok(Ok(left)) if left.sent(expects_continue) => {
                            discard(left.body, deadline).await;
                        }
                        Ok(_) => {}
                        Err(_) => shared.expire(),
                    }
                    drop(permits);
                });
            }
            // A successful response leaves a held body to its holder: the
            // exchange is still in progress and its response keeps the
            // permits, as the Git gateway's forwarded response does.
            Slot::Held | Slot::Left(_) | Slot::Awaited(_) | Slot::Done => {}
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
/// before it ended or failed, and fails once lingering for it has expired.
struct TrackedBody {
    body: Option<Body>,
    polled: bool,
    shared: Arc<Shared>,
}

impl TrackedBody {
    /// Lingering for this held body expired: the body is dropped unread and
    /// its holder reads the failure.
    fn fail_expired(&mut self) -> Poll<Option<Result<Frame<Bytes>, axum::Error>>> {
        self.body = None;
        self.finish();
        Poll::Ready(Some(Err(axum::Error::new(LingerExpired))))
    }

    /// Nothing is left to read: a waiting connection task is released.
    fn finish(&self) {
        *self.shared.slot.lock().unwrap() = Slot::Done;
    }

    /// The body was dropped unfinished: it goes to the connection task waiting
    /// for it, or stays for the handle. A task that stopped waiting drops it.
    fn hand_over(&self, left: LeftBody) {
        let mut slot = self.shared.slot.lock().unwrap();
        match std::mem::replace(&mut *slot, Slot::Done) {
            Slot::Held => *slot = Slot::Left(left),
            Slot::Awaited(sender) => {
                drop(slot);
                let _ = sender.send(left);
            }
            Slot::Left(_) | Slot::Done => {}
        }
    }
}

impl HttpBody for TrackedBody {
    type Data = Bytes;
    type Error = axum::Error;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        let this = &mut *self;
        if this.body.is_some() && this.shared.expired.load(Ordering::Acquire) {
            return this.fail_expired();
        }
        let Some(body) = this.body.as_mut() else {
            return Poll::Ready(None);
        };
        this.polled = true;
        let frame = Pin::new(body).poll_frame(cx);
        match frame {
            Poll::Pending => {
                // Expiry wakes the task registered here; an expiry before the
                // registration is seen by the check that follows it.
                this.shared.reader.register(cx.waker());
                if this.shared.expired.load(Ordering::Acquire) {
                    return this.fail_expired();
                }
            }
            Poll::Ready(None | Some(Err(_))) => {
                this.body = None;
                this.finish();
            }
            Poll::Ready(Some(Ok(_))) => {}
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
        match self.body.take() {
            Some(body) if !body.is_end_stream() => self.hand_over(LeftBody {
                body,
                polled: self.polled,
            }),
            _ => self.finish(),
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

    /// A body whose frames the test sends through the returned sender,
    /// counting its reads, the end of the body included.
    fn channel_body() -> (
        Body,
        tokio::sync::mpsc::UnboundedSender<Bytes>,
        Arc<AtomicUsize>,
    ) {
        let (sender, receiver) = tokio::sync::mpsc::unbounded_channel::<Bytes>();
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
        (body, sender, read)
    }

    /// An unsuccessful response, such as an upstream's early refusal.
    fn refusal(body: &'static str) -> Response {
        let mut response = Response::new(Body::from(body));
        *response.status_mut() = axum::http::StatusCode::PAYLOAD_TOO_LARGE;
        response
    }

    /// Tracks a request whose body has sent its first frame and is still held,
    /// as by an upstream request that answered early.
    async fn held_body(
        tasks: &ConnectionTasks,
    ) -> (
        Body,
        UnreadBody,
        tokio::sync::mpsc::UnboundedSender<Bytes>,
        Arc<AtomicUsize>,
    ) {
        let (body, sender, read) = channel_body();
        sender.send(Bytes::from_static(b"prefix")).unwrap();
        let (request, unread) = track(builder(tasks).body(body).unwrap());
        let mut holder = request.into_body();
        holder.frame().await.unwrap().unwrap();
        (holder, unread, sender, read)
    }

    #[tokio::test]
    async fn a_body_held_at_the_response_is_discarded_once_handed_over() {
        let tracker = TaskTracker::new();
        let tasks = ConnectionTasks::tracked_by(tracker.clone());
        let (holder, unread, sender, read) = held_body(&tasks).await;
        let permits = permits();
        let response = unread.linger(refusal("early"), permits.clone());
        assert_eq!(
            axum::body::to_bytes(response.into_body(), 64)
                .await
                .unwrap(),
            "early"
        );
        // The holder still has the body: the connection waits for it.
        tokio::task::yield_now().await;
        assert!(held(&permits));
        assert_eq!(read.load(Ordering::SeqCst), 1);

        for _ in 0..100 {
            sender.send(Bytes::from_static(b"x")).unwrap();
        }
        drop(sender);
        // The holder lets go of it unfinished; the rest is discarded.
        drop(holder);
        settle(&tracker).await;
        // The first frame, every remaining frame and the end of the body.
        assert_eq!(read.load(Ordering::SeqCst), 102);
        assert!(!held(&permits));
    }

    #[tokio::test(start_paused = true)]
    async fn a_body_held_past_the_deadline_is_stopped_before_the_permits_are_released() {
        let tracker = TaskTracker::new();
        let tasks = ConnectionTasks::tracked_by(tracker.clone());
        let (mut holder, unread, sender, read) = held_body(&tasks).await;
        let permits = permits();
        let started = Instant::now();
        unread.linger(refusal(""), permits.clone());
        // The permits never outlive the lingering deadline.
        settle(&tracker).await;
        assert_between(started.elapsed(), LINGER_TIMEOUT);
        assert!(!held(&permits));

        // The holder's next read fails, though more of the body has arrived:
        // it reads nothing more and the body is dropped unread.
        for _ in 0..10 {
            sender.send(Bytes::from_static(b"x")).unwrap();
        }
        assert!(holder.frame().await.unwrap().is_err());
        assert!(holder.frame().await.is_none());
        drop(holder);
        assert_eq!(read.load(Ordering::SeqCst), 1);
    }

    #[tokio::test(start_paused = true)]
    async fn expiry_wakes_a_holder_waiting_for_a_frame_the_client_never_sends() {
        let tracker = TaskTracker::new();
        let tasks = ConnectionTasks::tracked_by(tracker.clone());
        let (mut holder, unread, sender, read) = held_body(&tasks).await;
        // The holder waits for the next frame; the client sends nothing more
        // but keeps its connection, and with it the body, open.
        let waiting = tokio::spawn(async move { holder.frame().await.map(|frame| frame.is_err()) });
        tokio::task::yield_now().await;
        assert!(!waiting.is_finished());
        let permits = permits();
        let started = Instant::now();
        unread.linger(refusal(""), permits.clone());
        settle(&tracker).await;
        assert_between(started.elapsed(), LINGER_TIMEOUT);
        assert!(!held(&permits));

        // Woken by the expiry, its read fails at once and nothing more is read.
        let failed = tokio::time::timeout(Duration::from_millis(1), waiting)
            .await
            .expect("expiry wakes the waiting holder")
            .unwrap();
        assert_eq!(failed, Some(true));
        assert_eq!(read.load(Ordering::SeqCst), 1);
        drop(sender);
    }

    #[tokio::test(start_paused = true)]
    async fn a_body_handed_over_after_the_deadline_is_dropped_unread() {
        let tracker = TaskTracker::new();
        let tasks = ConnectionTasks::tracked_by(tracker.clone());
        let (holder, unread, sender, read) = held_body(&tasks).await;
        let permits = permits();
        unread.linger(refusal(""), permits.clone());
        settle(&tracker).await;
        assert!(!held(&permits));

        // Handed over too late, the body is dropped without another read.
        for _ in 0..10 {
            sender.send(Bytes::from_static(b"x")).unwrap();
        }
        drop(holder);
        tokio::task::yield_now().await;
        assert_eq!(read.load(Ordering::SeqCst), 1);
    }

    #[tokio::test(start_paused = true)]
    async fn a_body_held_after_a_successful_response_stays_with_its_holder() {
        let tracker = TaskTracker::new();
        let tasks = ConnectionTasks::tracked_by(tracker.clone());
        for status in [axum::http::StatusCode::OK, axum::http::StatusCode::FOUND] {
            let (mut holder, unread, sender, read) = held_body(&tasks).await;
            let permits = permits();
            let mut response = Response::new(Body::empty());
            *response.status_mut() = status;
            // Nothing waits: the response keeps its own permits.
            unread.linger(response, permits.clone());
            assert!(!held(&permits), "{status}");

            // Past the lingering deadline the holder still reads the whole body.
            tokio::time::sleep(LINGER_TIMEOUT * 2).await;
            for _ in 0..10 {
                sender.send(Bytes::from_static(b"x")).unwrap();
            }
            drop(sender);
            for _ in 0..10 {
                holder.frame().await.unwrap().unwrap();
            }
            assert!(holder.frame().await.is_none());
            assert_eq!(read.load(Ordering::SeqCst), 12, "{status}");
            settle(&tracker).await;
        }
    }

    #[tokio::test(start_paused = true)]
    async fn a_held_body_that_ends_releases_the_permits_at_once() {
        let tracker = TaskTracker::new();
        let tasks = ConnectionTasks::tracked_by(tracker.clone());

        // The holder reads the rest of the body to its end.
        let (mut holder, unread, sender, read) = held_body(&tasks).await;
        let read_to_its_end = permits();
        let started = Instant::now();
        unread.linger(refusal(""), read_to_its_end.clone());
        tokio::task::yield_now().await;
        assert!(held(&read_to_its_end));
        sender.send(Bytes::from_static(b"rest")).unwrap();
        drop(sender);
        holder.frame().await.unwrap().unwrap();
        assert!(holder.frame().await.is_none());
        settle(&tracker).await;
        assert!(!held(&read_to_its_end));
        assert!(started.elapsed() < LINGER_TIMEOUT);
        // The first frame, the rest and the end: nothing more was read.
        assert_eq!(read.load(Ordering::SeqCst), 3);
        drop(holder);

        // The holder drops a body known to have ended after its last frame.
        let (request, unread) = track(builder(&tasks).body(Body::from("whole")).unwrap());
        let mut holder = request.into_body();
        holder.frame().await.unwrap().unwrap();
        let ended = permits();
        let started = Instant::now();
        unread.linger(refusal(""), ended.clone());
        tokio::task::yield_now().await;
        assert!(held(&ended));
        drop(holder);
        settle(&tracker).await;
        assert!(!held(&ended));
        assert!(started.elapsed() < LINGER_TIMEOUT);
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
