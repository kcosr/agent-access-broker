//! A listener's HTTP server: the router served over hyper connections, as
//! `axum::serve` serves it, except that the server owns its connection tasks.
//! A graceful shutdown stops accepting, cancels pending TLS handshakes, and
//! lets every established connection finish its in-flight requests; a forced
//! one cancels the connections still open, and
//! the server returns only once every connection task has ended, so none
//! keeps running detached with the broker state.
use crate::ingress::request_lifetime::ConnectionClosed;
use axum::Router;
use axum::extract::ConnectInfo;
use axum::serve::Listener;
use hyper_util::rt::TokioIo;
use hyper_util::service::TowerToHyperService;
use std::future::Future;
use std::net::SocketAddr;
use std::pin::{Pin, pin};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Semaphore;
use tokio_rustls::TlsAcceptor;
use tokio_util::sync::CancellationToken;
use tokio_util::task::TaskTracker;
use tower::Layer;
use tracing::Dispatch;
use tracing::instrument::WithSubscriber;

const TLS_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(5);
const MAX_TLS_HANDSHAKES: usize = 64;
const TLS_CAPACITY_WARNING_INTERVAL: Duration = Duration::from_secs(30);

/// Captures only the selected listener's current, already validated TLS
/// identity. The identity stays fixed for the accepted connection; replacing
/// the runtime snapshot affects later accepts without retaining that snapshot.
pub(crate) type TlsConfigProvider = Arc<dyn Fn() -> Arc<rustls::ServerConfig> + Send + Sync>;

/// Serves `app` on `listener` until `shutdown` completes, then closes the
/// listener and shuts each connection down gracefully. Cancelling `force`
/// cancels the connections still open. Returns once every connection task
/// has ended; dropping the future cancels them without waiting.
///
/// Connection tasks run under the dispatcher current when serving starts.
pub(crate) async fn serve_http(
    mut listener: TcpListener,
    app: Router,
    shutdown: impl Future<Output = ()>,
    force: CancellationToken,
    tls: Option<TlsConfigProvider>,
    listener_name: &'static str,
) {
    let connections = Connections {
        tracker: TaskTracker::new(),
        cancel: force.child_token(),
        dispatch: tracing::dispatcher::get_default(Dispatch::clone),
    };
    let _cancel_on_drop = connections.cancel.clone().drop_guard();
    let graceful = CancellationToken::new();
    let handshakes = Arc::new(Semaphore::new(MAX_TLS_HANDSHAKES));
    let mut next_capacity_warning = tokio::time::Instant::now();
    let mut shutdown = pin!(shutdown);
    loop {
        tokio::select! {
            biased;
            () = &mut shutdown => break,
            () = connections.cancel.cancelled() => break,
            (stream, remote) = Listener::accept(&mut listener) => {
                match &tls {
                    Some(tls) => {
                        // Admission happens before a task is spawned. Saturation
                        // drops this socket; it never creates waiting tasks.
                        let Ok(permit) = handshakes.clone().try_acquire_owned() else {
                            let now = tokio::time::Instant::now();
                            if now >= next_capacity_warning {
                                tracing::warn!(
                                    event = "tls_handshake_capacity_exhausted",
                                    listener = listener_name,
                                    maxHandshakes = MAX_TLS_HANDSHAKES,
                                    "TLS handshake capacity exhausted; rejecting new connections"
                                );
                                next_capacity_warning = now + TLS_CAPACITY_WARNING_INTERVAL;
                            }
                            continue;
                        };
                        let acceptor = TlsAcceptor::from(tls());
                        let deadline = tokio::time::Instant::now() + TLS_HANDSHAKE_TIMEOUT;
                        let connections_for_handshake = connections.clone();
                        let app = app.clone();
                        let graceful = graceful.clone();
                        connections.spawn(async move {
                            let handshake = tokio::select! {
                                biased;
                                () = graceful.cancelled() => return,
                                result = tokio::time::timeout_at(
                                    deadline,
                                    acceptor.accept(stream),
                                ) => result,
                            };
                            // The permit covers only handshake work, not the
                            // lifetime of a successfully established connection.
                            drop(permit);
                            let stream = match handshake {
                                Ok(Ok(stream)) => stream,
                                Ok(Err(_)) => {
                                    tracing::trace!(event = "tls_handshake_failed");
                                    return;
                                }
                                Err(_) => {
                                    tracing::trace!(event = "tls_handshake_timed_out");
                                    return;
                                }
                            };
                            let protocol = match stream.get_ref().1.alpn_protocol() {
                                Some(b"h2") => Protocol::Http2,
                                Some(b"http/1.1") | None => Protocol::Http1,
                                Some(_) => return,
                            };
                            if !graceful.is_cancelled() {
                                connections_for_handshake
                                    .serve_connection(stream, remote, app, graceful, protocol)
                                    .await;
                            }
                        });
                    }
                    None => connections.serve(stream, remote, &app, &graceful),
                }
            }
        }
    }
    drop(listener);
    graceful.cancel();
    connections.tracker.close();
    connections.tracker.wait().await;
}

#[derive(Clone, Copy)]
enum Protocol {
    Http1,
    Http2,
}

/// The tasks of one server's connections, including the tasks hyper spawns
/// for them, each cancelled by the server's cancellation.
#[derive(Clone)]
struct Connections {
    tracker: TaskTracker,
    cancel: CancellationToken,
    dispatch: Dispatch,
}

/// A request's handle on its server's connection tasks, for work that keeps
/// its connection busy after the response, such as discarding a refused
/// request's unread body. Graceful shutdown waits for such work and forced
/// shutdown cancels it, as for the connections themselves.
#[derive(Clone)]
pub(crate) struct ConnectionTasks(Connections);

impl ConnectionTasks {
    pub(crate) fn spawn(&self, task: impl Future<Output = ()> + Send + 'static) {
        self.0.spawn(task);
    }

    /// Tasks tracked by `tracker` alone, for requests served in process.
    #[cfg(test)]
    pub(crate) fn tracked_by(tracker: TaskTracker) -> Self {
        Self(Connections {
            tracker,
            cancel: CancellationToken::new(),
            dispatch: tracing::dispatcher::get_default(Dispatch::clone),
        })
    }
}

impl Connections {
    fn serve(
        &self,
        stream: TcpStream,
        remote: SocketAddr,
        app: &Router,
        graceful: &CancellationToken,
    ) {
        let connections = self.clone();
        let app = app.clone();
        let graceful = graceful.clone();
        self.spawn(async move {
            connections
                .serve_connection(stream, remote, app, graceful, Protocol::Http1)
                .await;
        });
    }

    async fn serve_connection<I>(
        &self,
        stream: I,
        remote: SocketAddr,
        app: Router,
        graceful: CancellationToken,
        protocol: Protocol,
    ) where
        I: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        let closed = ConnectionClosed::default();
        let service = TowerToHyperService::new(
            axum::Extension(closed.clone()).layer(
                axum::Extension(ConnectInfo(remote))
                    .layer(axum::Extension(ConnectionTasks(self.clone())).layer(app)),
            ),
        );
        // Hyper's observed connection termination reaches each pending
        // request. This does not poll sockets independently or change
        // HTTP/1 half-close handling.
        let _closed = closed.token().clone().drop_guard();
        // The auto builder's upgrade path sniffs HTTP versions even when
        // configured http1_only/http2_only. Use protocol-specific builders so
        // ALPN is authoritative and enabling TLS HTTP/2 does not enable h2c.
        match protocol {
            Protocol::Http1 => {
                let connection = hyper::server::conn::http1::Builder::new()
                    .serve_connection(TokioIo::new(stream), service)
                    .with_upgrades();
                drain_connection(connection, graceful, |connection| {
                    connection.graceful_shutdown();
                })
                .await;
            }
            Protocol::Http2 => {
                let connection = hyper::server::conn::http2::Builder::new(self.clone())
                    .serve_connection(TokioIo::new(stream), service);
                drain_connection(connection, graceful, |connection| {
                    connection.graceful_shutdown();
                })
                .await;
            }
        }
    }

    fn spawn(&self, task: impl Future<Output = ()> + Send + 'static) {
        let cancel = self.cancel.clone();
        self.tracker.spawn(
            async move {
                tokio::select! {
                    () = cancel.cancelled() => {}
                    () = task => {}
                }
            }
            .with_subscriber(self.dispatch.clone()),
        );
    }
}

async fn drain_connection<C>(
    connection: C,
    graceful: CancellationToken,
    shutdown: impl FnOnce(Pin<&mut C>),
) where
    C: Future<Output = Result<(), hyper::Error>>,
{
    let mut connection = pin!(connection);
    let result = tokio::select! {
        result = connection.as_mut() => result,
        () = graceful.cancelled() => {
            shutdown(connection.as_mut());
            connection.await
        }
    };
    if let Err(error) = result {
        tracing::trace!(error = %error, "failed to serve connection");
    }
}

impl<F> hyper::rt::Executor<F> for Connections
where
    F: Future + Send + 'static,
    F::Output: Send + 'static,
{
    fn execute(&self, future: F) {
        self.spawn(async move {
            future.await;
        });
    }
}

#[cfg(test)]
mod tests;
