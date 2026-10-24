//! A listener's HTTP server: the router served over hyper connections, as
//! `axum::serve` serves it, except that the server owns its connection tasks.
//! A graceful shutdown stops accepting and lets every connection finish its
//! in-flight requests; a forced one cancels the connections still open, and
//! the server returns only once every connection task has ended, so none
//! keeps running detached with the broker state.
use crate::ingress::request_lifetime::ConnectionClosed;
use axum::Router;
use axum::extract::ConnectInfo;
use axum::serve::Listener;
use hyper_util::rt::TokioIo;
use hyper_util::server::conn::auto::Builder;
use hyper_util::service::TowerToHyperService;
use std::future::Future;
use std::net::SocketAddr;
use std::pin::pin;
use tokio::net::{TcpListener, TcpStream};
use tokio_util::sync::CancellationToken;
use tokio_util::task::TaskTracker;
use tower::Layer;
use tracing::Dispatch;
use tracing::instrument::WithSubscriber;

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
) {
    let connections = Connections {
        tracker: TaskTracker::new(),
        cancel: force.child_token(),
        dispatch: tracing::dispatcher::get_default(Dispatch::clone),
    };
    let _cancel_on_drop = connections.cancel.clone().drop_guard();
    let graceful = CancellationToken::new();
    let mut shutdown = pin!(shutdown);
    loop {
        tokio::select! {
            (stream, remote) = Listener::accept(&mut listener) => {
                connections.serve(stream, remote, &app, &graceful);
            }
            () = &mut shutdown => break,
            () = connections.cancel.cancelled() => break,
        }
    }
    drop(listener);
    graceful.cancel();
    connections.tracker.close();
    connections.tracker.wait().await;
}

/// The tasks of one server's connections, including the tasks hyper spawns
/// for them, each cancelled by the server's cancellation.
#[derive(Clone)]
struct Connections {
    tracker: TaskTracker,
    cancel: CancellationToken,
    dispatch: Dispatch,
}

impl Connections {
    fn serve(
        &self,
        stream: TcpStream,
        remote: SocketAddr,
        app: &Router,
        graceful: &CancellationToken,
    ) {
        let closed = ConnectionClosed::default();
        let service = TowerToHyperService::new(
            axum::Extension(closed.clone())
                .layer(axum::Extension(ConnectInfo(remote)).layer(app.clone())),
        );
        let builder = Builder::new(self.clone());
        let graceful = graceful.clone();
        self.spawn(async move {
            // Hyper's observed connection termination reaches each pending
            // request. This does not poll sockets independently or change
            // HTTP/1 half-close handling.
            let _closed = closed.token().clone().drop_guard();
            let mut connection =
                pin!(builder.serve_connection_with_upgrades(TokioIo::new(stream), service));
            let mut draining = false;
            loop {
                tokio::select! {
                    result = connection.as_mut() => {
                        if let Err(error) = result {
                            tracing::trace!(error = %error, "failed to serve connection");
                        }
                        break;
                    }
                    () = graceful.cancelled(), if !draining => {
                        draining = true;
                        connection.as_mut().graceful_shutdown();
                    }
                }
            }
        });
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
mod tests {
    use super::*;
    use crate::ingress::invocation_limits::{AdmissionCancellation, AdmissionCancellationReason};
    use crate::ingress::request_lifetime::{RequestLifetime, scope_request_lifetime};
    use axum::{Extension, body::Body, middleware, response::Response, routing::get};
    use std::time::Duration;
    use tokio::io::AsyncWriteExt;
    use tokio::sync::{mpsc, oneshot};

    #[tokio::test]
    async fn detected_http1_connection_close_cancels_pending_request() {
        let (capture, mut captured) = mpsc::unbounded_channel::<RequestLifetime>();
        let app = Router::new()
            .route("/pending", get(|Extension(capture): Extension<mpsc::UnboundedSender<RequestLifetime>>| async move {
                capture.send(RequestLifetime::current()).unwrap();
                std::future::pending::<Response<Body>>().await
            }))
            .layer(Extension(capture))
            .layer(middleware::from_fn(scope_request_lifetime));
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let (stop, stopping) = oneshot::channel();
        let server = tokio::spawn(serve_http(
            listener,
            app,
            async {
                let _ = stopping.await;
            },
            CancellationToken::new(),
        ));
        let mut client = TcpStream::connect(address).await.unwrap();
        client
            .write_all(b"GET /pending HTTP/1.1\r\nHost: localhost\r\n\r\n")
            .await
            .unwrap();
        let lifetime = tokio::time::timeout(Duration::from_secs(2), captured.recv())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(lifetime.reason(), None);
        drop(client);
        assert_eq!(
            tokio::time::timeout(Duration::from_secs(2), lifetime.cancelled())
                .await
                .unwrap(),
            AdmissionCancellationReason::OwnerAbandoned,
        );
        let _ = stop.send(());
        tokio::time::timeout(Duration::from_secs(2), server)
            .await
            .unwrap()
            .unwrap();
    }

    // HTTP/2 is enabled by the existing test dependency feature union. This
    // fixture adds no production protocol feature or connection policy.
    #[tokio::test]
    async fn http2_stream_reset_cancels_only_its_pending_request() {
        use axum::extract::Path;
        use http_body_util::Empty;
        use hyper_util::rt::TokioExecutor;

        let (capture, mut captured) = mpsc::unbounded_channel::<(String, RequestLifetime)>();
        let app = Router::new()
            .route(
                "/pending/{name}",
                get(
                    |Path(name): Path<String>,
                     Extension(capture): Extension<
                        mpsc::UnboundedSender<(String, RequestLifetime)>,
                    >| async move {
                        capture.send((name, RequestLifetime::current())).unwrap();
                        std::future::pending::<Response<Body>>().await
                    },
                ),
            )
            .route("/ready", get(|| async { "ready" }))
            .layer(Extension(capture))
            .layer(middleware::from_fn(scope_request_lifetime));
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let (stop, stopping) = oneshot::channel();
        let server = tokio::spawn(serve_http(
            listener,
            app,
            async {
                let _ = stopping.await;
            },
            CancellationToken::new(),
        ));
        let stream = TcpStream::connect(address).await.unwrap();
        let (mut sender, connection) = hyper::client::conn::http2::handshake::<
            _,
            _,
            Empty<bytes::Bytes>,
        >(TokioExecutor::new(), TokioIo::new(stream))
        .await
        .unwrap();
        let driver = tokio::spawn(connection);
        let request = |path: &str| {
            axum::http::Request::builder()
                .uri(format!("http://{address}/{path}"))
                .body(Empty::<bytes::Bytes>::new())
                .unwrap()
        };
        let mut first_sender = sender.clone();
        let first_request = request("pending/first");
        let first = tokio::spawn(async move { first_sender.send_request(first_request).await });
        let mut second_sender = sender.clone();
        let second_request = request("pending/second");
        let second = tokio::spawn(async move { second_sender.send_request(second_request).await });
        let mut lifetimes = std::collections::HashMap::new();
        for _ in 0..2 {
            let (name, lifetime) = tokio::time::timeout(Duration::from_secs(2), captured.recv())
                .await
                .unwrap()
                .unwrap();
            lifetimes.insert(name, lifetime);
        }
        first.abort();
        let _ = first.await;
        assert_eq!(
            tokio::time::timeout(Duration::from_secs(2), lifetimes["first"].cancelled())
                .await
                .unwrap(),
            AdmissionCancellationReason::OwnerAbandoned,
        );
        assert_eq!(lifetimes["second"].reason(), None);
        let response = tokio::time::timeout(
            Duration::from_secs(2),
            sender.send_request(request("ready")),
        )
        .await
        .unwrap()
        .unwrap();
        assert_eq!(response.status(), axum::http::StatusCode::OK);
        assert_eq!(lifetimes["second"].reason(), None);
        second.abort();
        let _ = second.await;
        drop(response);
        drop(sender);
        driver.abort();
        let _ = driver.await;
        let _ = stop.send(());
        tokio::time::timeout(Duration::from_secs(2), server)
            .await
            .unwrap()
            .unwrap();
    }
}
