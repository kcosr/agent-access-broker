//! A listener's HTTP server: the router served over hyper connections, as
//! `axum::serve` serves it, except that the server owns its connection tasks.
//! A graceful shutdown stops accepting and lets every connection finish its
//! in-flight requests; a forced one cancels the connections still open, and
//! the server returns only once every connection task has ended, so none
//! keeps running detached with the broker state.
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
        let service =
            TowerToHyperService::new(axum::Extension(ConnectInfo(remote)).layer(app.clone()));
        let builder = Builder::new(self.clone());
        let graceful = graceful.clone();
        self.spawn(async move {
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
