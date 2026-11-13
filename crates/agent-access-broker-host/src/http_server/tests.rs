use super::*;
use crate::ingress::invocation_limits::{AdmissionCancellation, AdmissionCancellationReason};
use crate::ingress::request_lifetime::{RequestLifetime, scope_request_lifetime};
use axum::{Extension, body::Body, middleware, response::Response, routing::get};
use http_body_util::{BodyExt, Empty};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName, pem::PemObject};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::{mpsc, oneshot};
use tokio_rustls::TlsConnector;

const TEST_TIMEOUT: Duration = Duration::from_secs(3);
const HTTP2_PREFACE: &[u8] = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";

fn server_config() -> Arc<rustls::ServerConfig> {
    let chain =
        CertificateDer::pem_slice_iter(include_bytes!("../listener_tls/fixtures/server-chain.pem"))
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
    let key = PrivateKeyDer::from_pem_slice(include_bytes!(
        "../listener_tls/fixtures/server-key-pkcs8.pem"
    ))
    .unwrap();
    let mut config = rustls::ServerConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_protocol_versions(&[&rustls::version::TLS13, &rustls::version::TLS12])
    .unwrap()
    .with_no_client_auth()
    .with_single_cert(chain, key)
    .unwrap();
    config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    Arc::new(config)
}

fn client_config(alpn: &[&[u8]]) -> Arc<rustls::ClientConfig> {
    let mut roots = rustls::RootCertStore::empty();
    roots
        .add(
            CertificateDer::from_pem_slice(include_bytes!("../listener_tls/fixtures/ca.pem"))
                .unwrap(),
        )
        .unwrap();
    let mut config = rustls::ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_protocol_versions(&[&rustls::version::TLS13, &rustls::version::TLS12])
    .unwrap()
    .with_root_certificates(roots)
    .with_no_client_auth();
    config.alpn_protocols = alpn.iter().map(|protocol| protocol.to_vec()).collect();
    Arc::new(config)
}

fn tls_provider() -> TlsConfigProvider {
    let config = server_config();
    Arc::new(move || config.clone())
}

async fn connect_tls(
    address: SocketAddr,
    alpn: &[&[u8]],
) -> tokio_rustls::client::TlsStream<TcpStream> {
    let socket = TcpStream::connect(address).await.unwrap();
    tokio::time::timeout(
        TEST_TIMEOUT,
        TlsConnector::from(client_config(alpn))
            .connect(ServerName::try_from("localhost").unwrap(), socket),
    )
    .await
    .unwrap()
    .unwrap()
}

struct TestServer {
    address: SocketAddr,
    stop: Option<oneshot::Sender<()>>,
    force: CancellationToken,
    task: Option<tokio::task::JoinHandle<()>>,
}

impl TestServer {
    async fn start(app: Router, tls: Option<TlsConfigProvider>) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let (stop, stopping) = oneshot::channel();
        let force = CancellationToken::new();
        let task = tokio::spawn(serve_http(
            listener,
            app,
            async {
                let _ = stopping.await;
            },
            force.clone(),
            tls,
            "public",
        ));
        Self {
            address,
            stop: Some(stop),
            force,
            task: Some(task),
        }
    }

    fn begin_shutdown(&mut self) {
        if let Some(stop) = self.stop.take() {
            let _ = stop.send(());
        }
    }

    async fn finish(mut self) {
        self.begin_shutdown();
        tokio::time::timeout(TEST_TIMEOUT, self.task.as_mut().unwrap())
            .await
            .unwrap()
            .unwrap();
        self.task.take();
    }
}

impl Drop for TestServer {
    fn drop(&mut self) {
        self.force.cancel();
        if let Some(task) = &self.task {
            task.abort();
        }
    }
}

async fn http1_get<I>(stream: I, path: &str) -> (axum::http::Version, bytes::Bytes)
where
    I: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let (mut sender, connection) = hyper::client::conn::http1::handshake(TokioIo::new(stream))
        .await
        .unwrap();
    let driver = tokio::spawn(connection);
    let response = tokio::time::timeout(
        TEST_TIMEOUT,
        sender.send_request(
            axum::http::Request::builder()
                .uri(path)
                .header("host", "localhost")
                .header("connection", "close")
                .body(Empty::<bytes::Bytes>::new())
                .unwrap(),
        ),
    )
    .await
    .unwrap()
    .unwrap();
    assert_eq!(response.status(), axum::http::StatusCode::OK);
    let version = response.version();
    let body = response.into_body().collect().await.unwrap().to_bytes();
    drop(sender);
    tokio::time::timeout(TEST_TIMEOUT, driver)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    (version, body)
}

#[tokio::test]
async fn detected_http1_connection_close_cancels_pending_request() {
    let (capture, mut captured) = mpsc::unbounded_channel::<RequestLifetime>();
    let app = Router::new()
        .route(
            "/pending",
            get(
                |Extension(capture): Extension<mpsc::UnboundedSender<RequestLifetime>>| async move {
                    capture.send(RequestLifetime::current()).unwrap();
                    std::future::pending::<Response<Body>>().await
                },
            ),
        )
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
        None,
        "public",
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

#[tokio::test]
async fn tls_http2_stream_reset_cancels_only_its_pending_request() {
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
        Some(tls_provider()),
        "public",
    ));
    let stream = connect_tls(address, &[b"h2"]).await;
    assert_eq!(stream.get_ref().1.alpn_protocol(), Some(b"h2".as_slice()));
    let (mut sender, connection) =
        hyper::client::conn::http2::handshake::<_, _, Empty<bytes::Bytes>>(
            TokioExecutor::new(),
            TokioIo::new(stream),
        )
        .await
        .unwrap();
    let driver = tokio::spawn(connection);
    let request = |path: &str| {
        axum::http::Request::builder()
            .uri(format!("https://{address}/{path}"))
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

#[tokio::test]
async fn tls_http1_and_absent_alpn_preserve_the_tcp_peer() {
    let app = Router::new().route(
        "/peer",
        get(|ConnectInfo(peer): ConnectInfo<SocketAddr>| async move { peer.to_string() }),
    );
    let server = TestServer::start(app, Some(tls_provider())).await;
    for alpn in [vec![b"http/1.1".as_slice()], vec![]] {
        let stream = connect_tls(server.address, &alpn).await;
        assert_eq!(stream.get_ref().1.alpn_protocol(), alpn.first().copied());
        let peer = stream.get_ref().0.local_addr().unwrap();
        let (version, body) = http1_get(stream, "/peer").await;
        assert_eq!(version, axum::http::Version::HTTP_11);
        assert_eq!(body, peer.to_string());
    }
    server.finish().await;
}

#[tokio::test]
async fn tls_http2_preserves_the_tcp_peer_and_negotiated_version() {
    let app = Router::new().route(
        "/peer",
        get(|ConnectInfo(peer): ConnectInfo<SocketAddr>| async move { peer.to_string() }),
    );
    let server = TestServer::start(app, Some(tls_provider())).await;
    let stream = connect_tls(server.address, &[b"http/1.1", b"h2"]).await;
    assert_eq!(stream.get_ref().1.alpn_protocol(), Some(b"h2".as_slice()));
    let peer = stream.get_ref().0.local_addr().unwrap();
    let (mut sender, connection) =
        hyper::client::conn::http2::handshake::<_, _, Empty<bytes::Bytes>>(
            hyper_util::rt::TokioExecutor::new(),
            TokioIo::new(stream),
        )
        .await
        .unwrap();
    let driver = tokio::spawn(connection);
    let response = tokio::time::timeout(
        TEST_TIMEOUT,
        sender.send_request(
            axum::http::Request::builder()
                .uri("https://localhost/peer")
                .body(Empty::new())
                .unwrap(),
        ),
    )
    .await
    .unwrap()
    .unwrap();
    assert_eq!(response.version(), axum::http::Version::HTTP_2);
    assert_eq!(response.status(), axum::http::StatusCode::OK);
    assert_eq!(
        response.into_body().collect().await.unwrap().to_bytes(),
        peer.to_string(),
    );
    drop(sender);
    driver.abort();
    let _ = driver.await;
    server.finish().await;
}

async fn read_until_closed(stream: &mut (impl AsyncRead + Unpin)) -> Vec<u8> {
    tokio::time::timeout(TEST_TIMEOUT, async {
        let mut result = Vec::new();
        let mut buffer = [0; 1024];
        loop {
            match stream.read(&mut buffer).await {
                Ok(0) => break,
                Ok(count) => result.extend_from_slice(&buffer[..count]),
                Err(error)
                    if matches!(
                        error.kind(),
                        std::io::ErrorKind::ConnectionReset | std::io::ErrorKind::UnexpectedEof
                    ) =>
                {
                    break;
                }
                Err(error) => panic!("unexpected connection error: {error}"),
            }
        }
        result
    })
    .await
    .expect("connection must close")
}

#[tokio::test]
async fn negotiated_protocol_is_enforced_without_plain_http2_sniffing() {
    use std::sync::atomic::{AtomicUsize, Ordering};

    let dispatched = Arc::new(AtomicUsize::new(0));
    let app = Router::new().fallback({
        let dispatched = dispatched.clone();
        move || {
            dispatched.fetch_add(1, Ordering::SeqCst);
            async { "unexpected" }
        }
    });
    let plain = TestServer::start(app.clone(), None).await;
    let tls = TestServer::start(app, Some(tls_provider())).await;
    let mut stream = TcpStream::connect(plain.address).await.unwrap();
    stream.write_all(HTTP2_PREFACE).await.unwrap();
    let response = read_until_closed(&mut stream).await;
    assert!(response.is_empty() || response.starts_with(b"HTTP/1.1 400"));

    for alpn in [vec![b"http/1.1".as_slice()], vec![]] {
        let mut stream = connect_tls(tls.address, &alpn).await;
        stream.write_all(HTTP2_PREFACE).await.unwrap();
        let response = read_until_closed(&mut stream).await;
        assert!(response.is_empty() || response.starts_with(b"HTTP/1.1 400"));
    }
    let mut stream = connect_tls(tls.address, &[b"h2"]).await;
    stream
        .write_all(b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n")
        .await
        .unwrap();
    let response = read_until_closed(&mut stream).await;
    assert!(!response.starts_with(b"HTTP/1.1 200"));
    assert_eq!(dispatched.load(Ordering::SeqCst), 0);
    plain.finish().await;
    tls.finish().await;
}

#[tokio::test]
async fn stalled_and_malformed_handshakes_do_not_block_valid_connections() {
    let (accepted, mut accepts) = mpsc::unbounded_channel();
    let config = server_config();
    let provider: TlsConfigProvider = Arc::new(move || {
        accepted.send(()).unwrap();
        config.clone()
    });
    let server = TestServer::start(
        Router::new().route("/", get(|| async { "ready" })),
        Some(provider),
    )
    .await;
    let mut stalled = TcpStream::connect(server.address).await.unwrap();
    accepts.recv().await.unwrap();
    let mut malformed = TcpStream::connect(server.address).await.unwrap();
    malformed.write_all(b"not a TLS record").await.unwrap();
    accepts.recv().await.unwrap();
    let stream = connect_tls(server.address, &[b"http/1.1"]).await;
    assert_eq!(http1_get(stream, "/").await.1, "ready");
    read_until_closed(&mut malformed).await;
    // Graceful shutdown cancels an unestablished connection without waiting
    // out the five-second handshake timeout.
    server.finish().await;
    assert!(read_until_closed(&mut stalled).await.is_empty());
}

#[tokio::test]
async fn handshake_capacity_is_bounded_and_recovers_after_timeouts() {
    let (accepted, mut accepts) = mpsc::unbounded_channel();
    let config = server_config();
    let provider: TlsConfigProvider = Arc::new(move || {
        accepted.send(()).unwrap();
        config.clone()
    });
    let server = TestServer::start(
        Router::new().route("/", get(|| async { "ready" })),
        Some(provider),
    )
    .await;
    let mut stalled = Vec::new();
    for _ in 0..MAX_TLS_HANDSHAKES {
        stalled.push(TcpStream::connect(server.address).await.unwrap());
        tokio::time::timeout(TEST_TIMEOUT, accepts.recv())
            .await
            .unwrap()
            .unwrap();
    }
    let mut excess = TcpStream::connect(server.address).await.unwrap();
    assert!(read_until_closed(&mut excess).await.is_empty());
    assert!(accepts.try_recv().is_err());
    // Start observing all sockets together: each admitted handshake must
    // close by its original deadline even though none sends a ClientHello.
    tokio::time::timeout(TLS_HANDSHAKE_TIMEOUT + TEST_TIMEOUT, async {
        for socket in &mut stalled {
            let mut byte = [0];
            assert_eq!(socket.read(&mut byte).await.unwrap(), 0);
        }
    })
    .await
    .expect("stalled handshakes must expire");
    let stream = connect_tls(server.address, &[b"http/1.1"]).await;
    assert_eq!(http1_get(stream, "/").await.1, "ready");
    server.finish().await;
}

#[tokio::test]
async fn successful_handshakes_release_capacity_while_connections_stay_open() {
    let server = TestServer::start(
        Router::new().route("/", get(|| async { "ready" })),
        Some(tls_provider()),
    )
    .await;
    let mut established = Vec::new();
    for _ in 0..=MAX_TLS_HANDSHAKES {
        established.push(connect_tls(server.address, &[b"http/1.1"]).await);
    }
    assert_eq!(http1_get(established.pop().unwrap(), "/").await.1, "ready");
    server.finish().await;
    for mut stream in established {
        assert!(read_until_closed(&mut stream).await.is_empty());
    }
}

#[tokio::test]
async fn tls_http1_disconnect_cancels_pending_request() {
    let (capture, mut captured) = mpsc::unbounded_channel::<RequestLifetime>();
    let app = Router::new()
        .route(
            "/pending",
            get(move || {
                let capture = capture.clone();
                async move {
                    capture.send(RequestLifetime::current()).unwrap();
                    std::future::pending::<Response<Body>>().await
                }
            }),
        )
        .layer(middleware::from_fn(scope_request_lifetime));
    let server = TestServer::start(app, Some(tls_provider())).await;
    let mut stream = connect_tls(server.address, &[b"http/1.1"]).await;
    stream
        .write_all(b"GET /pending HTTP/1.1\r\nHost: localhost\r\n\r\n")
        .await
        .unwrap();
    let lifetime = tokio::time::timeout(TEST_TIMEOUT, captured.recv())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(lifetime.reason(), None);
    drop(stream);
    assert_eq!(
        tokio::time::timeout(TEST_TIMEOUT, lifetime.cancelled())
            .await
            .unwrap(),
        AdmissionCancellationReason::OwnerAbandoned,
    );
    server.finish().await;
}

#[tokio::test]
async fn graceful_shutdown_drops_pending_handshake_router_owners() {
    let state = Arc::new(());
    let weak_state = Arc::downgrade(&state);
    let (accepted, mut accepts) = mpsc::unbounded_channel();
    let config = server_config();
    let provider: TlsConfigProvider = Arc::new(move || {
        accepted.send(()).unwrap();
        config.clone()
    });
    let server = TestServer::start(
        Router::new()
            .route("/", get(|| async { "ready" }))
            .layer(Extension(state)),
        Some(provider),
    )
    .await;
    let mut socket = TcpStream::connect(server.address).await.unwrap();
    accepts.recv().await.unwrap();
    assert!(weak_state.upgrade().is_some());
    server.finish().await;
    assert!(weak_state.upgrade().is_none());
    assert!(read_until_closed(&mut socket).await.is_empty());
}

#[tokio::test]
async fn forced_shutdown_drops_established_tls_request_and_connection_tasks() {
    let state = Arc::new(());
    let weak_state = Arc::downgrade(&state);
    let (capture, mut captured) = mpsc::unbounded_channel::<RequestLifetime>();
    let (owned, mut owners) = mpsc::unbounded_channel();
    let app = Router::new()
        .route(
            "/pending",
            get(move |Extension(tasks): Extension<ConnectionTasks>| {
                let capture = capture.clone();
                let owned = owned.clone();
                async move {
                    let (dropped, receiving) = oneshot::channel::<()>();
                    tasks.spawn(async move {
                        let _dropped = dropped;
                        std::future::pending::<()>().await;
                    });
                    owned.send(receiving).unwrap();
                    capture.send(RequestLifetime::current()).unwrap();
                    std::future::pending::<Response<Body>>().await
                }
            }),
        )
        .layer(Extension(state))
        .layer(middleware::from_fn(scope_request_lifetime));
    let server = TestServer::start(app, Some(tls_provider())).await;
    let mut stream = connect_tls(server.address, &[b"http/1.1"]).await;
    stream
        .write_all(b"GET /pending HTTP/1.1\r\nHost: localhost\r\n\r\n")
        .await
        .unwrap();
    let lifetime = tokio::time::timeout(TEST_TIMEOUT, captured.recv())
        .await
        .unwrap()
        .unwrap();
    let mut task_owner = owners.recv().await.unwrap();
    server.force.cancel();
    server.finish().await;
    assert_eq!(
        lifetime.reason(),
        Some(AdmissionCancellationReason::OwnerAbandoned)
    );
    assert_eq!(
        task_owner.try_recv(),
        Err(oneshot::error::TryRecvError::Closed)
    );
    assert!(weak_state.upgrade().is_none());
    assert!(read_until_closed(&mut stream).await.is_empty());
}

#[tokio::test]
async fn dropping_the_server_future_cancels_pending_handshakes() {
    let state = Arc::new(());
    let weak_state = Arc::downgrade(&state);
    let (accepted, mut accepts) = mpsc::unbounded_channel();
    let config = server_config();
    let provider: TlsConfigProvider = Arc::new(move || {
        accepted.send(()).unwrap();
        config.clone()
    });
    let mut server = TestServer::start(
        Router::new()
            .route("/", get(|| async { "ready" }))
            .layer(Extension(state)),
        Some(provider),
    )
    .await;
    let mut socket = TcpStream::connect(server.address).await.unwrap();
    accepts.recv().await.unwrap();
    let task = server.task.take().unwrap();
    task.abort();
    assert!(task.await.unwrap_err().is_cancelled());
    tokio::time::timeout(TEST_TIMEOUT, async {
        while weak_state.upgrade().is_some() {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("cancelled handshake must release router state");
    assert!(read_until_closed(&mut socket).await.is_empty());
}

#[tokio::test]
async fn graceful_tls_shutdown_drains_streaming_response_ownership() {
    use futures_util::StreamExt;
    use std::convert::Infallible;
    use std::sync::Mutex;

    let (release, released) = oneshot::channel();
    let released = Arc::new(Mutex::new(Some(released)));
    let (capture, mut captured) = mpsc::unbounded_channel::<RequestLifetime>();
    let app = Router::new()
        .route(
            "/stream",
            get(move || {
                let released = released.lock().unwrap().take().unwrap();
                let capture = capture.clone();
                async move {
                    capture.send(RequestLifetime::current()).unwrap();
                    Body::from_stream(
                        futures_util::stream::once(async {
                            Ok::<_, Infallible>(bytes::Bytes::from_static(b"first"))
                        })
                        .chain(futures_util::stream::once(async move {
                            let _ = released.await;
                            Ok::<_, Infallible>(bytes::Bytes::from_static(b"last"))
                        })),
                    )
                }
            }),
        )
        .layer(middleware::from_fn(scope_request_lifetime));
    let mut server = TestServer::start(app, Some(tls_provider())).await;
    let stream = connect_tls(server.address, &[b"http/1.1"]).await;
    let (mut sender, connection) = hyper::client::conn::http1::handshake(TokioIo::new(stream))
        .await
        .unwrap();
    let driver = tokio::spawn(connection);
    let response = sender
        .send_request(
            axum::http::Request::builder()
                .uri("/stream")
                .header("host", "localhost")
                .header("connection", "close")
                .body(Empty::<bytes::Bytes>::new())
                .unwrap(),
        )
        .await
        .unwrap();
    let lifetime = captured.recv().await.unwrap();
    let mut body = response.into_body();
    assert_eq!(
        body.frame().await.unwrap().unwrap().into_data().unwrap(),
        "first"
    );
    assert_eq!(lifetime.reason(), None);
    server.begin_shutdown();
    assert!(
        tokio::time::timeout(Duration::from_millis(25), server.task.as_mut().unwrap())
            .await
            .is_err(),
        "graceful shutdown must retain the streaming response"
    );
    release.send(()).unwrap();
    assert_eq!(body.collect().await.unwrap().to_bytes(), "last");
    drop(sender);
    tokio::time::timeout(TEST_TIMEOUT, driver)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    server.finish().await;
}

#[tokio::test]
async fn tls_http1_upgrade_uses_tracked_connection_tasks() {
    let (entered, mut entered_rx) = mpsc::unbounded_channel();
    let (dropped, mut dropped_rx) = mpsc::unbounded_channel();
    let app = Router::new().route(
        "/upgrade",
        get(
            move |Extension(tasks): Extension<ConnectionTasks>,
                  mut request: axum::extract::Request| {
                let entered = entered.clone();
                let dropped = dropped.clone();
                async move {
                    let upgrade = hyper::upgrade::on(&mut request);
                    tasks.spawn(async move {
                        let upgraded = upgrade.await.unwrap();
                        let mut stream = TokioIo::new(upgraded);
                        let mut input = [0; 4];
                        stream.read_exact(&mut input).await.unwrap();
                        assert_eq!(&input, b"ping");
                        stream.write_all(b"pong").await.unwrap();
                        stream.flush().await.unwrap();
                        let (guard, receiving) = oneshot::channel::<()>();
                        dropped.send(receiving).unwrap();
                        entered.send(()).unwrap();
                        let _guard = guard;
                        std::future::pending::<()>().await;
                    });
                    Response::builder()
                        .status(axum::http::StatusCode::SWITCHING_PROTOCOLS)
                        .header("connection", "upgrade")
                        .header("upgrade", "test-echo")
                        .body(Body::empty())
                        .unwrap()
                }
            },
        ),
    );
    let mut server = TestServer::start(app, Some(tls_provider())).await;
    let mut stream = connect_tls(server.address, &[b"http/1.1"]).await;
    stream
        .write_all(b"GET /upgrade HTTP/1.1\r\nHost: localhost\r\nConnection: upgrade\r\nUpgrade: test-echo\r\n\r\n")
        .await
        .unwrap();
    let mut headers = Vec::new();
    tokio::time::timeout(TEST_TIMEOUT, async {
        while !headers.ends_with(b"\r\n\r\n") {
            headers.push(stream.read_u8().await.unwrap());
        }
    })
    .await
    .unwrap();
    assert!(headers.starts_with(b"HTTP/1.1 101"));
    stream.write_all(b"ping").await.unwrap();
    let mut output = [0; 4];
    tokio::time::timeout(TEST_TIMEOUT, stream.read_exact(&mut output))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(&output, b"pong");
    entered_rx.recv().await.unwrap();
    let mut owner = dropped_rx.recv().await.unwrap();
    server.begin_shutdown();
    assert!(
        tokio::time::timeout(Duration::from_millis(25), server.task.as_mut().unwrap())
            .await
            .is_err(),
        "graceful shutdown must track the upgraded connection task"
    );
    server.force.cancel();
    server.finish().await;
    assert_eq!(owner.try_recv(), Err(oneshot::error::TryRecvError::Closed));
    assert!(read_until_closed(&mut stream).await.is_empty());
}
