//! Uploads and Git pushes refused while their body is still unread: over real
//! connections, the client finishes sending and reads the denial within the
//! lingering bounds, lingering keeps the request's concurrency permits and
//! follows the server's shutdown, and refusals before admission still never
//! read the body.
use super::invocation_limits::{ALICE, BOB, assert_limited, limit, limit_fixture, set_fake_limit};
use super::*;
use crate::http_server::ConnectionTasks;
use crate::ingress::lingering_close::{LINGER_MAX_BYTES, LINGER_TIMEOUT};
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpStream;
use tokio::net::tcp::OwnedReadHalf;
use tokio_util::task::TaskTracker;

const BOUNDARY: &str = "lingering-close-boundary";
const STEP: Duration = Duration::from_secs(30);

/// The metadata part of a fake echo upload for `project`, then the headers
/// of its file part.
fn upload_prefix(project: &str) -> String {
    format!(
        "--{BOUNDARY}\r\n\
         Content-Disposition: form-data; name=\"request\"\r\n\
         Content-Type: application/json\r\n\r\n\
         {{\"inputs\":{{\"project\":\"{project}\",\"message\":\"hello\"}}}}\r\n\
         --{BOUNDARY}\r\n\
         Content-Disposition: form-data; name=\"file0\"; filename=\"large.bin\"\r\n\
         Content-Type: application/octet-stream\r\n\r\n"
    )
}

fn upload_suffix() -> String {
    format!("\r\n--{BOUNDARY}--\r\n")
}

/// The head of an HTTP/1.1 upload whose body is `file_bytes` of file data
/// between [`upload_prefix`] and [`upload_suffix`].
fn upload_head(request_id: &str, project: &str, file_bytes: usize) -> String {
    let length = upload_prefix(project).len() + file_bytes + upload_suffix().len();
    format!(
        "POST /v1/invoke/fake/echo HTTP/1.1\r\n\
         host: 127.0.0.1\r\n\
         content-type: multipart/form-data; boundary={BOUNDARY}\r\n\
         {REQUEST_ID_HEADER}: {request_id}\r\n\
         content-length: {length}\r\n\r\n"
    )
}

/// Reads one HTTP/1.1 response, framed by its length or chunked encoding.
async fn read_response(reader: &mut BufReader<OwnedReadHalf>) -> std::io::Result<(u16, Vec<u8>)> {
    read_response_with_reason(reader)
        .await
        .map(|(status, _, body)| (status, body))
}

/// Reads one HTTP/1.1 response and its reason code header, if any.
pub(super) async fn read_response_with_reason(
    reader: &mut BufReader<OwnedReadHalf>,
) -> std::io::Result<(u16, Option<String>, Vec<u8>)> {
    let mut lines = Vec::new();
    loop {
        let mut line = String::new();
        if reader.read_line(&mut line).await? == 0 {
            return Err(std::io::ErrorKind::UnexpectedEof.into());
        }
        if line == "\r\n" {
            break;
        }
        lines.push(line.trim_end().to_ascii_lowercase());
    }
    let status = lines[0].split(' ').nth(1).unwrap().parse().unwrap();
    let header = |name: &str| {
        lines[1..].iter().find_map(|line| {
            line.split_once(':')
                .filter(|(header, _)| *header == name)
                .map(|(_, value)| value.trim().to_owned())
        })
    };
    let reason = header(&REASON_CODE_HEADER.to_ascii_lowercase());
    let mut body = Vec::new();
    if let Some(length) = header("content-length") {
        body.resize(length.parse().unwrap(), 0);
        reader.read_exact(&mut body).await?;
    } else {
        assert_eq!(header("transfer-encoding").as_deref(), Some("chunked"));
        loop {
            let mut size = String::new();
            reader.read_line(&mut size).await?;
            let size = usize::from_str_radix(size.trim_end(), 16).unwrap();
            let start = body.len();
            body.resize(start + size, 0);
            reader.read_exact(&mut body[start..]).await?;
            let mut end = [0; 2];
            reader.read_exact(&mut end).await?;
            if size == 0 {
                break;
            }
        }
    }
    Ok((status, reason, body))
}

async fn connect(
    broker: &TestBroker,
) -> (BufReader<OwnedReadHalf>, tokio::net::tcp::OwnedWriteHalf) {
    connect_to(broker.running().public_addr()).await
}

pub(super) async fn connect_to(
    address: SocketAddr,
) -> (BufReader<OwnedReadHalf>, tokio::net::tcp::OwnedWriteHalf) {
    let stream = TcpStream::connect(address).await.unwrap();
    let (read, write) = stream.into_split();
    (BufReader::new(read), write)
}

fn denial_reason(body: &[u8]) -> Value {
    let value: Value = serde_json::from_slice(body).unwrap();
    assert_eq!(value["decision"], "deny", "{value}");
    value["reasonCode"].clone()
}

/// A client that sends its whole upload before reading, the hardest case:
/// without lingering, the Broker closes the connection after refusing the
/// metadata, and the unread remainder resets it.
#[tokio::test]
async fn a_refused_upload_is_read_to_its_end_so_the_client_gets_the_denial() {
    let broker = TestBroker::start_config(&fake_config("")).await;
    let (mut reader, mut writer) = connect(&broker).await;
    let file_bytes = 6 * 1024 * 1024;
    assert!((file_bytes as u64) < LINGER_MAX_BYTES);
    let mut request = upload_head("lingering-denied", "OTHER", file_bytes).into_bytes();
    request.extend_from_slice(upload_prefix("OTHER").as_bytes());
    request.resize(request.len() + file_bytes, b'x');
    request.extend_from_slice(upload_suffix().as_bytes());
    tokio::time::timeout(STEP, writer.write_all(&request))
        .await
        .unwrap()
        .expect("the Broker reads the refused upload to its end");
    let (status, body) = tokio::time::timeout(STEP, read_response(&mut reader))
        .await
        .unwrap()
        .expect("the client reads the denial");
    assert_eq!(status, 403);
    assert_eq!(denial_reason(&body), "service_action_denied");

    // The connection stays usable: nothing was left unread.
    writer
        .write_all(b"GET /v1/healthz HTTP/1.1\r\nhost: 127.0.0.1\r\n\r\n")
        .await
        .unwrap();
    let (status, _) = tokio::time::timeout(STEP, read_response(&mut reader))
        .await
        .unwrap()
        .expect("the refused upload's connection serves the next request");
    assert_eq!(status, 200);
}

/// A remainder over the lingering cap is not read: the Broker closes the
/// connection after the cap, long before the declared body ends, which is
/// beyond what socket buffers can absorb too.
#[tokio::test]
async fn lingering_after_a_refusal_reads_a_bounded_amount() {
    let broker = TestBroker::start_config(&fake_config("")).await;
    let (mut reader, mut writer) = connect(&broker).await;
    let file_bytes = 16 * LINGER_MAX_BYTES as usize;
    let chunk = vec![b'x'; 64 * 1024];
    writer
        .write_all(upload_head("lingering-bounded", "OTHER", file_bytes).as_bytes())
        .await
        .unwrap();
    writer
        .write_all(upload_prefix("OTHER").as_bytes())
        .await
        .unwrap();
    writer.write_all(&chunk).await.unwrap();
    let (status, body) = tokio::time::timeout(STEP, read_response(&mut reader))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(status, 403);
    assert_eq!(denial_reason(&body), "service_action_denied");

    let mut sent = chunk.len();
    let refused = tokio::time::timeout(STEP, async {
        while sent < file_bytes {
            writer.write_all(&chunk).await?;
            sent += chunk.len();
        }
        Ok::<_, std::io::Error>(())
    })
    .await
    .expect("the Broker stops lingering within its time limit");
    assert!(
        refused.is_err(),
        "the Broker accepted the whole {file_bytes}-byte remainder"
    );
    assert!(sent < file_bytes, "{sent}");
}

/// An upload whose first frame holds the metadata for `project` and the
/// file part's headers. The test sends the rest through the returned sender,
/// after the response, as a client still uploading does. The counter records
/// the frames read, and the end of the body as one more.
fn streamed_upload(
    project: &str,
) -> (
    Body,
    tokio::sync::mpsc::UnboundedSender<Bytes>,
    Arc<AtomicUsize>,
) {
    streamed_body(Bytes::from(upload_prefix(project)))
}

/// A body whose first frame is `first`; the test sends the rest through the
/// returned sender. The counter records the frames read, and the end of the
/// body as one more.
fn streamed_body(
    first: Bytes,
) -> (
    Body,
    tokio::sync::mpsc::UnboundedSender<Bytes>,
    Arc<AtomicUsize>,
) {
    let (sender, receiver) = tokio::sync::mpsc::unbounded_channel();
    sender.send(first).unwrap();
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

/// Sends the rest of a [`streamed_upload`]: `frames` frames of file data and
/// the closing boundary, then its end. Returns how many reads that makes.
fn finish_upload(sender: tokio::sync::mpsc::UnboundedSender<Bytes>, frames: usize) -> usize {
    for _ in 0..frames {
        let _ = sender.send(Bytes::from(vec![b'x'; 1024]));
    }
    let _ = sender.send(Bytes::from(upload_suffix()));
    // The first frame, the file frames, the boundary and the end.
    frames + 3
}

fn upload_request(
    request_id: &str,
    token: &str,
    body: Body,
    tasks: &ConnectionTasks,
) -> Request<Body> {
    Request::builder()
        .method(Method::POST)
        .uri("/v1/invoke/fake/echo")
        .extension(ConnectInfo(
            "127.0.0.1:43200".parse::<SocketAddr>().unwrap(),
        ))
        .extension(tasks.clone())
        .header(REQUEST_ID_HEADER, request_id)
        .header(AUTHORIZATION, format!("Bearer {token}"))
        .header(
            CONTENT_TYPE,
            format!("multipart/form-data; boundary={BOUNDARY}"),
        )
        .body(body)
        .unwrap()
}

async fn settle(tracker: &TaskTracker) {
    tracker.close();
    tokio::time::timeout(STEP, tracker.wait())
        .await
        .expect("lingering is bounded");
    tracker.reopen();
}

#[tokio::test]
async fn only_refusals_after_admission_read_the_rest_of_the_body() {
    let fixture = limit_fixture(|config| set_fake_limit(config, 1, "1m")).await;
    let tracker = TaskTracker::new();
    let tasks = ConnectionTasks::tracked_by(tracker.clone());

    // Refused by policy after admission, which counts against the limit:
    // the connection reads the rest of the body to its end.
    let (body, sender, read) = streamed_upload("OTHER");
    let response = fixture
        .app
        .clone()
        .oneshot(upload_request("lingering-admitted", ALICE, body, &tasks))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    assert_eq!(
        response_json(response).await["reasonCode"],
        "service_action_denied"
    );
    let reads = finish_upload(sender, 64);
    settle(&tracker).await;
    assert_eq!(read.load(Ordering::SeqCst), reads);

    // Rate limited before admission: the body is never read.
    let (body, sender, read) = streamed_upload("TEST");
    let response = fixture
        .app
        .clone()
        .oneshot(upload_request("lingering-limited", ALICE, body, &tasks))
        .await
        .unwrap();
    assert_limited(response, 1).await;
    finish_upload(sender, 64);
    settle(&tracker).await;
    assert_eq!(read.load(Ordering::SeqCst), 0);
}

async fn assert_concurrency_limited(response: axum::response::Response) {
    assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(
        response_json(response).await["reasonCode"],
        "concurrency_limited"
    );
}

async fn wait_until(mut done: impl FnMut() -> bool) {
    tokio::time::timeout(STEP, async {
        while !done() {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("the condition holds in time");
}

#[tokio::test]
async fn lingering_keeps_the_request_permits_within_the_concurrency_limits() {
    let fixture = limit_fixture(|config| {
        config.limits.max_concurrent_requests = 2;
        config.limits.max_concurrent_requests_per_principal = 1;
    })
    .await;
    let guards = fixture.state.shared_ingress.clone();
    let tracker = TaskTracker::new();
    let tasks = ConnectionTasks::tracked_by(tracker.clone());
    let refuse = |request_id: &'static str, token: &'static str| {
        let (body, rest, _) = streamed_upload("OTHER");
        let response = fixture
            .app
            .clone()
            .oneshot(upload_request(request_id, token, body, &tasks));
        async move {
            let response = response.await.unwrap();
            assert_eq!(response.status(), StatusCode::FORBIDDEN);
            assert_eq!(
                response_json(response).await["reasonCode"],
                "service_action_denied"
            );
            rest
        }
    };

    // Alice's refused upload lingers for the rest of its body, holding her
    // only request slot.
    let alice_rest = refuse("permits-alice-refused", ALICE).await;
    assert_eq!(guards.principal_in_flight_requests("alice"), 1);
    assert_eq!(guards.global_in_flight_requests(), 1);
    assert_concurrency_limited(fixture.invoke("permits-alice-limited", ALICE).await).await;

    // Bob's lingers too, and together they fill the global capacity.
    let bob_rest = refuse("permits-bob-refused", BOB).await;
    assert_eq!(guards.global_in_flight_requests(), 2);
    assert_concurrency_limited(fixture.invoke("permits-bob-limited", BOB).await).await;

    // Alice's body finishes: her lingering ends and her next request runs.
    finish_upload(alice_rest, 4);
    wait_until(|| guards.principal_in_flight_requests("alice") == 0).await;
    assert_eq!(guards.global_in_flight_requests(), 1);
    assert_eq!(
        fixture
            .invoke("permits-alice-released", ALICE)
            .await
            .status(),
        StatusCode::OK
    );

    // Bob's never does: his lingering times out, then his request runs.
    settle(&tracker).await;
    assert_eq!(guards.global_in_flight_requests(), 0);
    assert_eq!(guards.principal_in_flight_requests("bob"), 0);
    assert_eq!(
        fixture.invoke("permits-bob-released", BOB).await.status(),
        StatusCode::OK
    );
    drop(bob_rest);
}

const SHUTDOWN_FILE_BYTES: usize = 1024 * 1024;

/// Starts a broker with `shutdown_timeout`, and on one connection an upload
/// refused after the first 64 KiB of its declared [`SHUTDOWN_FILE_BYTES`]
/// file, which then lingers. Returns the broker, its ingress guards and the
/// connection.
async fn lingering_broker(
    shutdown_timeout: Duration,
) -> (
    TestBroker,
    Arc<crate::ingress::guards::IngressGuards>,
    BufReader<OwnedReadHalf>,
    tokio::net::tcp::OwnedWriteHalf,
) {
    let broker = TestBroker::start_with(
        TestBroker::config_builder(&fake_config("")).shutdown_timeout(shutdown_timeout),
    )
    .await;
    let guards = broker.state().shared_ingress.clone();
    let (mut reader, mut writer) = connect(&broker).await;
    writer
        .write_all(upload_head("lingering-shutdown", "OTHER", SHUTDOWN_FILE_BYTES).as_bytes())
        .await
        .unwrap();
    writer
        .write_all(upload_prefix("OTHER").as_bytes())
        .await
        .unwrap();
    writer.write_all(&[b'x'; 64 * 1024]).await.unwrap();
    let (status, body) = tokio::time::timeout(STEP, read_response(&mut reader))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(status, 403);
    assert_eq!(denial_reason(&body), "service_action_denied");
    // The discarding task holds the request's permits while it waits.
    assert_eq!(guards.global_in_flight_requests(), 1);
    assert_eq!(guards.principal_in_flight_requests("anonymous"), 1);
    (broker, guards, reader, writer)
}

#[tokio::test]
async fn graceful_shutdown_waits_for_a_lingering_body_to_finish() {
    let (broker, guards, mut reader, mut writer) = lingering_broker(STEP).await;
    let stopping = tokio::spawn(broker.stop());
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert!(
        !stopping.is_finished(),
        "graceful shutdown waits for the lingering body"
    );
    assert_eq!(guards.global_in_flight_requests(), 1);

    // The rest arrives: discarding reads it to its end, and shutdown finishes
    // without being forced.
    let mut rest = vec![b'x'; SHUTDOWN_FILE_BYTES - 64 * 1024];
    rest.extend_from_slice(upload_suffix().as_bytes());
    writer
        .write_all(&rest)
        .await
        .expect("the stopping Broker still reads the lingering body");
    let report = tokio::time::timeout(STEP, stopping)
        .await
        .expect("shutdown finishes once the lingering body has")
        .unwrap();
    assert!(report.is_clean(), "{report:?}");
    assert_eq!(guards.global_in_flight_requests(), 0);
    assert_eq!(guards.principal_in_flight_requests("anonymous"), 0);
    // Nothing was left unread, so the connection closes in order.
    let mut tail = Vec::new();
    let closed = tokio::time::timeout(STEP, reader.read_to_end(&mut tail))
        .await
        .unwrap()
        .expect("the connection closes without a reset");
    assert_eq!(closed, 0, "{}", String::from_utf8_lossy(&tail));
}

#[tokio::test]
async fn forced_shutdown_cancels_a_lingering_body() {
    let (broker, guards, mut reader, _writer) = lingering_broker(Duration::from_millis(500)).await;
    let lingering = std::time::Instant::now();
    let report = tokio::time::timeout(LINGER_TIMEOUT, broker.stop())
        .await
        .expect("forced shutdown does not wait out the lingering timeout");
    assert!(report.was_forced(), "{report:?}");
    // The discarding task ended with its connection, before its own timeout,
    // and released the request's permits.
    assert!(lingering.elapsed() < LINGER_TIMEOUT);
    assert_eq!(guards.global_in_flight_requests(), 0);
    assert_eq!(guards.principal_in_flight_requests("anonymous"), 0);
    let mut tail = Vec::new();
    let closed = tokio::time::timeout(Duration::from_secs(1), reader.read_to_end(&mut tail))
        .await
        .expect("the connection is closed");
    if let Ok(read) = closed {
        assert_eq!(read, 0, "{}", String::from_utf8_lossy(&tail));
    }
}

const GIT_HOST: &str = "git.example.test";
const RECEIVE_PACK: &str = "/sip/service.git/git-receive-pack";

/// A gateway that may push `sip/service`, with room for large packs, that
/// refuses pushes to `refs/heads/protected`. Its upstream is not allowed, so
/// nothing is ever forwarded.
async fn push_gateway(configure: impl FnOnce(&mut BrokerConfig)) -> GatewayRouterFixture {
    test_gateway_router_with_config(true, &["repo.fetch", "repo.push"], |config| {
        let gateway = config.gateways.get_mut("gitlab_git").unwrap();
        gateway.request_body_max_bytes = Some(64 * 1024 * 1024);
        gateway.git.as_mut().unwrap().deny_ref_patterns = vec!["refs/heads/protected".into()];
        configure(config);
    })
    .await
}

/// A push's command prefix creating `reference`, as Git sends it, and the
/// start of its pack.
fn push_prefix(reference: &str) -> Vec<u8> {
    let command = format!(
        "{} {} {reference}\0report-status side-band-64k",
        "0".repeat(40),
        "2".repeat(40)
    );
    let mut prefix = format!("{:04x}{command}", command.len() + 4).into_bytes();
    prefix.extend_from_slice(b"0000PACK");
    prefix
}

/// A whole HTTP/1.1 receive-pack POST to `reference`, with `headers` and a
/// pack of `pack_bytes`, in one request as Git sends a push that fits its
/// `http.postBuffer`.
pub(super) fn push_request_bytes(reference: &str, headers: &str, pack_bytes: usize) -> Vec<u8> {
    let mut body = push_prefix(reference);
    body.resize(body.len() + pack_bytes, b'x');
    let mut request = format!(
        "POST {RECEIVE_PACK} HTTP/1.1\r\n\
         host: {GIT_HOST}\r\n\
         content-type: application/x-git-receive-pack-request\r\n\
         {headers}content-length: {}\r\n\r\n",
        body.len()
    )
    .into_bytes();
    request.extend_from_slice(&body);
    request
}

fn gateway_basic(token: &str) -> String {
    format!(
        "authorization: Basic {}\r\n",
        BASE64.encode(format!("agent-access:{token}"))
    )
}

/// Git writes a push's whole body before it reads the answer. Refused at
/// any point after admission, before or after the command prefix is read,
/// the Broker reads the rest of the body without forwarding it, so the
/// client gets the refusal instead of a reset and its connection stays
/// usable.
#[tokio::test]
async fn a_refused_push_is_read_to_its_end_so_the_client_gets_the_refusal() {
    let fixture = push_gateway(|_| {}).await;
    let address = fixture._broker.running().gateway_addr().unwrap();
    let authorization = gateway_basic(&fixture.agent_token);
    let pack_bytes = 6 * 1024 * 1024;
    assert!((pack_bytes as u64) < LINGER_MAX_BYTES);
    for (case, reference, headers, status, reason) in [
        (
            "refused before the body is read",
            "refs/heads/feature",
            format!("{authorization}content-encoding: gzip\r\n"),
            400,
            "gateway_header_denied",
        ),
        (
            "refused after the command prefix",
            "refs/heads/protected",
            authorization.clone(),
            403,
            "git_ref_denied",
        ),
        (
            "failed before reaching the upstream",
            "refs/heads/feature",
            authorization.clone(),
            502,
            "gateway_upstream_denied",
        ),
    ] {
        let (mut reader, mut writer) = connect_to(address).await;
        let request = push_request_bytes(reference, &headers, pack_bytes);
        tokio::time::timeout(STEP, writer.write_all(&request))
            .await
            .unwrap()
            .unwrap_or_else(|error| panic!("{case}: the push was not read to its end: {error}"));
        let (got, got_reason, _) =
            tokio::time::timeout(STEP, read_response_with_reason(&mut reader))
                .await
                .unwrap()
                .unwrap_or_else(|error| panic!("{case}: no refusal: {error}"));
        assert_eq!(
            (got, got_reason.as_deref()),
            (status, Some(reason)),
            "{case}"
        );

        // Nothing was left unread: the connection serves the next request.
        writer
            .write_all(
                format!(
                    "GET /sip/service.git/info/refs?service=git-upload-pack HTTP/1.1\r\n\
                     host: {GIT_HOST}\r\n{authorization}\r\n"
                )
                .as_bytes(),
            )
            .await
            .unwrap();
        let (next, next_reason, _) =
            tokio::time::timeout(STEP, read_response_with_reason(&mut reader))
                .await
                .unwrap()
                .unwrap_or_else(|error| panic!("{case}: the connection was closed: {error}"));
        assert_eq!(
            (next, next_reason.as_deref()),
            (502, Some("gateway_upstream_denied")),
            "{case}"
        );
    }
}

fn push_request_through_router(
    request_id: &str,
    token: &str,
    body: Body,
    tasks: &ConnectionTasks,
) -> Request<Body> {
    Request::builder()
        .method(Method::POST)
        .uri(RECEIVE_PACK)
        .extension(ConnectInfo(
            "127.0.0.1:43201".parse::<SocketAddr>().unwrap(),
        ))
        .extension(tasks.clone())
        .header("Host", GIT_HOST)
        .header(REQUEST_ID_HEADER, request_id)
        .header(
            AUTHORIZATION,
            format!("Basic {}", BASE64.encode(format!("agent-access:{token}"))),
        )
        .header(CONTENT_TYPE, "application/x-git-receive-pack-request")
        .body(body)
        .unwrap()
}

/// Sends `frames` frames of pack data, then ends the body. Returns how many
/// reads the whole body makes: the prefix, the frames and the end.
fn finish_push(sender: tokio::sync::mpsc::UnboundedSender<Bytes>, frames: usize) -> usize {
    for _ in 0..frames {
        let _ = sender.send(Bytes::from(vec![b'x'; 1024]));
    }
    frames + 2
}

#[tokio::test]
async fn only_push_refusals_after_admission_read_the_rest_of_the_pack() {
    let fixture = push_gateway(|config| {
        config
            .limits
            .invocations
            .services
            .insert("gitlab_git".into(), limit(1, "1m"));
    })
    .await;
    let tracker = TaskTracker::new();
    let tasks = ConnectionTasks::tracked_by(tracker.clone());

    // Refused after admission, which spends the window: the connection reads
    // the rest of the pack to its end.
    let (body, sender, read) = streamed_body(Bytes::from(push_prefix("refs/heads/protected")));
    let response = fixture
        .app
        .clone()
        .oneshot(push_request_through_router(
            "lingering-push-refused",
            &fixture.agent_token,
            body,
            &tasks,
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    assert_eq!(response.headers()[REASON_CODE_HEADER], "git_ref_denied");
    let reads = finish_push(sender, 64);
    settle(&tracker).await;
    assert_eq!(read.load(Ordering::SeqCst), reads);

    // Rate limited before admission: the pack is never read.
    let (body, sender, read) = streamed_body(Bytes::from(push_prefix("refs/heads/feature")));
    let response = fixture
        .app
        .clone()
        .oneshot(push_request_through_router(
            "lingering-push-limited",
            &fixture.agent_token,
            body,
            &tasks,
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(response.headers()[REASON_CODE_HEADER], "rate_limited");
    finish_push(sender, 64);
    settle(&tracker).await;
    assert_eq!(read.load(Ordering::SeqCst), 0);
}

/// The bytes of a pack POST's body the [`EarlyOrigin`] reads before it answers.
const EARLY_READ: usize = 64 * 1024;

/// An HTTPS Git origin that answers one pack POST early: it reads the request
/// head and at least [`EARLY_READ`] bytes of its body, answers 413 and then
/// keeps the connection open, reading nothing more, until told to close it.
struct EarlyOrigin {
    base_url: String,
    read: Arc<AtomicUsize>,
    close: std::sync::mpsc::Sender<()>,
    thread: Option<std::thread::JoinHandle<()>>,
}

impl EarlyOrigin {
    fn start() -> Self {
        use rustls::pki_types::{CertificateDer, PrivateKeyDer, pem::PemObject};
        use std::io::{Read, Write};
        let fixture = |name: &str| {
            std::fs::read(
                Path::new(env!("CARGO_MANIFEST_DIR"))
                    .join("../agent-access-core/tests/fixtures/outbound-tls")
                    .join(name),
            )
            .unwrap()
        };
        let tls = Arc::new(
            rustls::ServerConfig::builder_with_provider(Arc::new(
                rustls::crypto::ring::default_provider(),
            ))
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(
                CertificateDer::pem_slice_iter(&fixture("leaf-a.pem"))
                    .collect::<Result<Vec<_>, _>>()
                    .unwrap(),
                PrivateKeyDer::from_pem_slice(&fixture("leaf-a.key")).unwrap(),
            )
            .unwrap(),
        );
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let base_url = format!("https://{}", listener.local_addr().unwrap());
        let read = Arc::new(AtomicUsize::new(0));
        let counter = read.clone();
        let (close, closing) = std::sync::mpsc::channel::<()>();
        let thread = std::thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            stream.set_read_timeout(Some(STEP)).unwrap();
            let connection = rustls::ServerConnection::new(tls).unwrap();
            let mut tls = rustls::StreamOwned::new(connection, stream);
            let mut received = Vec::new();
            let mut buffer = [0_u8; 16 * 1024];
            let head = loop {
                let read = tls.read(&mut buffer).unwrap();
                assert!(read > 0, "the request ended early");
                received.extend_from_slice(&buffer[..read]);
                if let Some(end) = received.windows(4).position(|bytes| bytes == b"\r\n\r\n") {
                    break end + 4;
                }
            };
            while received.len() - head < EARLY_READ {
                let read = tls.read(&mut buffer).unwrap();
                assert!(read > 0, "the request ended early");
                received.extend_from_slice(&buffer[..read]);
            }
            counter.store(received.len() - head, Ordering::SeqCst);
            let answer = b"upstream refused the pack\n";
            write!(
                tls,
                "HTTP/1.1 413 Payload Too Large\r\ncontent-type: text/plain\r\ncontent-length: {}\r\n\r\n",
                answer.len()
            )
            .unwrap();
            tls.write_all(answer).unwrap();
            tls.flush().unwrap();
            // Unread bytes remain: closing resets the Broker's upload.
            let _ = closing.recv_timeout(STEP);
        });
        Self {
            base_url,
            read,
            close,
            thread: Some(thread),
        }
    }

    /// The body bytes it read before answering.
    fn read(&self) -> usize {
        self.read.load(Ordering::SeqCst)
    }

    /// Closes the connection and waits until it is closed.
    fn close(&mut self) {
        let _ = self.close.send(());
        self.thread.take().unwrap().join().unwrap();
    }
}

/// An upstream that answers a push early, before the whole pack was sent,
/// keeps the gateway's upstream request holding the unfinished body after
/// the response. Once that request lets go of it, the connection discards the
/// rest without forwarding it, so the client finishes sending and reuses the
/// connection, and the request's permits are released.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_push_answered_early_upstream_is_read_to_its_end_once_the_upstream_lets_go() {
    let mut origin = EarlyOrigin::start();
    let base_url = origin.base_url.clone();
    let fixture = push_gateway(|config| {
        let gateway = config.gateways.get_mut("gitlab_git").unwrap();
        gateway.upstream_base_url = base_url.clone();
        gateway.allowed_upstream_hosts = vec![format!("{base_url}/**")];
        config.network.outbound_tls = agent_access_core::OutboundTlsConfig {
            trust: agent_access_core::OutboundTlsTrustMode::Custom,
            ca_certificate: Some(
                Path::new(env!("CARGO_MANIFEST_DIR"))
                    .join("../agent-access-core/tests/fixtures/outbound-tls/ca-a.pem"),
            ),
        };
    })
    .await;
    let guards = fixture._broker.state().shared_ingress.clone();
    let address = fixture._broker.running().gateway_addr().unwrap();
    let authorization = gateway_basic(&fixture.agent_token);
    let pack_bytes = 4 * 1024 * 1024;
    let first_bytes = 256 * 1024;
    let request = push_request_bytes("refs/heads/feature", &authorization, pack_bytes);
    let split = request.len() - pack_bytes + first_bytes;

    // The client sends the command prefix and the start of the pack; the
    // origin answers before the rest arrives.
    let (mut reader, mut writer) = connect_to(address).await;
    writer.write_all(&request[..split]).await.unwrap();
    let (status, _, body) = tokio::time::timeout(STEP, read_response_with_reason(&mut reader))
        .await
        .unwrap()
        .expect("the client reads the origin's early answer");
    assert_eq!(status, 413);
    assert_eq!(body, b"upstream refused the pack\n");
    // The answer is delivered and the upstream request still holds the body:
    // the connection waits for it, holding the request's permits.
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert_eq!(guards.global_in_flight_requests(), 1);

    // The upstream lets go: the rest of the pack is discarded, not forwarded.
    origin.close();
    tokio::time::timeout(STEP, writer.write_all(&request[split..]))
        .await
        .unwrap()
        .expect("the Broker reads the rest of the pack");
    assert!(origin.read() >= EARLY_READ && origin.read() < first_bytes);

    // Nothing was left unread: the connection serves the next request.
    writer
        .write_all(
            format!(
                "GET /sip/service.git/info/refs?service=git-upload-pack HTTP/1.1\r\n\
                 host: {GIT_HOST}\r\n\r\n"
            )
            .as_bytes(),
        )
        .await
        .unwrap();
    let (next, reason, _) = tokio::time::timeout(STEP, read_response_with_reason(&mut reader))
        .await
        .unwrap()
        .expect("the connection serves the next request");
    assert_eq!(
        (next, reason.as_deref()),
        (401, Some("gateway_auth_required"))
    );
    wait_until(|| guards.global_in_flight_requests() == 0).await;
    assert_eq!(guards.principal_in_flight_requests("gateway-user"), 0);
}
