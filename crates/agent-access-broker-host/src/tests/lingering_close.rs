//! Uploads refused while their body is still unread, over real connections:
//! the client finishes sending and reads the denial, within the lingering
//! bounds, and refusals before admission still never read the body.
use super::invocation_limits::{ALICE, assert_limited, limit_fixture, set_fake_limit};
use super::*;
use crate::http_server::ConnectionTasks;
use crate::ingress::lingering_close::LINGER_MAX_BYTES;
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
    Ok((status, body))
}

async fn connect(
    broker: &TestBroker,
) -> (BufReader<OwnedReadHalf>, tokio::net::tcp::OwnedWriteHalf) {
    let stream = TcpStream::connect(broker.running().public_addr())
        .await
        .unwrap();
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
    let (sender, receiver) = tokio::sync::mpsc::unbounded_channel();
    sender.send(Bytes::from(upload_prefix(project))).unwrap();
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

fn upload_request(request_id: &str, body: Body, tasks: &ConnectionTasks) -> Request<Body> {
    Request::builder()
        .method(Method::POST)
        .uri("/v1/invoke/fake/echo")
        .extension(ConnectInfo(
            "127.0.0.1:43200".parse::<SocketAddr>().unwrap(),
        ))
        .extension(tasks.clone())
        .header(REQUEST_ID_HEADER, request_id)
        .header(AUTHORIZATION, format!("Bearer {ALICE}"))
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
        .oneshot(upload_request("lingering-admitted", body, &tasks))
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
        .oneshot(upload_request("lingering-limited", body, &tasks))
        .await
        .unwrap();
    assert_limited(response, 1).await;
    finish_upload(sender, 64);
    settle(&tracker).await;
    assert_eq!(read.load(Ordering::SeqCst), 0);
}
