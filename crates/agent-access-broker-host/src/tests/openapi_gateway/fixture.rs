use super::*;
use agent_access_core::imports::{
    ImportedCredentialBinding, ImportedCredentialDelivery, ImportedCredentialMode,
    ImportedDiscoveryCredential,
};
use agent_access_core::{
    BrokerTokenClass, BrokerTokenHasher, BrokerTokenIssueRequest, ImportedGatewayBinding,
};
use axum::extract::State;
use axum::response::Response;
use std::sync::Mutex;
use tokio::sync::Notify;

pub(super) const SERVICE: &str = "inventory";
pub(super) const GATEWAY_HOST: &str = "inventory.gateway.example.test";
pub(super) const UPSTREAM_TOKEN: &str = "synthetic-inventory-upstream-token";
pub(super) const BLOB: &[u8] = b"\x00\x01\x02\xffbinary\r\nbytes\x00";
// Gzip stream of BLOB with zero timestamp, retained as exact wire bytes.
pub(super) const ENCODED_BLOB: &[u8] = &[
    31, 139, 8, 0, 0, 0, 0, 0, 2, 255, 99, 96, 100, 250, 159, 148, 153, 151, 88, 84, 201, 203, 149,
    84, 89, 146, 90, 204, 0, 0, 85, 247, 198, 65, 18, 0, 0, 0,
];

#[derive(Clone, Copy)]
pub(super) enum Dialect {
    OpenApi31,
    Swagger2,
}
#[derive(Clone, Copy)]
pub(super) enum DefinitionSource {
    Upload,
    Url,
}
#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum UpstreamAuth {
    Anonymous,
    Bearer,
    Basic,
    Header,
}

#[derive(Clone, Copy)]
pub(super) enum RawReply {
    CloseBeforeHeaders,
    TruncatedLength,
    EarlyRejection,
}

#[derive(Clone)]
pub(super) struct Seen {
    pub method: Method,
    pub path: String,
    pub query: String,
    pub headers: HeaderMap,
    pub body: Vec<u8>,
}

#[derive(Default)]
struct UpstreamState {
    document: Mutex<Value>,
    requests: Mutex<Vec<Seen>>,
    writes: AtomicUsize,
    release: Arc<Notify>,
    upload_started: Arc<Notify>,
}

pub(super) struct Upstream {
    base: String,
    state: Arc<UpstreamState>,
    task: tokio::task::JoinHandle<()>,
}

impl Upstream {
    pub async fn start() -> Self {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let base = format!("http://{}", listener.local_addr().unwrap());
        let state = Arc::new(UpstreamState::default());
        let app = Router::new().fallback(upstream).with_state(state.clone());
        let task = tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        Self { base, state, task }
    }
    pub async fn raw(reply: RawReply) -> Self {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let base = format!("http://{}", listener.local_addr().unwrap());
        let state = Arc::new(UpstreamState::default());
        let observed = state.clone();
        let task = tokio::spawn(async move {
            let mut connections = tokio::task::JoinSet::new();
            loop {
                tokio::select! {
                    accepted = listener.accept() => {
                        let (socket, _) = accepted.unwrap();
                        let observed = observed.clone();
                        connections.spawn(async move {
                            tokio::time::timeout(Duration::from_secs(10), raw_connection(socket, observed, reply)).await.unwrap();
                        });
                    }
                    finished = connections.join_next(), if !connections.is_empty() => { finished.unwrap().unwrap(); }
                }
            }
        });
        Self { base, state, task }
    }
    pub fn endpoint(&self) -> String {
        format!("{}/api", self.base)
    }
    pub fn document_url(&self) -> String {
        format!("{}/spec.json", self.base)
    }
    pub fn document(&self, document: Value) {
        *self.state.document.lock().unwrap() = document;
    }
    pub fn api_requests(&self) -> Vec<Seen> {
        self.state.requests.lock().unwrap().clone()
    }
    pub fn writes(&self) -> usize {
        self.state.writes.load(Ordering::SeqCst)
    }
    pub fn release_stream(&self) {
        self.state.release.notify_one();
    }
    pub fn upload_started(&self) -> Arc<Notify> {
        self.state.upload_started.clone()
    }
}

async fn raw_connection(
    mut socket: tokio::net::TcpStream,
    state: Arc<UpstreamState>,
    reply: RawReply,
) {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let mut received = Vec::new();
    let split = loop {
        let mut bytes = [0; 2048];
        let count = socket.read(&mut bytes).await.unwrap();
        if count == 0 {
            return;
        }
        received.extend_from_slice(&bytes[..count]);
        assert!(received.len() <= 128 * 1024);
        if let Some(split) = received.windows(4).position(|bytes| bytes == b"\r\n\r\n") {
            break split + 4;
        }
    };
    let head = std::str::from_utf8(&received[..split]).unwrap().to_owned();
    let mut lines = head.split("\r\n");
    let mut request = lines.next().unwrap().split(' ');
    let method: Method = request.next().unwrap().parse().unwrap();
    let uri: axum::http::Uri = request.next().unwrap().parse().unwrap();
    let mut headers = HeaderMap::new();
    for line in lines.filter(|line| !line.is_empty()) {
        let (name, value) = line.split_once(':').unwrap();
        headers.append(
            axum::http::HeaderName::from_bytes(name.as_bytes()).unwrap(),
            HeaderValue::from_str(value.trim()).unwrap(),
        );
    }
    if matches!(reply, RawReply::EarlyRejection) {
        state.requests.lock().unwrap().push(Seen {
            method,
            path: uri.path().into(),
            query: uri.query().unwrap_or_default().into(),
            headers,
            body: vec![],
        });
        let body = "synthetic early rejection\n";
        socket.write_all(format!("HTTP/1.1 413 Payload Too Large\r\nContent-Type: text/plain\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len()).as_bytes()).await.unwrap();
        socket.shutdown().await.unwrap();
        return;
    }
    let body = raw_request_body(&mut socket, &headers, &mut received, split).await;
    // The ambiguous-write fixture observes a completed application input
    // before dropping the response, rather than counting an unread request.
    if method == Method::POST {
        state.writes.fetch_add(1, Ordering::SeqCst);
    }
    state.requests.lock().unwrap().push(Seen {
        method,
        path: uri.path().into(),
        query: uri.query().unwrap_or_default().into(),
        headers,
        body,
    });
    match reply {
        RawReply::CloseBeforeHeaders => {}
        RawReply::TruncatedLength => {
            socket.write_all(b"HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\nContent-Length: 20\r\nConnection: close\r\n\r\nshort").await.unwrap();
        }
        RawReply::EarlyRejection => unreachable!(),
    }
    socket.shutdown().await.unwrap();
}

async fn raw_read_more(socket: &mut tokio::net::TcpStream, received: &mut Vec<u8>) {
    use tokio::io::AsyncReadExt;
    let mut bytes = [0; 2048];
    let count = socket.read(&mut bytes).await.unwrap();
    assert_ne!(
        count, 0,
        "fixture request ended before its framing completed"
    );
    received.extend_from_slice(&bytes[..count]);
    assert!(received.len() <= 128 * 1024, "fixture wire-byte cap");
}

async fn raw_request_line(
    socket: &mut tokio::net::TcpStream,
    received: &mut Vec<u8>,
    cursor: &mut usize,
) -> Vec<u8> {
    loop {
        if let Some(end) = received[*cursor..]
            .windows(2)
            .position(|bytes| bytes == b"\r\n")
        {
            assert!(end <= 4096, "fixture framing-line cap");
            let line = received[*cursor..*cursor + end].to_vec();
            *cursor += end + 2;
            return line;
        }
        assert!(received.len() - *cursor <= 4096, "fixture framing-line cap");
        raw_read_more(socket, received).await;
    }
}

async fn raw_request_body(
    socket: &mut tokio::net::TcpStream,
    headers: &HeaderMap,
    received: &mut Vec<u8>,
    split: usize,
) -> Vec<u8> {
    if let Some(encoding) = headers.get("transfer-encoding") {
        assert_eq!(encoding, "chunked");
        assert!(!headers.contains_key(CONTENT_LENGTH));
        let mut cursor = split;
        let mut body = Vec::new();
        loop {
            let line = raw_request_line(socket, received, &mut cursor).await;
            let size = std::str::from_utf8(&line)
                .unwrap()
                .split(';')
                .next()
                .unwrap();
            assert!(!size.is_empty() && size.bytes().all(|byte| byte.is_ascii_hexdigit()));
            let size = usize::from_str_radix(size, 16).unwrap();
            assert!(size <= 64 * 1024 - body.len(), "fixture decoded-body cap");
            if size == 0 {
                // Consume the complete trailer section before recognizing EOF.
                loop {
                    let line = raw_request_line(socket, received, &mut cursor).await;
                    if line.is_empty() {
                        return body;
                    }
                    assert!(line.contains(&b':'), "fixture malformed request trailer");
                }
            }
            while received.len() - cursor < size + 2 {
                raw_read_more(socket, received).await;
            }
            body.extend_from_slice(&received[cursor..cursor + size]);
            cursor += size;
            assert_eq!(&received[cursor..cursor + 2], b"\r\n");
            cursor += 2;
        }
    }
    let length = headers
        .get(CONTENT_LENGTH)
        .map(|value| value.to_str().unwrap().parse::<usize>().unwrap())
        .unwrap_or(0);
    assert!(length <= 64 * 1024);
    while received.len() - split < length {
        raw_read_more(socket, received).await;
    }
    received[split..split + length].to_vec()
}
impl Drop for Upstream {
    fn drop(&mut self) {
        self.task.abort();
    }
}

async fn upstream(
    State(state): State<Arc<UpstreamState>>,
    request: Request<Body>,
) -> Response<Body> {
    let (head, body) = request.into_parts();
    if head.uri.path() == "/spec.json" {
        return Response::builder()
            .header(CONTENT_TYPE, "application/json")
            .body(Body::from(state.document.lock().unwrap().to_string()))
            .unwrap();
    }
    use futures_util::StreamExt;
    let writing = matches!(
        head.method,
        Method::POST | Method::PUT | Method::PATCH | Method::DELETE
    );
    let mut frames = body.into_data_stream();
    let mut body = Vec::new();
    let mut failed = false;
    let mut counted = false;
    while let Some(frame) = frames.next().await {
        match frame {
            Ok(frame) => {
                if writing && !counted && !frame.is_empty() {
                    counted = true;
                    state.writes.fetch_add(1, Ordering::SeqCst);
                    state.upload_started.notify_one();
                }
                body.extend_from_slice(&frame);
                assert!(body.len() <= 1024 * 1024);
            }
            Err(_) => {
                failed = true;
                break;
            }
        }
    }
    let seen = Seen {
        method: head.method.clone(),
        path: head.uri.path().into(),
        query: head.uri.query().unwrap_or_default().into(),
        headers: head.headers.clone(),
        body,
    };
    state.requests.lock().unwrap().push(seen.clone());
    let response = Response::builder()
        .header("X-Backend-Private", "must-not-pass")
        .header("Set-Cookie", "private=must-not-pass");
    if failed {
        return response
            .status(StatusCode::BAD_REQUEST)
            .body(Body::from("synthetic interrupted upload\n"))
            .unwrap();
    }
    match head.uri.path() {
        "/api/blob" | "/api/encoded" | "/api/artifacts/build-123" => {
            let ranged = head
                .headers
                .get("range")
                .is_some_and(|value| value == "bytes=2-5");
            let bytes = if head.uri.path() == "/api/encoded" {
                ENCODED_BLOB
            } else if ranged {
                &BLOB[2..6]
            } else {
                BLOB
            };
            let response = response
                .status(if ranged {
                    StatusCode::PARTIAL_CONTENT
                } else {
                    StatusCode::OK
                })
                .header(CONTENT_TYPE, "application/octet-stream")
                .header(CONTENT_LENGTH, bytes.len())
                .header("X-Checksum", "synthetic-checksum")
                .header("X-Api-Version", "1")
                .header("ETag", "\"synthetic-v1\"");
            let response = if head.uri.path() == "/api/encoded" {
                response.header(CONTENT_ENCODING, "gzip")
            } else {
                response
            };
            let response = if ranged {
                response.header("Content-Range", format!("bytes 2-5/{}", BLOB.len()))
            } else {
                response
            };
            response
                .body(if head.method == Method::HEAD {
                    Body::empty()
                } else {
                    Body::from(bytes.to_vec())
                })
                .unwrap()
        }
        "/api/empty" => response
            .status(StatusCode::NO_CONTENT)
            .body(Body::empty())
            .unwrap(),
        "/api/conditional" => response
            .status(StatusCode::NOT_MODIFIED)
            .header("ETag", "\"synthetic-v1\"")
            .body(Body::empty())
            .unwrap(),
        "/api/items/widget" if head.method == Method::PUT => response
            .status(StatusCode::NO_CONTENT)
            .body(Body::empty())
            .unwrap(),
        "/api/stream" => {
            let release = state.release.clone();
            let chunks = futures_util::stream::unfold((0, release), |(step, release)| async move {
                match step {
                    0 => Some((
                        Ok::<_, std::io::Error>(Bytes::from_static(b"first-chunk")),
                        (1, release),
                    )),
                    1 => {
                        release.notified().await;
                        Some((Ok(Bytes::from_static(b"last-chunk")), (2, release)))
                    }
                    _ => None,
                }
            });
            response
                .header(CONTENT_TYPE, "application/octet-stream")
                .body(Body::from_stream(chunks))
                .unwrap()
        }
        path if path.starts_with("/api/errors/") => {
            let status = path.rsplit('/').next().unwrap().parse::<u16>().unwrap();
            response
                .status(status)
                .header(CONTENT_TYPE, "text/plain")
                .header("Retry-After", "7")
                .header("WWW-Authenticate", "Bearer realm=private-upstream")
                .header("Location", "https://bypass.example.test/private")
                .body(Body::from(format!("synthetic backend {status}\n")))
                .unwrap()
        }
        _ => response
            .header(CONTENT_TYPE, "application/json")
            .body(Body::from(
                json!({"path":seen.path,"query":seen.query}).to_string(),
            ))
            .unwrap(),
    }
}

pub(super) fn document(dialect: Dialect, auth: UpstreamAuth, endpoint: &str) -> Value {
    let mut value = json!({"openapi":"3.1.1","info":{"title":"Synthetic inventory","version":"1"},
        "servers":[{"url":endpoint}],"paths":{}});
    let mut paths = serde_json::Map::new();
    let responses = json!({"default":{"description":"Synthetic reply","headers":{"X-Checksum":{"schema":{"type":"string"}}}}});
    let mut operation =
        |path: &str, method: &str, id: &str, parameters: Value, media: Option<&str>| {
            let mut operation =
                json!({"operationId":id,"parameters":parameters,"responses":responses});
            if let Some(media) = media {
                operation["requestBody"] =
                    json!({"required":true,"content":{media:{"schema":{"type":"object"}}}});
            }
            paths.entry(path.to_owned()).or_insert_with(|| json!({}))[method] = operation;
        };
    let id = json!({"name":"id","in":"path","required":true,"schema":{"type":"string","minLength":1,"maxLength":64}});
    operation(
        "/items/{id}",
        "get",
        "read_item",
        json!([id.clone(),
        {"name":"count","in":"query","schema":{"type":"integer","minimum":1,"maximum":10}},
        {"name":"X-Revision","in":"header","schema":{"type":"integer","minimum":1,"maximum":10}}]),
        None,
    );
    operation(
        "/items/{id}",
        "post",
        "update_item",
        json!([id]),
        Some("application/json"),
    );
    operation("/items/private", "get", "private_item", json!([]), None);
    for (path, method, id, media) in [
        ("/blob", "get", "download_blob", None),
        ("/blob", "head", "head_blob", None),
        ("/blob", "options", "options_blob", None),
        ("/encoded", "get", "encoded_blob", None),
        ("/empty", "get", "empty_result", None),
        ("/conditional", "get", "conditional", None),
        ("/stream", "get", "stream_blob", None),
        (
            "/upload",
            "post",
            "upload_bytes",
            Some("application/octet-stream"),
        ),
        (
            "/form",
            "post",
            "upload_form",
            Some("application/x-www-form-urlencoded"),
        ),
    ] {
        operation(path, method, id, json!([]), media);
    }
    operation(
        "/errors/{code}",
        "get",
        "error_status",
        json!([
            {"name":"code","in":"path","required":true,"schema":{"type":"integer","enum":[401,403,404,429,500,503,302]}}
        ]),
        None,
    );
    value["paths"] = Value::Object(paths);
    if auth != UpstreamAuth::Anonymous {
        value["components"] = json!({"securitySchemes":{"access":match auth {
            UpstreamAuth::Bearer => json!({"type":"http","scheme":"bearer"}),
            UpstreamAuth::Basic => json!({"type":"http","scheme":"basic"}),
            UpstreamAuth::Header => json!({"type":"apiKey","in":"header","name":"X-Inventory-Key"}),
            UpstreamAuth::Anonymous => unreachable!(),
        }}});
        value["security"] = json!([{"access":[]}]);
    }
    if matches!(dialect, Dialect::Swagger2) {
        let endpoint = url::Url::parse(endpoint).unwrap();
        let object = value.as_object_mut().unwrap();
        object.remove("openapi");
        object.remove("servers");
        object.insert("swagger".into(), json!("2.0"));
        object.insert("schemes".into(), json!([endpoint.scheme()]));
        object.insert("host".into(), json!(endpoint.authority()));
        object.insert("basePath".into(), json!(endpoint.path()));
        if let Some(components) = object.remove("components") {
            object.insert(
                "securityDefinitions".into(),
                components["securitySchemes"].clone(),
            );
        }
        for item in object
            .get_mut("paths")
            .unwrap()
            .as_object_mut()
            .unwrap()
            .values_mut()
        {
            for operation in item.as_object_mut().unwrap().values_mut() {
                for parameter in operation["parameters"].as_array_mut().unwrap() {
                    let schema = parameter.as_object_mut().unwrap().remove("schema").unwrap();
                    parameter
                        .as_object_mut()
                        .unwrap()
                        .extend(schema.as_object().unwrap().clone());
                }
                for response in operation["responses"].as_object_mut().unwrap().values_mut() {
                    for header in response["headers"].as_object_mut().unwrap().values_mut() {
                        *header = header["schema"].clone();
                    }
                }
                if let Some(body) = operation.as_object_mut().unwrap().remove("requestBody") {
                    let media = body["content"].as_object().unwrap().keys().next().unwrap();
                    operation["consumes"] = json!([media]);
                    operation["parameters"].as_array_mut().unwrap().push(json!({"name":"body","in":"body","required":true,"schema":{"type":"object"}}));
                }
            }
        }
    }
    value
}

pub(super) struct Fixture {
    pub seed: super::super::imports_foundation::Fixture,
    pub broker: TestBroker,
    pub client: reqwest::Client,
    pub admin: String,
    pub agent: String,
    endpoint: String,
    document_url: String,
}

impl Fixture {
    pub async fn start(upstream: &Upstream, configure: impl FnOnce(&mut BrokerConfig)) -> Self {
        let mut seed = super::super::imports_foundation::fixture();
        seed.config
            .imports
            .allowed_kinds
            .push("openapi_gateway".into());
        seed.config
            .imports
            .allowed_endpoints
            .extend([upstream.endpoint(), upstream.document_url()]);
        seed.config.imports.gateway_bindings.insert(
            SERVICE.into(),
            ImportedGatewayBinding {
                endpoint: upstream.endpoint(),
                broker_hosts: vec![GATEWAY_HOST.into()],
                auth_modes: vec!["bearer_broker_token".into(), "basic_broker_token".into()],
                allow_forwarded_identity: false,
                basic_broker_token_username: "agent-access".into(),
                egress_proxy: None,
                redirect_policy: "none".into(),
                request_body_max_bytes: Some(64 * 1024),
                response_body_max_bytes: Some(64 * 1024),
                streaming_idle_timeout_ms: Some(2000),
                correlation_headers: true,
            },
        );
        configure(&mut seed.config);
        let admin = issue(&seed, "admin", BrokerTokenClass::Admin, json!({}));
        let agent = issue(
            &seed,
            "alice",
            BrokerTokenClass::AgentInvoke,
            json!({"allowedServices":[SERVICE],"allowedExecutionContexts":["default"],"readOnly":false}),
        );
        let broker = TestBroker::start_with(
            TestBroker::config_builder(&seed.config)
                .gateway_listener()
                .unwrap()
                .shutdown_timeout(Duration::from_secs(5)),
        )
        .await;
        let client = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .no_gzip()
            .no_brotli()
            .no_deflate()
            .no_zstd()
            .timeout(Duration::from_secs(10))
            .build()
            .unwrap();
        Self {
            seed,
            broker,
            client,
            admin,
            agent,
            endpoint: upstream.endpoint(),
            document_url: upstream.document_url(),
        }
    }
    pub async fn ready(upstream: &Upstream, auth: UpstreamAuth, actions: &[&str]) -> Self {
        Self::ready_with(upstream, auth, actions, |_| {}).await
    }
    pub async fn ready_with(
        upstream: &Upstream,
        auth: UpstreamAuth,
        actions: &[&str],
        configure: impl FnOnce(&mut BrokerConfig),
    ) -> Self {
        let fixture = Self::start(upstream, configure).await;
        let document = document(Dialect::OpenApi31, auth, &upstream.endpoint());
        let preview = fixture
            .create_and_discover(DefinitionSource::Upload, auth, &document)
            .await;
        fixture.accept(&preview, actions).await;
        fixture.enable().await;
        fixture.grant(actions).await;
        fixture
    }
    pub fn public(&self, method: Method, path: &str) -> reqwest::RequestBuilder {
        self.client
            .request(
                method,
                format!("{}{path}", self.broker.running().public_url()),
            )
            .header(REQUEST_ID_HEADER, "gateway-acceptance-management")
    }
    pub fn gateway(&self, method: Method, path: &str, id: &str) -> reqwest::RequestBuilder {
        self.gateway_as(&self.agent, method, path, id)
    }
    pub fn gateway_on_host(
        &self,
        host: &str,
        method: Method,
        path: &str,
        id: &str,
    ) -> reqwest::RequestBuilder {
        let mut headers = HeaderMap::new();
        headers.insert(HOST, HeaderValue::from_str(host).unwrap());
        // RequestBuilder::header appends; headers replaces the default Host.
        self.gateway(method, path, id).headers(headers)
    }
    pub fn gateway_as(
        &self,
        token: &str,
        method: Method,
        path: &str,
        id: &str,
    ) -> reqwest::RequestBuilder {
        self.gateway_request(method, path, id).bearer_auth(token)
    }
    pub fn gateway_request(&self, method: Method, path: &str, id: &str) -> reqwest::RequestBuilder {
        self.client
            .request(
                method,
                format!(
                    "http://{}{path}",
                    self.broker.running().gateway_addr().unwrap()
                ),
            )
            .header(HOST, GATEWAY_HOST)
            .header(REQUEST_ID_HEADER, id)
    }
    pub fn issue_agent(&self, read_only: bool) -> String {
        self.issue_agent_for("alice", read_only)
    }
    pub fn issue_agent_for(&self, principal: &str, read_only: bool) -> String {
        issue(
            &self.seed,
            principal,
            BrokerTokenClass::AgentInvoke,
            json!({"allowedServices":[SERVICE],"allowedExecutionContexts":["default"],"readOnly":read_only}),
        )
    }
    pub async fn admin_request(
        &self,
        method: Method,
        path: &str,
        body: Option<Value>,
    ) -> (StatusCode, Value) {
        let mut request = self.public(method, path).bearer_auth(&self.admin);
        if let Some(body) = body {
            request = request.json(&body);
        }
        let response = request.send().await.unwrap();
        let status = response.status();
        (status, response.json().await.unwrap())
    }
    pub async fn admin_ok(&self, method: Method, path: &str, body: Option<Value>) -> Value {
        let (status, body) = self.admin_request(method, path, body).await;
        assert_eq!(status, StatusCode::OK, "{path}: {body}");
        body["result"].clone()
    }
    pub async fn detail(&self) -> Value {
        self.admin_ok(Method::GET, "/v1/admin/imports/inventory", None)
            .await
    }
    pub async fn create_and_discover(
        &self,
        source: DefinitionSource,
        auth: UpstreamAuth,
        document: &Value,
    ) -> Value {
        self.create_and_discover_with_bindings(
            source,
            auth,
            document,
            &[ImportedCredentialMode::Service],
        )
        .await
    }
    pub async fn create_and_discover_with_bindings(
        &self,
        source: DefinitionSource,
        auth: UpstreamAuth,
        document: &Value,
        modes: &[ImportedCredentialMode],
    ) -> Value {
        let mut definition = super::super::imports_foundation::definition();
        definition.service = SERVICE.into();
        definition.display_name = "Synthetic inventory gateway".into();
        definition.adapter_kind = "openapi_gateway".into();
        definition.endpoint = self.endpoint.clone();
        definition.discovery = ImportedDiscoveryCredential::Anonymous;
        definition.connection_settings.insert(
            "executionAuthentication".into(),
            if auth == UpstreamAuth::Anonymous {
                "anonymous"
            } else {
                "static"
            }
            .into(),
        );
        match source {
            DefinitionSource::Upload => {
                definition
                    .connection_settings
                    .insert("definitionSource".into(), "upload".into());
            }
            DefinitionSource::Url => {
                definition
                    .connection_settings
                    .insert("definitionUrl".into(), self.document_url.clone());
            }
        }
        definition.execution_bindings = if auth == UpstreamAuth::Anonymous {
            vec![]
        } else {
            definition
                .connection_settings
                .insert("securityScheme".into(), "access".into());
            let delivery = match auth {
                UpstreamAuth::Bearer => ImportedCredentialDelivery::Bearer,
                UpstreamAuth::Basic => ImportedCredentialDelivery::Basic,
                UpstreamAuth::Header => ImportedCredentialDelivery::RawHeader {
                    name: "X-Inventory-Key".into(),
                },
                UpstreamAuth::Anonymous => unreachable!(),
            };
            modes
                .iter()
                .map(|mode| ImportedCredentialBinding::token(*mode, delivery.clone()))
                .collect()
        };
        self.admin_ok(Method::POST, "/v1/admin/imports", Some(json!(definition)))
            .await;
        if auth != UpstreamAuth::Anonymous && modes.contains(&ImportedCredentialMode::Service) {
            let mut secret = versions(&self.detail().await);
            secret["token"] = json!(UPSTREAM_TOKEN);
            if auth == UpstreamAuth::Basic {
                secret["username"] = json!("synthetic-upstream-user");
            }
            self.admin_ok(
                Method::PUT,
                "/v1/admin/imports/inventory/credentials/execution",
                Some(secret),
            )
            .await;
        }
        match source {
            DefinitionSource::Upload => self.upload(document).await,
            DefinitionSource::Url => {
                self.admin_ok(
                    Method::POST,
                    "/v1/admin/imports/inventory/discover",
                    Some(versions(&self.detail().await)),
                )
                .await
            }
        }
    }
    pub async fn upload(&self, document: &Value) -> Value {
        let current = self.detail().await;
        let path = format!(
            "/v1/admin/imports/inventory/document?expectedVersion={}&expectedCatalogRevision={}&filename=inventory.json",
            current["service"]["version"], current["catalogRevision"]
        );
        let response = self
            .public(Method::PUT, &path)
            .bearer_auth(&self.admin)
            .header(CONTENT_TYPE, "application/json")
            .body(serde_json::to_vec(document).unwrap())
            .send()
            .await
            .unwrap();
        let status = response.status();
        let body: Value = response.json().await.unwrap();
        assert_eq!(status, StatusCode::OK, "{body}");
        body["result"].clone()
    }
    pub async fn accept(&self, preview: &Value, selected: &[&str]) -> Value {
        let mut request = versions(preview);
        request["manifestHash"] = preview["preview"]["manifestHash"].clone();
        request["confirmAffectedGrants"] = json!(true);
        request["selections"] = Value::Array(
            selected
                .iter()
                .map(|name| {
                    let tool = preview["preview"]["manifest"]["tools"]
                        .as_array()
                        .unwrap()
                        .iter()
                        .find(|tool| tool["definition"]["action"] == *name)
                        .unwrap_or_else(|| panic!("missing {name}: {preview}"));
                    assert!(
                        tool.get("unsupportedReason").is_none_or(Value::is_null),
                        "{tool}"
                    );
                    json!({"source":tool["definition"]["source"],"action":name,
                "readOnly":!matches!(*name, "update_item"|"upload_bytes"|"upload_form"|"write_then_drop")})
                })
                .collect(),
        );
        self.admin_ok(
            Method::POST,
            "/v1/admin/imports/inventory/accept",
            Some(request),
        )
        .await
    }
    pub async fn enable(&self) {
        let mut request = versions(&self.detail().await);
        request["status"] = json!("enabled");
        self.admin_ok(
            Method::POST,
            "/v1/admin/imports/inventory/status",
            Some(request),
        )
        .await;
    }
    pub async fn grant(&self, actions: &[&str]) {
        self.grant_for("alice", actions, "service", None).await;
    }
    pub async fn grant_for(
        &self,
        principal: &str,
        actions: &[&str],
        mode: &str,
        priority: Option<i32>,
    ) {
        self.admin_ok(Method::POST, "/v1/admin/policy/grants", Some(json!({
            "subjects":[format!("user:{principal}")],"executionContexts":["default"],"service":SERVICE,"actions":actions,
            "resources":{"resourceIds":[],"resourceGroupIds":[]},"credentialMode":mode,"priority":priority
        }))).await;
    }
    pub async fn put_personal(&self, principal: &str, auth: UpstreamAuth, token: &str) {
        let mut secret = json!({"token":token});
        if auth == UpstreamAuth::Basic {
            secret["username"] = json!(format!("synthetic-{principal}"));
        }
        let saved = self
            .admin_ok(
                Method::PUT,
                &format!("/v1/admin/principals/{principal}/credentials/connections/{SERVICE}"),
                Some(json!({"secret":secret})),
            )
            .await;
        assert!(!saved.to_string().contains(token));
    }
    pub async fn remove_personal(&self, principal: &str) {
        self.admin_ok(
            Method::DELETE,
            &format!("/v1/admin/principals/{principal}/credentials/connections/{SERVICE}"),
            None,
        )
        .await;
    }
    pub async fn terminal(&self, id: &str) -> Value {
        tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                let records =
                    read_audit_records(Path::new(&self.seed.config.audit.as_ref().unwrap().path));
                let terminal = records
                    .into_iter()
                    .filter(|row| {
                        row["agentRequestId"] == id
                            && row["providerAudit"]["gateway"]["phase"] != "started"
                    })
                    .collect::<Vec<_>>();
                if !terminal.is_empty() {
                    assert_eq!(terminal.len(), 1, "{terminal:?}");
                    return terminal[0].clone();
                }
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        })
        .await
        .expect("one terminal gateway audit")
    }
    pub async fn wait_for_queue(&self, principal: &str, expected: u64) {
        let state = self.broker.state();
        let snapshot = state.current();
        let limiter = &state.shared_invocations;
        let epoch = limiter
            .runtime_epoch(|| Arc::ptr_eq(&state.current(), &snapshot))
            .unwrap();
        let max_wait = snapshot
            .runtime
            .configured_invocation_limits()
            .max_wait(SERVICE);
        let owner = principal.to_owned();
        let resolve: crate::ingress::invocation_limits::InvocationLimitResolver =
            Arc::new(move || {
                let runtime = snapshot.runtime.clone();
                let owner = owner.clone();
                Box::pin(async move {
                    runtime
                        .effective_invocation_limit(&owner, SERVICE)
                        .await
                        .map(|value| value.limit())
                })
            });
        tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                let observed = limiter
                    .observe(epoch, principal, SERVICE, max_wait, resolve.clone())
                    .await
                    .unwrap();
                if observed.invocations.queued_requests == expected {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        })
        .await
        .expect("gateway queue reaches the expected size");
    }
    pub async fn restart_without_gateway(self) -> Self {
        let Self {
            mut seed,
            broker,
            client,
            admin,
            agent,
            endpoint,
            document_url,
        } = self;
        broker.stop().await;
        let source = seed.config.providers.registry();
        let mut registry = agent_access_core::BackendRegistry::new(source.registrations())
            .unwrap()
            .with_imported_adapters(source.imported_adapter_registrations().cloned())
            .unwrap()
            .with_gateways(
                source
                    .gateway_registrations()
                    .filter(|gateway| gateway.kind() != "openapi_gateway"),
            )
            .unwrap();
        let standalone_dialects = source
            .oauth_dialects()
            .filter(|dialect| registry.oauth_dialect(dialect.id()).is_none())
            .collect::<Vec<_>>();
        registry = registry.with_oauth_dialects(standalone_dialects).unwrap();
        seed.config.providers = agent_access_core::ProvidersConfig::new(Arc::new(registry));
        let broker = TestBroker::start_with(
            TestBroker::config_builder(&seed.config)
                .gateway_listener()
                .unwrap()
                .shutdown_timeout(Duration::from_secs(5)),
        )
        .await;
        Self {
            seed,
            broker,
            client,
            admin,
            agent,
            endpoint,
            document_url,
        }
    }
    pub async fn stop(self) {
        self.broker.stop().await;
    }
}

pub(super) fn versions(current: &Value) -> Value {
    json!({"expectedVersion":current["service"]["version"],"expectedCatalogRevision":current["catalogRevision"]})
}
fn issue(
    seed: &super::super::imports_foundation::Fixture,
    principal: &str,
    class: BrokerTokenClass,
    scopes: Value,
) -> String {
    seed.runtime
        .managed_store()
        .unwrap()
        .issue_broker_token(
            &BrokerTokenHasher::load(seed.config.broker_tokens.as_ref().unwrap()).unwrap(),
            BrokerTokenIssueRequest {
                principal_id: principal.into(),
                name: "gateway acceptance".into(),
                token_class: class,
                scopes,
                expires_at: None,
                created_by: "admin".into(),
            },
        )
        .unwrap()
        .token
}
