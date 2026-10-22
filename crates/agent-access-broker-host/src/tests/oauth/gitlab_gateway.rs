//! Git smart HTTP through the Git gateway on a GitLab OAuth credential
//! connection, against a fake GitLab instance over TLS: its token endpoint
//! rotates both tokens on every refresh and revokes the earlier ones, as
//! GitLab does, and its Git routes accept only current access as Basic
//! `oauth2:<token>`.
use super::*;
use agent_access_core::{
    ConnectionConfig, ConnectionOAuthConfig, CreateResourceRequest, GatewayConfig,
    GatewayGitConfig, GatewayUpstreamTokenAuth, ManagedPolicyGrantCreateRequest, OAuthBinding,
    OutboundTlsConfig, OutboundTlsTrustMode,
};
use agent_access_provider::{
    OAuthClientAuth, OAuthRotation, OAuthScopeMode, OAuthTokenEncoding, ResourceSelector,
};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, pem::PemObject};
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::process::{Command, Output, Stdio};
use std::sync::Mutex;
use std::sync::atomic::AtomicBool;
use std::thread::JoinHandle;

const GIT_HOST: &str = "git.example.test";
const CONNECTION: &str = "gitlab";
const GATEWAY: &str = "gitlab_git";
const PORTAL: &str = "under My access > Credentials in the Agent Access Broker portal";

fn tls_fixture(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../agent-access-core/tests/fixtures/outbound-tls")
        .join(name)
}

/// How the fake instance answers a refresh.
#[derive(Clone, Copy, Default)]
enum Refresh {
    /// Issue the next pair and revoke the earlier one.
    #[default]
    Rotate,
    /// A 5xx answer: the outcome is unknown.
    Fail,
    /// HTTP 429 with `Retry-After`.
    Throttle(u64),
}

/// A request the fake instance received.
#[derive(Clone, Debug)]
struct Seen {
    method: String,
    target: String,
    authorization: Option<String>,
}

/// Holds the next matching request until the test releases it.
struct Hold {
    arrived: tokio::sync::oneshot::Sender<()>,
    release: std::sync::mpsc::Receiver<()>,
}

struct Held {
    arrived: tokio::sync::oneshot::Receiver<()>,
    release: std::sync::mpsc::Sender<()>,
}

impl Held {
    async fn arrived(&mut self) {
        tokio::time::timeout(Duration::from_secs(20), &mut self.arrived)
            .await
            .expect("the held request arrives")
            .unwrap();
    }

    fn release(self) {
        let _ = self.release.send(());
    }
}

#[derive(Default)]
struct GitlabState {
    /// Token pairs issued so far; pair `n` is `gitlab-access-n` and
    /// `gitlab-refresh-n`.
    issued: usize,
    /// Tokens the Git routes accept: current OAuth access and stored tokens.
    accepted: BTreeSet<String>,
    /// Every Git request is refused, whatever it presents.
    refuse_git: bool,
    refresh: Refresh,
    requests: Vec<Seen>,
    hold_git: Option<Hold>,
    hold_refresh: Option<Hold>,
    /// Bare repositories the Git routes serve through `git http-backend`;
    /// without them, accepted Git requests answer a flush packet.
    repositories: Option<PathBuf>,
}

struct FakeGitlab {
    address: SocketAddr,
    state: Arc<Mutex<GitlabState>>,
    stopped: Arc<AtomicBool>,
    accept: Option<JoinHandle<()>>,
}

impl FakeGitlab {
    fn start() -> Self {
        let tls = Arc::new(
            rustls::ServerConfig::builder_with_provider(Arc::new(
                rustls::crypto::ring::default_provider(),
            ))
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(
                CertificateDer::pem_slice_iter(&std::fs::read(tls_fixture("leaf-a.pem")).unwrap())
                    .collect::<Result<Vec<_>, _>>()
                    .unwrap(),
                PrivateKeyDer::from_pem_slice(&std::fs::read(tls_fixture("leaf-a.key")).unwrap())
                    .unwrap(),
            )
            .unwrap(),
        );
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let state = Arc::new(Mutex::new(GitlabState::default()));
        let stopped = Arc::new(AtomicBool::new(false));
        let accept = {
            let (state, stopped) = (Arc::clone(&state), Arc::clone(&stopped));
            std::thread::spawn(move || {
                while let Ok((stream, _)) = listener.accept() {
                    if stopped.load(Ordering::Acquire) {
                        break;
                    }
                    // A held request must not hold up the others.
                    let (tls, state) = (Arc::clone(&tls), Arc::clone(&state));
                    std::thread::spawn(move || serve(tls, stream, &state));
                }
            })
        };
        Self {
            address,
            state,
            stopped,
            accept: Some(accept),
        }
    }

    fn base_url(&self) -> String {
        format!("https://{}", self.address)
    }

    fn state(&self) -> std::sync::MutexGuard<'_, GitlabState> {
        self.state.lock().unwrap()
    }

    /// GitLab no longer accepts the current OAuth access, as after a
    /// refresh elsewhere or a revocation.
    fn revoke_access(&self) {
        self.state()
            .accepted
            .retain(|token| !token.starts_with("gitlab-access-"));
    }

    fn requests(&self) -> Vec<Seen> {
        self.state().requests.clone()
    }

    /// The requests received since `before` of them, as `METHOD target`.
    fn routes_since(&self, before: usize) -> Vec<String> {
        self.requests()[before..]
            .iter()
            .map(|seen| format!("{} {}", seen.method, seen.target))
            .collect()
    }

    fn refreshes(&self) -> usize {
        self.requests()
            .iter()
            .filter(|seen| seen.method == "POST" && seen.target == "/oauth/token")
            .count()
            - 1
    }

    fn hold(&self, slot: impl FnOnce(&mut GitlabState) -> &mut Option<Hold>) -> Held {
        let (arrived, arrival) = tokio::sync::oneshot::channel();
        let (release, released) = std::sync::mpsc::channel();
        *slot(&mut self.state()) = Some(Hold {
            arrived,
            release: released,
        });
        Held {
            arrived: arrival,
            release,
        }
    }
}

impl Drop for FakeGitlab {
    fn drop(&mut self) {
        self.stopped.store(true, Ordering::Release);
        let _ = TcpStream::connect(self.address);
        if let Some(accept) = self.accept.take() {
            let _ = accept.join();
        }
    }
}

/// `Authorization: Basic` for `username:token`.
fn basic(username: &str, token: &str) -> String {
    format!("Basic {}", BASE64.encode(format!("{username}:{token}")))
}

struct Incoming {
    method: String,
    target: String,
    headers: BTreeMap<String, String>,
    body: Vec<u8>,
}

fn serve(tls: Arc<rustls::ServerConfig>, stream: TcpStream, state: &Mutex<GitlabState>) {
    let _ = stream.set_read_timeout(Some(Duration::from_secs(10)));
    let _ = stream.set_write_timeout(Some(Duration::from_secs(10)));
    let Ok(connection) = rustls::ServerConnection::new(tls) else {
        return;
    };
    let mut stream = rustls::StreamOwned::new(connection, stream);
    let Some(request) = read_request(&mut stream) else {
        return;
    };
    let (status, headers, body) = respond(state, request);
    let _ = write!(
        stream,
        "HTTP/1.1 {status}\r\n{headers}Content-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    );
    let _ = stream.write_all(&body);
    let _ = stream.flush();
}

fn read_line(reader: &mut impl BufRead) -> Option<String> {
    let mut bytes = Vec::new();
    reader.take(16_384).read_until(b'\n', &mut bytes).ok()?;
    if !bytes.ends_with(b"\n") {
        return None;
    }
    String::from_utf8(bytes).ok()
}

fn read_request(stream: &mut impl Read) -> Option<Incoming> {
    let mut reader = BufReader::new(stream);
    let line = read_line(&mut reader)?;
    let mut parts = line.split_whitespace();
    let (method, target) = (parts.next()?.to_owned(), parts.next()?.to_owned());
    let mut headers = BTreeMap::new();
    loop {
        let line = read_line(&mut reader)?;
        if line == "\r\n" {
            break;
        }
        let (name, value) = line.split_once(':')?;
        headers.insert(name.to_ascii_lowercase(), value.trim().to_owned());
    }
    let mut body = Vec::new();
    if headers
        .get("transfer-encoding")
        .is_some_and(|value| value.eq_ignore_ascii_case("chunked"))
    {
        loop {
            let size = read_line(&mut reader)?;
            let size = usize::from_str_radix(size.trim().split(';').next()?, 16).ok()?;
            if size == 0 {
                read_line(&mut reader)?;
                break;
            }
            let start = body.len();
            body.resize(start + size, 0);
            reader.read_exact(&mut body[start..]).ok()?;
            read_line(&mut reader)?;
        }
    } else if let Some(length) = headers.get("content-length") {
        body.resize(length.parse().ok()?, 0);
        reader.read_exact(&mut body).ok()?;
    }
    Some(Incoming {
        method,
        target,
        headers,
        body,
    })
}

type Reply = (String, String, Vec<u8>);

fn json_reply(status: &str, body: Value) -> Reply {
    (
        status.into(),
        "Content-Type: application/json\r\n".into(),
        body.to_string().into_bytes(),
    )
}

fn respond(state: &Mutex<GitlabState>, request: Incoming) -> Reply {
    let path = request
        .target
        .split('?')
        .next()
        .unwrap_or_default()
        .to_owned();
    let form = url::form_urlencoded::parse(&request.body)
        .into_owned()
        .collect::<BTreeMap<_, _>>();
    let grant = form.get("grant_type").map(String::as_str);
    let hold = {
        let mut state = state.lock().unwrap();
        state.requests.push(Seen {
            method: request.method.clone(),
            target: request.target.clone(),
            authorization: request.headers.get("authorization").cloned(),
        });
        match (request.method.as_str(), path.as_str()) {
            ("POST", "/oauth/token") if grant == Some("refresh_token") => state.hold_refresh.take(),
            ("POST", "/oauth/token" | "/oauth/revoke") | ("GET", "/api/v4/user") => None,
            _ => state.hold_git.take(),
        }
    };
    if let Some(hold) = hold {
        let _ = hold.arrived.send(());
        let _ = hold.release.recv_timeout(Duration::from_secs(30));
    }
    let mut state = state.lock().unwrap();
    match (request.method.as_str(), path.as_str()) {
        ("POST", "/oauth/token") => {
            return match (grant, state.refresh) {
                (Some("authorization_code"), _) => issue(&mut state, true),
                (Some("refresh_token"), Refresh::Rotate)
                    if form.get("refresh_token")
                        == Some(&format!("gitlab-refresh-{}", state.issued)) =>
                {
                    issue(&mut state, false)
                }
                (Some("refresh_token"), Refresh::Fail) => {
                    json_reply("500 Internal Server Error", json!({}))
                }
                (Some("refresh_token"), Refresh::Throttle(seconds)) => (
                    "429 Too Many Requests".into(),
                    format!("Retry-After: {seconds}\r\n"),
                    Vec::new(),
                ),
                _ => json_reply("400 Bad Request", json!({"error": "invalid_grant"})),
            };
        }
        ("GET", "/api/v4/user") => {
            return json_reply("200 OK", json!({"id": 42, "username": "alice"}));
        }
        ("POST", "/oauth/revoke") => return json_reply("200 OK", json!({})),
        _ => {}
    }
    let token = request
        .headers
        .get("authorization")
        .and_then(|value| value.strip_prefix("Basic "))
        .and_then(|encoded| BASE64.decode(encoded).ok())
        .and_then(|decoded| String::from_utf8(decoded).ok())
        .and_then(|decoded| decoded.strip_prefix("oauth2:").map(str::to_owned));
    let accepted = !state.refuse_git && token.is_some_and(|token| state.accepted.contains(&token));
    let repositories = state.repositories.clone();
    drop(state);
    if !accepted {
        return (
            "401 Unauthorized".into(),
            "WWW-Authenticate: Basic realm=\"GitLab\"\r\n".into(),
            b"HTTP Basic: Access denied\n".to_vec(),
        );
    }
    if let Some(root) = repositories {
        return http_backend(&root, &request, &path);
    }
    let content_type = match path.rsplit('/').next() {
        Some("refs") => "application/x-git-upload-pack-advertisement",
        Some("git-upload-pack") => "application/x-git-upload-pack-result",
        _ => "application/x-git-receive-pack-result",
    };
    (
        "200 OK".into(),
        format!("Content-Type: {content_type}\r\n"),
        b"0000".to_vec(),
    )
}

/// `git` with no inherited Git or proxy configuration.
fn isolated_git() -> Command {
    let mut command = Command::new("git");
    for (name, _) in std::env::vars_os() {
        let key = name.to_string_lossy();
        if key.starts_with("GIT_") || key.to_ascii_lowercase().ends_with("_proxy") {
            command.env_remove(name);
        }
    }
    command
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("GIT_TERMINAL_PROMPT", "0")
        .env("GIT_AUTHOR_NAME", "Gateway Test")
        .env("GIT_AUTHOR_EMAIL", "git@example.test")
        .env("GIT_COMMITTER_NAME", "Gateway Test")
        .env("GIT_COMMITTER_EMAIL", "git@example.test");
    command
}

/// One request served by `git http-backend` over the bare repositories
/// under `root`.
fn http_backend(root: &Path, request: &Incoming, path: &str) -> Reply {
    let query = request
        .target
        .split_once('?')
        .map_or("", |(_, query)| query);
    let header = |name: &str| request.headers.get(name).cloned().unwrap_or_default();
    let mut child = isolated_git()
        .arg("http-backend")
        .env("GIT_PROJECT_ROOT", root)
        .env("GIT_HTTP_EXPORT_ALL", "1")
        .env("PATH_INFO", path)
        .env("QUERY_STRING", query)
        .env("REQUEST_METHOD", &request.method)
        .env("CONTENT_TYPE", header("content-type"))
        .env("CONTENT_LENGTH", request.body.len().to_string())
        .env("REMOTE_ADDR", "127.0.0.1")
        .env("SERVER_PROTOCOL", "HTTP/1.1")
        .env("HTTP_GIT_PROTOCOL", header("git-protocol"))
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("git http-backend must be installed");
    let mut stdin = child.stdin.take().unwrap();
    let body = request.body.clone();
    let writer = std::thread::spawn(move || stdin.write_all(&body));
    let output = child.wait_with_output().unwrap();
    writer.join().unwrap().unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let boundary = output
        .stdout
        .windows(4)
        .position(|bytes| bytes == b"\r\n\r\n")
        .unwrap();
    let mut status = "200 OK".to_owned();
    let mut headers = String::new();
    for line in String::from_utf8_lossy(&output.stdout[..boundary]).split("\r\n") {
        let (name, value) = line.split_once(':').unwrap();
        if name.eq_ignore_ascii_case("status") {
            status = value.trim().to_owned();
        } else {
            headers.push_str(line);
            headers.push_str("\r\n");
        }
    }
    (status, headers, output.stdout[boundary + 4..].to_vec())
}

/// Issues the next token pair; GitLab revokes both earlier tokens. A code
/// exchange answers with `scope`; a refresh omits it.
fn issue(state: &mut GitlabState, exchange: bool) -> Reply {
    state
        .accepted
        .retain(|token| !token.starts_with("gitlab-access-"));
    state.issued += 1;
    let access = format!("gitlab-access-{}", state.issued);
    state.accepted.insert(access.clone());
    let mut body = json!({
        "access_token": access,
        "refresh_token": format!("gitlab-refresh-{}", state.issued),
        "token_type": "Bearer",
        "expires_in": 7200,
        "created_at": 1_760_000_000
    });
    if exchange {
        body["scope"] = json!("api write_repository");
    }
    json_reply("200 OK", body)
}

/// The OAuth fixture with a `gitlab` registration on `gitlab`, and a Git
/// gateway on the same instance whose personal credential connection uses
/// it, with a stored token form for service accounts. Alice may fetch and
/// push `team/project` through the gateway.
async fn gateway_fixture(gitlab: &FakeGitlab) -> OAuthFixture {
    let base = gitlab.base_url();
    let fixture = oauth_fixture_with(
        None,
        |_, config| {
            let client_secret_ref = config.oauth.registrations["stub"].client_secret_ref.clone();
            config.network.outbound_tls = OutboundTlsConfig {
                trust: OutboundTlsTrustMode::Custom,
                ca_certificate: Some(tls_fixture("ca-a.pem")),
            };
            config.oauth.registrations.insert(
                "gitlab".into(),
                OAuthRegistrationConfig {
                    login_binding: None,
                    adapter: OAuthAdapter::new("gitlab"),
                    base_url: base.clone(),
                    redirect_uri: "http://127.0.0.1/v1/oauth/callback/gitlab".into(),
                    client_id: "broker-app".into(),
                    client_secret_ref,
                    adapter_settings: Default::default(),
                    client_auth: OAuthClientAuth::ClientSecretPost,
                    encoding: OAuthTokenEncoding::Form,
                    rotation: OAuthRotation::RotateBoth,
                    allow_insecure_loopback: true,
                    permission_profiles: BTreeMap::from([(
                        "default".into(),
                        OAuthPermissionProfile {
                            scope_mode: OAuthScopeMode::Explicit,
                            scopes: Some(vec!["api".into(), "write_repository".into()]),
                            audience: "gitlab".into(),
                            target: base.clone(),
                        },
                    )]),
                },
            );
            config.credentials.connections.insert(
                CONNECTION.into(),
                ConnectionConfig {
                    display_name: Some("GitLab".into()),
                    token_profiles: Some(vec!["git-bearer-token".into()]),
                    service_account_token_profiles: None,
                    oauth: Some(ConnectionOAuthConfig {
                        registration: "gitlab".into(),
                        profile: "default".into(),
                    }),
                },
            );
            config
                .credentials
                .per_user
                .insert(GATEWAY.into(), connection_credential(CONNECTION));
            config.gateways.insert(
                GATEWAY.into(),
                GatewayConfig {
                    allow_forwarded_identity: false,
                    kind: "git_http".into(),
                    display_name: "GitLab Git".into(),
                    broker_hosts: vec![GIT_HOST.into()],
                    upstream_base_url: base.clone(),
                    allowed_upstream_hosts: vec![format!("{base}/**")],
                    egress_proxy: None,
                    auth_modes: vec!["basic_broker_token".into()],
                    basic_broker_token_username: "agent-access".into(),
                    credential_modes: vec!["per_user".into()],
                    upstream_token_auth: GatewayUpstreamTokenAuth::Basic {
                        username: "oauth2".into(),
                    },
                    redirect_policy: "none".into(),
                    request_body_max_bytes: None,
                    response_body_max_bytes: None,
                    streaming_idle_timeout_ms: None,
                    correlation_headers: true,
                    git: Some(GatewayGitConfig {
                        allow_fetch: true,
                        allow_push: true,
                        deny_ref_patterns: Vec::new(),
                        deny_delete_refs: true,
                        receive_pack_prefix_max_bytes: None,
                    }),
                },
            );
        },
        Vec::new(),
    )
    .await;
    fixture
        .runtime
        .create_managed_resource(CreateResourceRequest {
            id: Some("project".into()),
            display_name: None,
            resource_type: GIT_REPOSITORY_RESOURCE.id().clone(),
            selector: ResourceSelector::Exact {
                value: "team/project".into(),
            },
            allowed_execution_contexts: vec!["default".into()],
            enabled: true,
            attributes: Default::default(),
            created_by: "admin".into(),
        })
        .unwrap();
    git_grant(&fixture, "alice");
    fixture
}

fn git_grant(fixture: &OAuthFixture, principal: &str) {
    fixture
        .runtime
        .create_managed_policy_grant(ManagedPolicyGrantCreateRequest {
            grant_id: Some(format!("{principal}-git")),
            subjects: vec![format!("user:{principal}")],
            service: GATEWAY.into(),
            actions: vec!["repo.fetch".into(), "repo.push".into()],
            resources: ResourceSelection {
                resource_ids: vec!["project".into()],
                resource_group_ids: Vec::new(),
            },
            execution_contexts: vec!["default".into()],
            credential_mode: "per_user".into(),
            priority: None,
            status: None,
            description: None,
            created_by: "admin".into(),
        })
        .unwrap();
}

/// Connects alice's GitLab account through the portal consent flow.
async fn connect_gitlab(fixture: &OAuthFixture) {
    let connect = fixture
        .browser(
            Method::POST,
            "/v1/oauth/connect",
            "gitlab-git-connect",
            Some(json!({"registration": "gitlab", "intent": "connect"})),
        )
        .await;
    let status = connect.status();
    let connect = response_json(connect).await;
    assert_eq!(status, StatusCode::OK, "{connect}");
    let authorization_url =
        url::Url::parse(connect["result"]["authorizationUrl"].as_str().unwrap()).unwrap();
    let state = authorization_url
        .query_pairs()
        .find(|(key, _)| key == "state")
        .unwrap()
        .1
        .into_owned();
    let callback = fixture
        .browser(
            Method::GET,
            &format!(
                "/v1/oauth/callback/gitlab?{}",
                url::form_urlencoded::Serializer::new(String::new())
                    .append_pair("state", &state)
                    .append_pair("code", "one-use-code")
                    .finish()
            ),
            "gitlab-git-callback",
            None,
        )
        .await;
    assert_completion_page(callback, "Authorized", &[&state, "one-use-code"]).await;
}

#[derive(Clone, Copy)]
enum Git {
    /// `info/refs` for `git-upload-pack`.
    Discovery,
    UploadPack,
    ReceivePack,
}

/// A Git client's smart-HTTP request for `team/project` through the
/// gateway, authenticated with the Broker token `token`.
fn git_request(token: &str, git: Git, request_id: &str) -> Request<Body> {
    let builder = Request::builder()
        .extension(ConnectInfo(SOURCE.parse::<SocketAddr>().unwrap()))
        .header("Host", GIT_HOST)
        .header(AUTHORIZATION, basic("agent-access", token))
        .header("Git-Protocol", "version=2")
        .header(REQUEST_ID_HEADER, request_id);
    match git {
        Git::Discovery => builder
            .method(Method::GET)
            .uri("/team/project.git/info/refs?service=git-upload-pack")
            .body(Body::empty()),
        Git::UploadPack => builder
            .method(Method::POST)
            .uri("/team/project.git/git-upload-pack")
            .header(CONTENT_TYPE, "application/x-git-upload-pack-request")
            .body(Body::from("0014command=ls-refs\n0000")),
        Git::ReceivePack => {
            let command = format!(
                "{} {} refs/heads/feature\0report-status",
                "1".repeat(40),
                "2".repeat(40)
            );
            let mut body = format!("{:04x}{command}0000", command.len() + 4).into_bytes();
            body.extend_from_slice(b"PACK");
            builder
                .method(Method::POST)
                .uri("/team/project.git/git-receive-pack")
                .header(CONTENT_TYPE, "application/x-git-receive-pack-request")
                .body(Body::from(body))
        }
    }
    .unwrap()
}

/// A gateway answer, with its whole body read.
struct Answer {
    status: StatusCode,
    headers: axum::http::HeaderMap,
    body: String,
}

impl Answer {
    fn reason(&self) -> &str {
        self.headers
            .get(REASON_CODE_HEADER)
            .map(|value| value.to_str().unwrap())
            .unwrap_or_default()
    }

    /// A 403 Git shows as `remote:` output, with no challenge that would
    /// make Git prompt or a credential helper erase the Broker token.
    fn assert_reconnect(&self, message: &str) {
        assert_eq!(self.status, StatusCode::FORBIDDEN, "{}", self.body);
        assert_eq!(self.reason(), "credential_invalid");
        assert_eq!(
            self.headers[CONTENT_TYPE].to_str().unwrap(),
            "text/plain; charset=utf-8"
        );
        assert!(!self.headers.contains_key(WWW_AUTHENTICATE));
        assert_eq!(self.body, format!("{message}\n"));
    }
}

async fn send_git(app: Router, request: Request<Body>) -> Answer {
    let response = app.oneshot(request).await.unwrap();
    let status = response.status();
    let headers = response.headers().clone();
    let body = axum::body::to_bytes(response.into_body(), 1 << 20)
        .await
        .unwrap();
    Answer {
        status,
        headers,
        body: String::from_utf8(body.to_vec()).unwrap(),
    }
}

impl OAuthFixture {
    async fn git(&self, git: Git, request_id: &str) -> Answer {
        self.git_as(&self.agent_token, git, request_id).await
    }

    async fn git_as(&self, token: &str, git: Git, request_id: &str) -> Answer {
        send_git(
            self.broker.gateway_app(),
            git_request(token, git, request_id),
        )
        .await
    }

    /// Alice's current OAuth access version on the `gitlab` registration.
    async fn gitlab_access_version(&self) -> String {
        self.runtime
            .oauth_manager()
            .unwrap()
            .acquire("alice", &gitlab_binding())
            .await
            .unwrap()
            .access_version()
            .to_owned()
    }

    /// Another request's recovery refreshes alice's GitLab access, which
    /// revokes the access GitLab issued before.
    async fn refresh_gitlab_elsewhere(&self) {
        let version = self.gitlab_access_version().await;
        self.runtime
            .oauth_manager()
            .unwrap()
            .recover_after_unauthorized("alice", &gitlab_binding(), &version)
            .await
            .unwrap();
    }
}

fn gitlab_binding() -> OAuthBinding {
    OAuthBinding {
        registration: "gitlab".into(),
        permission_profile: "default".into(),
    }
}

fn git_route(git: Git) -> &'static str {
    match git {
        Git::Discovery => "GET /team/project.git/info/refs?service=git-upload-pack",
        Git::UploadPack => "POST /team/project.git/git-upload-pack",
        Git::ReceivePack => "POST /team/project.git/git-receive-pack",
    }
}

const REFRESH: &str = "POST /oauth/token";

/// Fetch and push through the gateway present alice's OAuth access as
/// Basic `oauth2:<access token>`, and the gateway's audit records name the
/// connection and the OAuth method.
#[tokio::test]
async fn git_through_the_gateway_presents_oauth_access_as_basic_oauth2() {
    let gitlab = FakeGitlab::start();
    let fixture = gateway_fixture(&gitlab).await;
    connect_gitlab(&fixture).await;
    let before = gitlab.requests().len();

    for (index, git) in [Git::Discovery, Git::UploadPack, Git::ReceivePack]
        .into_iter()
        .enumerate()
    {
        let answer = fixture.git(git, &format!("gitlab-git-{index}")).await;
        assert_eq!(answer.status, StatusCode::OK, "{}", answer.body);
        assert_eq!(answer.body, "0000");
    }
    let requests = gitlab.requests().split_off(before);
    assert_eq!(
        gitlab.routes_since(before),
        [
            git_route(Git::Discovery),
            git_route(Git::UploadPack),
            git_route(Git::ReceivePack)
        ]
    );
    for seen in &requests {
        assert_eq!(
            seen.authorization.as_deref(),
            Some(basic("oauth2", "gitlab-access-1").as_str())
        );
    }
    assert_eq!(gitlab.refreshes(), 0);

    let records = read_audit_records(&fixture.audit_path)
        .into_iter()
        .filter(|record| record["service"] == GATEWAY)
        .collect::<Vec<_>>();
    // A start and a completion record per request.
    assert_eq!(records.len(), 6, "{records:#?}");
    for record in records {
        assert_eq!(record["decision"], "allow", "{record}");
        assert_eq!(record["credentialMode"], "per_user", "{record}");
        assert_eq!(record["credentialConnection"], CONNECTION, "{record}");
        assert_eq!(
            record["providerAudit"]["gateway"]["credentialMethod"], "oauth",
            "{record}"
        );
    }
}

/// Ref discovery recovers once from a 401 with refreshed access; a second
/// 401 after that recovery answers 403 naming the portal reconnect.
#[tokio::test]
async fn discovery_recovers_once_from_a_401_with_refreshed_access() {
    let gitlab = FakeGitlab::start();
    let fixture = gateway_fixture(&gitlab).await;
    connect_gitlab(&fixture).await;
    gitlab.revoke_access();

    let before = gitlab.requests().len();
    let answer = fixture.git(Git::Discovery, "gitlab-git-recovered").await;
    assert_eq!(answer.status, StatusCode::OK, "{}", answer.body);
    assert_eq!(
        gitlab.routes_since(before),
        [
            git_route(Git::Discovery),
            REFRESH,
            git_route(Git::Discovery)
        ]
    );
    let requests = gitlab.requests();
    assert_eq!(
        requests[before].authorization.as_deref(),
        Some(basic("oauth2", "gitlab-access-1").as_str())
    );
    assert_eq!(
        requests[before + 2].authorization.as_deref(),
        Some(basic("oauth2", "gitlab-access-2").as_str())
    );

    // Refreshed access rejected too: no further recovery or attempt.
    gitlab.state().refuse_git = true;
    let before = gitlab.requests().len();
    let answer = fixture.git(Git::Discovery, "gitlab-git-rejected").await;
    answer.assert_reconnect(&format!(
        "GitLab rejected the connected account's renewed access; reconnect it {PORTAL}, then retry"
    ));
    assert_eq!(
        gitlab.routes_since(before),
        [
            git_route(Git::Discovery),
            REFRESH,
            git_route(Git::Discovery)
        ]
    );
    let record = read_audit_records(&fixture.audit_path)
        .into_iter()
        .rfind(|record| record["agentRequestId"] == "gitlab-git-rejected")
        .unwrap();
    assert_eq!(record["decision"], "deny");
    assert_eq!(record["reasonCode"], "credential_invalid");
    assert_eq!(record["upstreamStatus"], 401);
    assert_eq!(record["credentialConnection"], CONNECTION);
    assert_eq!(
        record["providerAudit"]["gateway"]["credentialMethod"],
        "oauth"
    );
}

/// A pack POST answered 401 is never replayed: the gateway rejects the
/// access it presented and answers 403, and the next request renews the
/// access.
#[tokio::test]
async fn pack_posts_answered_401_are_not_replayed() {
    let gitlab = FakeGitlab::start();
    let fixture = gateway_fixture(&gitlab).await;
    connect_gitlab(&fixture).await;
    let not_replayed = format!(
        "GitLab rejected the connected account's access and the Git request was not replayed; retry, and if it is rejected again, reconnect it {PORTAL}"
    );

    gitlab.revoke_access();
    let before = gitlab.requests().len();
    fixture
        .git(Git::UploadPack, "gitlab-git-fetch-rejected")
        .await
        .assert_reconnect(&not_replayed);
    assert_eq!(gitlab.routes_since(before), [git_route(Git::UploadPack)]);

    // The rejected access is not lent again: the push refreshes first.
    gitlab.state().refuse_git = true;
    let before = gitlab.requests().len();
    fixture
        .git(Git::ReceivePack, "gitlab-git-push-rejected")
        .await
        .assert_reconnect(&not_replayed);
    assert_eq!(
        gitlab.routes_since(before),
        [REFRESH, git_route(Git::ReceivePack)]
    );
    assert_eq!(
        gitlab.requests().last().unwrap().authorization.as_deref(),
        Some(basic("oauth2", "gitlab-access-2").as_str())
    );

    gitlab.state().refuse_git = false;
    let before = gitlab.requests().len();
    let answer = fixture.git(Git::Discovery, "gitlab-git-renewed").await;
    assert_eq!(answer.status, StatusCode::OK, "{}", answer.body);
    assert_eq!(
        gitlab.routes_since(before),
        [REFRESH, git_route(Git::Discovery)]
    );
    assert_eq!(
        gitlab.requests().last().unwrap().authorization.as_deref(),
        Some(basic("oauth2", "gitlab-access-3").as_str())
    );
}

/// GitLab revokes earlier tokens on every refresh. A refresh by another
/// request while a Git request is in flight makes GitLab reject that
/// request's access: ref discovery recovers with the successor, without a
/// second refresh; a pack POST fails without replay, and its late rejection
/// leaves the successor in use.
#[tokio::test]
async fn refresh_invalidation_during_in_flight_git_requests() {
    let gitlab = FakeGitlab::start();
    let fixture = gateway_fixture(&gitlab).await;
    connect_gitlab(&fixture).await;

    let before = gitlab.requests().len();
    let mut held = gitlab.hold(|state| &mut state.hold_git);
    let discovery = tokio::spawn(send_git(
        fixture.broker.gateway_app(),
        git_request(&fixture.agent_token, Git::Discovery, "gitlab-git-in-flight"),
    ));
    held.arrived().await;
    fixture.refresh_gitlab_elsewhere().await;
    held.release();
    let answer = discovery.await.unwrap();
    assert_eq!(answer.status, StatusCode::OK, "{}", answer.body);
    assert_eq!(
        gitlab.routes_since(before),
        [
            git_route(Git::Discovery),
            REFRESH,
            git_route(Git::Discovery)
        ]
    );
    let requests = gitlab.requests();
    assert_eq!(
        requests[before].authorization.as_deref(),
        Some(basic("oauth2", "gitlab-access-1").as_str())
    );
    assert_eq!(
        requests[before + 2].authorization.as_deref(),
        Some(basic("oauth2", "gitlab-access-2").as_str())
    );
    assert_eq!(gitlab.refreshes(), 1);

    let before = gitlab.requests().len();
    let mut held = gitlab.hold(|state| &mut state.hold_git);
    let fetch = tokio::spawn(send_git(
        fixture.broker.gateway_app(),
        git_request(
            &fixture.agent_token,
            Git::UploadPack,
            "gitlab-git-pack-in-flight",
        ),
    ));
    held.arrived().await;
    fixture.refresh_gitlab_elsewhere().await;
    held.release();
    fetch.await.unwrap().assert_reconnect(&format!(
        "GitLab rejected the connected account's access and the Git request was not replayed; retry, and if it is rejected again, reconnect it {PORTAL}"
    ));
    assert_eq!(
        gitlab.routes_since(before),
        [git_route(Git::UploadPack), REFRESH]
    );
    // The late 401 rejected only the access the POST presented.
    let before = gitlab.requests().len();
    let answer = fixture.git(Git::UploadPack, "gitlab-git-pack-after").await;
    assert_eq!(answer.status, StatusCode::OK, "{}", answer.body);
    assert_eq!(gitlab.routes_since(before), [git_route(Git::UploadPack)]);
    assert_eq!(
        gitlab.requests().last().unwrap().authorization.as_deref(),
        Some(basic("oauth2", "gitlab-access-3").as_str())
    );
    assert_eq!(gitlab.refreshes(), 2);
}

/// A refresh whose outcome is unknown leaves the connection needing
/// reconnect, as an unconnected account does: the gateway answers 403
/// naming the portal reconnect, and contacts GitLab no further for Git.
/// The revocation worker revokes the predecessor's tokens.
#[tokio::test]
async fn refresh_uncertain_and_unconnected_accounts_answer_403_naming_the_portal() {
    let gitlab = FakeGitlab::start();
    let fixture = gateway_fixture(&gitlab).await;
    let reconnect = format!(
        "GitLab has no usable connected account; connect or reconnect it {PORTAL}, then retry"
    );
    fixture
        .git(Git::Discovery, "gitlab-git-unconnected")
        .await
        .assert_reconnect(&reconnect);
    assert!(gitlab.requests().is_empty());

    connect_gitlab(&fixture).await;
    gitlab.revoke_access();
    gitlab.state().refresh = Refresh::Fail;
    let before = gitlab.requests().len();
    fixture
        .git(Git::Discovery, "gitlab-git-uncertain")
        .await
        .assert_reconnect(&reconnect);
    assert_eq!(
        gitlab.routes_since(before)[..2],
        [git_route(Git::Discovery), REFRESH]
    );
    let started = std::time::Instant::now();
    while gitlab
        .routes_since(before)
        .iter()
        .filter(|route| *route == "POST /oauth/revoke")
        .count()
        < 2
    {
        assert!(started.elapsed() < Duration::from_secs(20));
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    let before = gitlab.requests().len();
    for (git, request_id) in [
        (Git::Discovery, "gitlab-git-uncertain-again"),
        (Git::UploadPack, "gitlab-git-uncertain-fetch"),
    ] {
        fixture
            .git(git, request_id)
            .await
            .assert_reconnect(&reconnect);
    }
    assert_eq!(gitlab.routes_since(before), Vec::<String>::new());
}

/// A request arriving while another refreshes the connection waits for that
/// refresh and presents its successor, so GitLab sees one refresh. A
/// throttled refresh keeps its retryable answer and wait.
#[tokio::test]
async fn concurrent_requests_share_one_refresh_and_throttling_stays_retryable() {
    let gitlab = FakeGitlab::start();
    let fixture = gateway_fixture(&gitlab).await;
    connect_gitlab(&fixture).await;
    gitlab.revoke_access();

    let before = gitlab.requests().len();
    let mut held = gitlab.hold(|state| &mut state.hold_refresh);
    let recovering = tokio::spawn(send_git(
        fixture.broker.gateway_app(),
        git_request(
            &fixture.agent_token,
            Git::Discovery,
            "gitlab-git-recovering",
        ),
    ));
    held.arrived().await;
    let waiting = tokio::spawn(send_git(
        fixture.broker.gateway_app(),
        git_request(&fixture.agent_token, Git::UploadPack, "gitlab-git-waiting"),
    ));
    held.release();
    for answer in [recovering.await.unwrap(), waiting.await.unwrap()] {
        assert_eq!(answer.status, StatusCode::OK, "{}", answer.body);
    }
    let mut routes = gitlab.routes_since(before);
    routes.sort();
    let mut expected = vec![
        git_route(Git::Discovery),
        REFRESH,
        git_route(Git::Discovery),
        git_route(Git::UploadPack),
    ];
    expected.sort();
    assert_eq!(routes, expected);
    let upload = gitlab
        .requests()
        .into_iter()
        .rfind(|seen| format!("{} {}", seen.method, seen.target) == git_route(Git::UploadPack))
        .unwrap();
    assert_eq!(
        upload.authorization.as_deref(),
        Some(basic("oauth2", "gitlab-access-2").as_str())
    );

    gitlab.revoke_access();
    gitlab.state().refresh = Refresh::Throttle(30);
    let throttled = fixture.git(Git::Discovery, "gitlab-git-throttled").await;
    assert_eq!(
        throttled.status,
        StatusCode::TOO_MANY_REQUESTS,
        "{}",
        throttled.body
    );
    assert_eq!(throttled.reason(), "upstream_rate_limited");
    let retry_after = throttled.headers[RETRY_AFTER]
        .to_str()
        .unwrap()
        .parse::<u64>()
        .unwrap();
    assert!((1..=30).contains(&retry_after), "{retry_after}");
}

/// A service account's stored token on the same connection is presented as
/// Basic `oauth2:<token>`, never through OAuth; its 401 passes through.
#[tokio::test]
async fn a_service_account_token_on_the_connection_is_presented_as_basic() {
    let gitlab = FakeGitlab::start();
    let fixture = gateway_fixture(&gitlab).await;
    let store = fixture.runtime.managed_store().unwrap();
    store
        .create_principal(PrincipalWriteRequest {
            role: agent_access_core::PrincipalRole::User,
            self_service_enabled: None,
            principal_id: "robot".into(),
            kind: "service_account".into(),
            display_name: None,
            email: None,
            external_subject: None,
            created_by: "test".into(),
        })
        .unwrap();
    let robot = store
        .issue_broker_token(
            fixture.runtime.broker_token_hasher().unwrap(),
            BrokerTokenIssueRequest {
                principal_id: "robot".into(),
                name: "robot agent".into(),
                token_class: BrokerTokenClass::AgentInvoke,
                scopes: json!({"allowedExecutionContexts": ["default"]}),
                expires_at: None,
                created_by: "test".into(),
            },
        )
        .unwrap()
        .token;
    store
        .upsert_user_credential(
            fixture.runtime.credential_key_ring().unwrap(),
            CredentialWriteRequest {
                owner_principal_id: "robot".into(),
                service: CONNECTION.into(),
                name: "default".into(),
                profile: "git-bearer-token".into(),
                credential_kind: "bearer_token".into(),
                secret: json!({"token": "robot-token"}),
                metadata: json!({}),
                actor: "admin".into(),
            },
            agent_access_core::CredentialManagementPurpose::Administrative,
        )
        .unwrap();
    git_grant(&fixture, "robot");
    gitlab.state().accepted.insert("robot-token".into());

    let answer = fixture
        .git_as(&robot, Git::Discovery, "gitlab-git-robot")
        .await;
    assert_eq!(answer.status, StatusCode::OK, "{}", answer.body);
    assert_eq!(gitlab.routes_since(0), [git_route(Git::Discovery)]);
    assert_eq!(
        gitlab.requests()[0].authorization.as_deref(),
        Some(basic("oauth2", "robot-token").as_str())
    );
    let record = read_audit_records(&fixture.audit_path)
        .into_iter()
        .rfind(|record| record["agentRequestId"] == "gitlab-git-robot")
        .unwrap();
    assert_eq!(record["credentialConnection"], CONNECTION);
    assert_eq!(
        record["providerAudit"]["gateway"]["credentialMethod"],
        "token"
    );

    gitlab.state().accepted.remove("robot-token");
    let answer = fixture
        .git_as(&robot, Git::Discovery, "gitlab-git-robot-rejected")
        .await;
    assert_eq!(answer.status, StatusCode::UNAUTHORIZED, "{}", answer.body);
    assert_eq!(
        gitlab.routes_since(0),
        [git_route(Git::Discovery), git_route(Git::Discovery)]
    );
}

/// Offline validation accepts a GitLab Git gateway on the instance an OAuth
/// `gitlab` connection grants, in production.
#[test]
fn a_gitlab_git_gateway_validates_on_an_oauth_gitlab_connection() {
    let raw = format!(
        r#"{sample}
[oauth.registrations.gitlab]
adapter = "gitlab"
base_url = "https://gitlab.example.com"
redirect_uri = "https://broker.example.com/v1/oauth/callback/gitlab"
client_id = "broker-app"
client_secret_ref = "file:/etc/agent-access-broker/secrets/gitlab-oauth-client-secret"
client_auth = "client_secret_post"
rotation = "rotate_both"

[oauth.registrations.gitlab.permission_profiles.default]
scopes = ["api", "write_repository"]
audience = "gitlab"
target = "https://gitlab.example.com"

[credentials.connections.gitlab]
display_name = "GitLab"
token_profiles = ["git-bearer-token"]
oauth = {{ registration = "gitlab", profile = "default" }}

[credentials.per_user.gitlab_git]
type = "connection"
connection = "gitlab"

[gateways.gitlab_git]
kind = "git_http"
display_name = "GitLab Git"
broker_hosts = ["git.example.test"]
upstream_base_url = "https://gitlab.example.com/"
allowed_upstream_hosts = ["https://gitlab.example.com/**"]
auth_modes = ["basic_broker_token"]
basic_broker_token_username = "agent-access"
credential_modes = ["per_user"]
upstream_token_auth = {{ scheme = "basic", username = "oauth2" }}

[gateways.gitlab_git.git]
allow_fetch = true
allow_push = true
"#,
        sample = include_str!("../../../../../agent-access-broker.production.sample.toml"),
    );
    let config = agent_access_core::parse_broker_config_raw(
        "gitlab-git-oauth.toml",
        &raw,
        &Arc::new(crate::test_composition::backend_registry()),
    )
    .unwrap();
    agent_access_core::validate_broker_config(&config).unwrap();
}

/// Runs `git` in `dir` with no inherited configuration, protocol v2, no
/// redirects, a stall limit, and `config` after any credential helper is
/// cleared.
fn run_git(dir: &Path, config: &[String], args: &[String]) -> Output {
    let mut command = isolated_git();
    command.current_dir(dir).stdin(Stdio::null());
    for setting in [
        "protocol.version=2",
        "credential.helper=",
        "commit.gpgSign=false",
        "core.hooksPath=/dev/null",
        "http.followRedirects=false",
        "http.lowSpeedLimit=1",
        "http.lowSpeedTime=10",
    ]
    .into_iter()
    .map(str::to_owned)
    .chain(config.iter().cloned())
    {
        command.args(["-c", &setting]);
    }
    command.args(args).output().unwrap()
}

fn git_ok(dir: &Path, args: &[&str]) -> String {
    let args = args.iter().map(|arg| (*arg).to_owned()).collect::<Vec<_>>();
    let output = run_git(dir, &[], &args);
    assert!(
        output.status.success(),
        "git {args:?}: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout).unwrap().trim().to_owned()
}

/// A Git client of the gateway: it resolves the gateway host to its
/// loopback listener and signs in with a credential helper that supplies
/// the Broker token and logs what Git asks of it.
struct GitClient {
    config: Vec<String>,
    helper_log: PathBuf,
}

impl GitClient {
    async fn run(&self, dir: &Path, args: &[&str]) -> Output {
        let (dir, config) = (dir.to_owned(), self.config.clone());
        let args = args.iter().map(|arg| (*arg).to_owned()).collect::<Vec<_>>();
        tokio::task::spawn_blocking(move || run_git(&dir, &config, &args))
            .await
            .unwrap()
    }

    /// The operations Git asked of the credential helper.
    fn helper_operations(&self) -> Vec<String> {
        std::fs::read_to_string(&self.helper_log)
            .unwrap_or_default()
            .lines()
            .map(str::to_owned)
            .collect()
    }
}

/// A real Git client clones through the gateway on alice's OAuth
/// connection, signing in with a credential helper. When GitLab then
/// rejects the access, Git shows the gateway's 403 message as `remote:`
/// output and never asks the helper to erase the Broker token.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn real_git_clones_and_a_rejection_never_erases_the_broker_token() {
    let repositories = tempfile::TempDir::new().unwrap();
    let root = repositories.path();
    std::fs::create_dir(root.join("team")).unwrap();
    let bare = root.join("team/project.git");
    git_ok(
        root,
        &[
            "init",
            "--bare",
            "--initial-branch=main",
            "--object-format=sha1",
            "team/project.git",
        ],
    );
    git_ok(
        root,
        &[
            "init",
            "--initial-branch=main",
            "--object-format=sha1",
            "seed",
        ],
    );
    let seed = root.join("seed");
    std::fs::write(seed.join("file.txt"), "initial").unwrap();
    git_ok(&seed, &["add", "file.txt"]);
    git_ok(&seed, &["commit", "-m", "initial"]);
    git_ok(&seed, &["push", bare.to_str().unwrap(), "main"]);

    let gitlab = FakeGitlab::start();
    gitlab.state().repositories = Some(root.to_owned());
    let fixture = gateway_fixture(&gitlab).await;
    connect_gitlab(&fixture).await;
    let port = fixture.broker.running().gateway_addr().unwrap().port();
    let remote = format!("http://{GIT_HOST}:{port}/team/project.git");
    let helper_log = root.join("credential-helper.log");
    let client = GitClient {
        config: vec![
            format!("http.curloptResolve={GIT_HOST}:{port}:127.0.0.1"),
            format!(
                "credential.helper=!f() {{ echo \"$1\" >> '{}'; if test \"$1\" = get; then printf '%s\\n' username=agent-access 'password={}'; fi; }}; f",
                helper_log.display(),
                fixture.agent_token
            ),
        ],
        helper_log,
    };

    let before = gitlab.requests().len();
    let output = client.run(root, &["clone", &remote, "clone"]).await;
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let clone = root.join("clone");
    assert_eq!(
        git_ok(&clone, &["rev-parse", "HEAD"]),
        git_ok(&seed, &["rev-parse", "HEAD"])
    );
    let cloned = gitlab.requests().split_off(before);
    for route in [git_route(Git::Discovery), git_route(Git::UploadPack)] {
        assert!(
            cloned
                .iter()
                .any(|seen| format!("{} {}", seen.method, seen.target) == route),
            "{cloned:?}"
        );
    }
    for seen in &cloned {
        assert_eq!(
            seen.authorization.as_deref(),
            Some(basic("oauth2", "gitlab-access-1").as_str()),
            "{seen:?}"
        );
    }
    assert!(client.helper_operations().contains(&"get".to_owned()));

    gitlab.state().refuse_git = true;
    let output = client.run(&clone, &["fetch", "origin"]).await;
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(!output.status.success(), "{stderr}");
    let operations = client.helper_operations();
    assert!(
        !operations.contains(&"erase".to_owned()),
        "{operations:?}: {stderr}"
    );
    assert!(
        stderr.contains(&format!(
            "remote: GitLab rejected the connected account's renewed access; reconnect it {PORTAL}, then retry"
        )),
        "{stderr}"
    );
    assert!(stderr.contains("403"), "{stderr}");
}
