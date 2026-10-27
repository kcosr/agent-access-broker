//! Real Git smart-HTTP regression coverage. Requires `git` (including http-backend).
//! All repositories, credentials, configuration, listeners, and TLS trust are test-owned.
use agent_access_broker_host::test_support::IsolatedBroker;
use agent_access_broker_host::{AssemblyIdentity, BrokerComposition};
use agent_access_core::{
    BrokerTokenClass, BrokerTokenHasher, BrokerTokenIssueRequest, BrokerTokensConfig, ManagedStore,
    ManagedStoreConfig, ManagedStoreOpenMode, PrincipalRole, PrincipalWriteRequest,
};
use base64::{
    Engine as _,
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, pem::PemObject};
use serde_json::json;
use std::{
    collections::BTreeMap,
    fs,
    io::{BufRead, BufReader, Read, Write},
    net::{SocketAddr, TcpListener, TcpStream},
    path::{Path, PathBuf},
    process::{Command, Output, Stdio},
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
    thread::{self, JoinHandle},
    time::{Duration, Instant},
};
use tempfile::TempDir;

const COMMAND_TIMEOUT: Duration = Duration::from_secs(20);
const UPSTREAM_TOKEN: &str = "isolated-git-gateway-test-upstream-token";
const REPOSITORY: &str = "group/repo";
/// Larger than Git's default `http.postBuffer` (1 MiB), so Git sends its
/// flush-only probe POST before streaming the pack.
const LARGE_PUSH_BYTES: usize = 2 * 1024 * 1024;
const ORIGIN_BODY_MAX_BYTES: usize = 8 * 1024 * 1024;

// Proxy environment is a process-wide input to the real Broker runtime. Isolate
// it in a child instead of mutating the environment of a multithreaded test.
#[test]
fn real_git_clone_fetch_and_push_normalize_repository_suffix_without_following_redirects() {
    let mut command = Command::new(std::env::current_exe().unwrap());
    command
        .args([
            "--exact",
            "git_http_gateway_child",
            "--ignored",
            "--nocapture",
        ])
        .env("BROKER_GIT_HTTP_TEST_CHILD", "1");
    for (name, _) in std::env::vars_os() {
        if name
            .to_string_lossy()
            .to_ascii_lowercase()
            .ends_with("_proxy")
        {
            command.env_remove(name);
        }
    }
    command.env("NO_PROXY", "*").env("no_proxy", "*");
    let output = run_command_with_timeout(&mut command, &[], Duration::from_secs(90));
    assert!(
        output.status.success(),
        "Git gateway fixture failed: stdout={}; stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "run by the parent test with an isolated proxy environment"]
async fn git_http_gateway_child() {
    assert_eq!(
        std::env::var("BROKER_GIT_HTTP_TEST_CHILD").as_deref(),
        Ok("1")
    );
    let temp = TempDir::new().unwrap();
    private_permissions(temp.path());
    let root = temp.path();
    let upstream_repo = root.join("group/repo.git");
    fs::create_dir(root.join("group")).unwrap();
    git(
        root,
        &[
            "init",
            "--bare",
            "--initial-branch=main",
            "--object-format=sha1",
            "group/repo.git",
        ],
    );
    git(&upstream_repo, &["config", "http.receivepack", "true"]);
    git(
        root,
        &[
            "init",
            "--initial-branch=main",
            "--object-format=sha1",
            "seed",
        ],
    );
    let seed = root.join("seed");
    commit(&seed, "initial");
    git(&seed, &["push", upstream_repo.to_str().unwrap(), "main"]);

    let origin = GitOrigin::start(root);
    let (config_path, token) = broker_config(root, origin.address);
    // The configuration selects only the Git gateway, which needs no native
    // provider module.
    let broker = IsolatedBroker::new(
        BrokerComposition::builder().build().unwrap(),
        AssemblyIdentity::new("example-assembly", "9.8.7"),
    )
    .unwrap()
    .config_path(config_path)
    .gateway_listener()
    .expect("loopback gateway listener")
    .start()
    .await
    .unwrap();
    let base = format!("http://localhost:{}", broker.gateway_addr().unwrap().port());
    let authorization = format!(
        "http.extraHeader=Authorization: Basic {}",
        STANDARD.encode(format!("agent-access:{token}"))
    );

    for (index, suffix) in ["", ".git"].into_iter().enumerate() {
        let remote = format!("{base}/{REPOSITORY}{suffix}");
        let clone_name = format!("clone-{index}");
        let clone = root.join(&clone_name);
        let before = origin.requests();
        git(root, &["-c", &authorization, "clone", &remote, &clone_name]);
        assert_eq!(
            git_text(&clone, &["rev-parse", "HEAD"]),
            git_text(&seed, &["rev-parse", "HEAD"])
        );
        assert_fetch_requests(&origin.requests()[before.len()..]);

        commit(&seed, &format!("upstream-{index}"));
        git(&seed, &["push", upstream_repo.to_str().unwrap(), "main"]);
        let before = origin.requests();
        git(&clone, &["-c", &authorization, "fetch", "origin"]);
        assert_eq!(
            git_text(&clone, &["rev-parse", "origin/main"]),
            git_text(&seed, &["rev-parse", "HEAD"])
        );
        assert_fetch_requests(&origin.requests()[before.len()..]);

        commit(&clone, &format!("client-{index}"));
        let branch = format!("refs/heads/from-client-{index}");
        let before = origin.requests();
        git(
            &clone,
            &[
                "-c",
                &authorization,
                "push",
                "origin",
                &format!("HEAD:{branch}"),
            ],
        );
        assert_eq!(
            git_text(&clone, &["rev-parse", "HEAD"]),
            git_text(&upstream_repo, &["rev-parse", &branch])
        );
        let pushed = origin.requests();
        let pushed = &pushed[before.len()..];
        assert!(
            pushed.iter().any(|request| request.method == "GET"
                && request.target == "/group/repo.git/info/refs?service=git-receive-pack"),
            "{pushed:?}"
        );
        assert!(
            pushed.iter().any(|request| request.method == "POST"
                && request.target == "/group/repo.git/git-receive-pack"
                && request.has_pack),
            "{pushed:?}"
        );
        // A push within `http.postBuffer` is one receive-pack POST, no probe.
        assert!(!pushed.iter().any(|request| request.probe), "{pushed:?}");
    }

    // With default settings, Git precedes a push larger than `http.postBuffer`
    // with a probe POST whose whole body is a flush packet, then streams the
    // pack. Both must reach the upstream with the Broker's credential.
    let clone = root.join("clone-0");
    fs::write(
        clone.join("large.bin"),
        incompressible_bytes(LARGE_PUSH_BYTES),
    )
    .unwrap();
    git(&clone, &["add", "large.bin"]);
    git(&clone, &["commit", "-m", "large"]);
    let branch = "refs/heads/large-from-client";
    let before = origin.requests();
    git(
        &clone,
        &[
            "-c",
            &authorization,
            "push",
            "origin",
            &format!("HEAD:{branch}"),
        ],
    );
    assert_eq!(
        git_text(&clone, &["rev-parse", "HEAD"]),
        git_text(&upstream_repo, &["rev-parse", branch])
    );
    let pushed = origin.requests();
    let posts = pushed[before.len()..]
        .iter()
        .filter(|request| {
            request.method == "POST" && request.target == "/group/repo.git/git-receive-pack"
        })
        .collect::<Vec<_>>();
    assert_eq!(posts.len(), 2, "{posts:?}");
    assert!(posts[0].probe, "{posts:?}");
    assert!(
        posts[1].has_pack && posts[1].body_bytes > LARGE_PUSH_BYTES,
        "{posts:?}"
    );

    // Both client URL forms must reach only the same canonical upstream repo.
    let requests = origin.requests();
    assert!(!requests.is_empty());
    for request in &requests {
        assert!(
            request.target.starts_with("/group/repo.git/"),
            "{request:?}"
        );
        assert!(
            request.upstream_credential,
            "Broker must select the upstream credential"
        );
    }
    // Resource policy remains suffix-independent and rejects before dispatch.
    for suffix in ["", ".git"] {
        let output = git_output(
            root,
            &[
                "-c",
                &authorization,
                "ls-remote",
                &format!("{base}/group/unrelated{suffix}"),
            ],
        );
        assert!(!output.status.success());
        assert!(
            String::from_utf8_lossy(&output.stderr).contains("403"),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert_eq!(origin.requests().len(), requests.len());
    }

    // A separately authorized repo returns a redirect even at its canonical path.
    // Normalization must never change the Broker's no-redirect credential boundary.
    let response = reqwest::Client::builder()
        .no_proxy()
        .timeout(COMMAND_TIMEOUT)
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .unwrap()
        .get(format!(
            "{base}/group/redirect/info/refs?service=git-upload-pack"
        ))
        .basic_auth("agent-access", Some(&token))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), reqwest::StatusCode::MOVED_PERMANENTLY);
    assert!(!response.headers().contains_key(reqwest::header::LOCATION));
    let redirected = origin.requests();
    assert_eq!(redirected.len(), requests.len() + 1);
    assert_eq!(
        redirected.last().unwrap().target,
        "/group/redirect.git/info/refs?service=git-upload-pack"
    );

    broker.shutdown();
    let drained = broker.join().await.unwrap();
    assert_eq!(drained.unfinished_operations(), 0);
    assert_eq!(drained.audit_error(), None);
}

fn assert_fetch_requests(requests: &[UpstreamRequest]) {
    assert!(
        requests.iter().any(|request| request.method == "GET"
            && request.target == "/group/repo.git/info/refs?service=git-upload-pack"
            && request.protocol_v2),
        "{requests:?}"
    );
    // Protocol v2 makes clone/fetch exercise the POST after discovery as well.
    assert!(
        requests.iter().any(|request| request.method == "POST"
            && request.target == "/group/repo.git/git-upload-pack"
            && request.protocol_v2
            && request.fetch_command),
        "{requests:?}"
    );
}

fn broker_config(root: &Path, origin: SocketAddr) -> (PathBuf, String) {
    for (name, value) in [
        ("hash-key", URL_SAFE_NO_PAD.encode([17_u8; 32])),
        ("encryption-key", URL_SAFE_NO_PAD.encode([19_u8; 32])),
        ("upstream-token", UPSTREAM_TOKEN.to_owned()),
    ] {
        let path = root.join(name);
        fs::write(&path, value).unwrap();
        private_permissions(&path);
    }
    let ca = root.join("test-ca.pem");
    fs::write(
        &ca,
        include_bytes!("../../agent-access-core/tests/fixtures/outbound-tls/ca-a.pem"),
    )
    .unwrap();
    let path = root.join("broker.toml");
    let quoted_path =
        |name: &str| serde_json::to_string(&root.join(name).to_str().unwrap()).unwrap();
    let reference =
        |name: &str| serde_json::to_string(&format!("file:{}", root.join(name).display())).unwrap();
    fs::write(
        &path,
        format!(
            r#"
[deployment]
environment = "test"
[identity]
mode = "required"
authority = "managed"
[[identity.sources]]
name = "broker"
type = "broker_tokens"
header = "Authorization"
scheme = "Bearer"
[managed_store]
type = "sqlite"
path = {store}
auto_migrate = true
[broker_tokens]
hash_key_ref = {hash}
[credential_encryption]
active_key = "fixture"
[[credential_encryption.keys]]
id = "fixture"
provider = "file"
path = {encryption}
[credentials.service.git]
type = "bearer_token"
token_ref = {upstream}
[network.outbound_tls]
trust = "custom"
ca_certificate = {ca}
[gateways.git]
kind = "git_http"
display_name = "Test Git"
broker_hosts = ["localhost"]
upstream_base_url = "https://{origin}"
allowed_upstream_hosts = ["https://{origin}/**"]
auth_modes = ["basic_broker_token"]
credential_modes = ["service"]
redirect_policy = "none"
[gateways.git.git]
allow_fetch = true
allow_push = true
[policy]
authority = "toml"
default_decision = "deny"
[[policy.resources]]
id = "repo"
resource_type = "git_repository"
selector = {{ kind = "exact", value = "group/repo" }}
allowed_execution_contexts = ["default"]
[[policy.resources]]
id = "redirect"
resource_type = "git_repository"
selector = {{ kind = "exact", value = "group/redirect" }}
allowed_execution_contexts = ["default"]
[[policy.grants]]
subjects = ["user:git-tester"]
service = "git"
actions = ["repo.fetch", "repo.push"]
resources = {{ resource_ids = ["repo", "redirect"] }}
credential_mode = "service"
[limits]
upload_spool_dir = {spool}
"#,
            store = quoted_path("managed.sqlite"),
            hash = reference("hash-key"),
            encryption = quoted_path("encryption-key"),
            upstream = reference("upstream-token"),
            ca = quoted_path("test-ca.pem"),
            spool = quoted_path("spool"),
        ),
    )
    .unwrap();
    private_permissions(&path);
    // Seed the store the configuration names before the broker locks it.
    let store = ManagedStore::open(
        &ManagedStoreConfig {
            kind: "sqlite".into(),
            path: root.join("managed.sqlite").display().to_string(),
            require_registered_principal_for_invocation: false,
            auto_migrate: true,
        },
        ManagedStoreOpenMode::Startup,
    )
    .unwrap();
    store
        .create_principal(PrincipalWriteRequest {
            role: PrincipalRole::User,
            self_service_enabled: None,
            principal_id: "git-tester".into(),
            kind: "user".into(),
            display_name: None,
            email: None,
            external_subject: None,
            created_by: "test".into(),
        })
        .unwrap();
    let hasher = BrokerTokenHasher::load(&BrokerTokensConfig {
        hash_key_ref: format!("file:{}", root.join("hash-key").display()),
        ..Default::default()
    })
    .unwrap();
    let token = store.issue_broker_token(&hasher, BrokerTokenIssueRequest {
        principal_id: "git-tester".into(), name: "test token".into(), token_class: BrokerTokenClass::AgentInvoke,
        scopes: json!({"allowedServices": ["git"], "allowedExecutionContexts": ["default"]}),
        expires_at: None, created_by: "test".into(),
    }).unwrap().token;
    (path, token)
}

fn private_permissions(path: &Path) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(
            path,
            fs::Permissions::from_mode(if path.is_dir() { 0o700 } else { 0o600 }),
        )
        .unwrap();
    }
}

/// Deterministic bytes that zlib cannot shrink, so the pack stays large.
fn incompressible_bytes(len: usize) -> Vec<u8> {
    let mut state = 0x9e37_79b9_7f4a_7c15_u64;
    (0..len)
        .map(|_| {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            (state >> 56) as u8
        })
        .collect()
}

fn commit(repo: &Path, content: &str) {
    fs::write(repo.join("file.txt"), content).unwrap();
    git(repo, &["add", "file.txt"]);
    git(repo, &["commit", "-m", content]);
}

fn git(repo: &Path, args: &[&str]) {
    let output = git_output(repo, args);
    assert!(
        output.status.success(),
        "Git failed: stdout={}; stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

fn git_text(repo: &Path, args: &[&str]) -> String {
    let output = git_output(repo, args);
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout).unwrap().trim().to_owned()
}

fn git_command(repo: &Path) -> Command {
    let mut command = Command::new("git");
    command.current_dir(repo);
    // Inherited Git/proxy settings must not reach outside these isolated fixtures.
    for (name, _) in std::env::vars_os() {
        let key = name.to_string_lossy();
        if key.starts_with("GIT_") || key.to_ascii_lowercase().ends_with("_proxy") {
            command.env_remove(name);
        }
    }
    command
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env(
            "GIT_CONFIG_GLOBAL",
            if cfg!(windows) { "NUL" } else { "/dev/null" },
        )
        .env("GIT_TERMINAL_PROMPT", "0")
        .env("GIT_AUTHOR_NAME", "Gateway Test")
        .env("GIT_AUTHOR_EMAIL", "git@example.test")
        .env("GIT_COMMITTER_NAME", "Gateway Test")
        .env("GIT_COMMITTER_EMAIL", "git@example.test")
        .args([
            "-c",
            "protocol.version=2",
            "-c",
            "credential.helper=",
            "-c",
            "commit.gpgSign=false",
            "-c",
            if cfg!(windows) {
                "core.hooksPath=NUL"
            } else {
                "core.hooksPath=/dev/null"
            },
            "-c",
            "http.followRedirects=false",
            "-c",
            "http.lowSpeedLimit=1",
            "-c",
            "http.lowSpeedTime=10",
        ]);
    command
}

fn git_output(repo: &Path, args: &[&str]) -> Output {
    run_command(git_command(repo).args(args), &[])
}

// File-backed IO cannot deadlock on full pipes, and every test-owned process has a deadline.
fn run_command(command: &mut Command, input: &[u8]) -> Output {
    run_command_with_timeout(command, input, COMMAND_TIMEOUT)
}

fn run_command_with_timeout(command: &mut Command, input: &[u8], timeout: Duration) -> Output {
    let mut stdin = tempfile::tempfile().unwrap();
    stdin.write_all(input).unwrap();
    use std::io::{Seek, SeekFrom};
    stdin.seek(SeekFrom::Start(0)).unwrap();
    let mut stdout = tempfile::tempfile().unwrap();
    let mut stderr = tempfile::tempfile().unwrap();
    command
        .stdin(Stdio::from(stdin))
        .stdout(Stdio::from(stdout.try_clone().unwrap()))
        .stderr(Stdio::from(stderr.try_clone().unwrap()));
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        command.process_group(0);
    }
    let mut child = command
        .spawn()
        .expect("Git and git-http-backend must be installed");
    let started = Instant::now();
    let status = loop {
        if let Some(status) = child.try_wait().unwrap() {
            break status;
        }
        if started.elapsed() > timeout {
            #[cfg(unix)]
            unsafe {
                libc::kill(-(child.id() as i32), libc::SIGKILL);
            }
            let _ = child.kill();
            let _ = child.wait();
            panic!("Test subprocess exceeded {timeout:?}");
        }
        thread::sleep(Duration::from_millis(10));
    };
    stdout.seek(SeekFrom::Start(0)).unwrap();
    stderr.seek(SeekFrom::Start(0)).unwrap();
    let mut output = Output {
        status,
        stdout: Vec::new(),
        stderr: Vec::new(),
    };
    stdout.read_to_end(&mut output.stdout).unwrap();
    stderr.read_to_end(&mut output.stderr).unwrap();
    output
}

#[derive(Clone, Debug)]
struct UpstreamRequest {
    method: String,
    target: String,
    protocol_v2: bool,
    fetch_command: bool,
    has_pack: bool,
    /// The whole body is Git's flush-only large-push probe.
    probe: bool,
    body_bytes: usize,
    upstream_credential: bool,
}

struct GitOrigin {
    address: SocketAddr,
    stopped: Arc<AtomicBool>,
    thread: Option<JoinHandle<()>>,
    requests: Arc<Mutex<Vec<UpstreamRequest>>>,
}

impl GitOrigin {
    fn start(root: &Path) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let config = Arc::new(
            rustls::ServerConfig::builder_with_provider(Arc::new(
                rustls::crypto::ring::default_provider(),
            ))
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(
                CertificateDer::pem_slice_iter(include_bytes!(
                    "../../agent-access-core/tests/fixtures/outbound-tls/leaf-a.pem"
                ))
                .collect::<Result<Vec<_>, _>>()
                .unwrap(),
                PrivateKeyDer::from_pem_slice(include_bytes!(
                    "../../agent-access-core/tests/fixtures/outbound-tls/leaf-a.key"
                ))
                .unwrap(),
            )
            .unwrap(),
        );
        let stopped = Arc::new(AtomicBool::new(false));
        let stop = stopped.clone();
        let requests = Arc::new(Mutex::new(Vec::new()));
        let captured = requests.clone();
        let root = root.to_owned();
        let thread = thread::spawn(move || {
            while let Ok((stream, _)) = listener.accept() {
                if stop.load(Ordering::Acquire) {
                    break;
                }
                stream
                    .set_read_timeout(Some(Duration::from_secs(5)))
                    .unwrap();
                stream
                    .set_write_timeout(Some(Duration::from_secs(5)))
                    .unwrap();
                let connection = rustls::ServerConnection::new(config.clone()).unwrap();
                let mut tls = rustls::StreamOwned::new(connection, stream);
                serve_git(&mut tls, &root, address, &captured);
            }
        });
        Self {
            address,
            stopped,
            thread: Some(thread),
            requests,
        }
    }
    fn requests(&self) -> Vec<UpstreamRequest> {
        self.requests.lock().unwrap().clone()
    }
}

impl Drop for GitOrigin {
    fn drop(&mut self) {
        self.stopped.store(true, Ordering::Release);
        let _ = TcpStream::connect(self.address);
        if let Some(thread) = self.thread.take() {
            let result = thread.join();
            if !thread::panicking() {
                result.unwrap();
            }
        }
    }
}

fn serve_git(
    tls: &mut (impl Read + Write),
    root: &Path,
    address: SocketAddr,
    captured: &Mutex<Vec<UpstreamRequest>>,
) {
    let mut reader = BufReader::new(&mut *tls);
    let line = read_line(&mut reader);
    let mut parts = line.split_whitespace();
    let method = parts.next().unwrap();
    let target = parts.next().unwrap();
    let mut headers = BTreeMap::new();
    loop {
        let line = read_line(&mut reader);
        if line == "\r\n" {
            break;
        }
        let (name, value) = line.split_once(':').unwrap();
        headers.insert(name.to_ascii_lowercase(), value.trim().to_owned());
    }
    let mut body = Vec::new();
    if headers
        .get("transfer-encoding")
        .is_some_and(|value| value == "chunked")
    {
        loop {
            let line = read_line(&mut reader);
            let length = usize::from_str_radix(line.trim().split(';').next().unwrap(), 16).unwrap();
            if length == 0 {
                assert_eq!(read_line(&mut reader), "\r\n");
                break;
            }
            assert!(body.len() + length <= ORIGIN_BODY_MAX_BYTES);
            let offset = body.len();
            body.resize(offset + length, 0);
            reader.read_exact(&mut body[offset..]).unwrap();
            assert_eq!(read_line(&mut reader), "\r\n");
        }
    } else if let Some(length) = headers.get("content-length") {
        let length: usize = length.parse().unwrap();
        assert!(length <= ORIGIN_BODY_MAX_BYTES);
        body.resize(length, 0);
        reader.read_exact(&mut body).unwrap();
    }
    drop(reader);
    captured.lock().unwrap().push(UpstreamRequest {
        method: method.to_owned(),
        target: target.to_owned(),
        protocol_v2: headers
            .get("git-protocol")
            .is_some_and(|value| value == "version=2"),
        fetch_command: body
            .windows(b"command=fetch".len())
            .any(|bytes| bytes == b"command=fetch"),
        has_pack: body.windows(4).any(|bytes| bytes == b"PACK"),
        probe: body == b"0000",
        body_bytes: body.len(),
        upstream_credential: headers
            .get("authorization")
            .is_some_and(|value| value == &format!("Bearer {UPSTREAM_TOKEN}")),
    });
    let (path, query) = target.split_once('?').unwrap_or((target, ""));
    if !path.contains(".git/") || path.starts_with("/group/redirect.git/") {
        // Model GitLab's missing-suffix 301, plus an explicit canonical redirect probe.
        write!(tls, "HTTP/1.1 301 Moved Permanently\r\nLocation: https://{address}/group/repo.git/info/refs?service=git-upload-pack\r\nContent-Length: 0\r\nConnection: close\r\n\r\n").unwrap();
    } else {
        let output = run_command(
            git_command(root)
                .arg("http-backend")
                .env("GIT_PROJECT_ROOT", root)
                .env("GIT_HTTP_EXPORT_ALL", "1")
                .env("PATH_INFO", path)
                .env("QUERY_STRING", query)
                .env("REQUEST_METHOD", method)
                .env(
                    "CONTENT_TYPE",
                    headers
                        .get("content-type")
                        .map(String::as_str)
                        .unwrap_or(""),
                )
                .env("CONTENT_LENGTH", body.len().to_string())
                .env("REMOTE_ADDR", "127.0.0.1")
                .env("SERVER_PROTOCOL", "HTTP/1.1")
                .env(
                    "HTTP_GIT_PROTOCOL",
                    headers
                        .get("git-protocol")
                        .map(String::as_str)
                        .unwrap_or(""),
                ),
            &body,
        );
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
        let headers = String::from_utf8_lossy(&output.stdout[..boundary]);
        let payload = &output.stdout[boundary + 4..];
        let mut status = "200 OK";
        let mut forwarded = String::new();
        for line in headers.split("\r\n") {
            let (name, value) = line.split_once(':').unwrap();
            if name.eq_ignore_ascii_case("status") {
                status = value.trim();
            } else {
                forwarded.push_str(line);
                forwarded.push_str("\r\n");
            }
        }
        write!(
            tls,
            "HTTP/1.1 {status}\r\n{forwarded}Content-Length: {}\r\nConnection: close\r\n\r\n",
            payload.len()
        )
        .unwrap();
        tls.write_all(payload).unwrap();
    }
    tls.flush().unwrap();
}

fn read_line(reader: &mut impl BufRead) -> String {
    let mut bytes = Vec::new();
    reader.take(16_384).read_until(b'\n', &mut bytes).unwrap();
    assert!(
        bytes.ends_with(b"\n"),
        "HTTP fixture received an incomplete or oversized line"
    );
    String::from_utf8(bytes).unwrap()
}
