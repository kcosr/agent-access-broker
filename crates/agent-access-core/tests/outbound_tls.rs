use agent_access_cloudbees_ci::CLOUDBEES_CI_BACKEND;
use agent_access_core::{
    BackendRegistry, BrokerConfig, BrokerRuntime, ExecutionContext, GatewayConfig,
    GovernedOperationContext, IdentityContext, InvokeRequest, OperationContext, OutboundTlsConfig,
    OutboundTlsTrustMode, PreparedOutboundTls, SourceContext,
};
use agent_access_provider::ProviderResultStreamSource;
use futures_util::StreamExt;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, pem::PemObject};
use serde_json::json;
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::path::Path;
use std::process::Command;
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicBool, Ordering},
};
use std::thread::JoinHandle;
use std::time::Duration;

const CA_A: &str = include_str!("fixtures/outbound-tls/ca-a.pem");
const CA_B: &str = include_str!("fixtures/outbound-tls/ca-b.pem");
const ARTIFACT: &[u8] = b"verified TLS artifact\n";

// The child owns its certificate and proxy environment. No test mutates the
// environment of a multithreaded process, and the host CA store is never used.
#[test]
fn outbound_tls_real_https_matrix() {
    let temp = tempfile::tempdir().unwrap();
    let system_ca = temp.path().join("system.pem");
    std::fs::write(&system_ca, CA_A).unwrap();
    let empty_dir = temp.path().join("empty");
    std::fs::create_dir(&empty_dir).unwrap();
    let mut command = Command::new(std::env::current_exe().unwrap());
    command
        .args(["--exact", "outbound_tls_child", "--ignored", "--nocapture"])
        .env("BROKER_OUTBOUND_TLS_TEST_CHILD", "1")
        .env("SSL_CERT_FILE", system_ca)
        .env("SSL_CERT_DIR", empty_dir);
    for name in [
        "HTTP_PROXY",
        "http_proxy",
        "HTTPS_PROXY",
        "https_proxy",
        "ALL_PROXY",
        "all_proxy",
        "NO_PROXY",
        "no_proxy",
    ] {
        command.env_remove(name);
    }
    let output = command.output().unwrap();
    assert!(
        output.status.success(),
        "{}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

#[tokio::test]
#[ignore = "run by outbound_tls_real_https_matrix with an isolated native trust environment"]
async fn outbound_tls_child() {
    assert_eq!(
        std::env::var("BROKER_OUTBOUND_TLS_TEST_CHILD").as_deref(),
        Ok("1")
    );
    let server_a = HttpsServer::start(
        include_str!("fixtures/outbound-tls/leaf-a.pem"),
        include_str!("fixtures/outbound-tls/leaf-a.key"),
    );
    let server_b = HttpsServer::start(
        include_str!("fixtures/outbound-tls/leaf-b.pem"),
        include_str!("fixtures/outbound-tls/leaf-b.key"),
    );
    let temp = tempfile::tempdir().unwrap();
    let bundle = temp.path().join("custom.pem");
    std::fs::write(&bundle, CA_B).unwrap();

    for (mode, accepts_a, accepts_b) in [
        (OutboundTlsTrustMode::System, true, false),
        (OutboundTlsTrustMode::Custom, false, true),
        (OutboundTlsTrustMode::SystemPlusCustom, true, true),
    ] {
        let trust = PreparedOutboundTls::load(&OutboundTlsConfig {
            trust: mode,
            ca_certificate: (mode != OutboundTlsTrustMode::System).then(|| bundle.clone()),
        })
        .unwrap();
        let client = trust
            .apply(
                reqwest::Client::builder()
                    .no_proxy()
                    .timeout(Duration::from_secs(3)),
            )
            .build()
            .unwrap();
        assert_eq!(
            client.get(server_a.url()).send().await.is_ok(),
            accepts_a,
            "{mode:?} CA A"
        );
        assert_eq!(
            client.get(server_b.url()).send().await.is_ok(),
            accepts_b,
            "{mode:?} CA B"
        );
        let wrong_name_client = trust
            .apply(
                reqwest::Client::builder()
                    .no_proxy()
                    .timeout(Duration::from_secs(3))
                    .resolve("wrong-name.invalid", server_b.address),
            )
            .build()
            .unwrap();
        assert!(
            wrong_name_client
                .get(format!(
                    "https://wrong-name.invalid:{}/",
                    server_b.address.port()
                ))
                .send()
                .await
                .is_err(),
            "hostname verification must remain enabled for {mode:?}"
        );
    }

    cloudbees_and_gateway_retain_and_reload_roots(&temp, &bundle, &server_a, &server_b).await;
}

async fn cloudbees_and_gateway_retain_and_reload_roots(
    temp: &tempfile::TempDir,
    bundle: &Path,
    server_a: &HttpsServer,
    server_b: &HttpsServer,
) {
    let config = cloudbees_config(temp.path(), bundle, &server_b.url());
    let runtime = BrokerRuntime::new(config.clone()).unwrap();
    let list = runtime
        .invoke(
            context("build.artifact.list"),
            InvokeRequest::new(json!({
                "controller":"ci", "job":"demo", "buildNumber":1
            })),
        )
        .await;
    assert_eq!(list.status, 200, "{:?}", list.envelope);

    // Every subsequent client must use the admitted snapshot, including a Git
    // client built after the file disappears and the separate download client.
    std::fs::remove_file(bundle).unwrap();
    let download = runtime
        .invoke_required_stream(
            context("build.artifact.download"),
            InvokeRequest::new(json!({
                "controller":"ci", "job":"demo", "buildNumber":1, "artifactPath":"file.txt"
            })),
        )
        .await;
    assert_eq!(download.status, 200, "{:?}", download.envelope);
    let bytes = match download.stream.unwrap().source {
        ProviderResultStreamSource::Memory(bytes) => bytes,
        ProviderResultStreamSource::Stream(source) => {
            let mut stream = source.lock().unwrap().take().unwrap();
            let mut bytes = Vec::new();
            while let Some(chunk) = stream.next().await {
                bytes.extend_from_slice(&chunk.unwrap());
            }
            bytes
        }
    };
    assert_eq!(bytes, ARTIFACT);
    assert!(gateway_get(&runtime, server_b).await);
    assert!(BrokerRuntime::new_for_reload(config.clone(), &runtime).is_err());
    std::fs::write(bundle, "invalid PEM").unwrap();
    assert!(BrokerRuntime::new_for_reload(config.clone(), &runtime).is_err());
    assert!(gateway_get(&runtime, server_b).await);

    // Same TOML/path, different bundle contents: the new runtime trusts A and
    // rejects B, while requests retained by the old runtime continue using B.
    std::fs::write(bundle, CA_A).unwrap();
    let replacement = BrokerRuntime::new_for_reload(config, &runtime).unwrap();
    assert!(gateway_get(&replacement, server_a).await);
    assert!(!gateway_get(&replacement, server_b).await);
    assert!(gateway_get(&runtime, server_b).await);
    assert!(!gateway_get(&runtime, server_a).await);
    let requests = server_b.requests.lock().unwrap();
    assert!(
        requests
            .iter()
            .any(|path| path.starts_with("/job/demo/1/api/json?"))
    );
    assert!(
        requests
            .iter()
            .any(|path| path == "/job/demo/1/artifact/file.txt")
    );
}

async fn gateway_get(runtime: &BrokerRuntime, server: &HttpsServer) -> bool {
    let gateway: GatewayConfig = toml::from_str(&format!(
        r#"
kind = "git_http"
display_name = "test"
upstream_base_url = {:?}
"#,
        server.url()
    ))
    .unwrap();
    let (client, _) = runtime.gateway_http_client("git", &gateway).unwrap();
    client.get(server.url()).send().await.is_ok()
}

fn context(action: &str) -> GovernedOperationContext {
    GovernedOperationContext {
        operation: OperationContext {
            agent_request_id: format!("tls-{action}"),
            broker_request_id: format!("tls-{action}"),
            identity: IdentityContext::anonymous(),
            service: "cloudbees_ci".into(),
            action: action.into(),
            source: SourceContext::unknown(),
        },
        execution_context: ExecutionContext::new("default").unwrap(),
    }
}

fn cloudbees_config(temp: &Path, bundle: &Path, base: &str) -> BrokerConfig {
    std::fs::write(temp.join("username"), "test").unwrap();
    std::fs::write(temp.join("token"), "synthetic-test-token").unwrap();
    agent_access_core::parse_broker_config_raw(
        "outbound-tls-test.toml",
        &format!(
            r#"
[network.outbound_tls]
trust = "custom"
ca_certificate = {bundle:?}
[identity]
mode = "anonymous"
authority = "toml"
[credentials.service.cloudbees_ci]
type = "basic_api_token"
username_ref = {username:?}
token_ref = {token:?}
[policy]
authority = "toml"
default_decision = "deny"
[[policy.resources]]
id = "job"
resource_type = "cloudbees_ci_job"
selector = {{ kind = "exact", value = "ci/demo" }}
allowed_execution_contexts = ["default"]
enabled = true
[[policy.grants]]
subjects = ["group:anonymous"]
service = "cloudbees_ci"
actions = ["build.artifact.list", "build.artifact.download"]
resources = {{ resource_ids = ["job"] }}
credential_mode = "service"
[providers.cloudbees_ci]
allowed_upstream_hosts = [{allowed:?}]
[providers.cloudbees_ci.controllers.ci]
base_url = {base:?}
"#,
            bundle = bundle.to_str().unwrap(),
            username = format!("file:{}", temp.join("username").display()),
            token = format!("file:{}", temp.join("token").display()),
            allowed = format!("{base}**"),
        ),
        &Arc::new(BackendRegistry::new([&CLOUDBEES_CI_BACKEND]).unwrap()),
    )
    .unwrap()
}

struct HttpsServer {
    address: SocketAddr,
    stopped: Arc<AtomicBool>,
    thread: Option<JoinHandle<()>>,
    requests: Arc<Mutex<Vec<String>>>,
}

impl HttpsServer {
    fn start(certificate: &str, key: &str) -> Self {
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
                CertificateDer::pem_slice_iter(certificate.as_bytes())
                    .collect::<Result<Vec<_>, _>>()
                    .unwrap(),
                PrivateKeyDer::from_pem_slice(key.as_bytes()).unwrap(),
            )
            .unwrap(),
        );
        let stopped = Arc::new(AtomicBool::new(false));
        let stop = Arc::clone(&stopped);
        let requests = Arc::new(Mutex::new(Vec::new()));
        let captured = Arc::clone(&requests);
        let thread = std::thread::spawn(move || {
            while let Ok((stream, _)) = listener.accept() {
                if stop.load(Ordering::Acquire) {
                    break;
                }
                stream
                    .set_read_timeout(Some(Duration::from_secs(3)))
                    .unwrap();
                stream
                    .set_write_timeout(Some(Duration::from_secs(3)))
                    .unwrap();
                let connection = rustls::ServerConnection::new(Arc::clone(&config)).unwrap();
                let mut tls = rustls::StreamOwned::new(connection, stream);
                let mut header = Vec::new();
                let mut byte = [0_u8; 1];
                while header.len() < 16_384 && !header.ends_with(b"\r\n\r\n") {
                    match tls.read(&mut byte) {
                        Ok(1) => header.push(byte[0]),
                        _ => break,
                    }
                }
                if !header.ends_with(b"\r\n\r\n") {
                    continue;
                }
                let request = String::from_utf8(header).unwrap();
                let path = request.split_whitespace().nth(1).unwrap().to_owned();
                let (body, content_type): (&[u8], &str) = if path
                    .starts_with("/job/demo/1/api/json?")
                {
                    (br#"{"number":1,"artifacts":[{"relativePath":"file.txt","fileName":"file.txt"}]}"#, "application/json")
                } else if path == "/job/demo/1/artifact/file.txt" {
                    (ARTIFACT, "text/plain")
                } else {
                    (b"ok", "text/plain")
                };
                captured.lock().unwrap().push(path);
                let response = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                    body.len()
                );
                let _ = tls
                    .write_all(response.as_bytes())
                    .and_then(|_| tls.write_all(body));
                let _ = tls.flush();
            }
        });
        Self {
            address,
            stopped,
            thread: Some(thread),
            requests,
        }
    }

    fn url(&self) -> String {
        format!("https://{}/", self.address)
    }
}

impl Drop for HttpsServer {
    fn drop(&mut self) {
        self.stopped.store(true, Ordering::Release);
        let _ = TcpStream::connect(self.address);
        self.thread.take().unwrap().join().unwrap();
    }
}
