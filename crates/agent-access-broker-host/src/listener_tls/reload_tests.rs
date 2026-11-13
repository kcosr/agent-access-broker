//! A candidate must not rotate either listener before every reload check passes.
use super::*;
use crate::lifecycle::StartupHooks;
use crate::reload::start_reloadable_state;
use crate::state::{ReloadableState, RuntimeSnapshot};
use crate::test_support::FixtureDir;
use agent_access_core::test_support::ProviderFixtures;
use axum::body::Body;
use axum::extract::ConnectInfo;
use axum::http::{Request, StatusCode};
use serde_json::Value;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Mutex, mpsc};
use std::time::Duration;
use tower::ServiceExt;

const WAIT: Duration = Duration::from_secs(30);
const RELOAD_TIMEOUT: Duration = Duration::from_secs(2);

struct CandidateGate {
    armed: AtomicBool,
    entered: tokio::sync::Notify,
    resume: Mutex<mpsc::Receiver<()>>,
}

struct ReleaseCandidate(Option<mpsc::SyncSender<()>>);

impl Drop for ReleaseCandidate {
    fn drop(&mut self) {
        if let Some(resume) = self.0.take() {
            let _ = resume.send(());
        }
    }
}

struct Fixture {
    state: Arc<ReloadableState>,
    directory: FixtureDir,
    public: Files,
    gateway: Files,
    gate: Arc<CandidateGate>,
    release: Option<ReleaseCandidate>,
}

impl Fixture {
    async fn new(timeout: Duration) -> Self {
        let directory = FixtureDir::new().unwrap();
        directory.secret_file("admin-token", "admin-token").unwrap();
        let public = Files::new();
        let gateway = Files::new();
        let tls_files = ListenerTlsFiles {
            public: Some(public.identity.clone()),
            gateway: Some(gateway.identity.clone()),
        };
        let (resume, receive) = mpsc::sync_channel(1);
        let gate = Arc::new(CandidateGate {
            armed: AtomicBool::new(false),
            entered: tokio::sync::Notify::new(),
            resume: Mutex::new(receive),
        });
        let mut providers = ProviderFixtures::new();
        let factory_gate = gate.clone();
        providers.insert("fake", move |context| {
            if factory_gate.armed.swap(false, Ordering::SeqCst) {
                // Reload builds providers only after loading both TLS identities.
                // Holding this point lets the test fail a later admission stage.
                factory_gate.entered.notify_one();
                factory_gate
                    .resume
                    .lock()
                    .unwrap()
                    .recv_timeout(WAIT)
                    .expect("the test must release its candidate");
            }
            context.registered_provider().unwrap()
        });
        let config_path = directory
            .secret_file("broker.toml", config(&directory, "active.jsonl"))
            .unwrap();
        let state = start_reloadable_state(
            config_path,
            Arc::new(crate::test_composition::backend_registry()),
            crate::broker_build_status(),
            None,
            timeout,
            WAIT,
            tls_files,
            StartupHooks {
                provider_fixtures: Some(providers),
                ..StartupHooks::default()
            },
        )
        .await
        .unwrap();
        Self {
            state,
            directory,
            public,
            gateway,
            gate,
            release: Some(ReleaseCandidate(Some(resume))),
        }
    }

    fn rotate(&self) {
        self.public.replace(ROTATED_CHAIN, ROTATED_KEY);
        self.gateway.replace(ROTATED_CHAIN, ROTATED_KEY);
        let prepared = self.state.listener_tls_files.load().unwrap();
        assert_identity(&prepared.public, ROTATED_CHAIN);
        assert_identity(&prepared.gateway, ROTATED_CHAIN);
        self.gate.armed.store(true, Ordering::SeqCst);
    }

    async fn entered(&self) {
        tokio::time::timeout(WAIT, self.gate.entered.notified())
            .await
            .expect("candidate did not reach the stage after TLS loading");
    }

    fn release(&mut self) {
        drop(self.release.take());
    }

    async fn finish(self) {
        self.state
            .audit_registry
            .shutdown_and_drain(WAIT)
            .await
            .unwrap();
    }
}

fn config(directory: &FixtureDir, audit: &str) -> String {
    format!(
        r#"[deployment]
environment = "test"
enable_fake_service = true
[providers.fake]
[identity]
mode = "optional"
authority = "toml"
[[identity.sources]]
name = "admin"
type = "static_principals"
header = "Authorization"
scheme = "Bearer"
[[identity.sources.principals]]
principal = "admin"
token_refs = ["file:{}"]
[management]
enabled = true
admin_principals = ["admin"]
allow_classless_admin_identities = true
[policy]
authority = "toml"
default_decision = "deny"
[limits]
upload_spool_dir = "{}"
[audit]
type = "jsonl"
path = "{}"
"#,
        directory.join("admin-token").display(),
        directory.join("spool").display(),
        directory.join(audit).display(),
    )
}

fn assert_identity(identity: &Option<Arc<rustls::ServerConfig>>, chain: &str) {
    assert_eq!(
        handshake(
            identity.as_ref().unwrap().clone(),
            &rustls::version::TLS13,
            b"h2"
        ),
        parse_certificate_chain(chain.as_bytes()).unwrap(),
    );
}

fn assert_unchanged(state: &ReloadableState, original: &Arc<RuntimeSnapshot>) {
    let current = state.current();
    assert!(Arc::ptr_eq(original, &current));
    assert_eq!(current.generation, 1);
    for (before, after) in [
        (&original.listener_tls.public, &current.listener_tls.public),
        (
            &original.listener_tls.gateway,
            &current.listener_tls.gateway,
        ),
    ] {
        assert!(Arc::ptr_eq(
            before.as_ref().unwrap(),
            after.as_ref().unwrap()
        ));
        assert_identity(after, CHAIN);
    }
}

#[derive(Clone, Copy)]
enum Trigger {
    Http,
    Signal,
}

async fn reload(state: Arc<ReloadableState>, trigger: Trigger) -> (StatusCode, Value) {
    match trigger {
        Trigger::Http => {
            let (router, mcp) = crate::router::public_router(state);
            let response = router
                .oneshot(
                    Request::builder()
                        .method("POST")
                        .uri("/v1/admin/config/reload")
                        .extension(ConnectInfo(
                            "127.0.0.1:43000".parse::<SocketAddr>().unwrap(),
                        ))
                        .header("authorization", "Bearer admin-token")
                        .header("x-agent-access-request-id", "tls-late-reload")
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();
            let status = response.status();
            let body = axum::body::to_bytes(response.into_body(), usize::MAX)
                .await
                .unwrap();
            mcp.close_sessions().await;
            (status, serde_json::from_slice(&body).unwrap())
        }
        Trigger::Signal => {
            let response = state.reload_from_signal().await;
            (
                response.status,
                serde_json::json!({
                    "decision": response.decision(),
                    "reasonCode": response.reason_code(),
                    "error": {"message": response.message()},
                }),
            )
        }
    }
}

async fn audit_failure_preserves_identities(trigger: Trigger) {
    let mut fixture = Fixture::new(WAIT).await;
    let original = fixture.state.current();
    fixture.rotate();
    fixture
        .directory
        .secret_file("broker.toml", config(&fixture.directory, "candidate.jsonl"))
        .unwrap();
    let task = tokio::spawn(reload(fixture.state.clone(), trigger));
    fixture.entered().await;
    assert_unchanged(&fixture.state, &original);

    // The candidate's lock and TLS loads have succeeded. Its audit open must
    // now fail without touching the still-writable active audit destination.
    std::fs::create_dir(fixture.directory.join("candidate.jsonl")).unwrap();
    fixture.release();
    let (status, body) = tokio::time::timeout(WAIT, task).await.unwrap().unwrap();
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE, "{body}");
    assert_eq!(body["reasonCode"], "config_admission_failed");
    assert!(
        body["error"]["message"].as_str().unwrap().contains("audit"),
        "{body}"
    );
    assert_unchanged(&fixture.state, &original);

    // A subsequent admitted candidate can publish the same valid replacements.
    std::fs::remove_dir(fixture.directory.join("candidate.jsonl")).unwrap();
    let (status, body) = reload(fixture.state.clone(), trigger).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let current = fixture.state.current();
    assert_eq!(current.generation, 2);
    assert_identity(&current.listener_tls.public, ROTATED_CHAIN);
    assert_identity(&current.listener_tls.gateway, ROTATED_CHAIN);
    fixture.finish().await;
}

async fn timeout_preserves_identities(trigger: Trigger) {
    let mut fixture = Fixture::new(RELOAD_TIMEOUT).await;
    let original = fixture.state.current();
    fixture.rotate();
    let task = tokio::spawn(reload(fixture.state.clone(), trigger));
    fixture.entered().await;
    assert_unchanged(&fixture.state, &original);
    // The deadline uses a real Instant. Start this wait after the controlled
    // gate is reached, so even a late task start cannot shorten the expiry.
    tokio::time::sleep(RELOAD_TIMEOUT + Duration::from_millis(50)).await;
    assert_unchanged(&fixture.state, &original);
    assert!(
        !task.is_finished(),
        "timed-out admission must join its blocking worker"
    );
    fixture.release();
    let (status, body) = tokio::time::timeout(WAIT, task).await.unwrap().unwrap();
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE, "{body}");
    assert_eq!(body["reasonCode"], "config_admission_failed");
    assert_eq!(body["error"]["message"], "reload admission timed out");
    assert_unchanged(&fixture.state, &original);
    fixture.finish().await;
}

#[tokio::test]
async fn http_audit_failure_after_tls_loading_preserves_both_identities() {
    audit_failure_preserves_identities(Trigger::Http).await;
}

#[tokio::test]
async fn signal_audit_failure_after_tls_loading_preserves_both_identities() {
    audit_failure_preserves_identities(Trigger::Signal).await;
}

#[tokio::test]
async fn http_timeout_after_tls_loading_preserves_both_identities() {
    timeout_preserves_identities(Trigger::Http).await;
}

#[tokio::test]
async fn signal_timeout_after_tls_loading_preserves_both_identities() {
    timeout_preserves_identities(Trigger::Signal).await;
}
