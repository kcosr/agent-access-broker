use agent_access_broker::{build_identity, composition};
use agent_access_broker_host::BrokerApplication;
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use serde_json::Value;
use std::fs;
use std::io::{BufRead, BufReader};
use std::net::{SocketAddr, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Output, Stdio};
use std::sync::mpsc;
use std::sync::{Mutex, MutexGuard};
use std::thread;
use std::time::{Duration, Instant};
use tempfile::TempDir;

#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;

const START_TIMEOUT: Duration = Duration::from_secs(5);
const EXIT_TIMEOUT: Duration = Duration::from_secs(3);
static STATE_LOCK_TEST_MUTEX: Mutex<()> = Mutex::new(());
/// The broker's default log filter, set for every broker these tests start.
/// An inherited `RUST_LOG` such as `warn` would hide the INFO
/// `broker_listening` event that names a broker's bound address, and whose
/// absence shows that a conflicting broker never bound its listener.
const BROKER_LOG_FILTER: &str = "agent_access_broker=info,agent_access_broker_host=info,agent_access_core=info,agent_access_provider=info,axum=warn,tower=warn";
/// Set for the child test process that checks an inherited filter.
const INHERITED_FILTER_CHILD: &str = "BROKER_STATE_LOCKS_INHERITED_FILTER_CHILD";

#[test]
fn serve_locks_reject_second_process_by_shared_state_domain_and_validate_is_offline() {
    let _guard = state_lock_test_guard();
    let temp = TempDir::new().unwrap();
    private_dir(temp.path());
    let first = BrokerConfigPaths::new(temp.path(), "first", true, true);
    write_config(&first);
    let first_process = BrokerProcess::start(&first.config_path);

    let validate = Command::new(broker_bin())
        .arg("--config")
        .arg(&first.config_path)
        .arg("config")
        .arg("validate")
        .output()
        .unwrap();
    assert!(
        validate.status.success(),
        "config validate should remain offline; stderr={}",
        String::from_utf8_lossy(&validate.stderr)
    );
    assert!(
        String::from_utf8_lossy(&validate.stdout).starts_with("broker config valid: "),
        "config validate stdout should remain human-readable: {}",
        String::from_utf8_lossy(&validate.stdout)
    );
    assert!(
        validate.stderr.is_empty(),
        "config validate should not emit tracing stderr: {}",
        String::from_utf8_lossy(&validate.stderr)
    );
    assert!(
        serde_json::from_slice::<Value>(&validate.stdout).is_err(),
        "config validate stdout must not be trace JSON"
    );

    let shared_store = BrokerConfigPaths::new(temp.path(), "shared-store", true, true)
        .with_managed_store_path(first.managed_store_path.clone().unwrap());
    write_config(&shared_store);
    let stderr = run_expect_startup_failure(&shared_store.config_path);
    assert!(
        stderr.contains("managed_store state lock is held"),
        "stderr did not identify managed_store lock: {stderr}"
    );

    let shared_audit = BrokerConfigPaths::new(temp.path(), "shared-audit", false, true)
        .with_audit_path(first.audit_path.clone().unwrap());
    write_config(&shared_audit);
    let stderr = run_expect_startup_failure(&shared_audit.config_path);
    assert!(
        stderr.contains("audit state lock is held"),
        "stderr did not identify audit lock: {stderr}"
    );
    assert!(
        stderr.contains("nodeId"),
        "stderr did not show the holder's node ID: {stderr}"
    );
    assert!(
        stderr.contains(r#""program":"agent-access-broker""#)
            && stderr.contains(&format!(
                r#""programVersion":"{}""#,
                env!("CARGO_PKG_VERSION")
            )),
        "stderr did not show the holder's assembly identity: {stderr}"
    );

    let shared_spool = BrokerConfigPaths::new(temp.path(), "shared-spool", false, true)
        .with_spool_dir(first.spool_dir.clone());
    write_config(&shared_spool);
    // Failing without a broker_listening event, the conflicting broker
    // never bound its public listener.
    let stderr = run_expect_startup_failure(&shared_spool.config_path);
    assert!(
        stderr.contains("upload_spool state lock is held"),
        "stderr did not identify upload spool lock: {stderr}"
    );

    drop(first_process);
}

#[test]
fn audit_verify_needs_a_stopped_broker_and_a_sqlite_audit_database() {
    let _guard = state_lock_test_guard();
    let temp = TempDir::new().unwrap();
    private_dir(temp.path());
    let database = temp
        .path()
        .join("audit-verify")
        .join("audit")
        .join("audit.sqlite");
    let paths = BrokerConfigPaths::new(temp.path(), "audit-verify", false, true)
        .with_audit_path(database.clone());
    write_config(&paths);
    let verify = |config_path: &Path| {
        Command::new(broker_bin())
            .arg("--config")
            .arg(config_path)
            .arg("audit")
            .arg("verify")
            .output()
            .unwrap()
    };

    // A running broker owns the audit state lock.
    let process = BrokerProcess::start(&paths.config_path);
    let held = verify(&paths.config_path);
    assert!(!held.status.success());
    let stderr = String::from_utf8_lossy(&held.stderr);
    assert!(stderr.contains("audit state lock is held"), "{stderr}");
    drop(process);

    let verified = verify(&paths.config_path);
    let stdout = String::from_utf8_lossy(&verified.stdout);
    assert!(
        verified.status.success(),
        "stdout={stdout}; stderr={}",
        String::from_utf8_lossy(&verified.stderr)
    );
    for line in [
        "schema: ok",
        "integrity_check: ok",
        "fts_integrity_check: ok",
        "audit database verified",
    ] {
        assert!(stdout.contains(line), "{stdout}");
    }
    assert!(stdout.contains("database_id: "), "{stdout}");

    // Any problem exits non-zero.
    rusqlite::Connection::open(&database)
        .unwrap()
        .execute_batch("DROP TRIGGER audit_events_fts_delete;")
        .unwrap();
    let broken = verify(&paths.config_path);
    assert_eq!(broken.status.code(), Some(1));
    let stdout = String::from_utf8_lossy(&broken.stdout);
    assert!(stdout.contains("schema: 1 problem(s)"), "{stdout}");

    // JSONL or disabled audit is a usage error.
    for (name, audit) in [
        ("audit-verify-jsonl", true),
        ("audit-verify-disabled", false),
    ] {
        let paths = BrokerConfigPaths::new(temp.path(), name, false, audit);
        write_config(&paths);
        let usage = verify(&paths.config_path);
        assert_eq!(usage.status.code(), Some(2), "{name}");
        let stderr = String::from_utf8_lossy(&usage.stderr);
        assert!(
            stderr.contains("audit verify requires [audit] type = \"sqlite\""),
            "{name}: {stderr}"
        );
    }
}

#[test]
fn serve_emits_json_startup_events_and_invalid_filter_warning() {
    let _guard = state_lock_test_guard();
    let temp = TempDir::new().unwrap();
    private_dir(temp.path());
    let paths = BrokerConfigPaths::new(temp.path(), "startup-json", true, true);
    write_config(&paths);

    let process = BrokerProcess::start_with_env(
        &paths.config_path,
        &[("RUST_LOG", "agent_access_broker=notalevel")],
    );
    // broker_listening names the bound address, not the requested port 0.
    let addr = process.addr();
    assert!(addr.ip().is_loopback() && addr.port() != 0, "{addr}");
    TcpStream::connect(addr).expect("the logged address accepts connections");
    let (output, stderr) = process.stop();
    assert!(
        output.stdout.is_empty(),
        "serve mode should not write startup diagnostics to stdout: {}",
        String::from_utf8_lossy(&output.stdout)
    );
    let events = stderr_json_events(stderr.as_bytes());
    let invalid_filter = event_by_name(&events, "logging_filter_invalid");
    assert_eq!(invalid_filter["envVar"], "RUST_LOG");
    assert_eq!(
        invalid_filter["fallback"],
        "agent_access_broker=info,agent_access_broker_host=info,agent_access_core=info,agent_access_provider=info,axum=warn,tower=warn"
    );
    assert!(
        invalid_filter["error"]
            .as_str()
            .is_some_and(|error| !error.is_empty()),
        "invalid filter event must include parse error string: {invalid_filter:?}"
    );

    let starting = event_by_name(&events, "broker_starting");
    let config_path = paths.config_path.display().to_string();
    let address = addr.to_string();
    assert_eq!(starting["configPath"].as_str(), Some(config_path.as_str()));
    assert_eq!(starting["publicListen"].as_str(), Some("127.0.0.1:0"));
    assert!(starting.get("adminListen").is_none());
    assert_eq!(starting["reloadTimeoutMs"].as_u64(), Some(30_000));
    assert_eq!(starting["bodyHardCapBytes"], Value::Null);
    // The status the assembly's own application derives.
    let application = BrokerApplication::new(composition().unwrap(), build_identity()).unwrap();
    let build = serde_json::to_value(application.status()).unwrap();
    let assembly = &build["assembly"];
    assert_eq!(starting["assemblyName"], assembly["name"]);
    assert_eq!(starting["assemblyVersion"], assembly["version"]);
    assert_eq!(starting["qualification"], assembly["qualification"]);
    assert_eq!(
        starting["assemblyProvenance"],
        assembly["source"]["provenance"]
    );
    match assembly["source"]["revision"].as_str() {
        Some(revision) => assert_eq!(starting["assemblyRevision"].as_str(), Some(revision)),
        None => assert!(starting.get("assemblyRevision").is_none()),
    }
    assert_eq!(
        starting["inventoryFingerprint"],
        build["inventoryFingerprint"]
    );
    for removed in ["brokerVersion", "buildCommit", "buildProvenance"] {
        assert!(starting.get(removed).is_none(), "{removed}: {starting}");
    }

    let listening = event_by_name(&events, "broker_listening");
    assert_eq!(listening["listener"].as_str(), Some("public"));
    assert_eq!(listening["address"].as_str(), Some(address.as_str()));
}

/// `RUST_LOG=warn cargo test` must not hide the events the start helpers
/// read: the child test process inherits a warning-only filter.
#[test]
fn start_helpers_read_startup_events_under_an_inherited_warning_only_filter() {
    let _guard = state_lock_test_guard();
    let output = Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "inherited_warning_only_filter_child",
            "--ignored",
            "--nocapture",
        ])
        .env("RUST_LOG", "warn")
        .env(INHERITED_FILTER_CHILD, "1")
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        output.status.success() && stdout.contains("inherited warning-only filter checked"),
        "stdout={stdout}; stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
#[ignore = "run by start_helpers_read_startup_events_under_an_inherited_warning_only_filter"]
fn inherited_warning_only_filter_child() {
    assert_eq!(
        std::env::var(INHERITED_FILTER_CHILD).as_deref(),
        Ok("1"),
        "run only by its parent test"
    );
    assert_eq!(std::env::var("RUST_LOG").as_deref(), Ok("warn"));
    let temp = TempDir::new().unwrap();
    private_dir(temp.path());
    let first = BrokerConfigPaths::new(temp.path(), "inherited-filter", false, true);
    write_config(&first);
    let process = BrokerProcess::start(&first.config_path);
    assert_ne!(process.addr().port(), 0);
    // A conflicting broker is still seen failing before it binds.
    let shared_audit = BrokerConfigPaths::new(temp.path(), "inherited-filter-audit", false, true)
        .with_audit_path(first.audit_path.clone().unwrap());
    write_config(&shared_audit);
    let stderr = run_expect_startup_failure(&shared_audit.config_path);
    assert!(stderr.contains("audit state lock is held"), "{stderr}");
    assert!(stderr.contains("broker_start_failed"), "{stderr}");
    drop(process);
    println!("inherited warning-only filter checked");
}

#[test]
fn serve_allows_disjoint_state_sets() {
    let _guard = state_lock_test_guard();
    let temp = TempDir::new().unwrap();
    private_dir(temp.path());
    let first = BrokerConfigPaths::new(temp.path(), "disjoint-a", true, true);
    let second = BrokerConfigPaths::new(temp.path(), "disjoint-b", true, true);
    write_config(&first);
    write_config(&second);

    let first_process = BrokerProcess::start(&first.config_path);
    let second_process = BrokerProcess::start(&second.config_path);

    drop(second_process);
    drop(first_process);
}

#[test]
fn serve_auto_creates_state_directories_before_locking() {
    let _guard = state_lock_test_guard();
    let temp = TempDir::new().unwrap();
    private_dir(temp.path());
    let paths = BrokerConfigPaths::new(temp.path(), "fresh", true, true);
    write_config(&paths);

    let process = BrokerProcess::start(&paths.config_path);

    let managed_store = paths.managed_store_path.as_ref().unwrap();
    let audit = paths.audit_path.as_ref().unwrap();
    assert!(managed_store.parent().unwrap().is_dir());
    assert!(audit.parent().unwrap().is_dir());
    assert!(paths.spool_dir.is_dir());
    assert!(
        managed_store
            .with_file_name("managed.sqlite3.agent-access.lock")
            .is_file()
    );
    assert!(
        audit
            .with_file_name("audit.jsonl.agent-access.lock")
            .is_file()
    );
    assert!(
        paths
            .spool_dir
            .join(".agent-access-broker.spool.lock")
            .is_file()
    );

    drop(process);
}

struct BrokerConfigPaths {
    config_path: PathBuf,
    service_token_path: PathBuf,
    managed_store_path: Option<PathBuf>,
    audit_path: Option<PathBuf>,
    spool_dir: PathBuf,
}

impl BrokerConfigPaths {
    fn new(root: &Path, name: &str, managed_store: bool, audit: bool) -> Self {
        let base = root.join(name);
        Self {
            config_path: base.join("broker.toml"),
            service_token_path: base.join("service-token"),
            managed_store_path: managed_store.then(|| base.join("managed").join("managed.sqlite3")),
            audit_path: audit.then(|| base.join("audit").join("audit.jsonl")),
            spool_dir: base.join("spool"),
        }
    }

    fn with_managed_store_path(mut self, path: PathBuf) -> Self {
        self.managed_store_path = Some(path);
        self
    }

    fn with_audit_path(mut self, path: PathBuf) -> Self {
        self.audit_path = Some(path);
        self
    }

    fn with_spool_dir(mut self, path: PathBuf) -> Self {
        self.spool_dir = path;
        self
    }
}

/// A `serve` process on a loopback port the broker chose itself.
struct BrokerProcess {
    child: Option<Child>,
    stderr: Option<StderrLog>,
    addr: SocketAddr,
}

impl BrokerProcess {
    fn start(config_path: &Path) -> Self {
        Self::start_with_env(config_path, &[])
    }

    /// Starts `serve` on port 0 and waits until its stderr reports the public
    /// listener's `broker_listening` event, which names the bound address.
    /// The broker binds before logging that event, so every earlier startup
    /// event has been written by then. Binding port 0 leaves no window in
    /// which another process could take a port chosen in advance.
    fn start_with_env(config_path: &Path, envs: &[(&str, &str)]) -> Self {
        let mut command = broker_command(config_path);
        for (name, value) in envs {
            command.env(name, value);
        }
        let (mut process, mut stderr) = Self::spawn(command);
        let deadline = Instant::now() + START_TIMEOUT;
        loop {
            let remaining = deadline.saturating_duration_since(Instant::now());
            let Some(line) = stderr.next_line(remaining) else {
                process.stderr = Some(stderr);
                let (output, stderr) = process.stop();
                panic!(
                    "broker did not log broker_listening within {START_TIMEOUT:?}: status={}; stdout={}; stderr={stderr}",
                    output.status,
                    String::from_utf8_lossy(&output.stdout)
                );
            };
            if let Some(addr) = public_listening_address(&line) {
                process.addr = addr;
                process.stderr = Some(stderr);
                return process;
            }
        }
    }

    /// Spawns `command`, whose child the returned process kills when dropped,
    /// and reads its stderr. The address is unknown until it is logged.
    fn spawn(mut command: Command) -> (Self, StderrLog) {
        let mut child = command.spawn().unwrap();
        let stderr = StderrLog::read(child.stderr.take().unwrap());
        let process = Self {
            child: Some(child),
            stderr: None,
            addr: SocketAddr::from(([127, 0, 0, 1], 0)),
        };
        (process, stderr)
    }

    fn addr(&self) -> SocketAddr {
        self.addr
    }

    /// Kills the process and returns its stdout and complete stderr.
    fn stop(mut self) -> (Output, String) {
        let mut child = self.child.take().expect("broker process is present");
        if child.try_wait().ok().flatten().is_none() {
            let _ = child.kill();
        }
        let output = child.wait_with_output().unwrap();
        let stderr = self
            .stderr
            .take()
            .expect("broker stderr is present")
            .finish();
        (output, stderr)
    }
}

impl Drop for BrokerProcess {
    fn drop(&mut self) {
        let Some(child) = self.child.as_mut() else {
            return;
        };
        if child.try_wait().ok().flatten().is_none() {
            let _ = child.kill();
        }
        let _ = child.wait();
    }
}

/// The address of a public `broker_listening` event line.
fn public_listening_address(line: &str) -> Option<SocketAddr> {
    let event = serde_json::from_str::<Value>(line).ok()?;
    if event["event"] != "broker_listening" || event["listener"] != "public" {
        return None;
    }
    Some(
        event["address"]
            .as_str()
            .and_then(|address| address.parse().ok())
            .unwrap_or_else(|| panic!("broker_listening has no socket address: {line}")),
    )
}

/// A child's stderr, read line by line on a thread as it is written.
struct StderrLog {
    lines: mpsc::Receiver<String>,
    seen: Vec<String>,
    reader: thread::JoinHandle<()>,
}

impl StderrLog {
    fn read(stderr: std::process::ChildStderr) -> Self {
        let (sender, lines) = mpsc::channel();
        let reader = thread::spawn(move || {
            for line in BufReader::new(stderr).lines() {
                let Ok(line) = line else {
                    break;
                };
                if sender.send(line).is_err() {
                    break;
                }
            }
        });
        Self {
            lines,
            seen: Vec::new(),
            reader,
        }
    }

    /// The next line, or `None` once stderr closes or `timeout` passes.
    fn next_line(&mut self, timeout: Duration) -> Option<String> {
        let line = self.lines.recv_timeout(timeout).ok()?;
        self.seen.push(line.clone());
        Some(line)
    }

    /// Every line, once the stopped child has closed stderr.
    fn finish(mut self) -> String {
        self.reader.join().unwrap();
        self.seen.extend(self.lines.try_iter());
        self.seen.join("\n")
    }
}

/// Runs `serve` on port 0, expecting it to fail before binding its public
/// listener, and returns its stderr. A `broker_listening` event means it
/// bound the listener first.
fn run_expect_startup_failure(config_path: &Path) -> String {
    let (mut process, mut stderr) = BrokerProcess::spawn(broker_command(config_path));
    let deadline = Instant::now() + EXIT_TIMEOUT;
    while let Some(line) = stderr.next_line(deadline.saturating_duration_since(Instant::now())) {
        if public_listening_address(&line).is_some() {
            process.stderr = Some(stderr);
            let (output, stderr) = process.stop();
            panic!(
                "conflicting broker bound its public listener; stdout={}; stderr={stderr}",
                String::from_utf8_lossy(&output.stdout)
            );
        }
    }
    // Stderr closes as the process exits; reap it within the same bound.
    let exiting = Instant::now();
    let child = process.child.as_mut().expect("broker process is present");
    while child.try_wait().unwrap().is_none() {
        assert!(
            exiting.elapsed() <= EXIT_TIMEOUT,
            "broker did not fail within {EXIT_TIMEOUT:?}; stderr={}",
            stderr.seen.join("\n")
        );
        thread::sleep(Duration::from_millis(25));
    }
    process.stderr = Some(stderr);
    let (output, stderr) = process.stop();
    assert!(
        !output.status.success(),
        "broker unexpectedly exited successfully; stdout={}; stderr={stderr}",
        String::from_utf8_lossy(&output.stdout)
    );
    stderr
}

fn broker_command(config_path: &Path) -> Command {
    let mut command = Command::new(broker_bin());
    command
        .arg("--config")
        .arg(config_path)
        .arg("serve")
        .arg("--listen")
        .arg("127.0.0.1:0")
        .env("RUST_LOG", BROKER_LOG_FILTER)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    command
}

fn broker_bin() -> &'static str {
    env!("CARGO_BIN_EXE_agent-access-broker")
}

fn stderr_json_events(stderr: &[u8]) -> Vec<Value> {
    let stderr = String::from_utf8_lossy(stderr);
    let events = stderr
        .lines()
        .filter(|line| !line.trim().is_empty())
        .map(|line| {
            serde_json::from_str::<Value>(line)
                .unwrap_or_else(|error| panic!("stderr line was not JSON: {line}; error={error}"))
        })
        .collect::<Vec<_>>();
    assert!(
        !events.is_empty(),
        "serve stderr did not contain JSON events"
    );
    events
}

fn event_by_name<'a>(events: &'a [Value], name: &str) -> &'a Value {
    events
        .iter()
        .find(|event| event.get("event").and_then(Value::as_str) == Some(name))
        .unwrap_or_else(|| panic!("event {name} not found in {events:?}"))
}

fn write_config(paths: &BrokerConfigPaths) {
    fs::create_dir_all(paths.config_path.parent().unwrap()).unwrap();
    private_dir(paths.config_path.parent().unwrap());
    fs::write(&paths.service_token_path, "service-token").unwrap();
    let managed_store = paths
        .managed_store_path
        .as_ref()
        .map(|path| {
            let key_path = paths.config_path.with_extension("identity-key");
            fs::write(&key_path, URL_SAFE_NO_PAD.encode([19u8; 32])).unwrap();
            format!(
                r#"
[managed_store]
type = "sqlite"
path = "{path}"
auto_migrate = true
[credential_encryption]
active_key = "fixture"
[[credential_encryption.keys]]
id = "fixture"
provider = "file"
path = "{key_path}"
"#,
                path = path.display(),
                key_path = key_path.display()
            )
        })
        .unwrap_or_default();
    let audit = paths
        .audit_path
        .as_ref()
        .map(|path| {
            let kind = if path
                .extension()
                .is_some_and(|extension| extension == "sqlite")
            {
                "sqlite"
            } else {
                "jsonl"
            };
            format!(
                r#"
[audit]
type = "{kind}"
path = "{path}"
"#,
                path = path.display()
            )
        })
        .unwrap_or_default();
    let config = format!(
        r#"[deployment]
environment = "test"
enable_fake_service = true

[providers.fake]

[identity]
mode = "anonymous"
authority = "toml"

[credentials.service.fake]
type = "bearer_token"
token_ref = "file:{service_token}"

[policy]
authority = "toml"
default_decision = "deny"

[[policy.resources]]
id = "fake-test"
resource_type = "fake_project"
selector = {{ kind = "exact", value = "TEST" }}
allowed_execution_contexts = ["default"]
enabled = true

[[policy.grants]]
subjects = ["group:anonymous"]
service = "fake"
actions = ["echo"]
resources = {{ resource_ids = ["fake-test"] }}
credential_mode = "service"

[limits]
upload_spool_dir = "{spool_dir}"

{managed_store}
{audit}
"#,
        service_token = paths.service_token_path.display(),
        spool_dir = paths.spool_dir.display(),
        managed_store = managed_store,
        audit = audit,
    );
    fs::write(&paths.config_path, config).unwrap();
}

fn state_lock_test_guard() -> MutexGuard<'static, ()> {
    STATE_LOCK_TEST_MUTEX
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

fn private_dir(path: &Path) {
    fs::create_dir_all(path).unwrap();
    #[cfg(unix)]
    fs::set_permissions(path, fs::Permissions::from_mode(0o700)).unwrap();
}
