use agent_access_broker_host::test_support::{FixtureDir, IsolatedBroker};
use agent_access_core::{
    BrokerTokenClass, BrokerTokenHasher, BrokerTokenIssueRequest, BrokerTokensConfig, ManagedStore,
    ManagedStoreConfig, ManagedStoreOpenMode, PrincipalAccessPatchRequest, PrincipalRole,
    PrincipalWriteRequest,
};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use serde_json::{Value, json};
use std::io::Write;
use std::path::Path;
use std::process::{Command, Stdio};
use wiremock::matchers::{body_json, method, path, query_param};
use wiremock::{Mock, MockServer, ResponseTemplate};

fn command(url: &str) -> Command {
    identity_command(url, "identity-token")
}

fn identity_command(url: &str, section: &str) -> Command {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_agent-access"));
    for (key, _) in std::env::vars().filter(|(key, _)| key.starts_with("AGENT_ACCESS_")) {
        cmd.env_remove(key);
    }
    cmd.env("AGENT_ACCESS_CONFIG", "/dev/null");
    cmd.args(["--url", url, "--no-token", "admin", "principals", section]);
    cmd
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn admin_identity_token_import_preserves_exact_file_and_stdin_bytes() {
    let server = MockServer::start().await;
    // The CLI does not silently repair malformed input; the server validates it.
    let token = "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee\n";
    Mock::given(method("PUT"))
        .and(path("/v1/admin/principals/alice/identity-token"))
        .and(body_json(serde_json::json!({"token": token})))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(serde_json::json!({"ok":true,"result":{"configured":true}})),
        )
        .expect(2)
        .mount(&server)
        .await;
    let dir = tempfile::tempdir().unwrap();
    let file = dir.path().join("identity-token");
    std::fs::write(&file, token).unwrap();
    let output = command(&server.uri())
        .args(["set", "alice", "--identity-token-file"])
        .arg(&file)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let mut child = command(&server.uri())
        .args(["set", "alice", "--identity-token-stdin"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(token.as_bytes())
        .unwrap();
    let output = child.wait_with_output().unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(!String::from_utf8_lossy(&output.stdout).contains(token));
    assert!(!String::from_utf8_lossy(&output.stderr).contains(token));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn admin_identity_token_lifecycle_uses_explicit_admin_routes() {
    let server = MockServer::start().await;
    for (action, verb, suffix) in [
        ("inspect", "GET", ""),
        ("reveal", "POST", "/reveal"),
        ("generate", "POST", "/generate"),
        ("remove", "DELETE", ""),
    ] {
        Mock::given(method(verb))
            .and(path(format!(
                "/v1/admin/principals/alice/identity-token{suffix}"
            )))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(serde_json::json!({"ok":true,"result":{}})),
            )
            .expect(1)
            .mount(&server)
            .await;
        let output = command(&server.uri())
            .args([action, "alice"])
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{action}: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
}

#[test]
fn identity_token_import_requires_exactly_one_non_argv_secret_source() {
    for args in [
        vec!["set", "alice"],
        vec![
            "set",
            "alice",
            "--identity-token-file",
            "file",
            "--identity-token-stdin",
        ],
        vec!["set", "alice", "--token-value", "secret"],
    ] {
        let output = command("http://127.0.0.1:1").args(args).output().unwrap();
        assert!(!output.status.success());
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn admin_identity_access_lifecycle_sends_explicit_versions() {
    let server = MockServer::start().await;
    let route = "/v1/admin/principals/alice/identity-access";
    Mock::given(method("GET"))
        .and(path(route))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "ok":true,"result":{"principalId":"alice","paused":false,"version":1}
        })))
        .expect(1)
        .mount(&server)
        .await;
    let output = identity_command(&server.uri(), "identity-access")
        .args(["inspect", "alice"])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    for (action, paused, version) in [("pause", true, 1), ("resume", false, 2)] {
        Mock::given(method("PATCH"))
            .and(path(route))
            .and(body_json(
                serde_json::json!({"paused":paused,"expectedVersion":version}),
            ))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "ok":true,"result":{"principalId":"alice","paused":paused,"version":version+1}
            })))
            .expect(1)
            .mount(&server)
            .await;
        let output = identity_command(&server.uri(), "identity-access")
            .args([action, "alice", "--expected-version", &version.to_string()])
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{action}: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn admin_identity_bindings_lifecycle_preserves_subject_and_versions() {
    let server = MockServer::start().await;
    let route = "/v1/admin/principals/alice/identity-bindings";
    let binding = "00000000-0000-4000-8000-000000000001";
    let detail = format!("{route}/{binding}");
    let username = "Alice+team@example.test";
    for (action, verb, body) in [
        ("list", "GET", None),
        (
            "create",
            "POST",
            Some(
                serde_json::json!({"namespace":"Managed.Linux","username":username,"readOnly":false}),
            ),
        ),
    ] {
        let mut mock = Mock::given(method(verb)).and(path(route));
        if let Some(body) = body {
            mock = mock.and(body_json(body));
        }
        mock.respond_with(
            ResponseTemplate::new(200).set_body_json(serde_json::json!({"ok":true,"result":{}})),
        )
        .expect(1)
        .mount(&server)
        .await;
        let mut command = identity_command(&server.uri(), "identity-bindings");
        command.args([action, "alice"]);
        if action == "create" {
            command.args(["--namespace", "Managed.Linux", "--username", username]);
        }
        let output = command.output().unwrap();
        assert!(
            output.status.success(),
            "{action}: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
    Mock::given(method("POST"))
        .and(path(route))
        .and(body_json(serde_json::json!({
            "namespace":"Managed.Linux","username":"reader","readOnly":true
        })))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(serde_json::json!({"ok":true,"result":{}})),
        )
        .expect(1)
        .mount(&server)
        .await;
    let output = identity_command(&server.uri(), "identity-bindings")
        .args([
            "create",
            "alice",
            "--namespace",
            "Managed.Linux",
            "--username",
            "reader",
            "--read-only",
        ])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    // Only the supplied settings are sent, with the version fence.
    for (settings, body, version) in [
        (
            &["--enabled", "false"][..],
            serde_json::json!({"enabled":false,"expectedVersion":1}),
            1,
        ),
        (
            &["--read-only", "true"][..],
            serde_json::json!({"readOnly":true,"expectedVersion":2}),
            2,
        ),
        (
            &["--enabled", "true", "--read-only", "false"][..],
            serde_json::json!({"enabled":true,"readOnly":false,"expectedVersion":3}),
            3,
        ),
    ] {
        Mock::given(method("PATCH"))
            .and(path(&detail))
            .and(body_json(body.clone()))
            .respond_with(ResponseTemplate::new(200).set_body_json(
                serde_json::json!({"ok":true,"result":{"bindingId":binding,"version":version+1}}),
            ))
            .expect(1)
            .mount(&server)
            .await;
        let output = identity_command(&server.uri(), "identity-bindings")
            .args(["update", "alice", binding])
            .args(settings)
            .args(["--expected-version", &version.to_string()])
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{body}: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
    Mock::given(method("DELETE"))
        .and(path(&detail))
        .and(query_param("expectedVersion", "4"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(serde_json::json!({"ok":true,"result":{"deleted":true}})),
        )
        .expect(1)
        .mount(&server)
        .await;
    let output = identity_command(&server.uri(), "identity-bindings")
        .args(["delete", "alice", binding, "--expected-version", "4"])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn admin_identity_token_update_sends_settings_and_revision() {
    let server = MockServer::start().await;
    let route = "/v1/admin/principals/alice/identity-token";
    for (settings, body, revision) in [
        (
            &["--enabled", "false"][..],
            serde_json::json!({"enabled":false,"expectedRevision":1}),
            1,
        ),
        (
            &["--read-only", "true"][..],
            serde_json::json!({"readOnly":true,"expectedRevision":2}),
            2,
        ),
        (
            &["--read-only", "false", "--enabled", "true"][..],
            serde_json::json!({"enabled":true,"readOnly":false,"expectedRevision":3}),
            3,
        ),
    ] {
        Mock::given(method("PATCH"))
            .and(path(route))
            .and(body_json(body.clone()))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "ok":true,"result":{"principalId":"alice","revision":revision+1}
            })))
            .expect(1)
            .mount(&server)
            .await;
        let output = command(&server.uri())
            .args(["update", "alice"])
            .args(settings)
            .args(["--expected-revision", &revision.to_string()])
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{body}: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        let printed: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
        assert_eq!(printed["result"]["revision"], revision + 1);
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn identity_controls_reject_obsolete_token_commands_and_unversioned_writes() {
    let server = MockServer::start().await;
    for (section, args) in [
        ("identity-token", vec!["pause", "alice"]),
        ("identity-token", vec!["resume", "alice"]),
        ("identity-access", vec!["pause", "alice"]),
        (
            "identity-access",
            vec!["resume", "alice", "--expected-version", "0"],
        ),
        (
            "identity-bindings",
            vec!["disable", "alice", "binding", "--expected-version", "1"],
        ),
        (
            "identity-bindings",
            vec!["enable", "alice", "binding", "--expected-version", "1"],
        ),
        ("identity-bindings", vec!["delete", "alice", "binding"]),
        (
            "identity-bindings",
            vec!["update", "alice", "binding", "--expected-version", "1"],
        ),
        (
            "identity-bindings",
            vec!["update", "alice", "binding", "--enabled", "false"],
        ),
        (
            "identity-token",
            vec!["update", "alice", "--expected-revision", "1"],
        ),
        (
            "identity-token",
            vec![
                "update",
                "alice",
                "--read-only",
                "true",
                "--expected-revision",
                "0",
            ],
        ),
    ] {
        let output = identity_command(&server.uri(), section)
            .args(args)
            .output()
            .unwrap();
        assert_eq!(
            output.status.code(),
            Some(2),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
    assert!(server.received_requests().await.unwrap().is_empty());
}

fn toml_string(value: impl std::fmt::Display) -> String {
    serde_json::to_string(&value.to_string()).unwrap()
}

/// A managed broker whose relay caller configures the `managed_linux`
/// username namespace, with JSONL audit.
fn managed_document(directory: &FixtureDir, key: &Path, relay: &Path) -> String {
    format!(
        r#"
[identity]
mode = "required"
authority = "managed"

[[identity.sources]]
name = "broker"
type = "broker_tokens"
header = "Authorization"
scheme = "Bearer"

[identity.trusted_callers.relay]
credential_ref = {relay}
credential_transport = "caller_authorization"
username_namespace = "managed_linux"
context_mode = "fixed"
execution_context = "default"

[managed_store]
type = "sqlite"
path = {store}
auto_migrate = true

[broker_tokens]
hash_key_ref = {hash_key}

[credential_encryption]
active_key = "test"

[[credential_encryption.keys]]
id = "test"
provider = "file"
path = {key}

[management]
enabled = true

[policy]
authority = "managed"
default_decision = "deny"

[audit]
type = "jsonl"
path = {audit}

[limits]
upload_spool_dir = {spool}
"#,
        relay = toml_string(format_args!("file:{}", relay.display())),
        store = toml_string(directory.join("store.sqlite").display()),
        hash_key = toml_string(format_args!("file:{}", key.display())),
        key = toml_string(key.display()),
        audit = toml_string(directory.join("audit.jsonl").display()),
        spool = toml_string(directory.join("upload-spool").display()),
    )
}

/// Seeds the administrator and the managed human alice before the broker
/// opens the store, and returns the administrator's token.
fn seed_admin_and_alice(directory: &FixtureDir, key: &Path) -> String {
    let store = ManagedStore::open(
        &ManagedStoreConfig {
            kind: "sqlite".into(),
            path: directory.join("store.sqlite").display().to_string(),
            auto_migrate: true,
            require_registered_principal_for_invocation: false,
        },
        ManagedStoreOpenMode::Startup,
    )
    .unwrap();
    for principal in ["admin", "alice"] {
        store
            .create_principal(PrincipalWriteRequest {
                role: PrincipalRole::User,
                self_service_enabled: None,
                principal_id: principal.into(),
                kind: "user".into(),
                display_name: None,
                email: None,
                external_subject: None,
                created_by: "test".into(),
            })
            .unwrap();
    }
    store
        .patch_principal_access(PrincipalAccessPatchRequest {
            principal_id: "admin".into(),
            role: Some(PrincipalRole::Admin),
            self_service_enabled: None,
            actor: "test".into(),
        })
        .unwrap();
    let hasher = BrokerTokenHasher::load(&BrokerTokensConfig {
        hash_key_ref: format!("file:{}", key.display()),
        ..Default::default()
    })
    .unwrap();
    store
        .issue_broker_token(
            &hasher,
            BrokerTokenIssueRequest {
                principal_id: "admin".into(),
                name: "identity path admin".into(),
                token_class: BrokerTokenClass::Admin,
                scopes: json!({}),
                expires_at: None,
                created_by: "test".into(),
            },
        )
        .unwrap()
        .token
}

/// The administration success record of `operation` at `index`.
fn success_target(records: &[Value], operation: &str, index: usize) -> Value {
    records
        .iter()
        .filter(|record| {
            record["action"] == operation
                && record["providerAudit"]["management"]["phase"] == "success"
        })
        .nth(index)
        .unwrap_or_else(|| panic!("no success record {index} of {operation}"))["providerAudit"]
        ["management"]["target"]
        .clone()
}

/// Both update commands against a real broker: the broker accepts the bodies
/// the CLI sends, settings and fences change only as requested, a no-op keeps
/// the fence, stale fences are refused, the secret's lifecycle keeps the
/// settings, and success audit carries the transaction's before/after values.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn identity_path_update_commands_drive_a_real_broker() {
    let application = IsolatedBroker::new(
        agent_access_broker::composition().unwrap(),
        agent_access_broker::build_identity(),
    )
    .unwrap();
    let directory = application.directory().clone();
    let key = directory
        .secret_file("key", URL_SAFE_NO_PAD.encode([29_u8; 32]))
        .unwrap();
    let relay = directory
        .secret_file("relay.secret", "synthetic-cli-relay-secret-0123456789")
        .unwrap();
    let document = managed_document(&directory, &key, &relay);
    let admin = seed_admin_and_alice(&directory, &key);
    let admin_token = directory.secret_file("admin.token", admin).unwrap();
    let broker = application.config_document(document).start().await.unwrap();
    let url = broker.public_url();
    let cli = |args: &[&str]| {
        let mut command = Command::new(env!("CARGO_BIN_EXE_agent-access"));
        for (key, _) in std::env::vars().filter(|(key, _)| key.starts_with("AGENT_ACCESS_")) {
            command.env_remove(key);
        }
        let output = command
            .env("AGENT_ACCESS_CONFIG", "/dev/null")
            .args(["--url", &url, "--token-file"])
            .arg(&admin_token)
            .args([
                "--identity-header",
                "Authorization",
                "--identity-scheme",
                "Bearer",
                "admin",
                "principals",
            ])
            .args(args)
            .output()
            .unwrap();
        let response: Value = serde_json::from_slice(&output.stdout).unwrap_or_else(|error| {
            panic!(
                "{args:?}: invalid JSON {error}; stderr={}",
                String::from_utf8_lossy(&output.stderr)
            )
        });
        (output.status.success(), response)
    };
    let ok = |args: &[&str]| {
        let (success, response) = cli(args);
        assert!(success, "{args:?}: {response}");
        response["result"].clone()
    };
    let stale = |args: &[&str]| {
        let (success, response) = cli(args);
        assert!(!success, "{args:?} accepted a stale fence: {response}");
        assert_eq!(
            response["reasonCode"], "identity_version_conflict",
            "{response}"
        );
    };
    let settings = |result: &Value, fence: &str| {
        (
            result["enabled"].as_bool().unwrap(),
            result["readOnly"].as_bool().unwrap(),
            result[fence].as_i64().unwrap(),
        )
    };

    let created = ok(&[
        "identity-bindings",
        "create",
        "alice",
        "--namespace",
        "managed_linux",
        "--username",
        "Reader.Alice",
        "--read-only",
    ]);
    assert_eq!(settings(&created, "version"), (true, true, 1));
    let binding = created["bindingId"].as_str().unwrap().to_owned();
    let update = |settings: &[&'static str], version: &'static str| {
        let mut args = vec!["identity-bindings", "update", "alice", binding.as_str()];
        args.extend_from_slice(settings);
        args.extend_from_slice(&["--expected-version", version]);
        args
    };
    let disabled = ok(&update(&["--enabled", "false"], "1"));
    assert_eq!(settings(&disabled, "version"), (false, true, 2));
    // Repeating the current value writes nothing and keeps the version.
    let unchanged = ok(&update(&["--enabled", "false"], "2"));
    assert_eq!(settings(&unchanged, "version"), (false, true, 2));
    stale(&update(&["--read-only", "false"], "1"));
    let restored = ok(&update(&["--enabled", "true", "--read-only", "false"], "2"));
    assert_eq!(settings(&restored, "version"), (true, false, 3));

    // The not-configured inventory row takes settings before any secret exists.
    let inventory = ok(&["identity-token", "inspect", "alice"]);
    assert_eq!(inventory["configured"], false);
    assert_eq!(settings(&inventory, "revision"), (true, false, 1));
    let read_only = ok(&[
        "identity-token",
        "update",
        "alice",
        "--read-only",
        "true",
        "--expected-revision",
        "1",
    ]);
    assert_eq!(read_only["configured"], false);
    assert_eq!(settings(&read_only, "revision"), (true, true, 2));
    stale(&[
        "identity-token",
        "update",
        "alice",
        "--enabled",
        "false",
        "--expected-revision",
        "1",
    ]);
    let generated = ok(&["identity-token", "generate", "alice"]);
    assert_eq!(generated["configured"], true);
    assert_eq!(settings(&generated, "revision"), (true, true, 3));
    let disabled = ok(&[
        "identity-token",
        "update",
        "alice",
        "--enabled",
        "false",
        "--expected-revision",
        "3",
    ]);
    assert_eq!(settings(&disabled, "revision"), (false, true, 4));
    let inventory = ok(&["identity-token", "inspect", "alice"]);
    assert_eq!(inventory["configured"], true);
    assert_eq!(settings(&inventory, "revision"), (false, true, 4));

    let records = broker.audit().unwrap().records();
    assert_eq!(
        success_target(&records, "admin.principals.identity_bindings.create", 0)["after"],
        json!({"enabled":true,"readOnly":true,"version":1})
    );
    let patch = "admin.principals.identity_bindings.patch";
    for (index, before, after) in [
        (0, (true, true, 1), (false, true, 2)),
        (1, (false, true, 2), (false, true, 2)),
        (2, (false, true, 2), (true, false, 3)),
    ] {
        let target = success_target(&records, patch, index);
        assert_eq!(target["bindingId"], binding.as_str());
        assert_eq!(target["namespace"], "managed_linux");
        assert_eq!(settings(&target["before"], "version"), before, "{target}");
        assert_eq!(settings(&target["after"], "version"), after, "{target}");
    }
    let patch = "admin.principals.identity_token.patch";
    for (index, before, after) in [
        (0, (true, false, 1), (true, true, 2)),
        (1, (true, true, 3), (false, true, 4)),
    ] {
        let target = success_target(&records, patch, index);
        assert_eq!(target["principal"], "alice");
        assert_eq!(settings(&target["before"], "revision"), before, "{target}");
        assert_eq!(settings(&target["after"], "revision"), after, "{target}");
    }
    assert_eq!(
        success_target(&records, "admin.principals.identity_token.generate", 0)["after"],
        json!({"configured":true,"enabled":true,"readOnly":true,"revision":3})
    );
    // Every token PATCH was audited before it ran, including the stale one.
    assert_eq!(
        records
            .iter()
            .filter(|record| record["action"] == patch
                && record["providerAudit"]["management"]["phase"] == "preflight")
            .count(),
        3
    );
    let text = broker.audit().unwrap().text();
    assert!(!text.contains("Reader.Alice"));
    assert!(!text.contains("synthetic-cli-relay-secret"));
    broker.shutdown();
    broker.join().await.unwrap();
}
