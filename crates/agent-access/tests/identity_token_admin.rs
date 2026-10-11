use std::io::Write;
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
            Some(serde_json::json!({"namespace":"Managed.Linux","username":username})),
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
    for (action, enabled, version) in [("disable", false, 1), ("enable", true, 2)] {
        Mock::given(method("PATCH"))
            .and(path(&detail))
            .and(body_json(serde_json::json!({"enabled":enabled,"expectedVersion":version})))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({"ok":true,"result":{"bindingId":binding,"version":version+1,"enabled":enabled}})))
            .expect(1).mount(&server).await;
        let output = identity_command(&server.uri(), "identity-bindings")
            .args([
                action,
                "alice",
                binding,
                "--expected-version",
                &version.to_string(),
            ])
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{action}: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
    Mock::given(method("DELETE"))
        .and(path(&detail))
        .and(query_param("expectedVersion", "3"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(serde_json::json!({"ok":true,"result":{"deleted":true}})),
        )
        .expect(1)
        .mount(&server)
        .await;
    let output = identity_command(&server.uri(), "identity-bindings")
        .args(["delete", "alice", binding, "--expected-version", "3"])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
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
        ("identity-bindings", vec!["disable", "alice", "binding"]),
        ("identity-bindings", vec!["delete", "alice", "binding"]),
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
