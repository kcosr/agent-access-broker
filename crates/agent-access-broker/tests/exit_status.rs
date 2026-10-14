//! Exit statuses of the built executable: configuration errors exit 3 from
//! `config validate`, explicit `serve` and the default command alike, while
//! other startup failures exit 1. Every case fails before it could bind a
//! listener or take a state lock.
use std::fs;
use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use tempfile::TempDir;

#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;

const MALFORMED: &str = "[identity\nmode = \"anonymous\"\n";
const INVALID: &str = r#"
[deployment]
environment = "development"

[identity]
mode = "anonymous"
authority = "toml"

[policy]
authority = "toml"
default_decision = "deny"

[[policy.grants]]
subjects = ["group:anonymous"]
service = "no_such_service"
actions = ["echo"]
credential_mode = "service"
"#;

#[test]
fn configuration_errors_exit_three_from_every_command() {
    let temp = private_temp_dir();
    let malformed = write_config(temp.path(), "malformed.toml", MALFORMED);
    let invalid = write_config(temp.path(), "invalid.toml", INVALID);
    let missing = temp.path().join("missing.toml");
    for config in [&malformed, &invalid, &missing] {
        let validate = run(config, &["config", "validate"]);
        assert_eq!(validate.status.code(), Some(3), "{}", describe(&validate));

        let serve = run(config, &["serve", "--listen", "127.0.0.1:0"]);
        assert_eq!(serve.status.code(), Some(3), "{}", describe(&serve));
        assert_error_rendering(&serve);

        // Without a subcommand the broker serves on its default address; a
        // configuration error stops it before it binds.
        let default = run(config, &[]);
        assert_eq!(default.status.code(), Some(3), "{}", describe(&default));
        assert_error_rendering(&default);
    }
}

#[test]
fn other_startup_failures_exit_one() {
    let temp = private_temp_dir();
    let spool = temp.path().join("spool");
    let config = write_config(
        temp.path(),
        "valid.toml",
        &format!(
            r#"
[deployment]
environment = "development"

[identity]
mode = "anonymous"
authority = "toml"

[policy]
authority = "toml"
default_decision = "deny"

[limits]
upload_spool_dir = "{}"
"#,
            spool.display()
        ),
    );

    let timeout = run(
        &config,
        &[
            "serve",
            "--listen",
            "127.0.0.1:0",
            "--shutdown-timeout-ms",
            "0",
        ],
    );
    assert_eq!(timeout.status.code(), Some(1), "{}", describe(&timeout));
    assert_error_rendering(&timeout);

    let occupied = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = occupied.local_addr().unwrap().to_string();
    let bind = run(&config, &["serve", "--listen", &address]);
    assert_eq!(bind.status.code(), Some(1), "{}", describe(&bind));
    assert_error_rendering(&bind);
}

fn run(config: &Path, args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_agent-access-broker"))
        .arg("--config")
        .arg(config)
        .args(args)
        .env_remove("RUST_LOG")
        .output()
        .unwrap()
}

fn assert_error_rendering(output: &Output) {
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.lines().any(|line| line.starts_with("Error: ")),
        "{}",
        describe(output)
    );
}

fn describe(output: &Output) -> String {
    format!(
        "status={:?}; stdout={}; stderr={}",
        output.status.code(),
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    )
}

fn write_config(directory: &Path, name: &str, body: &str) -> PathBuf {
    let path = directory.join(name);
    fs::write(&path, body).unwrap();
    path
}

fn private_temp_dir() -> TempDir {
    let temp = TempDir::new().unwrap();
    #[cfg(unix)]
    fs::set_permissions(temp.path(), fs::Permissions::from_mode(0o700)).unwrap();
    temp
}
