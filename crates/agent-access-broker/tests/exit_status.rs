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
const MINIMAL: &str = r#"
[deployment]
environment = "development"

[identity]
mode = "anonymous"
authority = "toml"

[policy]
authority = "toml"
default_decision = "deny"
"#;
const UNKNOWN_SERVICE_GRANT: &str = r#"
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
    let invalid = write_config(
        temp.path(),
        "invalid.toml",
        &format!(
            "{MINIMAL}{UNKNOWN_SERVICE_GRANT}{}",
            limits(&temp.path().join("spool"))
        ),
    );
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
fn an_omitted_upload_spool_dir_is_a_configuration_error_naming_it() {
    let temp = private_temp_dir();
    let without_table = write_config(temp.path(), "without-table.toml", MINIMAL);
    let without_setting = write_config(
        temp.path(),
        "without-setting.toml",
        &format!("{MINIMAL}\n[limits]\nmax_concurrent_requests = 5\n"),
    );
    for (config, expected) in [
        (
            &without_table,
            "missing field `upload_spool_dir` in table `[limits]`",
        ),
        (&without_setting, "missing field `upload_spool_dir`"),
    ] {
        // Run where the removed default would have put the spool.
        for args in [
            &["config", "validate"][..],
            &["serve", "--listen", "127.0.0.1:0"][..],
        ] {
            let output = run_in(temp.path(), config, args);
            assert_eq!(output.status.code(), Some(3), "{}", describe(&output));
            let stderr = String::from_utf8_lossy(&output.stderr);
            assert!(stderr.contains(expected), "{}", describe(&output));
        }
    }
    assert!(!temp.path().join("target").exists());
}

#[test]
fn other_startup_failures_exit_one() {
    let temp = private_temp_dir();
    let config = write_config(
        temp.path(),
        "valid.toml",
        &format!("{MINIMAL}{}", limits(&temp.path().join("spool"))),
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

/// A `[limits]` table spooling uploads in `spool`.
fn limits(spool: &Path) -> String {
    format!(
        "\n[limits]\nupload_spool_dir = {:?}\n",
        spool.display().to_string()
    )
}

fn run(config: &Path, args: &[&str]) -> Output {
    command(config, args).output().unwrap()
}

fn run_in(directory: &Path, config: &Path, args: &[&str]) -> Output {
    command(config, args)
        .current_dir(directory)
        .output()
        .unwrap()
}

fn command(config: &Path, args: &[&str]) -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_agent-access-broker"));
    command
        .arg("--config")
        .arg(config)
        .args(args)
        .env_remove("RUST_LOG");
    command
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
