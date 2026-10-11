use std::io::Write;
use std::path::Path;
use std::process::{Command, Output, Stdio};

const TOKEN_ENV_VARS: &[&str] = &[
    "AGENT_ACCESS_CONFIG",
    "AGENT_ACCESS_TOKEN",
    "AGENT_ACCESS_TOKEN_FILE",
    "AGENT_ACCESS_TOKEN_ENV",
    "AGENT_ACCESS_NO_TOKEN",
    "AGENT_ACCESS_URL",
    "AGENT_ACCESS_IDENTITY_HEADER",
    "AGENT_ACCESS_IDENTITY_SCHEME",
    "AGENT_ACCESS_ALLOW_INSECURE_BROKER_HTTP",
];

#[test]
fn auth_token_status_succeeds_without_default_config() {
    let temp = tempfile::tempdir().unwrap();
    let output = agent_access(&temp.path().join("xdg"))
        .args(["auth", "token", "status"])
        .output()
        .unwrap();

    assert_success(&output);
    let stdout = stdout(&output);
    assert!(stdout.contains("identity: enabled"));
    assert!(stdout.contains("configured token file: none"));
    assert!(stdout.contains("configured token file status: not configured"));
    assert!(stdout.contains("effective token source: none"));
    assert!(stdout.contains("effective token status: absent"));
}

#[test]
fn auth_token_status_reports_configured_file_and_fallbacks_without_revealing_tokens() {
    let temp = tempfile::tempdir().unwrap();
    let config = temp.path().join("config.toml");
    let token_file = temp.path().join("identity.token");
    write_cli_config(&config, &token_file, false);

    std::fs::write(&token_file, "  stored-secret  \n").unwrap();
    let present = agent_access(temp.path())
        .args([
            "--config",
            config.to_str().unwrap(),
            "auth",
            "token",
            "status",
        ])
        .output()
        .unwrap();
    assert_success(&present);
    let present_stdout = stdout(&present);
    assert!(present_stdout.contains("configured token file status: present"));
    assert!(present_stdout.contains("effective token source: config identity.token_file"));
    assert!(present_stdout.contains("effective token status: present"));
    assert!(!present_stdout.contains("stored-secret"));

    std::fs::write(&token_file, " \n").unwrap();
    let fallback = agent_access(temp.path())
        .env("AGENT_ACCESS_TOKEN", "fallback-secret")
        .args([
            "--config",
            config.to_str().unwrap(),
            "auth",
            "token",
            "status",
        ])
        .output()
        .unwrap();
    assert_success(&fallback);
    let fallback_stdout = stdout(&fallback);
    assert!(fallback_stdout.contains("configured token file status: empty"));
    assert!(fallback_stdout.contains("effective token source: AGENT_ACCESS_TOKEN"));
    assert!(fallback_stdout.contains("effective token status: present"));
    assert!(!fallback_stdout.contains("fallback-secret"));

    std::fs::remove_file(&token_file).unwrap();
    let missing = agent_access(temp.path())
        .args([
            "--config",
            config.to_str().unwrap(),
            "auth",
            "token",
            "status",
        ])
        .output()
        .unwrap();
    assert_success(&missing);
    let missing_stdout = stdout(&missing);
    assert!(missing_stdout.contains("configured token file status: missing"));
    assert!(missing_stdout.contains("effective token source: none"));
    assert!(missing_stdout.contains("effective token status: absent"));
}

#[test]
fn auth_token_status_expands_home_relative_configured_token_file() {
    let temp = tempfile::tempdir().unwrap();
    let config = temp.path().join("config.toml");
    let home = temp.path().join("home");
    let token_file = home.join(".config").join("agent-access").join("token");
    std::fs::create_dir_all(token_file.parent().unwrap()).unwrap();
    std::fs::write(&token_file, "home-token\n").unwrap();
    write_cli_config_value(&config, "~/.config/agent-access/token", false);

    let output = agent_access_with_home(temp.path(), &home)
        .args([
            "--config",
            config.to_str().unwrap(),
            "auth",
            "token",
            "status",
        ])
        .output()
        .unwrap();

    assert_success(&output);
    let stdout = stdout(&output);
    assert!(stdout.contains(&format!("configured token file: {}", token_file.display())));
    assert!(stdout.contains("configured token file status: present"));
    assert!(stdout.contains("effective token source: config identity.token_file"));
    assert!(!stdout.contains("home-token"));
}

#[test]
fn auth_token_configured_tilde_user_path_is_not_expanded() {
    let temp = tempfile::tempdir().unwrap();
    let config = temp.path().join("config.toml");
    let home = temp.path().join("home");
    write_cli_config_value(&config, "~other/agent-access/token", false);

    let output = agent_access_with_home(temp.path(), &home)
        .args([
            "--config",
            config.to_str().unwrap(),
            "auth",
            "token",
            "status",
        ])
        .output()
        .unwrap();

    assert_success(&output);
    let stdout = stdout(&output);
    assert!(stdout.contains("configured token file: ~other/agent-access/token"));
    assert!(stdout.contains("configured token file status: missing"));
    assert!(stdout.contains("effective token source: none"));
}

#[cfg(unix)]
#[test]
fn auth_token_configured_tilde_fails_when_home_is_missing() {
    let temp = tempfile::tempdir().unwrap();
    let config = temp.path().join("config.toml");
    write_cli_config_value(&config, "~/.config/agent-access/token", false);

    let output = agent_access(temp.path())
        .env_remove("HOME")
        .args([
            "--config",
            config.to_str().unwrap(),
            "auth",
            "token",
            "status",
        ])
        .output()
        .unwrap();

    assert_eq!(output.status.code(), Some(3));
    assert!(stderr(&output).contains(
        "config identity.token_file uses '~' but the current user's home directory is unavailable"
    ));
}

#[test]
fn auth_token_status_reports_disabled_identity() {
    let temp = tempfile::tempdir().unwrap();
    let config = temp.path().join("config.toml");
    let token_file = temp.path().join("identity.token");
    write_cli_config(&config, &token_file, true);

    let output = agent_access(temp.path())
        .args([
            "--config",
            config.to_str().unwrap(),
            "auth",
            "token",
            "status",
        ])
        .output()
        .unwrap();

    assert_success(&output);
    let stdout = stdout(&output);
    assert!(stdout.contains("identity: disabled"));
    assert!(stdout.contains("effective token source: disabled"));
    assert!(stdout.contains("effective token status: disabled"));
}

#[test]
fn auth_token_status_fails_for_unreadable_configured_file_even_when_disabled() {
    let temp = tempfile::tempdir().unwrap();
    let config = temp.path().join("config.toml");
    let token_file = temp.path().join("token-directory");
    std::fs::create_dir(&token_file).unwrap();
    write_cli_config(&config, &token_file, true);

    let output = agent_access(temp.path())
        .args([
            "--config",
            config.to_str().unwrap(),
            "auth",
            "token",
            "status",
        ])
        .output()
        .unwrap();

    assert_eq!(output.status.code(), Some(3));
    let stdout = stdout(&output);
    assert!(stdout.contains("identity: disabled"));
    assert!(stdout.contains("configured token file status: unreadable"));
    assert!(stderr(&output).contains("configured token file is unreadable"));
}

#[test]
fn auth_token_set_and_clear_mutate_configured_file() {
    let temp = tempfile::tempdir().unwrap();
    let config = temp.path().join("config.toml");
    let token_file = temp.path().join("nested").join("identity.token");
    write_cli_config(&config, &token_file, false);

    let set = run_with_stdin(
        agent_access(temp.path()).args([
            "--config",
            config.to_str().unwrap(),
            "auth",
            "token",
            "set",
            "--token-stdin",
        ]),
        "  new-token  \n",
    );
    assert_success(&set);
    assert_eq!(std::fs::read_to_string(&token_file).unwrap(), "new-token\n");

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(&token_file).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
        let dir_mode = std::fs::metadata(token_file.parent().unwrap())
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(dir_mode, 0o700);
    }

    let clear = agent_access(temp.path())
        .args([
            "--config",
            config.to_str().unwrap(),
            "auth",
            "token",
            "clear",
        ])
        .output()
        .unwrap();
    assert_success(&clear);
    assert_eq!(std::fs::read(&token_file).unwrap(), b"");

    std::fs::remove_file(&token_file).unwrap();
    let clear_missing = agent_access(temp.path())
        .args([
            "--config",
            config.to_str().unwrap(),
            "auth",
            "token",
            "clear",
        ])
        .output()
        .unwrap();
    assert_success(&clear_missing);
    assert!(stdout(&clear_missing).contains("already absent"));
}

#[test]
fn auth_token_set_and_clear_expand_home_relative_configured_token_file() {
    let temp = tempfile::tempdir().unwrap();
    let config = temp.path().join("config.toml");
    let home = temp.path().join("home");
    let token_file = home.join(".config").join("agent-access").join("token");
    write_cli_config_value(&config, "~/.config/agent-access/token", false);

    let set = run_with_stdin(
        agent_access_with_home(temp.path(), &home).args([
            "--config",
            config.to_str().unwrap(),
            "auth",
            "token",
            "set",
            "--token-stdin",
        ]),
        "  home-write-token  \n",
    );
    assert_success(&set);
    assert_eq!(
        std::fs::read_to_string(&token_file).unwrap(),
        "home-write-token\n"
    );
    assert!(stdout(&set).contains(&format!(
        "configured token file updated: {}",
        token_file.display()
    )));

    let clear = agent_access_with_home(temp.path(), &home)
        .args([
            "--config",
            config.to_str().unwrap(),
            "auth",
            "token",
            "clear",
        ])
        .output()
        .unwrap();
    assert_success(&clear);
    assert_eq!(std::fs::read(&token_file).unwrap(), b"");
    assert!(stdout(&clear).contains(&format!(
        "configured token file cleared: {}",
        token_file.display()
    )));
}

#[cfg(unix)]
#[test]
fn auth_token_set_preserves_existing_inode_and_mode() {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};

    let temp = tempfile::tempdir().unwrap();
    let config = temp.path().join("config.toml");
    let token_file = temp.path().join("identity.token");
    write_cli_config(&config, &token_file, false);
    std::fs::write(&token_file, "old-token\n").unwrap();
    std::fs::set_permissions(&token_file, std::fs::Permissions::from_mode(0o640)).unwrap();
    let before = std::fs::metadata(&token_file).unwrap();

    let output = run_with_stdin(
        agent_access(temp.path()).args([
            "--config",
            config.to_str().unwrap(),
            "auth",
            "token",
            "set",
            "--token-stdin",
        ]),
        "replacement-token\n",
    );

    assert_success(&output);
    let after = std::fs::metadata(&token_file).unwrap();
    assert_eq!(before.ino(), after.ino());
    assert_eq!(after.permissions().mode() & 0o777, 0o640);
    assert_eq!(
        std::fs::read_to_string(&token_file).unwrap(),
        "replacement-token\n"
    );
}

#[test]
fn auth_token_commands_reject_global_token_source_flags() {
    for flag in ["--token-value", "--token-file", "--token-env"] {
        let temp = tempfile::tempdir().unwrap();
        let value = temp.path().join("value");
        let output = agent_access(temp.path())
            .args([flag, value.to_str().unwrap(), "auth", "token", "status"])
            .output()
            .unwrap();
        assert_eq!(output.status.code(), Some(3));
        assert!(stderr(&output).contains("auth token commands do not accept"));
    }
}

#[test]
fn strict_token_sources_fail_before_broker_calls() {
    let temp = tempfile::tempdir().unwrap();
    let empty_file = temp.path().join("empty.token");
    std::fs::write(&empty_file, " \n").unwrap();
    let home = temp.path().join("home");
    let home_token = home
        .join(".config")
        .join("agent-access")
        .join("empty.token");
    std::fs::create_dir_all(home_token.parent().unwrap()).unwrap();
    std::fs::write(&home_token, " \n").unwrap();

    let empty_value = agent_access(temp.path())
        .args(["--token-value", "  ", "auth", "status"])
        .output()
        .unwrap();
    assert_eq!(empty_value.status.code(), Some(3));
    assert!(stderr(&empty_value).contains("token value must not be empty"));

    let empty_explicit_file = agent_access(temp.path())
        .args([
            "--token-file",
            empty_file.to_str().unwrap(),
            "auth",
            "status",
        ])
        .output()
        .unwrap();
    assert_eq!(empty_explicit_file.status.code(), Some(3));
    assert!(stderr(&empty_explicit_file).contains("is empty"));

    for token_file_arg in [
        "--token-file ~/.config/agent-access/empty.token",
        "--token-file=~/.config/agent-access/empty.token",
    ] {
        let mut command = agent_access_with_home(temp.path(), &home);
        match token_file_arg.split_once(' ') {
            Some((flag, value)) => {
                command.args([flag, value, "auth", "status"]);
            }
            None => {
                command.args([token_file_arg, "auth", "status"]);
            }
        }
        let output = command.output().unwrap();
        assert_eq!(output.status.code(), Some(3));
        let stderr = stderr(&output);
        assert!(stderr.contains("is empty"));
        assert!(stderr.contains(&home_token.display().to_string()));
    }

    let missing_env = agent_access(temp.path())
        .args(["--token-env", "AGENT_ACCESS_TEST_MISSING", "auth", "status"])
        .output()
        .unwrap();
    assert_eq!(missing_env.status.code(), Some(3));
    assert!(stderr(&missing_env).contains("is not set"));

    let missing_fallback_file = agent_access(temp.path())
        .env("AGENT_ACCESS_TOKEN_FILE", temp.path().join("missing.token"))
        .args(["auth", "token", "status"])
        .output()
        .unwrap();
    assert_eq!(missing_fallback_file.status.code(), Some(3));
    let missing_stdout = stdout(&missing_fallback_file);
    assert!(missing_stdout.contains("effective token source: AGENT_ACCESS_TOKEN_FILE"));
    assert!(missing_stdout.contains("effective token status: error"));

    let empty_fallback_file = agent_access_with_home(temp.path(), &home)
        .env(
            "AGENT_ACCESS_TOKEN_FILE",
            "~/.config/agent-access/empty.token",
        )
        .args(["auth", "token", "status"])
        .output()
        .unwrap();
    assert_eq!(empty_fallback_file.status.code(), Some(3));
    let empty_stdout = stdout(&empty_fallback_file);
    assert!(empty_stdout.contains("effective token source: AGENT_ACCESS_TOKEN_FILE"));
    assert!(empty_stdout.contains("effective token status: error"));
    let stderr = stderr(&empty_fallback_file);
    assert!(stderr.contains("is empty"));
    assert!(stderr.contains(&home_token.display().to_string()));
}

#[test]
fn config_validate_accepts_home_relative_identity_token_file_without_file() {
    let temp = tempfile::tempdir().unwrap();
    let config = temp.path().join("config.toml");
    write_cli_config_value(&config, "~/.config/agent-access/missing-token", false);

    let output = agent_access(temp.path())
        .args(["--config", config.to_str().unwrap(), "config", "validate"])
        .output()
        .unwrap();

    assert_success(&output);
}

#[test]
fn unrelated_request_file_argument_remains_literal() {
    let temp = tempfile::tempdir().unwrap();
    let home = temp.path().join("home");
    let expanded = home
        .join(".config")
        .join("agent-access")
        .join("request.json");
    std::fs::create_dir_all(expanded.parent().unwrap()).unwrap();
    std::fs::write(&expanded, "{}").unwrap();

    let output = agent_access_with_home(temp.path(), &home)
        .args([
            "send",
            "--request-file",
            "~/.config/agent-access/request.json",
        ])
        .output()
        .unwrap();

    assert_eq!(output.status.code(), Some(3));
    assert!(stderr(&output).contains("failed to read ~/.config/agent-access/request.json"));
}

fn agent_access(xdg_config_home: &Path) -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_agent-access"));
    for var in TOKEN_ENV_VARS {
        command.env_remove(var);
    }
    command.env("XDG_CONFIG_HOME", xdg_config_home);
    command
}

fn agent_access_with_home(xdg_config_home: &Path, home: &Path) -> Command {
    let mut command = agent_access(xdg_config_home);
    command.env("HOME", home);
    command.env("USERPROFILE", home);
    command
}

fn run_with_stdin(command: &mut Command, input: &str) -> Output {
    let mut child = command
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .as_mut()
        .unwrap()
        .write_all(input.as_bytes())
        .unwrap();
    child.wait_with_output().unwrap()
}

fn write_cli_config(path: &Path, token_file: &Path, disabled: bool) {
    write_cli_config_value(path, &token_file.display().to_string(), disabled);
}

fn write_cli_config_value(path: &Path, token_file: &str, disabled: bool) {
    std::fs::write(
        path,
        format!(
            "[identity]\ndisabled = {disabled}\ntoken_file = {:?}\n",
            token_file
        ),
    )
    .unwrap();
}

fn assert_success(output: &Output) {
    assert_eq!(
        output.status.code(),
        Some(0),
        "stdout:\n{}\nstderr:\n{}",
        stdout(output),
        stderr(output)
    );
}

fn stdout(output: &Output) -> String {
    String::from_utf8_lossy(&output.stdout).to_string()
}

fn stderr(output: &Output) -> String {
    String::from_utf8_lossy(&output.stderr).to_string()
}
