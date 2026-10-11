use std::io::Write;
use std::path::{Path, PathBuf};
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

const REQUEST: &str = "protocol=https\nhost=git.example.test\n\n";

#[test]
fn get_returns_configured_file_token_with_exact_git_fields() {
    let fixture = Fixture::new();
    let token = "configured-file-token";
    fixture.write_token(&fixture.token_file, token);
    fixture.write_config(Some(&fixture.token_file), None, false);

    let output = fixture.run_get(REQUEST, |_| {});

    assert_credential(&output, token);
}

#[test]
fn get_honors_every_effective_token_source() {
    struct Case {
        name: &'static str,
        configure: fn(&Fixture, &mut Command, &str),
    }

    let cases = [
        Case {
            name: "command-line file",
            configure: |fixture, command, token| {
                fixture.write_token(&fixture.token_file, token);
                command.args(["--token-file", fixture.token_file.to_str().unwrap()]);
            },
        },
        Case {
            name: "command-line environment variable",
            configure: |_, command, token| {
                command.env("TEST_AGENT_ACCESS_TOKEN", token);
                command.args(["--token-env", "TEST_AGENT_ACCESS_TOKEN"]);
            },
        },
        Case {
            name: "configured environment variable",
            configure: |fixture, command, token| {
                fixture.write_config(None, Some("TEST_AGENT_ACCESS_TOKEN"), false);
                command.env("TEST_AGENT_ACCESS_TOKEN", token);
            },
        },
        Case {
            name: "AGENT_ACCESS_TOKEN",
            configure: |_, command, token| {
                command.env("AGENT_ACCESS_TOKEN", token);
            },
        },
        Case {
            name: "AGENT_ACCESS_TOKEN_FILE",
            configure: |fixture, command, token| {
                fixture.write_token(&fixture.token_file, token);
                command.env("AGENT_ACCESS_TOKEN_FILE", &fixture.token_file);
            },
        },
        Case {
            name: "AGENT_ACCESS_TOKEN_ENV",
            configure: |_, command, token| {
                command.env("TEST_AGENT_ACCESS_TOKEN", token);
                command.env("AGENT_ACCESS_TOKEN_ENV", "TEST_AGENT_ACCESS_TOKEN");
            },
        },
    ];

    for case in cases {
        let fixture = Fixture::new();
        let token = format!("{}-token", case.name.replace(' ', "-"));
        let output = fixture.run_get(REQUEST, |command| {
            (case.configure)(&fixture, command, &token);
        });
        assert_credential(&output, &token);
    }
}

#[test]
fn get_preserves_existing_token_source_precedence() {
    let fixture = Fixture::new();
    let cli_file = fixture.root.path().join("cli.token");
    let config_file = fixture.root.path().join("config.token");
    let fallback_file = fixture.root.path().join("fallback.token");
    fixture.write_token(&cli_file, "cli-file-token");
    fixture.write_token(&config_file, "config-file-token");
    fixture.write_token(&fallback_file, "fallback-file-token");
    fixture.write_config(Some(&config_file), Some("TEST_CONFIG_TOKEN_ENV"), false);

    let output = fixture.run_get(REQUEST, |command| {
        command.args(["--token-file", cli_file.to_str().unwrap()]);
        command.args(["--token-env", "TEST_CLI_TOKEN_ENV"]);
        command.env("TEST_CLI_TOKEN_ENV", "cli-env-token");
        command.env("TEST_CONFIG_TOKEN_ENV", "config-env-token");
        command.env("AGENT_ACCESS_TOKEN", "fallback-value-token");
        command.env("AGENT_ACCESS_TOKEN_FILE", fallback_file);
        command.env("AGENT_ACCESS_TOKEN_ENV", "TEST_FALLBACK_TOKEN_ENV");
        command.env("TEST_FALLBACK_TOKEN_ENV", "fallback-env-token");
    });

    assert_credential(&output, "cli-file-token");
    for losing_token in [
        "cli-env-token",
        "config-file-token",
        "config-env-token",
        "fallback-value-token",
        "fallback-file-token",
        "fallback-env-token",
    ] {
        assert_not_disclosed(&output, losing_token);
    }
}

#[test]
fn get_rejects_a_literal_command_line_token_without_disclosing_it() {
    let fixture = Fixture::new();
    let token = "literal-command-line-secret";

    let output = fixture.run_get(REQUEST, |command| {
        command.args(["--token-value", token]);
    });

    assert_quit(&output, "literal command-line token");
    assert_not_disclosed(&output, token);
}

#[test]
fn get_accepts_unknown_fields_and_ignores_input_credentials() {
    let fixture = Fixture::new();
    let token = "effective-token";
    let supplied_password = "input-password-must-not-leak";
    let output = fixture.run_get(
        &format!(
            "protocol=https\nhost=git.example.test\npath=owner/repo.git\nusername=someone\npassword={supplied_password}\nfuture-field=future-value\n\n"
        ),
        |command| {
            command.env("AGENT_ACCESS_TOKEN", token);
        },
    );

    assert_credential(&output, token);
    assert_not_disclosed(&output, supplied_password);
}

#[test]
fn get_accepts_eof_and_blank_line_termination() {
    let fixture = Fixture::new();
    for input in [
        "protocol=https\nhost=git.example.test\n",
        "protocol=https\nhost=git.example.test\n\nignored=after-terminator\n",
    ] {
        let output = fixture.run_get(input, |command| {
            command.env("AGENT_ACCESS_TOKEN", "terminator-token");
        });
        assert_credential(&output, "terminator-token");
    }
}

#[test]
fn get_failures_quit_without_partial_credentials_or_token_disclosure() {
    let fixture = Fixture::new();
    let empty_file = fixture.root.path().join("empty.token");
    fixture.write_token(&empty_file, "   ");
    let missing_file = fixture.root.path().join("missing.token");
    let directory = fixture.root.path().join("token-directory");
    std::fs::create_dir(&directory).unwrap();

    let cases = [
        ("missing token", REQUEST.to_string(), None),
        ("empty token", REQUEST.to_string(), Some(empty_file.clone())),
        (
            "missing token file",
            REQUEST.to_string(),
            Some(missing_file),
        ),
        (
            "invalid token file type",
            REQUEST.to_string(),
            Some(directory),
        ),
        (
            "missing protocol",
            "host=git.example.test\n\n".to_string(),
            None,
        ),
        ("missing host", "protocol=https\n\n".to_string(), None),
        (
            "empty protocol",
            "protocol=\nhost=git.example.test\n\n".to_string(),
            None,
        ),
        ("empty host", "protocol=https\nhost=\n\n".to_string(), None),
        (
            "whitespace protocol",
            "protocol=  \nhost=git.example.test\n\n".to_string(),
            None,
        ),
        (
            "whitespace host",
            "protocol=https\nhost=  \n\n".to_string(),
            None,
        ),
        (
            "malformed record",
            "protocol=https\nhost=git.example.test\nnot-a-record\n\n".to_string(),
            None,
        ),
    ];

    for (name, input, file) in cases {
        let output = fixture.run_get(&input, |command| {
            if let Some(file) = &file {
                command.args(["--token-file", file.to_str().unwrap()]);
            }
        });
        assert_quit(&output, name);
    }
}

#[test]
fn identity_disabled_get_quits_even_when_a_token_exists() {
    let fixture = Fixture::new();
    fixture.write_token(&fixture.token_file, "disabled-secret");
    fixture.write_config(Some(&fixture.token_file), None, true);

    let output = fixture.run_get(REQUEST, |_| {});

    assert_quit(&output, "disabled identity");
    assert_not_disclosed(&output, "disabled-secret");
}

#[test]
fn store_and_erase_consume_input_without_changing_the_agent_access_token() {
    let fixture = Fixture::new();
    fixture.write_token(&fixture.token_file, "authoritative-token");
    fixture.write_config(Some(&fixture.token_file), None, false);
    for (operation, input) in [
        (
            "store",
            "protocol=https\nhost=git.example.test\nusername=agent-access\npassword=replacement-from-git\n\n",
        ),
        (
            "erase",
            "protocol=https\nhost=git.example.test\nusername=agent-access\npassword=replacement-from-git\n",
        ),
    ] {
        let output = fixture.run(operation, input, |_| {});
        assert_success(&output);
        assert!(output.stdout.is_empty(), "{operation} emitted stdout");
        assert!(output.stderr.is_empty(), "{operation} emitted stderr");
        assert_eq!(
            std::fs::read_to_string(&fixture.token_file).unwrap(),
            "authoritative-token\n"
        );
        assert_not_disclosed(&output, "replacement-from-git");
    }
}

#[test]
fn capability_is_empty_and_unknown_operation_is_rejected_without_secrets() {
    let fixture = Fixture::new();
    let capability = fixture.run("capability", "", |_| {});
    assert_success(&capability);
    assert!(capability.stdout.is_empty());
    assert!(capability.stderr.is_empty());

    let unknown = fixture.run("frobnicate", REQUEST, |command| {
        command.env("AGENT_ACCESS_TOKEN", "unknown-operation-secret");
    });
    assert!(!unknown.status.success());
    assert!(stdout(&unknown).is_empty());
    assert_not_disclosed(&unknown, "unknown-operation-secret");
}

#[test]
fn url_scoped_git_configuration_returns_credentials_only_for_the_matching_host() {
    let fixture = Fixture::new();
    fixture.write_token(&fixture.token_file, "git-fill-token");
    fixture.write_config(Some(&fixture.token_file), None, false);
    let git_config = fixture.root.path().join("gitconfig");
    let helper = format!(
        "!{} --config {} auth git-credential",
        shell_quote(Path::new(env!("CARGO_BIN_EXE_agent-access"))),
        shell_quote(&fixture.config)
    );
    std::fs::write(
        &git_config,
        format!(
            "[credential \"https://git.example.test\"]\n\thelper =\n\thelper = {}\n",
            git_config_quote(&helper)
        ),
    )
    .unwrap();

    let matching = run_git_fill(&fixture, &git_config, "git.example.test");
    assert_success(&matching);
    let matching_stdout = stdout(&matching);
    assert!(matching_stdout.contains("protocol=https\n"));
    assert!(matching_stdout.contains("host=git.example.test\n"));
    assert!(matching_stdout.contains("username=agent-access\n"));
    assert!(matching_stdout.contains("password=git-fill-token\n"));

    let other = run_git_fill(&fixture, &git_config, "other.example.test");
    assert!(!other.status.success());
    assert_not_disclosed(&other, "git-fill-token");
    assert!(!stdout(&other).contains("username=agent-access"));
}

struct Fixture {
    root: tempfile::TempDir,
    config: PathBuf,
    token_file: PathBuf,
}

impl Fixture {
    fn new() -> Self {
        let root = tempfile::tempdir().unwrap();
        let config = root.path().join("config.toml");
        let token_file = root.path().join("identity.token");
        std::fs::write(&config, "[identity]\ndisabled = false\n").unwrap();
        Self {
            root,
            config,
            token_file,
        }
    }

    fn command(&self) -> Command {
        let mut command = Command::new(env!("CARGO_BIN_EXE_agent-access"));
        for variable in TOKEN_ENV_VARS {
            command.env_remove(variable);
        }
        command
            .env_remove("TEST_AGENT_ACCESS_TOKEN")
            .env_remove("TEST_CLI_TOKEN_ENV")
            .env_remove("TEST_CONFIG_TOKEN_ENV")
            .env_remove("TEST_FALLBACK_TOKEN_ENV")
            .env("XDG_CONFIG_HOME", self.root.path())
            .args(["--config", self.config.to_str().unwrap()]);
        command
    }

    fn run_get(&self, input: &str, configure: impl FnOnce(&mut Command)) -> Output {
        self.run("get", input, configure)
    }

    fn run(&self, operation: &str, input: &str, configure: impl FnOnce(&mut Command)) -> Output {
        let mut command = self.command();
        configure(&mut command);
        command.args(["auth", "git-credential", operation]);
        run_with_stdin(&mut command, input)
    }

    fn write_config(&self, token_file: Option<&Path>, token_env: Option<&str>, disabled: bool) {
        let mut config = format!("[identity]\ndisabled = {disabled}\n");
        if let Some(path) = token_file {
            config.push_str(&format!("token_file = {:?}\n", path.display().to_string()));
        }
        if let Some(name) = token_env {
            config.push_str(&format!("token_env = {name:?}\n"));
        }
        std::fs::write(&self.config, config).unwrap();
    }

    fn write_token(&self, path: &Path, token: &str) {
        std::fs::write(path, format!("{token}\n")).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).unwrap();
        }
    }
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
        .take()
        .unwrap()
        .write_all(input.as_bytes())
        .unwrap();
    child.wait_with_output().unwrap()
}

fn run_git_fill(fixture: &Fixture, config: &Path, host: &str) -> Output {
    let mut command = Command::new("git");
    command
        .args(["credential", "fill"])
        .env("GIT_CONFIG_GLOBAL", config)
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_TERMINAL_PROMPT", "0")
        .env("HOME", fixture.root.path())
        .env("XDG_CONFIG_HOME", fixture.root.path());
    for variable in TOKEN_ENV_VARS {
        command.env_remove(variable);
    }
    run_with_stdin(&mut command, &format!("protocol=https\nhost={host}\n\n"))
}

fn assert_credential(output: &Output, token: &str) {
    assert_success(output);
    let stdout = stdout(output);
    assert!(
        stdout == format!("username=agent-access\npassword={token}\n")
            || stdout == format!("username=agent-access\npassword={token}\n\n"),
        "unexpected credential protocol response shape"
    );
    assert!(output.stderr.is_empty(), "successful get emitted stderr");
}

fn assert_quit(output: &Output, case: &str) {
    assert_success(output);
    let stdout = stdout(output);
    assert!(
        stdout == "quit=true\n" || stdout == "quit=true\n\n",
        "{case}: failure did not return only quit=true"
    );
    let stderr = stderr(output);
    assert!(
        stderr.starts_with("agent-access:"),
        "{case}: missing actionable agent-access diagnostic"
    );
    assert!(!stdout.contains("username="), "{case}: partial username");
    assert!(!stdout.contains("password="), "{case}: partial password");
}

fn assert_not_disclosed(output: &Output, secret: &str) {
    assert!(
        !stdout(output).contains(secret),
        "secret disclosed on stdout"
    );
    assert!(
        !stderr(output).contains(secret),
        "secret disclosed on stderr"
    );
}

fn assert_success(output: &Output) {
    assert_eq!(
        output.status.code(),
        Some(0),
        "command failed with status {:?}",
        output.status.code()
    );
}

fn stdout(output: &Output) -> String {
    String::from_utf8_lossy(&output.stdout).into_owned()
}

fn stderr(output: &Output) -> String {
    String::from_utf8_lossy(&output.stderr).into_owned()
}

fn shell_quote(path: &Path) -> String {
    format!("'{}'", path.display().to_string().replace('\'', "'\\''"))
}

fn git_config_quote(value: &str) -> String {
    format!("\"{}\"", value.replace('\\', "\\\\").replace('\"', "\\\""))
}
