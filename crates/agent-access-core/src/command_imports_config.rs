//! `[command_imports.<name>]`: the operator's approval of a local executable
//! for the `command` import kind, with its process settings and limits.
//!
//! The table key is the command name an import's `command:<name>` endpoint
//! names; the executable path is not import identity. Validation is offline:
//! a missing or non-executable `path` only warns, because binaries are
//! replaced freely and must not stop the Broker.
use crate::BrokerConfig;
use crate::imports::{ImportEndpointForm, is_command_name};
use crate::network::is_inherited_network_variable;
use serde::Deserialize;
use std::collections::BTreeMap;
use std::path::Path;
use std::time::Duration;

/// Default per-call deadline, including the wait for a budget permit.
pub const COMMAND_DEFAULT_TIMEOUT: &str = "30s";
/// Longest accepted `timeout`.
pub const COMMAND_MAX_TIMEOUT_SECONDS: u64 = 10 * 60;
/// Default stdout cap of one process.
pub const COMMAND_DEFAULT_MAX_OUTPUT_BYTES: u64 = 1024 * 1024;
/// Maximum JSON overhead outside encoded file content in a download response.
pub const COMMAND_DOWNLOAD_ENVELOPE_OVERHEAD_BYTES: u64 = 16 * 1024;
/// Default number of concurrent processes or response workers per command name.
pub const COMMAND_DEFAULT_MAX_CONCURRENT: u32 = 4;
/// Default working directory of every process.
pub const COMMAND_DEFAULT_WORKING_DIR: &str = "/";
/// Longest `env` value, in bytes.
pub const COMMAND_MAX_ENV_VALUE_BYTES: usize = 4 * 1024;
/// Most `env` entries one command may set.
pub const COMMAND_MAX_ENV_ENTRIES: usize = 64;
/// `[command_imports]`, keyed by approved command name.
pub type CommandImportsConfig = BTreeMap<String, CommandImportConfig>;

/// Whether a command receives the Broker's egress settings.
#[derive(Debug, Clone, Copy, Default, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum CommandNetwork {
    /// The request's `network` object and the convenience variables carry
    /// the Broker's proxy route, its `NO_PROXY` entries, and the
    /// `[network.outbound_tls]` trust mode with the configured
    /// `ca_certificate` path. The Broker never reads, copies or passes
    /// certificates; the command loads the configured file itself.
    #[default]
    Inherit,
    /// Nothing is passed; `env` may supply the command's own settings.
    None,
}

impl CommandNetwork {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Inherit => "inherit",
            Self::None => "none",
        }
    }
}

/// One `[command_imports.<name>]` entry. Neither setting restricts what the
/// command can reach: commands are trusted like linked modules. `env` is not
/// for secrets.
#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct CommandImportConfig {
    /// Absolute path of the executable, run as `<path> describe|invoke|verify`.
    pub path: String,
    /// Per-call deadline in the `s`/`m`/`h` syntax, at most ten minutes.
    #[serde(default = "default_timeout")]
    pub timeout: String,
    /// Stdout cap of one process, at most `limits.max_upstream_response_bytes`.
    #[serde(default = "default_max_output_bytes")]
    pub max_output_bytes: u64,
    /// Opt-in decoded file cap. Absence disables download actions.
    #[serde(default)]
    pub max_download_bytes: Option<u64>,
    /// Concurrent processes or response workers of this command name, shared
    /// by every import of it; at most `limits.max_concurrent_requests`.
    #[serde(default = "default_max_concurrent")]
    pub max_concurrent: u32,
    /// Absolute working directory of every process.
    #[serde(default = "default_working_dir")]
    pub working_dir: String,
    #[serde(default)]
    pub network: CommandNetwork,
    /// Operator opt-in to include up to 4 KiB of escaped stderr in the
    /// `command_import_failed` log line. The Broker cannot redact secrets a
    /// command prints, so `config validate` warns while it is on.
    #[serde(default)]
    pub log_stderr: bool,
    /// The complete process environment besides the network variables; the
    /// Broker clears everything else.
    #[serde(default)]
    pub env: BTreeMap<String, String>,
}

impl CommandImportConfig {
    /// Encoded stdout cap for downloads: padded base64 plus bounded JSON overhead.
    /// `None` means downloads are disabled or the arithmetic overflows.
    pub fn download_output_bytes(&self) -> Option<u64> {
        self.max_download_bytes?
            .checked_add(2)?
            .checked_div(3)?
            .checked_mul(4)?
            .checked_add(COMMAND_DOWNLOAD_ENVELOPE_OVERHEAD_BYTES)
    }

    /// The validated `timeout`.
    pub fn timeout(&self) -> Option<Duration> {
        parse_timeout_seconds(&self.timeout).map(Duration::from_secs)
    }
}

fn default_timeout() -> String {
    COMMAND_DEFAULT_TIMEOUT.into()
}
fn default_max_output_bytes() -> u64 {
    COMMAND_DEFAULT_MAX_OUTPUT_BYTES
}
fn default_max_concurrent() -> u32 {
    COMMAND_DEFAULT_MAX_CONCURRENT
}
fn default_working_dir() -> String {
    COMMAND_DEFAULT_WORKING_DIR.into()
}

/// Seconds of a `timeout` such as `30s`, `2m` or `1h`, within one second and
/// ten minutes.
fn parse_timeout_seconds(value: &str) -> Option<u64> {
    let split = value.find(|ch: char| !ch.is_ascii_digit())?;
    let (digits, unit) = value.split_at(split);
    let amount = digits.parse::<u64>().ok().filter(|_| !digits.is_empty())?;
    let multiplier = match unit {
        "s" => 1,
        "m" => 60,
        "h" => 60 * 60,
        _ => return None,
    };
    amount
        .checked_mul(multiplier)
        .filter(|seconds| (1..=COMMAND_MAX_TIMEOUT_SECONDS).contains(seconds))
}

fn is_env_name(name: &str) -> bool {
    let bytes = name.as_bytes();
    !bytes.is_empty()
        && (bytes[0].is_ascii_alphabetic() || bytes[0] == b'_')
        && bytes
            .iter()
            .all(|b| b.is_ascii_alphanumeric() || *b == b'_')
}

fn absolute(path: &str) -> bool {
    !path.contains('\0') && Path::new(path).is_absolute()
}

pub(crate) fn validate_command_imports(config: &BrokerConfig, errors: &mut Vec<String>) {
    for (name, command) in &config.command_imports {
        if !is_command_name(name) {
            errors.push(format!(
                "command_imports key {name:?} must match ^[a-z][a-z0-9_-]{{0,62}}$"
            ));
            continue;
        }
        let label = format!("command_imports.{name}");
        if !absolute(&command.path) {
            errors.push(format!("{label}.path must be an absolute path"));
        }
        if !absolute(&command.working_dir) {
            errors.push(format!("{label}.working_dir must be an absolute path"));
        }
        if command.timeout().is_none() {
            errors.push(format!(
                "{label}.timeout must use the s, m, or h duration syntax and be between 1s and 10m"
            ));
        }
        if command.max_output_bytes == 0
            || command.max_output_bytes > config.limits.max_upstream_response_bytes
        {
            errors.push(format!(
                "{label}.max_output_bytes must be between 1 and limits.max_upstream_response_bytes"
            ));
        }
        if let Some(decoded) = command.max_download_bytes {
            if decoded == 0 || decoded > config.limits.max_download_bytes {
                errors.push(format!(
                    "{label}.max_download_bytes must be between 1 and limits.max_download_bytes"
                ));
            }
            match command.download_output_bytes() {
                Some(encoded) => {
                    if encoded > config.limits.max_upstream_response_bytes {
                        errors.push(format!(
                            "{label}.max_download_bytes requires an encoded response exceeding limits.max_upstream_response_bytes"
                        ));
                    }
                    // Capture and JSON scan scratch each permit up to 2E capacity;
                    // decoded storage is at most D. Vec allocations must fit isize.
                    let capacities_fit = isize::try_from(decoded).is_ok()
                        && encoded
                            .checked_mul(2)
                            .is_some_and(|capacity| isize::try_from(capacity).is_ok());
                    if !capacities_fit {
                        errors.push(format!(
                            "{label}.max_download_bytes requires allocations not representable on this platform"
                        ));
                    }
                }
                None => errors.push(format!(
                    "{label}.max_download_bytes overflows the encoded response limit"
                )),
            }
        }
        if command.max_concurrent == 0
            || command.max_concurrent > config.limits.max_concurrent_requests
        {
            errors.push(format!(
                "{label}.max_concurrent must be between 1 and limits.max_concurrent_requests"
            ));
        }
        if command.env.len() > COMMAND_MAX_ENV_ENTRIES {
            errors.push(format!(
                "{label}.env sets more than {COMMAND_MAX_ENV_ENTRIES} variables"
            ));
        }
        for (key, value) in &command.env {
            if !is_env_name(key) {
                errors.push(format!(
                    "{label}.env key {key:?} must match ^[A-Za-z_][A-Za-z0-9_]*$"
                ));
            } else if command.network == CommandNetwork::Inherit
                && is_inherited_network_variable(key)
            {
                errors.push(format!(
                    "{label}.env must not set {key}, which the Broker sets from its egress settings; use network = \"none\" to supply your own"
                ));
            }
            if value.contains('\0') || value.len() > COMMAND_MAX_ENV_VALUE_BYTES {
                errors.push(format!(
                    "{label}.env value of {key} must have no NUL and at most {COMMAND_MAX_ENV_VALUE_BYTES} bytes"
                ));
            }
        }
    }
}

/// Offline conditions that leave the configuration valid but an approved
/// command unusable or verbose: a missing or non-executable `path`, an
/// enabled `log_stderr`, or entries no linked and allowed `command` kind
/// can use. `config validate`, startup and reload report them.
pub fn command_import_warnings(config: &BrokerConfig) -> Vec<String> {
    let mut warnings = Vec::new();
    if config.command_imports.is_empty() {
        return warnings;
    }
    let usable_kind = config.imports.enabled
        && config.imports.allowed_kinds.iter().any(|kind| {
            config
                .providers
                .registry()
                .imported_adapter(kind)
                .is_some_and(|adapter| adapter.endpoint_form() == ImportEndpointForm::Command)
        });
    if !usable_kind {
        warnings.push(
            "command_imports entries are unusable: enable imports with a linked command import kind in imports.allowed_kinds"
                .into(),
        );
    }
    for (name, command) in &config.command_imports {
        if !is_command_name(name) || !absolute(&command.path) {
            continue;
        }
        if !is_executable_file(Path::new(&command.path)) {
            warnings.push(format!(
                "command_imports.{name}.path is missing or not an executable file; its calls fail until it is installed"
            ));
        }
        if command.log_stderr {
            warnings.push(format!(
                "command_imports.{name}.log_stderr is on: failure logs include up to 4 KiB of the command's stderr, which the Broker cannot redact"
            ));
        }
    }
    warnings
}

#[cfg(unix)]
fn is_executable_file(path: &Path) -> bool {
    use std::os::unix::fs::PermissionsExt;
    std::fs::metadata(path)
        .is_ok_and(|metadata| metadata.is_file() && metadata.permissions().mode() & 0o111 != 0)
}

#[cfg(not(unix))]
fn is_executable_file(_path: &Path) -> bool {
    // Command imports run only on Unix.
    false
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{BackendRegistry, parse_broker_config_raw};
    use std::sync::Arc;

    fn config(table: &str) -> Result<BrokerConfig, String> {
        parse_broker_config_raw(
            "command.toml",
            &format!(
                "[identity]\nmode = \"anonymous\"\nauthority = \"toml\"\n[policy]\nauthority = \"toml\"\ndefault_decision = \"deny\"\n[limits]\nupload_spool_dir = \"upload-spool\"\nmax_concurrent_requests = 8\nmax_upstream_response_bytes = 2097152\n{table}"
            ),
            &Arc::new(BackendRegistry::empty()),
        )
        .map_err(|error| error.to_string())
    }

    fn errors(table: &str) -> Vec<String> {
        let config = config(table).unwrap();
        let mut errors = Vec::new();
        validate_command_imports(&config, &mut errors);
        errors
    }

    #[test]
    fn the_sample_table_parses_with_defaults() {
        let config = config(
            "[command_imports.ticketing]\npath = \"/opt/agent-commands/ticketing/bin/ticketing-command\"\n[command_imports.ticketing.env]\nPATH = \"/usr/local/bin:/usr/bin:/bin\"\nLANG = \"C.UTF-8\"\n",
        )
        .unwrap();
        let command = &config.command_imports["ticketing"];
        assert_eq!(command.timeout(), Some(Duration::from_secs(30)));
        assert_eq!(command.max_output_bytes, 1024 * 1024);
        assert_eq!(command.max_download_bytes, None);
        assert_eq!(command.download_output_bytes(), None);
        assert_eq!(command.max_concurrent, 4);
        assert_eq!(command.working_dir, "/");
        assert_eq!(command.network, CommandNetwork::Inherit);
        assert!(!command.log_stderr);
        assert_eq!(command.env.len(), 2);
        let mut errors = Vec::new();
        validate_command_imports(&config, &mut errors);
        assert!(errors.is_empty(), "{errors:?}");
    }

    #[test]
    fn download_caps_are_opt_in_and_fit_both_global_ceilings() {
        let mut config = config(
            r#"[command_imports.ticketing]
path = "/bin/true"
"#,
        )
        .unwrap();
        let validate = |config: &BrokerConfig| {
            let mut errors = Vec::new();
            validate_command_imports(config, &mut errors);
            errors
        };
        assert!(validate(&config).is_empty());
        config
            .command_imports
            .get_mut("ticketing")
            .unwrap()
            .max_download_bytes = Some(1);
        let encoded = COMMAND_DOWNLOAD_ENVELOPE_OVERHEAD_BYTES + 4;
        assert_eq!(
            config.command_imports["ticketing"].download_output_bytes(),
            Some(encoded)
        );
        config.limits.max_download_bytes = 1;
        config.limits.max_upstream_response_bytes = encoded;
        config
            .command_imports
            .get_mut("ticketing")
            .unwrap()
            .max_output_bytes = 1;
        assert!(validate(&config).is_empty());
        config.limits.max_upstream_response_bytes = encoded - 1;
        assert!(
            validate(&config)
                .iter()
                .any(|error| error.contains("encoded response"))
        );
        config.limits.max_upstream_response_bytes = encoded;
        config.limits.max_download_bytes = 0;
        assert!(
            validate(&config)
                .iter()
                .any(|error| error.contains("limits.max_download_bytes"))
        );
        config
            .command_imports
            .get_mut("ticketing")
            .unwrap()
            .max_download_bytes = Some(0);
        assert!(
            validate(&config)
                .iter()
                .any(|error| error.contains("between 1"))
        );
    }

    #[test]
    fn download_encoded_caps_include_padding_and_reject_arithmetic_or_platform_overflow() {
        let mut config = config(
            r#"[command_imports.ticketing]
path = "/bin/true"
"#,
        )
        .unwrap();
        let command = config.command_imports.get_mut("ticketing").unwrap();
        for (decoded, encoded) in [(1, 4), (2, 4), (3, 4), (4, 8), (8_388_608, 11_184_812)] {
            command.max_download_bytes = Some(decoded);
            assert_eq!(
                command.download_output_bytes(),
                Some(encoded + COMMAND_DOWNLOAD_ENVELOPE_OVERHEAD_BYTES)
            );
        }
        command.max_download_bytes = Some(u64::MAX);
        assert_eq!(command.download_output_bytes(), None);
        config.limits.max_download_bytes = u64::MAX;
        config.limits.max_upstream_response_bytes = u64::MAX;
        let mut errors = Vec::new();
        validate_command_imports(&config, &mut errors);
        assert!(
            errors.iter().any(|error| error.contains("overflows")),
            "{errors:?}"
        );
        config
            .command_imports
            .get_mut("ticketing")
            .unwrap()
            .max_download_bytes = Some((isize::MAX as u64) / 2);
        errors.clear();
        validate_command_imports(&config, &mut errors);
        assert!(
            errors.iter().any(|error| error.contains("platform")),
            "{errors:?}"
        );
    }

    #[test]
    fn invalid_entries_are_rejected() {
        let cases = [
            (
                "[command_imports.Ticketing]\npath = \"/bin/true\"\n",
                "must match",
            ),
            (
                "[command_imports.ticketing]\npath = \"bin/true\"\n",
                "path must be an absolute path",
            ),
            (
                "[command_imports.ticketing]\npath = \"/bin/true\"\nworking_dir = \"var\"\n",
                "working_dir must be an absolute path",
            ),
            (
                "[command_imports.ticketing]\npath = \"/bin/true\"\ntimeout = \"11m\"\n",
                "timeout",
            ),
            (
                "[command_imports.ticketing]\npath = \"/bin/true\"\ntimeout = \"0s\"\n",
                "timeout",
            ),
            (
                "[command_imports.ticketing]\npath = \"/bin/true\"\ntimeout = \"30\"\n",
                "timeout",
            ),
            (
                "[command_imports.ticketing]\npath = \"/bin/true\"\nmax_output_bytes = 2097153\n",
                "max_output_bytes",
            ),
            (
                "[command_imports.ticketing]\npath = \"/bin/true\"\nmax_output_bytes = 0\n",
                "max_output_bytes",
            ),
            (
                "[command_imports.ticketing]\npath = \"/bin/true\"\nmax_concurrent = 9\n",
                "max_concurrent",
            ),
            (
                "[command_imports.ticketing]\npath = \"/bin/true\"\nmax_concurrent = 0\n",
                "max_concurrent",
            ),
            (
                "[command_imports.ticketing]\npath = \"/bin/true\"\n[command_imports.ticketing.env]\n\"1BAD\" = \"x\"\n",
                "env key",
            ),
            (
                "[command_imports.ticketing]\npath = \"/bin/true\"\n[command_imports.ticketing.env]\nHTTPS_PROXY = \"http://proxy.example.net\"\n",
                "must not set HTTPS_PROXY",
            ),
            (
                "[command_imports.ticketing]\npath = \"/bin/true\"\n[command_imports.ticketing.env]\nTOKEN_HINT = \"a\\u0000b\"\n",
                "no NUL",
            ),
        ];
        for (table, expected) in cases {
            let errors = errors(table);
            assert!(
                errors.iter().any(|error| error.contains(expected)),
                "{table}: {errors:?}"
            );
        }
        let long = format!(
            "[command_imports.ticketing]\npath = \"/bin/true\"\n[command_imports.ticketing.env]\nLONG = \"{}\"\n",
            "x".repeat(COMMAND_MAX_ENV_VALUE_BYTES + 1)
        );
        assert!(errors(&long).iter().any(|error| error.contains("no NUL")));
        // Unknown fields and network modes are configuration errors.
        assert!(config("[command_imports.ticketing]\npath = \"/bin/true\"\nargs = []\n").is_err());
        assert!(
            config("[command_imports.ticketing]\npath = \"/bin/true\"\nnetwork = \"host\"\n")
                .is_err()
        );
    }

    #[test]
    fn network_none_lets_env_supply_its_own_proxy_settings() {
        assert!(
            errors(
                "[command_imports.ticketing]\npath = \"/bin/true\"\nnetwork = \"none\"\n[command_imports.ticketing.env]\nHTTPS_PROXY = \"http://proxy.example.net\"\nSSL_CERT_FILE = \"/etc/ssl/certs/ca.pem\"\n"
            )
            .is_empty()
        );
    }

    #[test]
    fn timeouts_accept_seconds_minutes_and_one_hour_bounds() {
        assert_eq!(parse_timeout_seconds("1s"), Some(1));
        assert_eq!(parse_timeout_seconds("10m"), Some(600));
        assert_eq!(parse_timeout_seconds("601s"), None);
        assert_eq!(parse_timeout_seconds("1h"), None);
        assert_eq!(parse_timeout_seconds("s"), None);
        assert_eq!(parse_timeout_seconds("1d"), None);
        assert_eq!(parse_timeout_seconds(" 30s"), None);
    }

    #[cfg(unix)]
    #[test]
    fn a_missing_binary_or_stderr_logging_only_warns() {
        use std::os::unix::fs::PermissionsExt;
        let temp = tempfile::TempDir::new().unwrap();
        let script = temp.path().join("tool");
        std::fs::write(&script, "#!/bin/sh\n").unwrap();
        std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o700)).unwrap();
        let missing = temp.path().join("missing");
        let config = config(&format!(
            "[command_imports.present]\npath = \"{}\"\nlog_stderr = true\n[command_imports.absent]\npath = \"{}\"\n",
            script.display(),
            missing.display()
        ))
        .unwrap();
        let mut errors = Vec::new();
        validate_command_imports(&config, &mut errors);
        assert!(errors.is_empty(), "{errors:?}");
        let warnings = command_import_warnings(&config);
        assert_eq!(
            warnings,
            [
                "command_imports entries are unusable: enable imports with a linked command import kind in imports.allowed_kinds",
                "command_imports.absent.path is missing or not an executable file; its calls fail until it is installed",
                "command_imports.present.log_stderr is on: failure logs include up to 4 KiB of the command's stderr, which the Broker cannot redact",
            ]
        );
        std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o600)).unwrap();
        assert!(!is_executable_file(&script));
        assert!(!is_executable_file(temp.path()));
    }
}
