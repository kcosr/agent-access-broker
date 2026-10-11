//! Thin administrative wrappers for the managed import lifecycle.
use super::*;
use serde_json::{Value, json};

#[derive(Debug, Subcommand)]
pub(crate) enum AdminImportsCommand {
    List,
    Get {
        service: String,
    },
    /// Create a disabled draft from an ImportedServiceDefinition JSON file.
    Create {
        #[arg(long)]
        request_file: PathBuf,
    },
    /// Update draft/settings using the versioned definition request JSON.
    Update {
        service: String,
        #[arg(long)]
        request_file: PathBuf,
    },
    /// Fetch the complete upstream tool catalog into a review preview.
    Discover {
        service: String,
        #[command(flatten)]
        version: ImportVersionArgs,
    },
    Preview {
        service: String,
    },
    /// Accept explicitly selected, named and classified tools from a preview.
    Accept {
        service: String,
        #[arg(long)]
        request_file: PathBuf,
    },
    /// Change service availability, preserving retained identities and grants.
    Status {
        service: String,
        #[arg(value_parser = ["enabled", "disabled", "retired"])]
        status: String,
        #[command(flatten)]
        version: ImportVersionArgs,
        #[arg(long)]
        confirm: bool,
    },
    /// Change one accepted action's availability; changed definitions require acceptance.
    ActionStatus {
        service: String,
        action: String,
        #[arg(value_parser = ["enabled", "disabled", "retired"])]
        status: String,
        #[command(flatten)]
        version: ImportVersionArgs,
        #[arg(long)]
        confirm: bool,
    },
    Credentials {
        #[command(subcommand)]
        command: ImportCredentialsCommand,
    },
}

#[derive(Debug, Args)]
pub(crate) struct ImportVersionArgs {
    #[arg(long, value_parser = parse_expected_version)]
    expected_version: i64,
    #[arg(long, value_parser = parse_catalog_revision)]
    expected_catalog_revision: i64,
}

#[derive(Debug, Subcommand)]
pub(crate) enum ImportCredentialsCommand {
    Put {
        service: String,
        #[arg(value_parser = ["execution", "discovery", "transport"])]
        purpose: String,
        #[command(flatten)]
        version: ImportVersionArgs,
        #[command(flatten)]
        secret: ImportSecretArgs,
    },
    Delete {
        service: String,
        #[arg(value_parser = ["execution", "discovery", "transport"])]
        purpose: String,
        #[command(flatten)]
        version: ImportVersionArgs,
    },
}

#[derive(Debug, Args)]
#[group(required = true, multiple = false)]
pub(crate) struct ImportSecretArgs {
    /// Read the backend token from a regular UTF-8 file (maximum 32 KiB).
    #[arg(long)]
    secret_file: Option<PathBuf>,
    /// Read the backend token from an environment variable.
    #[arg(long)]
    secret_env: Option<String>,
    /// Read the backend token from stdin (maximum 32 KiB).
    #[arg(long)]
    secret_stdin: bool,
}

fn parse_catalog_revision(value: &str) -> std::result::Result<i64, String> {
    value
        .parse::<i64>()
        .ok()
        .filter(|value| *value >= 0)
        .ok_or_else(|| "catalog revision must be a non-negative integer".into())
}

impl ImportVersionArgs {
    fn body(&self) -> Value {
        json!({"expectedVersion":self.expected_version,"expectedCatalogRevision":self.expected_catalog_revision})
    }
}

fn service_path(service: &str) -> String {
    format!("/v1/admin/imports/{}", encoded_path_segment(service))
}

fn read_secret_reader(mut reader: impl Read) -> Result<String> {
    let mut bytes = Vec::new();
    reader
        .by_ref()
        .take(32 * 1024 + 1)
        .read_to_end(&mut bytes)
        .context("cannot read imported service token")?;
    if bytes.len() > 32 * 1024 {
        anyhow::bail!("imported service token exceeds 32 KiB");
    }
    let token = String::from_utf8(bytes)
        .map_err(|_| anyhow::anyhow!("imported service token must be UTF-8"))?;
    validate_secret(token)
}

fn validate_secret(token: String) -> Result<String> {
    let token = token.trim().to_owned();
    if token.is_empty()
        || token.len() > 32 * 1024
        || !token.bytes().all(|byte| (0x21..=0x7e).contains(&byte))
    {
        anyhow::bail!(
            "imported service token must be nonempty, at most 32 KiB, and contain only visible ASCII characters"
        );
    }
    Ok(token)
}

impl ImportSecretArgs {
    fn read(&self) -> Result<String> {
        if let Some(path) = &self.secret_file {
            if !fs::metadata(path)
                .context("cannot inspect imported service token file")?
                .is_file()
            {
                anyhow::bail!("imported service token file must be a regular file");
            }
            let file = fs::File::open(path).context("cannot open imported service token file")?;
            if !file.metadata()?.is_file() {
                anyhow::bail!("imported service token file must be a regular file");
            }
            read_secret_reader(file)
        } else if let Some(name) = &self.secret_env {
            let token = env::var(name).map_err(|_| {
                anyhow::anyhow!("cannot read imported service token environment variable")
            })?;
            validate_secret(token)
        } else if self.secret_stdin {
            read_secret_reader(std::io::stdin().lock())
        } else {
            anyhow::bail!("select a backend token source");
        }
    }
}

pub(crate) async fn run(ctx: &CliContext<'_>, command: &AdminImportsCommand) -> Result<()> {
    let (method, path, body) = match command {
        AdminImportsCommand::List => {
            return run_broker_get(ctx, "/v1/admin/imports", ResponseShape::Object).await;
        }
        AdminImportsCommand::Get { service } => {
            return run_broker_get(ctx, &service_path(service), ResponseShape::Object).await;
        }
        AdminImportsCommand::Preview { service } => {
            return run_broker_get(
                ctx,
                &format!("{}/preview", service_path(service)),
                ResponseShape::Object,
            )
            .await;
        }
        AdminImportsCommand::Create { request_file } => (
            reqwest::Method::POST,
            "/v1/admin/imports".into(),
            read_json_file(request_file),
        ),
        AdminImportsCommand::Update {
            service,
            request_file,
        } => (
            reqwest::Method::PATCH,
            service_path(service),
            read_json_file(request_file),
        ),
        AdminImportsCommand::Discover { service, version } => (
            reqwest::Method::POST,
            format!("{}/discover", service_path(service)),
            version.body(),
        ),
        AdminImportsCommand::Accept {
            service,
            request_file,
        } => (
            reqwest::Method::POST,
            format!("{}/accept", service_path(service)),
            read_json_file(request_file),
        ),
        AdminImportsCommand::Status {
            service,
            status,
            version,
            confirm,
        } => {
            let mut body = version.body();
            body["status"] = json!(status);
            body["confirm"] = json!(confirm);
            (
                reqwest::Method::POST,
                format!("{}/status", service_path(service)),
                body,
            )
        }
        AdminImportsCommand::ActionStatus {
            service,
            action,
            status,
            version,
            confirm,
        } => {
            let mut body = version.body();
            body["status"] = json!(status);
            body["confirm"] = json!(confirm);
            (
                reqwest::Method::POST,
                format!(
                    "{}/actions/{}/status",
                    service_path(service),
                    encoded_path_segment(action)
                ),
                body,
            )
        }
        AdminImportsCommand::Credentials { command } => match command {
            ImportCredentialsCommand::Put {
                service,
                purpose,
                version,
                secret,
            } => {
                let mut body = version.body();
                body["token"] = json!(require_cli_input(secret.read()));
                (
                    reqwest::Method::PUT,
                    format!("{}/credentials/{purpose}", service_path(service)),
                    body,
                )
            }
            ImportCredentialsCommand::Delete {
                service,
                purpose,
                version,
            } => (
                reqwest::Method::DELETE,
                format!("{}/credentials/{purpose}", service_path(service)),
                version.body(),
            ),
        },
    };
    if matches!(command, AdminImportsCommand::Discover { .. }) {
        // Discovery has a broker-side 60-second operation limit. Keep the usual
        // TLS/auth setup while allowing that bounded operation to return its result.
        let resolved = ctx.settings;
        let endpoint = require_cli_input(endpoint(&resolved.url, &path));
        let client = require_cli_input(http_client(resolved));
        let response = request_builder(client.request(method, endpoint), resolved)
            .timeout(Duration::from_secs(75))
            .json(&body)
            .send()
            .await
            .context("broker import discovery request failed")
            .unwrap_or_else(|error| exit_network_error(error));
        let (status, value) = response_value(response, ResponseShape::Object).await?;
        print_value_and_exit(status, value);
    }
    run_broker_json_method(ctx, method, &path, Some(body)).await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn credentials_require_a_single_nonliteral_backend_secret_source() {
        let args = [
            "agent-access",
            "admin",
            "imports",
            "credentials",
            "put",
            "example",
            "execution",
            "--expected-version",
            "1",
            "--expected-catalog-revision",
            "0",
        ];
        assert!(Cli::try_parse_from(args).is_err());
        let mut with_file = args.to_vec();
        with_file.extend(["--secret-file", "token.txt"]);
        assert!(Cli::try_parse_from(with_file.clone()).is_ok());
        with_file.push("--secret-stdin");
        assert!(Cli::try_parse_from(with_file).is_err());
        let mut inline = args.to_vec();
        inline.extend(["--secret", "inline-token"]);
        assert!(Cli::try_parse_from(inline).is_err());
    }

    #[test]
    fn lifecycle_versions_and_status_values_are_checked() {
        assert!(
            Cli::try_parse_from([
                "agent-access",
                "admin",
                "imports",
                "status",
                "example",
                "enabled",
                "--expected-version",
                "1",
                "--expected-catalog-revision",
                "0"
            ])
            .is_ok()
        );
        assert!(
            Cli::try_parse_from([
                "agent-access",
                "admin",
                "imports",
                "action-status",
                "example",
                "read",
                "quarantined",
                "--expected-version",
                "1",
                "--expected-catalog-revision",
                "0"
            ])
            .is_err()
        );
        assert!(parse_catalog_revision("-1").is_err());
        assert!(parse_catalog_revision("9223372036854775808").is_err());
        assert_eq!(service_path("a/b"), "/v1/admin/imports/a%2Fb");
    }

    #[test]
    fn token_reader_bounds_and_redacts_errors() {
        assert_eq!(read_secret_reader(&b"token\n"[..]).unwrap(), "token");
        for token in [
            Vec::new(),
            vec![b'x'; 32 * 1024 + 1],
            vec![255],
            b"secret\r\ninjected".to_vec(),
        ] {
            let error = read_secret_reader(token.as_slice())
                .unwrap_err()
                .to_string();
            assert!(!error.contains("injected"));
        }
    }
}
