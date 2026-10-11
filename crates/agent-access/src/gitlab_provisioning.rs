use super::*;
use serde_json::{Value, json};

#[derive(Debug, Subcommand)]
pub(super) enum ProjectTokenCommand {
    List {
        project: String,
        #[command(flatten)]
        page: ProvisioningPageArgs,
    },
    View {
        project: String,
        token_id: u64,
    },
    Create {
        project: String,
        #[arg(long)]
        name: String,
        #[arg(long)]
        access_level: u32,
        #[arg(long, value_delimiter = ',', required = true)]
        scopes: Vec<String>,
        #[command(flatten)]
        delivery: TokenDeliveryArgs,
    },
    Rotate {
        project: String,
        token_id: u64,
        #[command(flatten)]
        delivery: TokenDeliveryArgs,
    },
    Revoke {
        project: String,
        token_id: u64,
    },
}
#[derive(Debug, Subcommand)]
pub(super) enum ServiceAccountCommand {
    List {
        project: String,
        #[command(flatten)]
        page: ProvisioningPageArgs,
    },
    View {
        project: String,
        user_id: u64,
    },
    Create {
        project: String,
        #[arg(long)]
        name: String,
        #[arg(long)]
        username: Option<String>,
    },
    Delete {
        project: String,
        user_id: u64,
    },
    MemberSet {
        project: String,
        user_id: u64,
        #[arg(long)]
        access_level: u32,
    },
    Token {
        #[command(subcommand)]
        command: ServiceAccountTokenCommand,
    },
}
#[derive(Debug, Subcommand)]
pub(super) enum ServiceAccountTokenCommand {
    List {
        project: String,
        user_id: u64,
        #[command(flatten)]
        page: ProvisioningPageArgs,
    },
    Create {
        project: String,
        user_id: u64,
        #[arg(long)]
        name: String,
        #[arg(long, value_delimiter = ',', required = true)]
        scopes: Vec<String>,
        #[command(flatten)]
        delivery: TokenDeliveryArgs,
    },
    Rotate {
        project: String,
        user_id: u64,
        token_id: u64,
        #[command(flatten)]
        delivery: TokenDeliveryArgs,
    },
    Revoke {
        project: String,
        user_id: u64,
        token_id: u64,
    },
}
#[derive(Debug, Args)]
pub(super) struct ProvisioningPageArgs {
    #[arg(long)]
    max_results: Option<u32>,
    #[arg(long)]
    page_token: Option<String>,
}
impl ProvisioningPageArgs {
    fn apply(&self, inputs: &mut Value) {
        if let Some(n) = self.max_results {
            inputs["maxResults"] = json!(n);
        }
        if let Some(token) = &self.page_token {
            inputs["pageToken"] = json!(token);
        }
    }
}
#[derive(Debug, Args)]
pub(super) struct TokenDeliveryArgs {
    /// Required token expiry in YYYY-MM-DD UTC, within operator limits.
    #[arg(long)]
    expires_at: String,
    /// Write only the issued token to a new private file; stdout retains metadata.
    #[arg(long)]
    token_output: Option<PathBuf>,
}

pub(super) async fn run_project_token(
    ctx: &CliContext<'_>,
    command: &ProjectTokenCommand,
) -> Result<()> {
    use ProjectTokenCommand::*;
    let (action, inputs, delivery) = match command {
        List { project, page } => {
            let mut inputs = json!({"project":project});
            page.apply(&mut inputs);
            ("list", inputs, None)
        }
        View { project, token_id } => ("view", json!({"project":project,"tokenId":token_id}), None),
        Create {
            project,
            name,
            access_level,
            scopes,
            delivery,
        } => (
            "create",
            json!({"project":project,"name":name,"accessLevel":access_level,"scopes":scopes}),
            Some(delivery),
        ),
        Rotate {
            project,
            token_id,
            delivery,
        } => (
            "rotate",
            json!({"project":project,"tokenId":token_id}),
            Some(delivery),
        ),
        Revoke { project, token_id } => (
            "revoke",
            json!({"project":project,"tokenId":token_id}),
            None,
        ),
    };
    run_provisioning(
        ctx,
        &format!("project.access_token.{action}"),
        inputs,
        delivery,
    )
    .await
}
pub(super) async fn run_service_account(
    ctx: &CliContext<'_>,
    command: &ServiceAccountCommand,
) -> Result<()> {
    use ServiceAccountCommand::*;
    let (action, inputs) = match command {
        List { project, page } => {
            let mut inputs = json!({"project":project});
            page.apply(&mut inputs);
            ("list", inputs)
        }
        View { project, user_id } => ("view", json!({"project":project,"userId":user_id})),
        Create {
            project,
            name,
            username,
        } => {
            let mut inputs = json!({"project":project,"name":name});
            if let Some(username) = username {
                inputs["username"] = json!(username);
            }
            ("create", inputs)
        }
        Delete { project, user_id } => ("delete", json!({"project":project,"userId":user_id})),
        MemberSet {
            project,
            user_id,
            access_level,
        } => (
            "member.set",
            json!({"project":project,"userId":user_id,"accessLevel":access_level}),
        ),
        Token { command } => return run_service_account_token(ctx, command).await,
    };
    run_provisioning(ctx, &format!("service_account.{action}"), inputs, None).await
}
async fn run_service_account_token(
    ctx: &CliContext<'_>,
    command: &ServiceAccountTokenCommand,
) -> Result<()> {
    use ServiceAccountTokenCommand::*;
    let (action, inputs, delivery) = match command {
        List {
            project,
            user_id,
            page,
        } => {
            let mut inputs = json!({"project":project,"userId":user_id});
            page.apply(&mut inputs);
            ("list", inputs, None)
        }
        Create {
            project,
            user_id,
            name,
            scopes,
            delivery,
        } => (
            "create",
            json!({"project":project,"userId":user_id,"name":name,"scopes":scopes}),
            Some(delivery),
        ),
        Rotate {
            project,
            user_id,
            token_id,
            delivery,
        } => (
            "rotate",
            json!({"project":project,"userId":user_id,"tokenId":token_id}),
            Some(delivery),
        ),
        Revoke {
            project,
            user_id,
            token_id,
        } => (
            "revoke",
            json!({"project":project,"userId":user_id,"tokenId":token_id}),
            None,
        ),
    };
    run_provisioning(
        ctx,
        &format!("service_account.token.{action}"),
        inputs,
        delivery,
    )
    .await
}
async fn run_provisioning(
    ctx: &CliContext<'_>,
    action: &str,
    mut inputs: Value,
    delivery: Option<&TokenDeliveryArgs>,
) -> Result<()> {
    if let Some(delivery) = delivery {
        inputs["expiresAt"] = json!(delivery.expires_at);
    }
    if ctx.output.is_some() {
        if delivery.is_some() {
            crate::exit_cli_input_error(anyhow::anyhow!(
                "typed token issuance uses --token-output instead of generic --output"
            ));
        }
        return crate::run_invoke_parts(ctx, "gitlab", action, inputs).await;
    }
    // Reserve the destination before a non-repeatable issuance, rejecting existing files and symlinks.
    let mut output = delivery
        .and_then(|d| d.token_output.as_ref())
        .map(|path| {
            let mut options = fs::OpenOptions::new();
            options.write(true).create_new(true);
            #[cfg(unix)]
            options.mode(0o600);
            options
                .open(path)
                .context("cannot reserve new token output file; no issuance attempted")
        })
        .transpose()?;
    let (status, mut value) =
        send_invoke_parts_with_options(ctx, "gitlab", action, inputs, ResponseOptions::default())
            .await?;
    if let Some(file) = output.as_mut() {
        // Remove the secret before any printing, including failure responses.
        let token = value
            .get_mut("result")
            .and_then(Value::as_object_mut)
            .and_then(|r| r.remove("issuedToken"));
        if let Some(token) = token {
            let token = token
                .as_str()
                .filter(|s| !s.is_empty() && s.len() <= 8192 && !s.chars().any(char::is_control))
                .context(
                    "malformed issued token; reconcile upstream token metadata before retrying",
                )?;
            if file
                .write_all(token.as_bytes())
                .and_then(|_| file.write_all(b"\n"))
                .and_then(|_| file.sync_all())
                .is_err()
            {
                eprintln!(
                    "Token issuance completed but token file delivery failed. Reconcile or revoke the token using the metadata below; do not repeat issuance automatically."
                );
                print_value_and_exit(500, value);
            }
            value["result"]["tokenWritten"] = json!(true);
        } else if value["decision"] == "deny"
            && value["result"].get("mutationStatus").is_none()
            && let Some(path) = delivery.and_then(|d| d.token_output.as_ref())
        {
            // Cleanup must never hide the Broker's definitive denial or alter its exit code.
            let cleanup = || -> std::io::Result<()> {
                #[cfg(unix)]
                {
                    use std::os::unix::fs::MetadataExt;
                    let reserved = file.metadata()?;
                    let current = match fs::symlink_metadata(path) {
                        Ok(metadata) => metadata,
                        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
                        Err(error) => return Err(error),
                    };
                    if current.dev() != reserved.dev() || current.ino() != reserved.ino() {
                        return Ok(());
                    }
                }
                fs::remove_file(path)
            };
            if let Err(error) = cleanup() {
                eprintln!(
                    "Cannot remove unused token output reservation {}: {error}. Issuance was denied.",
                    path.display()
                );
            }
        } else if (200..300).contains(&status) && value["decision"] == "allow" {
            anyhow::bail!(
                "successful issuance response omitted its token; reconcile upstream state before retrying"
            );
        }
    }
    print_invoke_value_and_exit(status, value, ResponseFormat::Json);
}
