//! `agent-access admin usernames …`, `admin access-keys …` and
//! `admin access-key-types …`: typed wrappers for the administration routes of
//! usernames and access keys. Each command is one request; the broker
//! validates names, access key types and lifetimes. A person's own access keys
//! are created from their browser session and have no command.

use super::*;

#[derive(Debug, Subcommand)]
pub(crate) enum AdminAccountUsernamesCommand {
    /// Show every person's and service account's username.
    List,
    /// Show one principal's username: its mode, the name held and where it stands.
    Inspect { principal: String },
    /// Set how a person's name is decided. from_email follows the email: it derives at
    /// once for a person whose name was set by hand, and only fills in a missing name
    /// for one who already follows it. manual keeps the name held now until an
    /// administrator changes it.
    Mode {
        principal: String,
        #[arg(value_parser = ["from_email", "manual"])]
        mode: String,
    },
    /// Set a person's username by hand; the person stops following their email.
    /// A changed name ends the person's access keys.
    Set {
        principal: String,
        account_username: String,
    },
    /// Leave a person without a username, in manual mode. It ends the person's access keys.
    Clear { principal: String },
    /// Confirm that the account is the person already known by the name it holds.
    Confirm {
        principal: String,
        /// The name the account holds now.
        account_username: String,
    },
}

#[derive(Debug, Subcommand)]
pub(crate) enum AdminAccessKeysCommand {
    /// List access keys with what each would resolve as now.
    List {
        /// Only this principal's keys.
        #[arg(long)]
        principal: Option<String>,
        #[arg(long)]
        include_revoked: bool,
        #[arg(long)]
        include_expired: bool,
    },
    /// Issue an access key for a person or a service account, of types the
    /// owner's access key type setting allows. The key is printed once.
    Issue {
        /// The person or service account the key belongs to.
        principal: String,
        #[arg(long)]
        name: String,
        /// An access key type the key carries; repeat for more.
        #[arg(long = "access-key-type", required = true)]
        access_key_types: Vec<String>,
        /// A lifetime offered by every selected access key type, such as 8h, 30d or never.
        #[arg(long)]
        ttl: String,
    },
    /// Revoke an access key. Revocation is final.
    Revoke { key_id: String },
}

#[derive(Debug, Subcommand)]
pub(crate) enum AdminAccessKeyTypesCommand {
    /// Show the configured access key types: name, description, lifetime options, default and self-service.
    List,
}

fn principal_account_username_path(principal: &str) -> String {
    format!(
        "/v1/admin/principals/{}/account-username",
        encoded_path_segment(principal)
    )
}

pub(crate) async fn run_admin_account_usernames(
    ctx: &CliContext<'_>,
    command: &AdminAccountUsernamesCommand,
) -> Result<()> {
    let (method, path, body) = match command {
        AdminAccountUsernamesCommand::List => (
            reqwest::Method::GET,
            "/v1/admin/account-usernames".to_string(),
            None,
        ),
        AdminAccountUsernamesCommand::Inspect { principal } => (
            reqwest::Method::GET,
            principal_account_username_path(principal),
            None,
        ),
        AdminAccountUsernamesCommand::Mode { principal, mode } => (
            reqwest::Method::PUT,
            principal_account_username_path(principal),
            Some(serde_json::json!({"mode": mode})),
        ),
        AdminAccountUsernamesCommand::Set {
            principal,
            account_username,
        } => (
            reqwest::Method::PUT,
            principal_account_username_path(principal),
            Some(serde_json::json!({"mode": "manual", "accountUsername": account_username})),
        ),
        AdminAccountUsernamesCommand::Clear { principal } => (
            reqwest::Method::PUT,
            principal_account_username_path(principal),
            Some(serde_json::json!({"mode": "manual", "accountUsername": null})),
        ),
        AdminAccountUsernamesCommand::Confirm {
            principal,
            account_username,
        } => (
            reqwest::Method::POST,
            format!("{}/confirm", principal_account_username_path(principal)),
            Some(serde_json::json!({"accountUsername": account_username})),
        ),
    };
    run_broker_json_method(ctx, method, &path, body).await
}

pub(crate) async fn run_admin_access_keys(
    ctx: &CliContext<'_>,
    command: &AdminAccessKeysCommand,
) -> Result<()> {
    let (method, path, body) = match command {
        AdminAccessKeysCommand::List {
            principal,
            include_revoked,
            include_expired,
        } => {
            let mut query = form_urlencoded::Serializer::new(String::new());
            if let Some(principal) = principal {
                query.append_pair("principal", principal);
            }
            if *include_revoked {
                query.append_pair("includeRevoked", "true");
            }
            if *include_expired {
                query.append_pair("includeExpired", "true");
            }
            let query = query.finish();
            let path = if query.is_empty() {
                "/v1/admin/access-keys".to_string()
            } else {
                format!("/v1/admin/access-keys?{query}")
            };
            (reqwest::Method::GET, path, None)
        }
        AdminAccessKeysCommand::Issue {
            principal,
            name,
            access_key_types,
            ttl,
        } => (
            reqwest::Method::POST,
            format!(
                "/v1/admin/principals/{}/access-keys",
                encoded_path_segment(principal)
            ),
            Some(serde_json::json!({
                "name": name,
                "accessKeyTypes": access_key_types,
                "lifetime": ttl,
            })),
        ),
        AdminAccessKeysCommand::Revoke { key_id } => (
            reqwest::Method::DELETE,
            format!("/v1/admin/access-keys/{}", encoded_path_segment(key_id)),
            None,
        ),
    };
    run_broker_json_method(ctx, method, &path, body).await
}

pub(crate) async fn run_admin_access_key_types(
    ctx: &CliContext<'_>,
    command: &AdminAccessKeyTypesCommand,
) -> Result<()> {
    match command {
        AdminAccessKeyTypesCommand::List => {
            run_broker_json_method(
                ctx,
                reqwest::Method::GET,
                "/v1/admin/access-key-types",
                None,
            )
            .await
        }
    }
}
