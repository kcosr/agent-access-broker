mod credential_input;
mod discovery;
mod gitlab_provisioning;
mod gitlab_search;
mod import_commands;
mod mcp;
mod output;
#[cfg(test)]
mod request_timeout_tests;
#[cfg(test)]
use agent_access_core::ExitPolicy;
use agent_access_core::imports::ImportedCredentialInputPolicy;
use agent_access_core::{
    API_CATALOG_VERSION, AgentTokenServiceRestriction, ApiActionSpec, ApiCatalog, CliConfig,
    CliTlsConfig, ConfigError, CredentialInputField, HttpRouteSpec, InvokeRequest,
    ResourceSelection, RouteAccess, SEND_SCHEMA_VERSION, cli_exit_code_for_http_status,
    expand_current_user_home, generic_send_schema, load_cli_config, load_cli_tls_certificates,
    split_service_action, validate_cli_config, validate_cli_config_file,
};
use agent_access_provider::{
    ActionIo, MultipartUploadSpec, REQUEST_ID_HEADER, RESULT_METADATA_HEADER,
    is_loopback_or_localhost, is_service_name,
    presentation::{ReadContentFormat, ResponseFormat, ResponseOptions},
};
use anyhow::{Context, Result};
use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64;
use clap::{Args, Parser, Subcommand, ValueEnum};
use percent_encoding::{AsciiSet, CONTROLS, utf8_percent_encode};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::env;
use std::fs;
use std::io::{BufRead, IsTerminal, Read, Seek, SeekFrom, Write};
#[cfg(unix)]
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::time::Duration;
use url::{Url, form_urlencoded};
use uuid::Uuid;

mod audit_commands;
mod resource_commands;
use audit_commands::{AdminAuditCommand, AuditCommand};
use resource_commands::{ResourceGroupsCommand, ResourcesCommand};

const INVOCATION_TIMEOUT_MESSAGE: &str = "broker request timed out; the Broker request may still be queued or executing; do not resubmit a mutation without reconciling its outcome";
const CLI_STREAMING_IDLE_TIMEOUT: Duration = Duration::from_secs(30);
const NORMALIZED_CONTENT_FILE_MAX_BYTES: u64 = 536_870_912;
const NORMALIZED_CONTENT_FILE_HELP: &str = "Read normalized rich content from PATH (maximum 512 MiB / 536870912 bytes; provider and server limits may be lower; '-' is a literal path, not stdin)";
const PATH_SEGMENT_ENCODE_SET: &AsciiSet = &CONTROLS
    .add(b' ')
    .add(b'"')
    .add(b'#')
    .add(b'%')
    .add(b'/')
    .add(b':')
    .add(b'<')
    .add(b'>')
    .add(b'?')
    .add(b'[')
    .add(b'\\')
    .add(b']')
    .add(b'^')
    .add(b'`')
    .add(b'{')
    .add(b'|')
    .add(b'}');

#[derive(Debug, Parser)]
#[command(name = "agent-access")]
#[command(about = "Agent Access Broker CLI")]
struct Cli {
    #[arg(long, global = true, help_heading = "Broker Connection Options")]
    config: Option<PathBuf>,
    #[arg(long, global = true, help_heading = "Broker Connection Options")]
    url: Option<String>,
    #[arg(
        long,
        global = true,
        help_heading = "Broker Identity Options",
        help = "Broker identity token value"
    )]
    token_value: Option<String>,
    #[arg(
        long,
        global = true,
        help_heading = "Broker Identity Options",
        help = "Broker identity token environment variable"
    )]
    token_env: Option<String>,
    #[arg(
        long,
        global = true,
        help_heading = "Broker Identity Options",
        help = "Broker identity token file"
    )]
    token_file: Option<PathBuf>,
    #[arg(long, global = true, help_heading = "Broker Identity Options")]
    identity_header: Option<String>,
    #[arg(long, global = true, help_heading = "Broker Identity Options")]
    identity_scheme: Option<String>,
    #[arg(
        long,
        global = true,
        help_heading = "Broker Identity Options",
        help = "Disable broker identity token lookup"
    )]
    no_token: bool,
    #[arg(long, global = true, help_heading = "Broker Connection Options")]
    allow_insecure_broker_http: bool,
    /// Save a provider response or download to PATH; use - for stdout.
    #[arg(
        long,
        global = true,
        value_name = "PATH",
        help_heading = "Output Options"
    )]
    output: Option<PathBuf>,
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Expose broker provider actions to local MCP clients.
    Mcp {
        #[command(subcommand)]
        command: McpCommand,
    },
    Auth {
        #[command(subcommand)]
        command: AuthCommand,
    },
    Broker {
        #[command(subcommand)]
        command: BrokerCommand,
    },
    Config {
        #[command(subcommand)]
        command: ConfigCommand,
    },
    Services {
        #[command(subcommand)]
        command: ServicesCommand,
    },
    ResourceAccess {
        #[command(subcommand)]
        command: ResourceAccessCommand,
    },
    Actions {
        #[command(subcommand)]
        command: ActionsCommand,
    },
    Credentials {
        #[command(subcommand)]
        command: CredentialsCommand,
    },
    Tokens {
        #[command(subcommand)]
        command: TokensCommand,
    },
    /// Query your own audit records (needs SQLite audit storage).
    Audit {
        #[command(subcommand)]
        command: AuditCommand,
    },
    Admin {
        #[command(subcommand)]
        command: AdminCommand,
    },
    Jira {
        #[command(subcommand)]
        command: JiraCommand,
    },
    Confluence {
        #[command(subcommand)]
        command: ConfluenceCommand,
    },
    Gitlab {
        #[command(subcommand)]
        command: GitlabCommand,
    },
    CloudbeesCi {
        #[command(subcommand)]
        command: CloudbeesCiCommand,
    },
    /// Read and manage the connected Gmail account.
    Gmail {
        #[command(subcommand)]
        command: GmailCommand,
    },
    /// Submit notifications to configured Microsoft Teams Workflows.
    Teams {
        #[command(subcommand)]
        command: TeamsCommand,
    },
    /// Read records through the development OAuth integration.
    #[command(name = "oauth-stub")]
    OAuthStub {
        #[command(subcommand)]
        command: OAuthStubCommand,
    },
    Spec {
        #[command(subcommand)]
        command: SpecCommand,
    },
    Send {
        #[arg(long)]
        request_json: Option<String>,
        #[arg(long)]
        request_file: Option<PathBuf>,
        #[arg(long)]
        request_stdin: bool,
    },
    Invoke {
        service_action: String,
        #[arg(long)]
        input_json: Option<String>,
        #[arg(long)]
        input_file: Option<PathBuf>,
        #[arg(long)]
        input_stdin: bool,
        #[arg(long, value_enum)]
        read_content_format: Option<ReadContentFormatArg>,
        #[arg(long, value_enum)]
        output_format: Option<OutputFormatArg>,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
enum ReadContentFormatArg {
    Native,
    Markdown,
    Text,
}

impl From<ReadContentFormatArg> for ReadContentFormat {
    fn from(value: ReadContentFormatArg) -> Self {
        match value {
            ReadContentFormatArg::Native => Self::Native,
            ReadContentFormatArg::Markdown => Self::Markdown,
            ReadContentFormatArg::Text => Self::Text,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
enum OutputFormatArg {
    Json,
    Markdown,
}

impl From<OutputFormatArg> for ResponseFormat {
    fn from(value: OutputFormatArg) -> Self {
        match value {
            OutputFormatArg::Json => Self::Json,
            OutputFormatArg::Markdown => Self::Markdown,
        }
    }
}

#[derive(Debug, Args)]
struct EmbeddedAndWholeOutputArgs {
    #[arg(long, value_enum)]
    read_content_format: Option<ReadContentFormatArg>,
    #[arg(long, value_enum)]
    output_format: Option<OutputFormatArg>,
}

#[derive(Debug, Args)]
struct EmbeddedOutputArgs {
    #[arg(long, value_enum)]
    read_content_format: Option<ReadContentFormatArg>,
}

#[derive(Debug, Args)]
struct WholeOutputArgs {
    /// Response representation: json (default) or markdown.
    #[arg(long, value_enum)]
    output_format: Option<OutputFormatArg>,
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum SpecAuthArg {
    Include,
    Omit,
}

impl SpecAuthArg {
    fn as_str(self) -> &'static str {
        match self {
            Self::Include => "include",
            Self::Omit => "omit",
        }
    }
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum SpecVisibilityArg {
    Caller,
    All,
}

impl SpecVisibilityArg {
    fn as_str(self) -> &'static str {
        match self {
            Self::Caller => "caller",
            Self::All => "all",
        }
    }
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum SpecOutputArg {
    Json,
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum ConfluencePageMovePositionArg {
    Before,
    After,
    Append,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
enum JiraContentFormatArg {
    Adf,
    Markdown,
    #[value(name = "plain_text")]
    PlainText,
}

impl JiraContentFormatArg {
    fn as_str(self) -> &'static str {
        match self {
            Self::Adf => "adf",
            Self::Markdown => "markdown",
            Self::PlainText => "plain_text",
        }
    }

    fn is_json(self) -> bool {
        matches!(self, Self::Adf)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
enum ConfluencePageContentFormatArg {
    Storage,
    #[value(name = "atlas_doc_format")]
    AtlasDocFormat,
    Markdown,
    #[value(name = "plain_text")]
    PlainText,
}

impl ConfluencePageContentFormatArg {
    fn as_str(self) -> &'static str {
        match self {
            Self::Storage => "storage",
            Self::AtlasDocFormat => "atlas_doc_format",
            Self::Markdown => "markdown",
            Self::PlainText => "plain_text",
        }
    }

    fn is_json(self) -> bool {
        matches!(self, Self::AtlasDocFormat)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
enum ConfluenceContentFormatArg {
    Storage,
    Markdown,
    #[value(name = "plain_text")]
    PlainText,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
enum GitlabContentFormatArg {
    Markdown,
    #[value(name = "plain_text")]
    PlainText,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
enum GitlabProjectionArg {
    Full,
    Summary,
}

impl GitlabProjectionArg {
    fn as_str(self) -> &'static str {
        match self {
            Self::Full => "full",
            Self::Summary => "summary",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
enum GitlabPositionTypeArg {
    Text,
    File,
    Image,
}

impl GitlabPositionTypeArg {
    fn as_str(self) -> &'static str {
        match self {
            Self::Text => "text",
            Self::File => "file",
            Self::Image => "image",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
enum GitlabReviewerStateArg {
    Reviewed,
    RequestedChanges,
}

impl GitlabReviewerStateArg {
    fn as_str(self) -> &'static str {
        match self {
            Self::Reviewed => "reviewed",
            Self::RequestedChanges => "requestedChanges",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
enum GitlabWebhookEventArg {
    Push,
    #[value(name = "tag_push")]
    TagPush,
    Issues,
    #[value(name = "confidential_issues")]
    ConfidentialIssues,
    #[value(name = "merge_requests")]
    MergeRequests,
    Notes,
    #[value(name = "confidential_notes")]
    ConfidentialNotes,
    Jobs,
    Pipelines,
    #[value(name = "wiki_pages")]
    WikiPages,
    Deployments,
    Releases,
    Milestones,
    #[value(name = "feature_flags")]
    FeatureFlags,
    Emoji,
    #[value(name = "resource_access_tokens")]
    ResourceAccessTokens,
    #[value(name = "resource_deploy_tokens")]
    ResourceDeployTokens,
    Vulnerabilities,
}

impl GitlabWebhookEventArg {
    fn as_str(self) -> &'static str {
        match self {
            Self::Push => "push",
            Self::TagPush => "tag_push",
            Self::Issues => "issues",
            Self::ConfidentialIssues => "confidential_issues",
            Self::MergeRequests => "merge_requests",
            Self::Notes => "notes",
            Self::ConfidentialNotes => "confidential_notes",
            Self::Jobs => "jobs",
            Self::Pipelines => "pipelines",
            Self::WikiPages => "wiki_pages",
            Self::Deployments => "deployments",
            Self::Releases => "releases",
            Self::Milestones => "milestones",
            Self::FeatureFlags => "feature_flags",
            Self::Emoji => "emoji",
            Self::ResourceAccessTokens => "resource_access_tokens",
            Self::ResourceDeployTokens => "resource_deploy_tokens",
            Self::Vulnerabilities => "vulnerabilities",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
enum GitlabWebhookTestEventArg {
    Push,
    #[value(name = "tag_push")]
    TagPush,
    Issues,
    #[value(name = "confidential_issues")]
    ConfidentialIssues,
    #[value(name = "merge_requests")]
    MergeRequests,
    Notes,
    Jobs,
    Pipelines,
    #[value(name = "wiki_pages")]
    WikiPages,
    Releases,
    Milestones,
    Emoji,
    #[value(name = "resource_access_tokens")]
    ResourceAccessTokens,
    #[value(name = "resource_deploy_tokens")]
    ResourceDeployTokens,
    Vulnerabilities,
}

impl GitlabWebhookTestEventArg {
    fn as_str(self) -> &'static str {
        match self {
            Self::Push => "push",
            Self::TagPush => "tag_push",
            Self::Issues => "issues",
            Self::ConfidentialIssues => "confidential_issues",
            Self::MergeRequests => "merge_requests",
            Self::Notes => "notes",
            Self::Jobs => "jobs",
            Self::Pipelines => "pipelines",
            Self::WikiPages => "wiki_pages",
            Self::Releases => "releases",
            Self::Milestones => "milestones",
            Self::Emoji => "emoji",
            Self::ResourceAccessTokens => "resource_access_tokens",
            Self::ResourceDeployTokens => "resource_deploy_tokens",
            Self::Vulnerabilities => "vulnerabilities",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
enum GitlabWebhookBranchFilterStrategyArg {
    Wildcard,
    Regex,
    #[value(name = "all_branches")]
    AllBranches,
}

impl GitlabWebhookBranchFilterStrategyArg {
    fn as_str(self) -> &'static str {
        match self {
            Self::Wildcard => "wildcard",
            Self::Regex => "regex",
            Self::AllBranches => "all_branches",
        }
    }
}

#[derive(Debug, Default, Args)]
struct GitlabRequiredContentArgs {
    #[arg(
        long,
        group = "content_source",
        requires = "content_format",
        required_unless_present = "content_file"
    )]
    content: Option<String>,
    #[arg(long, group = "content_source", requires = "content_format", required_unless_present = "content", help = NORMALIZED_CONTENT_FILE_HELP)]
    content_file: Option<PathBuf>,
    #[arg(long, value_enum, requires = "content_source")]
    content_format: Option<GitlabContentFormatArg>,
}

#[derive(Debug, Default, Args)]
struct GitlabOptionalContentArgs {
    #[arg(long, group = "content_source", requires = "content_format")]
    content: Option<String>,
    #[arg(long, group = "content_source", requires = "content_format", help = NORMALIZED_CONTENT_FILE_HELP)]
    content_file: Option<PathBuf>,
    #[arg(long, value_enum, requires = "content_source")]
    content_format: Option<GitlabContentFormatArg>,
}

#[derive(Debug, Default, Args)]
struct GitlabOptionalCommitMessageArgs {
    #[arg(long, group = "commit_message_source")]
    commit_message: Option<String>,
    #[arg(
        long,
        group = "commit_message_source",
        help = "Read the optional Git commit-message template from a bounded UTF-8 file; stdin is not accepted"
    )]
    commit_message_file: Option<PathBuf>,
}

#[derive(Debug, Default, Args)]
struct GitlabPositionArgs {
    #[arg(long, group = "position_source", requires = "expected_head_sha")]
    position_file: Option<PathBuf>,
    #[arg(long, value_enum, group = "position_source", requires = "expected_head_sha", requires_all = ["old_path", "new_path"])]
    position_type: Option<GitlabPositionTypeArg>,
    #[arg(long, requires = "position_type")]
    old_path: Option<String>,
    #[arg(long, requires = "position_type")]
    new_path: Option<String>,
    #[arg(long, requires = "position_type")]
    old_line: Option<u64>,
    #[arg(long, requires = "position_type")]
    new_line: Option<u64>,
    #[arg(long, requires = "position_type")]
    range_start_old_line: Option<u64>,
    #[arg(long, requires = "position_type")]
    range_start_new_line: Option<u64>,
    #[arg(long, requires = "position_type")]
    range_end_old_line: Option<u64>,
    #[arg(long, requires = "position_type")]
    range_end_new_line: Option<u64>,
    #[arg(long, requires = "position_type")]
    position_width: Option<u64>,
    #[arg(long, requires = "position_type")]
    position_height: Option<u64>,
    #[arg(
        long,
        requires = "position_type",
        help = "Zero-based horizontal image coordinate (non-negative integer)"
    )]
    position_x: Option<u64>,
    #[arg(
        long,
        requires = "position_type",
        help = "Zero-based vertical image coordinate (non-negative integer)"
    )]
    position_y: Option<u64>,
}

impl GitlabContentFormatArg {
    fn as_str(self) -> &'static str {
        match self {
            Self::Markdown => "markdown",
            Self::PlainText => "plain_text",
        }
    }
}

impl ConfluenceContentFormatArg {
    fn as_str(self) -> &'static str {
        match self {
            Self::Storage => "storage",
            Self::Markdown => "markdown",
            Self::PlainText => "plain_text",
        }
    }
}

trait NormalizedContentFormatArg: Copy {
    fn as_str(self) -> &'static str;
    fn is_json(self) -> bool;
}

impl NormalizedContentFormatArg for JiraContentFormatArg {
    fn as_str(self) -> &'static str {
        self.as_str()
    }

    fn is_json(self) -> bool {
        self.is_json()
    }
}

impl NormalizedContentFormatArg for ConfluencePageContentFormatArg {
    fn as_str(self) -> &'static str {
        self.as_str()
    }

    fn is_json(self) -> bool {
        self.is_json()
    }
}

impl NormalizedContentFormatArg for ConfluenceContentFormatArg {
    fn as_str(self) -> &'static str {
        self.as_str()
    }

    fn is_json(self) -> bool {
        false
    }
}

impl NormalizedContentFormatArg for GitlabContentFormatArg {
    fn as_str(self) -> &'static str {
        self.as_str()
    }

    fn is_json(self) -> bool {
        false
    }
}

impl ConfluencePageMovePositionArg {
    fn as_str(self) -> &'static str {
        match self {
            Self::Before => "before",
            Self::After => "after",
            Self::Append => "append",
        }
    }
}

#[derive(Debug, Subcommand)]
enum SpecCommand {
    Catalog {
        #[arg(long, value_enum, default_value_t = SpecAuthArg::Include)]
        auth: SpecAuthArg,
        #[arg(long, value_enum, default_value_t = SpecVisibilityArg::Caller)]
        visibility: SpecVisibilityArg,
        #[arg(long, value_enum, default_value_t = SpecOutputArg::Json)]
        output_format: SpecOutputArg,
    },
    Openapi {
        #[arg(long, value_enum, default_value_t = SpecAuthArg::Include)]
        auth: SpecAuthArg,
        #[arg(long, value_enum, default_value_t = SpecVisibilityArg::Caller)]
        visibility: SpecVisibilityArg,
        #[arg(long, value_enum, default_value_t = SpecOutputArg::Json)]
        output_format: SpecOutputArg,
    },
    SendSchema {
        #[arg(long, value_enum, default_value_t = SpecAuthArg::Include)]
        auth: SpecAuthArg,
        #[arg(long, value_enum, default_value_t = SpecVisibilityArg::Caller)]
        visibility: SpecVisibilityArg,
        #[arg(long, value_enum, default_value_t = SpecOutputArg::Json)]
        output_format: SpecOutputArg,
        #[arg(long)]
        offline: bool,
    },
}

#[derive(Debug, Subcommand)]
enum AuthCommand {
    Status,
    Token {
        #[command(subcommand)]
        command: AuthTokenCommand,
    },
    GitCredential {
        #[arg(value_enum)]
        operation: GitCredentialOperation,
    },
}

#[derive(Debug, Subcommand)]
enum BrokerCommand {
    Status,
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum GitCredentialOperation {
    Get,
    Store,
    Erase,
    Capability,
}

#[derive(Debug, Subcommand)]
enum AuthTokenCommand {
    Status,
    Set {
        #[arg(long)]
        token_stdin: bool,
    },
    Clear,
}

#[derive(Debug, Subcommand)]
enum ConfigCommand {
    Validate,
}

#[derive(Debug, Args)]
struct DiscoveryListArgs {
    #[arg(long)]
    prefix: Option<String>,
    #[arg(long)]
    verbose: bool,
}

#[derive(Debug, Subcommand)]
enum ResourceAccessCommand {
    /// Describe local single-target access by action and resource type, with configured resource references and optional live listing actions.
    Describe {
        #[arg(long)]
        service: String,
        /// Filter to one exact canonical action ID.
        #[arg(long)]
        action: Option<String>,
        #[arg(
            long,
            help = "Filter access and configured references to this registered resource type"
        )]
        resource_type: Option<String>,
        #[arg(long)]
        prefix: Option<String>,
        #[arg(
            long,
            help = "Configured reference page size (1–100, default 50); coverage repeats on every page"
        )]
        limit: Option<u32>,
        #[arg(
            long,
            help = "Opaque continuation cursor; repeat the same service, action, resource type, prefix, and limit"
        )]
        cursor: Option<String>,
    },
}

#[derive(Debug, Subcommand)]
enum ServicesCommand {
    List {
        #[command(flatten)]
        projection: DiscoveryListArgs,
    },
    Describe {
        service: String,
    },
}

#[derive(Debug, Subcommand)]
enum ActionsCommand {
    List {
        #[arg(long)]
        service: String,
        #[arg(
            long,
            help = "Concrete resource value; checks single-target policy only, not upstream existence or complete-request authorization"
        )]
        resource: Option<String>,
        #[arg(
            long,
            requires = "resource",
            help = "Resource type of --resource; required when the service authorizes several resource types"
        )]
        resource_type: Option<String>,
        #[command(flatten)]
        projection: DiscoveryListArgs,
    },
    /// Describe an action and its MCP wrapper. Invoke details require authentication and caller-visible catalog eligibility; anonymous callers receive HTTP 401 (exit 6) and should use services describe for the raw definition.
    Describe {
        #[arg(long)]
        service: String,
        action: String,
    },
}

#[derive(Debug, Args)]
struct CredentialPutArgs {
    #[arg(
        long,
        help = "Token profile to store, from the connection's tokenProfiles in `credentials targets`; required when it accepts several"
    )]
    profile: Option<String>,
    #[arg(long, help_heading = "Credential Field Options")]
    username: Option<String>,
    #[arg(long, help_heading = "Credential Field Options")]
    username_env: Option<String>,
    #[arg(long, help_heading = "Credential Field Options")]
    username_file: Option<PathBuf>,
    #[arg(long = "field", value_parser = parse_named_value, help_heading = "Credential Field Options", help = "Credential field literal as name=value")]
    field: Vec<NamedValue>,
    #[arg(long = "field-env", value_parser = parse_named_value, help_heading = "Credential Field Options", help = "Credential field from environment as name=ENV_VAR")]
    field_env: Vec<NamedValue>,
    #[arg(long = "field-file", value_parser = parse_named_path, help_heading = "Credential Field Options", help = "Credential field from file as name=PATH")]
    field_file: Vec<NamedPath>,
    #[arg(
        long = "field-stdin",
        help_heading = "Credential Field Options",
        help = "Credential field name to read from stdin"
    )]
    field_stdin: Option<String>,
    #[arg(long)]
    display_name: Option<String>,
    #[arg(long)]
    expires_at: Option<String>,
    #[arg(long, help = "Verify the stored token after saving it")]
    verify: bool,
    #[arg(
        long = "verify-service",
        requires = "verify",
        help = "Consuming service to verify through"
    )]
    verify_service: Option<String>,
    #[arg(
        long = "verify-repository",
        requires = "verify",
        help = "Repository a Git gateway consumer verifies against"
    )]
    verify_repository: Option<String>,
}

#[derive(Debug, Args)]
struct CredentialVerifyArgs {
    #[arg(long, help = "Consuming service to verify through")]
    service: Option<String>,
    #[arg(long, help = "Repository a Git gateway consumer verifies against")]
    repository: Option<String>,
}

#[derive(Debug, Subcommand)]
#[allow(clippy::large_enum_variant)]
enum CredentialsCommand {
    /// List your credential connections and retained stored credentials.
    List,
    /// List the connections whose token you can store now, with the token
    /// profiles each accepts, their labels and input forms.
    Targets,
    /// Show your stored token's metadata for a connection.
    Inspect { connection: String },
    /// Store or replace your token for a connection.
    Put {
        connection: String,
        #[command(flatten)]
        input: CredentialPutArgs,
    },
    /// Delete your token for a connection.
    Delete { connection: String },
    /// Verify your token for a connection through one of its services.
    Verify {
        connection: String,
        #[command(flatten)]
        verify: CredentialVerifyArgs,
    },
    /// Delete a retained stored credential the configuration no longer selects.
    DeleteRetained { credential_id: String },
}

#[derive(Debug, Subcommand)]
#[allow(clippy::large_enum_variant)]
enum TokensCommand {
    EffectiveAccess {
        #[arg(long)]
        request_file: PathBuf,
    },
    List {
        #[arg(long)]
        include_revoked: bool,
        #[arg(long)]
        include_expired: bool,
    },
    Issue {
        #[arg(long)]
        name: String,
        #[arg(long, conflicts_with = "expires_at")]
        ttl: Option<String>,
        #[arg(long)]
        expires_at: Option<String>,
        #[arg(long, conflicts_with_all = ["ttl", "expires_at"])]
        never: bool,
        #[arg(long = "service")]
        services: Vec<String>,
        #[arg(long = "action", value_parser = parse_token_action_restriction)]
        actions: Vec<TokenActionRestriction>,
        #[arg(long = "resource-id", value_parser = parse_token_resource_reference, help = "Restrict a service to a catalog resource: SERVICE=ID")]
        resource_ids: Vec<TokenResourceReference>,
        #[arg(long = "resource-group-id", value_parser = parse_token_resource_reference, help = "Restrict a service to a live resource group: SERVICE=ID")]
        resource_group_ids: Vec<TokenResourceReference>,
        #[arg(
            long = "restrict-resources",
            help = "Apply an empty resource restriction to SERVICE; selected IDs are added to it"
        )]
        restricted_services: Vec<String>,
        #[arg(long, conflicts_with_all = ["actions", "resource_ids", "resource_group_ids", "restricted_services"])]
        service_restrictions_file: Option<PathBuf>,
        #[arg(long = "execution-context", required = true)]
        execution_contexts: Vec<String>,
    },
    Inspect {
        token_id: String,
    },
    Revoke {
        token_id: String,
    },
    Pause {
        token_id: String,
    },
    Resume {
        token_id: String,
    },
}

#[derive(Debug, Subcommand)]
#[allow(clippy::large_enum_variant)]
enum AdminCommand {
    /// Configure and review database-managed upstream integrations.
    Imports {
        #[command(subcommand)]
        command: import_commands::AdminImportsCommand,
    },
    Store {
        #[command(subcommand)]
        command: AdminStoreCommand,
    },
    Config {
        #[command(subcommand)]
        command: AdminConfigCommand,
    },
    Principals {
        #[command(subcommand)]
        command: AdminPrincipalsCommand,
    },
    Groups {
        #[command(subcommand)]
        command: AdminGroupsCommand,
    },
    Rights {
        #[command(subcommand)]
        command: AdminRightsCommand,
    },
    Tokens {
        #[command(subcommand)]
        command: AdminTokensCommand,
    },
    Credentials {
        #[command(subcommand)]
        command: AdminCredentialsCommand,
    },
    Policy {
        #[command(subcommand)]
        command: AdminPolicyCommand,
    },
    /// Query the audit store (needs SQLite audit storage).
    Audit {
        #[command(subcommand)]
        command: AdminAuditCommand,
    },
}

#[derive(Debug, Subcommand)]
enum AdminStoreCommand {
    Status,
}

#[derive(Debug, Subcommand)]
enum AdminConfigCommand {
    Status,
    Reload,
}

#[derive(Debug, Subcommand)]
enum AdminPrincipalsCommand {
    List,
    Inspect {
        principal: String,
    },
    Create {
        principal: String,
        #[arg(long, default_value = "user")]
        kind: String,
        #[arg(long)]
        display_name: Option<String>,
        #[arg(long)]
        email: Option<String>,
        #[arg(long)]
        external_subject: Option<String>,
        #[arg(long, default_value = "user", value_parser = ["user", "auditor", "service_policy_manager", "admin"])]
        role: String,
        #[arg(long, action = clap::ArgAction::Set)]
        self_service_enabled: Option<bool>,
    },
    Update {
        principal: String,
        #[arg(long, conflicts_with = "clear_display_name")]
        display_name: Option<String>,
        #[arg(long)]
        clear_display_name: bool,
        #[arg(long, conflicts_with = "clear_email")]
        email: Option<String>,
        #[arg(long)]
        clear_email: bool,
    },
    Enable {
        principal: String,
    },
    Disable {
        principal: String,
    },
    Access {
        #[command(subcommand)]
        command: AdminPrincipalAccessCommand,
    },
    Groups {
        #[command(subcommand)]
        command: AdminPrincipalGroupsCommand,
    },
    LoginMethods {
        #[command(subcommand)]
        command: AdminPrincipalLoginMethodsCommand,
    },
    Password {
        #[command(subcommand)]
        command: AdminPrincipalPasswordCommand,
    },
    IdentityToken {
        #[command(subcommand)]
        command: AdminIdentityTokenCommand,
    },
    IdentityAccess {
        #[command(subcommand)]
        command: AdminIdentityAccessCommand,
    },
    IdentityBindings {
        #[command(subcommand)]
        command: AdminIdentityBindingsCommand,
    },
    ServiceLimits {
        #[command(subcommand)]
        command: AdminPrincipalServiceLimitsCommand,
    },
}

#[derive(Debug, Subcommand)]
enum AdminPrincipalServiceLimitsCommand {
    /// Show the effective invocation limit for every configured service.
    List { principal: String },
    /// Set the principal's invocation limit override for one service.
    Set {
        principal: String,
        service: String,
        /// Admitted requests allowed in any trailing window (1 to 1000000).
        #[arg(long)]
        requests: u64,
        /// Rolling window in s, m, h, or d, for example 30s or 1m (1s to 1d).
        #[arg(long, value_parser = parse_broker_duration_seconds)]
        window: u64,
    },
    /// Remove the override so the service limit or default applies again.
    Clear { principal: String, service: String },
}

#[derive(Debug, Subcommand)]
enum AdminIdentityAccessCommand {
    /// Show the common trusted username and fingerprint access gate.
    Inspect { principal: String },
    /// Pause trusted identity access, preserving Broker tokens and sign-in.
    Pause {
        principal: String,
        #[arg(long, value_parser = clap::value_parser!(i64).range(1..))]
        expected_version: i64,
    },
    /// Resume trusted identity access.
    Resume {
        principal: String,
        #[arg(long, value_parser = clap::value_parser!(i64).range(1..))]
        expected_version: i64,
    },
}

/// One trusted-identity access path's settings; an update names at least one.
#[derive(Debug, Args)]
#[group(required = true, multiple = true)]
struct IdentityPathSettingsArgs {
    /// Admit (true) or refuse (false) requests through this path.
    #[arg(long, action = clap::ArgAction::Set)]
    enabled: Option<bool>,
    /// Limit this path to actions classified as reads (true) or restore full access (false).
    #[arg(long, action = clap::ArgAction::Set)]
    read_only: Option<bool>,
}

impl IdentityPathSettingsArgs {
    /// The request body: only the supplied settings and the version fence.
    fn body(&self, fence: &str, expected: i64) -> serde_json::Value {
        let mut body = serde_json::Map::new();
        if let Some(enabled) = self.enabled {
            body.insert("enabled".into(), serde_json::json!(enabled));
        }
        if let Some(read_only) = self.read_only {
            body.insert("readOnly".into(), serde_json::json!(read_only));
        }
        body.insert(fence.into(), serde_json::json!(expected));
        serde_json::Value::Object(body)
    }
}

#[derive(Debug, Subcommand)]
enum AdminIdentityBindingsCommand {
    /// Show exact username bindings and currently configured namespaces.
    List { principal: String },
    /// Attach a configured namespace and exact username to a managed human.
    Create {
        principal: String,
        #[arg(long)]
        namespace: String,
        #[arg(long)]
        username: String,
        /// Limit the new binding to actions classified as reads.
        #[arg(long)]
        read_only: bool,
    },
    /// Change a binding's Enabled and Read-only settings.
    Update {
        principal: String,
        binding: String,
        #[command(flatten)]
        settings: IdentityPathSettingsArgs,
        #[arg(long, value_parser = clap::value_parser!(i64).range(1..))]
        expected_version: i64,
    },
    Delete {
        principal: String,
        binding: String,
        #[arg(long, value_parser = clap::value_parser!(i64).range(1..))]
        expected_version: i64,
    },
}

#[derive(Debug, Subcommand)]
enum AdminIdentityTokenCommand {
    Inspect {
        principal: String,
    },
    Reveal {
        principal: String,
    },
    Generate {
        principal: String,
    },
    Remove {
        principal: String,
    },
    Set {
        principal: String,
        #[arg(
            long,
            required_unless_present = "identity_token_stdin",
            conflicts_with = "identity_token_stdin"
        )]
        identity_token_file: Option<PathBuf>,
        #[arg(long, required_unless_present = "identity_token_file")]
        identity_token_stdin: bool,
    },
    /// Change the identity token's Enabled and Read-only settings, keeping its secret.
    Update {
        principal: String,
        #[command(flatten)]
        settings: IdentityPathSettingsArgs,
        #[arg(long, value_parser = clap::value_parser!(i64).range(1..))]
        expected_revision: i64,
    },
}

#[derive(Debug, Subcommand)]
enum AdminGroupsCommand {
    List,
    Inspect {
        group: String,
    },
    Create {
        group: String,
        #[arg(long)]
        display_name: Option<String>,
        #[arg(long)]
        description: Option<String>,
        /// Add newly created Microsoft accounts to this group after admission.
        #[arg(long)]
        auto_enroll_new_microsoft_users: bool,
    },
    Update {
        group: String,
        #[arg(long, conflicts_with = "clear_display_name")]
        display_name: Option<String>,
        #[arg(long)]
        clear_display_name: bool,
        #[arg(long, conflicts_with = "clear_description")]
        description: Option<String>,
        #[arg(long)]
        clear_description: bool,
        /// Enable or disable automatic local membership for new Microsoft accounts.
        #[arg(long, action = clap::ArgAction::Set)]
        auto_enroll_new_microsoft_users: Option<bool>,
    },
    Enable {
        group: String,
    },
    Disable {
        group: String,
    },
    Members {
        #[command(subcommand)]
        command: AdminGroupMembersCommand,
    },
    ExternalGroupBindings {
        #[command(subcommand)]
        command: AdminExternalGroupBindingsCommand,
    },
}

#[derive(Debug, Subcommand)]
enum AdminGroupMembersCommand {
    List { group: String },
    Add { group: String, principal: String },
    Delete { group: String, principal: String },
}

#[derive(Debug, Subcommand)]
enum AdminExternalGroupBindingsCommand {
    List {
        group: String,
    },
    Create {
        group: String,
        #[arg(long, value_parser = parse_uuid)]
        external_group_id: Uuid,
    },
    Enable {
        group: String,
        #[arg(value_parser = parse_uuid)]
        binding_id: Uuid,
    },
    Disable {
        group: String,
        #[arg(value_parser = parse_uuid)]
        binding_id: Uuid,
    },
    Delete {
        group: String,
        #[arg(value_parser = parse_uuid)]
        binding_id: Uuid,
    },
}

#[derive(Debug, Subcommand)]
enum AdminPrincipalAccessCommand {
    /// Set the account role and/or personal self-service permission.
    Set {
        principal: String,
        #[arg(long, value_parser = ["user", "auditor", "service_policy_manager", "admin"])]
        role: Option<String>,
        #[arg(long, action = clap::ArgAction::Set)]
        self_service_enabled: Option<bool>,
    },
}

#[derive(Debug, Subcommand)]
enum AdminPrincipalGroupsCommand {
    Add { principal: String, group: String },
    Delete { principal: String, group: String },
}

#[derive(Debug, Subcommand)]
enum AdminPrincipalLoginMethodsCommand {
    List {
        principal: String,
    },
    Oidc {
        #[command(subcommand)]
        command: AdminPrincipalOidcCommand,
    },
}

#[derive(Debug, Subcommand)]
enum AdminPrincipalOidcCommand {
    Link {
        principal: String,
        #[arg(long, value_parser = parse_uuid)]
        user_object_id: Uuid,
    },
    Unlink {
        principal: String,
    },
}

#[derive(Debug, Subcommand)]
enum AdminPrincipalPasswordCommand {
    /// Reset an existing active local password; never enables sign-in.
    Reset {
        principal: String,
        #[arg(long)]
        password_env: Option<String>,
        #[arg(long)]
        password_file: Option<PathBuf>,
        #[arg(long)]
        password_stdin: bool,
        #[arg(long)]
        no_must_change_password: bool,
    },
    /// Enable or re-enable separate Broker password sign-in.
    Enable {
        principal: String,
        #[arg(long, required = true)]
        acknowledge_separate_sign_in: bool,
        #[arg(long)]
        password_env: Option<String>,
        #[arg(long)]
        password_file: Option<PathBuf>,
        #[arg(long)]
        password_stdin: bool,
        #[arg(long)]
        no_must_change_password: bool,
    },
    Disable {
        principal: String,
    },
    Unlock {
        principal: String,
    },
}

#[derive(Debug, Subcommand)]
enum AdminRightsCommand {
    List,
    Grant {
        principal: String,
        #[arg(long)]
        right: String,
        #[arg(long)]
        service: Option<String>,
        #[arg(long)]
        credential_name: Option<String>,
        #[arg(long)]
        expires_at: Option<String>,
        #[arg(long)]
        reason: Option<String>,
    },
    Revoke {
        right_id: String,
    },
}

#[derive(Debug, Subcommand)]
#[allow(clippy::large_enum_variant)]
enum AdminTokensCommand {
    EffectiveAccess {
        principal: String,
        #[arg(long)]
        request_file: PathBuf,
    },
    List,
    Issue {
        principal: String,
        #[arg(long)]
        name: String,
        #[arg(long, default_value = "agent_invoke")]
        token_class: String,
        #[arg(long, conflicts_with = "expires_at")]
        ttl: Option<String>,
        #[arg(long)]
        expires_at: Option<String>,
        #[arg(long, conflicts_with_all = ["ttl", "expires_at"])]
        never: bool,
        #[arg(long = "service")]
        services: Vec<String>,
        #[arg(long = "action", value_parser = parse_token_action_restriction)]
        actions: Vec<TokenActionRestriction>,
        #[arg(long = "resource-id", value_parser = parse_token_resource_reference, help = "Restrict a service to a catalog resource: SERVICE=ID")]
        resource_ids: Vec<TokenResourceReference>,
        #[arg(long = "resource-group-id", value_parser = parse_token_resource_reference, help = "Restrict a service to a live resource group: SERVICE=ID")]
        resource_group_ids: Vec<TokenResourceReference>,
        #[arg(
            long = "restrict-resources",
            help = "Apply an empty resource restriction to SERVICE; selected IDs are added to it"
        )]
        restricted_services: Vec<String>,
        #[arg(long, conflicts_with_all = ["actions", "resource_ids", "resource_group_ids", "restricted_services"])]
        service_restrictions_file: Option<PathBuf>,
        #[arg(long = "execution-context")]
        execution_contexts: Vec<String>,
    },
    Revoke {
        token_id: String,
    },
    Pause {
        token_id: String,
    },
    Resume {
        token_id: String,
    },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum BrokerTokenAction {
    Pause,
    Resume,
}

impl BrokerTokenAction {
    fn path_segment(self) -> &'static str {
        match self {
            Self::Pause => "pause",
            Self::Resume => "resume",
        }
    }
}

fn self_token_action_path(token_id: &str, action: BrokerTokenAction) -> String {
    format!("/v1/tokens/{token_id}/{}", action.path_segment())
}

fn admin_token_action_path(token_id: &str, action: BrokerTokenAction) -> String {
    format!("/v1/admin/tokens/{token_id}/{}", action.path_segment())
}

#[derive(Debug, Subcommand)]
#[allow(clippy::large_enum_variant)]
enum AdminCredentialsCommand {
    /// List a principal's credential connections and retained stored credentials.
    List { principal: String },
    /// List stored credentials by ID, active and retained, with their stored service and name.
    ListStored {
        #[arg(long)]
        principal: Option<String>,
    },
    /// List the connections whose token you can store for a principal, with
    /// the token profiles each accepts, their labels and input forms.
    Targets { principal: String },
    /// Show a principal's stored token metadata for a connection.
    Inspect {
        principal: String,
        connection: String,
    },
    /// Store or replace a principal's token for a connection.
    Put {
        principal: String,
        connection: String,
        #[command(flatten)]
        input: CredentialPutArgs,
    },
    /// Delete a principal's token for a connection.
    Delete {
        principal: String,
        connection: String,
    },
    /// Verify a principal's token for a connection, probing as that principal.
    Verify {
        principal: String,
        connection: String,
        #[command(flatten)]
        verify: CredentialVerifyArgs,
    },
    /// Show any stored credential by its ID.
    InspectById { credential_id: String },
    /// Delete any stored credential by its ID, such as a retained one.
    DeleteById { credential_id: String },
    Rewrap {
        #[arg(long)]
        from_key: String,
        #[arg(long)]
        to_key: String,
    },
}

#[derive(Debug, Subcommand)]
#[allow(clippy::large_enum_variant)]
enum AdminPolicyCommand {
    Resources {
        #[command(subcommand)]
        command: ResourcesCommand,
    },
    ResourceGroups {
        #[command(subcommand)]
        command: ResourceGroupsCommand,
    },
    EffectiveAccess {
        #[arg(long)]
        request_file: PathBuf,
    },
    Status,
    Catalog,
    Grants {
        #[command(subcommand)]
        command: AdminPolicyGrantsCommand,
    },
    Managers {
        #[command(subcommand)]
        command: AdminPolicyManagersCommand,
    },
}

#[derive(Debug, Subcommand)]
enum AdminPolicyManagersCommand {
    List {
        #[arg(long)]
        service: Option<String>,
    },
    Grant {
        #[arg(long)]
        service: String,
        #[arg(long)]
        principal: String,
    },
    Revoke {
        #[arg(long)]
        service: String,
        #[arg(long)]
        principal: String,
    },
}

#[derive(Debug, Subcommand)]
#[allow(clippy::large_enum_variant)]
enum AdminPolicyGrantsCommand {
    List {
        #[arg(long)]
        subject: Option<String>,
        #[arg(long)]
        service: Option<String>,
        #[arg(long)]
        status: Option<String>,
        #[arg(long = "execution-context")]
        execution_context: Option<String>,
    },
    Inspect {
        grant_ref: String,
    },
    Create {
        #[arg(long)]
        grant_id: Option<String>,
        #[arg(long = "subject", required = true)]
        subjects: Vec<String>,
        #[arg(long)]
        service: String,
        #[arg(long = "action", required = true)]
        actions: Vec<String>,
        #[arg(long = "execution-context", required = true)]
        execution_contexts: Vec<String>,
        #[arg(long = "resource-id", conflicts_with_all = ["resources_json", "resources_file"])]
        resource_ids: Vec<String>,
        #[arg(long = "resource-group-id", conflicts_with_all = ["resources_json", "resources_file"])]
        resource_group_ids: Vec<String>,
        #[arg(long, conflicts_with_all = ["resource_ids", "resource_group_ids", "resources_file"])]
        resources_json: Option<String>,
        #[arg(long, conflicts_with_all = ["resource_ids", "resource_group_ids", "resources_json"])]
        resources_file: Option<PathBuf>,
        #[arg(long)]
        credential_mode: String,
        #[arg(long)]
        priority: Option<i32>,
        #[arg(long)]
        status: Option<String>,
        #[arg(long)]
        description: Option<String>,
    },
    Update {
        grant_ref: String,
        #[arg(long, value_parser = parse_expected_version)]
        expected_version: i64,
        #[arg(long = "subject")]
        subjects: Vec<String>,
        #[arg(long)]
        service: Option<String>,
        #[arg(long = "action")]
        actions: Vec<String>,
        #[arg(long = "execution-context")]
        execution_contexts: Vec<String>,
        #[arg(long = "resource-id", conflicts_with_all = ["resources_json", "resources_file"])]
        resource_ids: Vec<String>,
        #[arg(long = "resource-group-id", conflicts_with_all = ["resources_json", "resources_file"])]
        resource_group_ids: Vec<String>,
        #[arg(long, conflicts_with_all = ["resource_ids", "resource_group_ids", "resources_file"])]
        resources_json: Option<String>,
        #[arg(long, conflicts_with_all = ["resource_ids", "resource_group_ids", "resources_json"])]
        resources_file: Option<PathBuf>,
        #[arg(long)]
        credential_mode: Option<String>,
        #[arg(long, conflicts_with = "clear_priority")]
        priority: Option<i32>,
        #[arg(long)]
        clear_priority: bool,
        #[arg(long)]
        status: Option<String>,
        #[arg(long, conflicts_with = "clear_description")]
        description: Option<String>,
        #[arg(long)]
        clear_description: bool,
    },
    Validate {
        #[arg(long)]
        grant_id: Option<String>,
        #[arg(long, value_parser = parse_expected_version)]
        expected_version: Option<i64>,
        #[arg(long = "subject")]
        subjects: Vec<String>,
        #[arg(long)]
        service: Option<String>,
        #[arg(long = "action")]
        actions: Vec<String>,
        #[arg(long = "execution-context")]
        execution_contexts: Vec<String>,
        #[arg(long = "resource-id", conflicts_with_all = ["resources_json", "resources_file"])]
        resource_ids: Vec<String>,
        #[arg(long = "resource-group-id", conflicts_with_all = ["resources_json", "resources_file"])]
        resource_group_ids: Vec<String>,
        #[arg(long, conflicts_with_all = ["resource_ids", "resource_group_ids", "resources_file"])]
        resources_json: Option<String>,
        #[arg(long, conflicts_with_all = ["resource_ids", "resource_group_ids", "resources_json"])]
        resources_file: Option<PathBuf>,
        #[arg(long)]
        credential_mode: Option<String>,
        #[arg(long, conflicts_with = "clear_priority")]
        priority: Option<i32>,
        #[arg(long)]
        clear_priority: bool,
        #[arg(long)]
        status: Option<String>,
        #[arg(long, conflicts_with = "clear_description")]
        description: Option<String>,
        #[arg(long)]
        clear_description: bool,
    },
    Enable {
        grant_ref: String,
        #[arg(long, value_parser = parse_expected_version)]
        expected_version: i64,
    },
    Disable {
        grant_ref: String,
        #[arg(long, value_parser = parse_expected_version)]
        expected_version: i64,
    },
    Delete {
        grant_ref: String,
        #[arg(long, value_parser = parse_expected_version)]
        expected_version: i64,
    },
    Subjects {
        #[command(subcommand)]
        command: AdminPolicyGrantSubjectsCommand,
    },
    Export,
}

#[derive(Debug, Subcommand)]
enum AdminPolicyGrantSubjectsCommand {
    Add {
        grant_ref: String,
        #[arg(long)]
        subject: String,
        #[arg(long, value_parser = parse_expected_version)]
        expected_version: i64,
    },
    Remove {
        grant_ref: String,
        #[arg(long)]
        subject: String,
        #[arg(long, value_parser = parse_expected_version)]
        expected_version: i64,
        #[arg(long, default_value = "reject", value_parser = ["reject", "disable_grant"])]
        last_subject_behavior: String,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct NamedValue {
    name: String,
    value: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct NamedPath {
    name: String,
    path: PathBuf,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct TokenActionRestriction {
    service: String,
    action: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct TokenResourceReference {
    service: String,
    id: String,
}

#[derive(Debug, Subcommand)]
enum JiraCommand {
    Project {
        #[command(subcommand)]
        command: JiraProjectCommand,
    },
    IssueType {
        #[command(subcommand)]
        command: JiraIssueTypeCommand,
    },
    Issue {
        #[command(subcommand)]
        command: JiraIssueCommand,
    },
}

#[derive(Debug, Subcommand)]
enum JiraProjectCommand {
    /// Inspect project details and discover fields for JQL searches.
    View {
        project: String,
        #[arg(long, value_enum, value_delimiter = ',', num_args = 0.., help = "Metadata sections (default: fields); pass --include alone for identity only")]
        include: Option<Vec<JiraProjectSection>>,
        #[arg(long, help = "Filter included metadata by name, ID, or JQL reference")]
        query: Option<String>,
        #[arg(long, value_enum)]
        output_format: Option<OutputFormatArg>,
    },
    List {
        #[arg(long, value_parser = clap::value_parser!(u32).range(1..=100))]
        max_results: Option<u32>,
        #[arg(long)]
        page_token: Option<String>,
        #[arg(long, value_enum)]
        output_format: Option<OutputFormatArg>,
    },
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum JiraProjectSection {
    Fields,
    Versions,
    Components,
    #[value(name = "issueTypes")]
    IssueTypes,
    Statuses,
}

impl JiraProjectSection {
    fn as_str(self) -> &'static str {
        match self {
            Self::Fields => "fields",
            Self::Versions => "versions",
            Self::Components => "components",
            Self::IssueTypes => "issueTypes",
            Self::Statuses => "statuses",
        }
    }
}

#[derive(Debug, Subcommand)]
enum JiraIssueTypeCommand {
    List {
        #[arg(long)]
        project: String,
        #[arg(long)]
        start_at: Option<u32>,
        #[arg(long, value_parser = clap::value_parser!(u32).range(1..=100))]
        max_results: Option<u32>,
        #[arg(long, value_enum)]
        output_format: Option<OutputFormatArg>,
    },
}

#[derive(Debug, Subcommand)]
enum JiraIssueCommand {
    View {
        issue: Option<String>,
        #[arg(long)]
        issue_url: Option<String>,
        #[arg(
            long,
            help = "Include one chronological page of full comment and reply bodies"
        )]
        include_comments: bool,
        #[arg(long, value_enum)]
        read_content_format: Option<ReadContentFormatArg>,
        #[arg(long, value_enum)]
        output_format: Option<OutputFormatArg>,
    },
    Create {
        #[arg(long)]
        project: String,
        #[arg(long)]
        issue_type_id: String,
        #[arg(long)]
        summary: String,
        #[arg(long, group = "content_source", requires = "content_format")]
        content: Option<String>,
        #[arg(
            long,
            group = "content_source",
            requires = "content_format",
            help = NORMALIZED_CONTENT_FILE_HELP
        )]
        content_file: Option<PathBuf>,
        #[arg(long, value_enum, requires = "content_source")]
        content_format: Option<JiraContentFormatArg>,
        #[arg(long, value_enum)]
        read_content_format: Option<ReadContentFormatArg>,
    },
    Child {
        #[command(subcommand)]
        command: JiraIssueChildCommand,
    },
    Update {
        issue: Option<String>,
        #[arg(long)]
        issue_url: Option<String>,
        #[arg(long)]
        summary: Option<String>,
        #[arg(long, group = "content_source", requires = "content_format")]
        content: Option<String>,
        #[arg(
            long,
            group = "content_source",
            requires = "content_format",
            help = NORMALIZED_CONTENT_FILE_HELP
        )]
        content_file: Option<PathBuf>,
        #[arg(long, value_enum, requires = "content_source")]
        content_format: Option<JiraContentFormatArg>,
        #[arg(long, value_enum)]
        read_content_format: Option<ReadContentFormatArg>,
        #[arg(long)]
        notify_users: bool,
        #[arg(
            long,
            help = "Send notifyUsers=false; Jira may require project or global admin permission for issue edits"
        )]
        suppress_notifications: bool,
    },
    Parent {
        #[command(subcommand)]
        command: JiraIssueParentCommand,
    },
    Dependency {
        #[command(subcommand)]
        command: JiraIssueDependencyCommand,
    },
    Search {
        /// JQL filter and/or ordering; empty browses a finite authorized project scope.
        #[arg(long)]
        jql: Option<String>,
        #[arg(long)]
        text: Option<String>,
        /// Optional project narrowing; omission uses effective broker authorization.
        #[arg(long = "project")]
        projects: Vec<String>,
        #[arg(long)]
        max_results: Option<u32>,
        #[arg(long)]
        next_page_token: Option<String>,
        #[arg(long, value_enum)]
        output_format: Option<OutputFormatArg>,
    },
    Comment {
        #[command(subcommand)]
        command: JiraCommentCommand,
    },
    Attach {
        issue: String,
        #[arg(required = true)]
        files: Vec<PathBuf>,
        #[arg(long)]
        content_type: Option<String>,
    },
    Attachment {
        #[command(subcommand)]
        command: JiraAttachmentCommand,
    },
    Verify {
        issue: String,
        #[arg(long)]
        expect_comment_id: Option<String>,
        #[arg(long)]
        expect_attachment_id: Option<String>,
        #[arg(long, value_enum)]
        output_format: Option<OutputFormatArg>,
    },
}

#[derive(Debug, Subcommand)]
enum JiraIssueChildCommand {
    Create {
        #[arg(long)]
        project: String,
        #[arg(long)]
        issue_type_id: String,
        #[arg(long)]
        summary: String,
        #[arg(long)]
        parent: Option<String>,
        #[arg(long)]
        parent_url: Option<String>,
        #[arg(long, group = "content_source", requires = "content_format")]
        content: Option<String>,
        #[arg(
            long,
            group = "content_source",
            requires = "content_format",
            help = NORMALIZED_CONTENT_FILE_HELP
        )]
        content_file: Option<PathBuf>,
        #[arg(long, value_enum, requires = "content_source")]
        content_format: Option<JiraContentFormatArg>,
    },
}

#[derive(Debug, Subcommand)]
enum JiraIssueParentCommand {
    Set {
        issue: Option<String>,
        #[arg(long)]
        issue_url: Option<String>,
        #[arg(long)]
        parent: Option<String>,
        #[arg(long)]
        parent_url: Option<String>,
    },
}

#[derive(Debug, Subcommand)]
enum JiraIssueDependencyCommand {
    Add {
        #[arg(long)]
        blocking: Option<String>,
        #[arg(long)]
        blocking_url: Option<String>,
        #[arg(long)]
        blocked: Option<String>,
        #[arg(long)]
        blocked_url: Option<String>,
    },
}

#[derive(Debug, Subcommand)]
enum JiraCommentCommand {
    List {
        #[arg(long)]
        issue: Option<String>,
        #[arg(long)]
        issue_url: Option<String>,
        #[arg(long)]
        max_results: Option<u32>,
        #[arg(long)]
        start_at: Option<u32>,
        #[arg(long)]
        order_by: Option<String>,
        #[arg(long, help = "Include full comment and reply bodies in this page")]
        include_bodies: bool,
        #[arg(long, value_enum)]
        read_content_format: Option<ReadContentFormatArg>,
        #[arg(long, value_enum)]
        output_format: Option<OutputFormatArg>,
    },
    View {
        comment_id: String,
        #[arg(long)]
        issue: Option<String>,
        #[arg(long)]
        issue_url: Option<String>,
        #[arg(long, value_enum)]
        read_content_format: Option<ReadContentFormatArg>,
        #[arg(long, value_enum)]
        output_format: Option<OutputFormatArg>,
    },
    Add {
        #[arg(long)]
        issue: Option<String>,
        #[arg(long)]
        issue_url: Option<String>,
        #[arg(
            long,
            group = "content_source",
            requires = "content_format",
            required_unless_present = "content_file"
        )]
        content: Option<String>,
        #[arg(
            long,
            group = "content_source",
            requires = "content_format",
            required_unless_present = "content",
            help = NORMALIZED_CONTENT_FILE_HELP
        )]
        content_file: Option<PathBuf>,
        #[arg(long, value_enum, requires = "content_source")]
        content_format: Option<JiraContentFormatArg>,
        #[arg(long)]
        visibility_file: Option<PathBuf>,
        #[arg(long, value_enum)]
        read_content_format: Option<ReadContentFormatArg>,
    },
    Reply {
        parent_comment_id: String,
        #[arg(long)]
        issue: Option<String>,
        #[arg(long)]
        issue_url: Option<String>,
        #[arg(
            long,
            group = "content_source",
            requires = "content_format",
            required_unless_present = "content_file"
        )]
        content: Option<String>,
        #[arg(
            long,
            group = "content_source",
            requires = "content_format",
            required_unless_present = "content",
            help = NORMALIZED_CONTENT_FILE_HELP
        )]
        content_file: Option<PathBuf>,
        #[arg(long, value_enum, requires = "content_source")]
        content_format: Option<JiraContentFormatArg>,
        #[arg(long)]
        visibility_file: Option<PathBuf>,
        #[arg(long, value_enum)]
        read_content_format: Option<ReadContentFormatArg>,
    },
    Update {
        comment_id: String,
        #[arg(long)]
        issue: Option<String>,
        #[arg(long)]
        issue_url: Option<String>,
        #[arg(
            long,
            group = "content_source",
            requires = "content_format",
            required_unless_present = "content_file"
        )]
        content: Option<String>,
        #[arg(
            long,
            group = "content_source",
            requires = "content_format",
            required_unless_present = "content",
            help = NORMALIZED_CONTENT_FILE_HELP
        )]
        content_file: Option<PathBuf>,
        #[arg(long, value_enum, requires = "content_source")]
        content_format: Option<JiraContentFormatArg>,
        #[arg(long)]
        visibility_file: Option<PathBuf>,
        #[arg(long, action = clap::ArgAction::Set, default_value_t = false)]
        notify_users: bool,
        #[arg(long, value_enum)]
        read_content_format: Option<ReadContentFormatArg>,
    },
    Delete {
        comment_id: String,
        #[arg(long)]
        issue: Option<String>,
        #[arg(long)]
        issue_url: Option<String>,
    },
    Property {
        #[command(subcommand)]
        command: JiraCommentPropertyCommand,
    },
}

#[derive(Debug, Subcommand)]
enum JiraCommentPropertyCommand {
    List {
        comment_id: String,
        #[arg(long)]
        issue: Option<String>,
        #[arg(long)]
        issue_url: Option<String>,
        #[arg(long, value_enum)]
        output_format: Option<OutputFormatArg>,
    },
    Get {
        comment_id: String,
        property_key: String,
        #[arg(long)]
        issue: Option<String>,
        #[arg(long)]
        issue_url: Option<String>,
        #[arg(long, value_enum)]
        output_format: Option<OutputFormatArg>,
    },
    Set {
        comment_id: String,
        property_key: String,
        #[arg(long)]
        issue: Option<String>,
        #[arg(long)]
        issue_url: Option<String>,
        #[arg(long)]
        value_file: PathBuf,
    },
    Delete {
        comment_id: String,
        property_key: String,
        #[arg(long)]
        issue: Option<String>,
        #[arg(long)]
        issue_url: Option<String>,
    },
}

#[derive(Debug, Subcommand)]
enum JiraAttachmentCommand {
    List {
        issue: Option<String>,
        #[arg(long)]
        issue_url: Option<String>,
        #[arg(long, value_enum)]
        output_format: Option<OutputFormatArg>,
    },
    Download {
        issue: String,
        attachment_id: String,
    },
}

#[derive(Debug, Subcommand)]
enum ConfluenceCommand {
    Space {
        #[command(subcommand)]
        command: ConfluenceSpaceCommand,
    },
    Page {
        #[command(subcommand)]
        command: ConfluencePageCommand,
    },
    Blog {
        #[command(subcommand)]
        command: ConfluenceBlogCommand,
    },
}

#[derive(Debug, Subcommand)]
enum ConfluenceSpaceCommand {
    List {
        #[arg(long, value_parser = clap::value_parser!(u32).range(1..=100))]
        max_results: Option<u32>,
        #[arg(long)]
        page_token: Option<String>,
        #[arg(long, value_enum)]
        output_format: Option<OutputFormatArg>,
    },
}

#[derive(Debug, Subcommand)]
enum ConfluencePageCommand {
    View {
        page_id: Option<String>,
        #[arg(long)]
        page_url: Option<String>,
        #[command(flatten)]
        response: EmbeddedAndWholeOutputArgs,
    },
    Search {
        /// CQL filter and/or ordering; empty browses the authorized content scope.
        #[arg(long)]
        cql: Option<String>,
        #[arg(long)]
        text: Option<String>,
        /// Optional space narrowing; omission uses effective broker authorization.
        #[arg(long = "space")]
        spaces: Vec<String>,
        #[arg(long)]
        max_results: Option<u32>,
        #[arg(long)]
        next_page_token: Option<String>,
        #[command(flatten)]
        response: WholeOutputArgs,
    },
    Create {
        #[arg(long)]
        space: String,
        #[arg(long)]
        title: String,
        #[arg(long, conflicts_with = "parent_url")]
        parent: Option<String>,
        #[arg(long)]
        parent_url: Option<String>,
        #[arg(
            long,
            required_unless_present = "content_file",
            conflicts_with = "content_file"
        )]
        content: Option<String>,
        #[arg(
            long,
            required_unless_present = "content",
            conflicts_with = "content",
            help = NORMALIZED_CONTENT_FILE_HELP
        )]
        content_file: Option<PathBuf>,
        #[arg(long, value_enum)]
        content_format: ConfluencePageContentFormatArg,
    },
    Update {
        page_id: String,
        #[arg(long)]
        base_version: u64,
        #[arg(long)]
        title: Option<String>,
        #[arg(
            long,
            required_unless_present = "content_file",
            conflicts_with = "content_file"
        )]
        content: Option<String>,
        #[arg(
            long,
            required_unless_present = "content",
            conflicts_with = "content",
            help = NORMALIZED_CONTENT_FILE_HELP
        )]
        content_file: Option<PathBuf>,
        #[arg(long, value_enum)]
        content_format: ConfluencePageContentFormatArg,
    },
    Move {
        #[arg(conflicts_with = "page_url")]
        page_id: Option<String>,
        #[arg(long)]
        page_url: Option<String>,
        #[arg(long, value_enum)]
        position: ConfluencePageMovePositionArg,
        #[arg(long, conflicts_with = "target_url")]
        target: Option<String>,
        #[arg(long)]
        target_url: Option<String>,
    },
    Attach {
        page_id: String,
        #[arg(required = true)]
        files: Vec<PathBuf>,
        #[arg(long)]
        content_type: Option<String>,
    },
    Attachment {
        #[command(subcommand)]
        command: ConfluenceAttachmentCommand,
    },
    Draft {
        #[command(subcommand)]
        command: ConfluencePageDraftCommand,
    },
    FooterComment {
        #[command(subcommand)]
        command: ConfluencePageCommentCommand,
    },
    InlineComment {
        #[command(subcommand)]
        command: ConfluencePageInlineCommentCommand,
    },
    Verify {
        page_id: String,
        #[arg(long)]
        expect_version: Option<u64>,
        #[arg(long)]
        expect_title: Option<String>,
        #[arg(long)]
        expect_attachment_id: Option<String>,
        #[command(flatten)]
        response: WholeOutputArgs,
    },
}

#[derive(Debug, Subcommand)]
enum ConfluencePageDraftCommand {
    Create {
        #[arg(long)]
        space: String,
        #[arg(long)]
        title: String,
        #[arg(long, conflicts_with = "parent_url")]
        parent: Option<String>,
        #[arg(long)]
        parent_url: Option<String>,
        #[arg(
            long,
            required_unless_present = "content_file",
            conflicts_with = "content_file"
        )]
        content: Option<String>,
        #[arg(
            long,
            required_unless_present = "content",
            conflicts_with = "content",
            help = NORMALIZED_CONTENT_FILE_HELP
        )]
        content_file: Option<PathBuf>,
        #[arg(long, value_enum)]
        content_format: ConfluenceContentFormatArg,
    },
    Stage {
        page_id: String,
        #[arg(long)]
        base_version: u64,
        #[arg(long)]
        title: Option<String>,
        #[arg(
            long,
            required_unless_present = "content_file",
            conflicts_with = "content_file"
        )]
        content: Option<String>,
        #[arg(
            long,
            required_unless_present = "content",
            conflicts_with = "content",
            help = NORMALIZED_CONTENT_FILE_HELP
        )]
        content_file: Option<PathBuf>,
        #[arg(long, value_enum)]
        content_format: ConfluenceContentFormatArg,
    },
    View {
        page_id: String,
        #[arg(long)]
        draft_handle: String,
        #[arg(long)]
        body_format: String,
        #[command(flatten)]
        response: EmbeddedAndWholeOutputArgs,
    },
    Update {
        page_id: String,
        #[arg(long)]
        draft_handle: String,
        #[arg(long)]
        title: Option<String>,
        #[arg(
            long,
            required_unless_present = "content_file",
            conflicts_with = "content_file"
        )]
        content: Option<String>,
        #[arg(
            long,
            required_unless_present = "content",
            conflicts_with = "content",
            help = NORMALIZED_CONTENT_FILE_HELP
        )]
        content_file: Option<PathBuf>,
        #[arg(long, value_enum)]
        content_format: ConfluenceContentFormatArg,
    },
    Publish {
        page_id: String,
        #[arg(long)]
        draft_handle: String,
        #[arg(long)]
        body_format: String,
    },
    Discard {
        page_id: String,
        #[arg(long)]
        draft_handle: String,
    },
    Verify {
        page_id: String,
        #[arg(long)]
        draft_handle: String,
        #[arg(long)]
        expect_version: Option<u64>,
        #[arg(long)]
        expect_title: Option<String>,
        #[arg(long)]
        expect_attachment_id: Option<String>,
        #[command(flatten)]
        response: WholeOutputArgs,
    },
    Attach {
        page_id: String,
        #[arg(long)]
        draft_handle: String,
        #[arg(required = true)]
        files: Vec<PathBuf>,
        #[arg(long)]
        content_type: Option<String>,
    },
    Attachment {
        #[command(subcommand)]
        command: ConfluencePageDraftAttachmentCommand,
    },
}

#[derive(Debug, Subcommand)]
enum ConfluencePageDraftAttachmentCommand {
    List {
        page_id: String,
        #[arg(long)]
        draft_handle: String,
        #[arg(long)]
        max_results: Option<u32>,
        #[arg(long)]
        next_page_token: Option<String>,
        #[command(flatten)]
        response: WholeOutputArgs,
    },
    Download {
        page_id: String,
        #[arg(long)]
        draft_handle: String,
        #[arg(long)]
        attachment_id: String,
    },
}

#[derive(Debug, Subcommand)]
enum ConfluenceAttachmentCommand {
    List {
        page_id: Option<String>,
        #[arg(long)]
        page_url: Option<String>,
        #[arg(long)]
        max_results: Option<u32>,
        #[arg(long)]
        next_page_token: Option<String>,
        #[command(flatten)]
        response: WholeOutputArgs,
    },
    Download {
        page_id: String,
        #[arg(long)]
        attachment_id: String,
    },
}

#[derive(Debug, Subcommand)]
enum ConfluencePageCommentCommand {
    List {
        page_id: String,
        #[arg(long)]
        body_format: Option<String>,
        #[arg(long)]
        sort: Option<String>,
        #[arg(long)]
        max_results: Option<u32>,
        #[arg(long)]
        next_page_token: Option<String>,
        #[command(flatten)]
        response: EmbeddedAndWholeOutputArgs,
    },
    View {
        comment_id: String,
        #[arg(long)]
        body_format: Option<String>,
        #[command(flatten)]
        response: EmbeddedAndWholeOutputArgs,
    },
    Add {
        page_id: String,
        #[arg(
            long,
            required_unless_present = "content_file",
            conflicts_with = "content_file"
        )]
        content: Option<String>,
        #[arg(
            long,
            required_unless_present = "content",
            conflicts_with = "content",
            help = NORMALIZED_CONTENT_FILE_HELP
        )]
        content_file: Option<PathBuf>,
        #[arg(long, value_enum)]
        content_format: ConfluenceContentFormatArg,
        #[command(flatten)]
        response: EmbeddedOutputArgs,
    },
    Update {
        comment_id: String,
        #[arg(long)]
        base_version: u64,
        #[arg(
            long,
            required_unless_present = "content_file",
            conflicts_with = "content_file"
        )]
        content: Option<String>,
        #[arg(
            long,
            required_unless_present = "content",
            conflicts_with = "content",
            help = NORMALIZED_CONTENT_FILE_HELP
        )]
        content_file: Option<PathBuf>,
        #[arg(long, value_enum)]
        content_format: ConfluenceContentFormatArg,
        #[command(flatten)]
        response: EmbeddedOutputArgs,
    },
    Delete {
        comment_id: String,
    },
    Replies {
        comment_id: String,
        #[arg(long)]
        body_format: Option<String>,
        #[arg(long)]
        max_results: Option<u32>,
        #[arg(long)]
        next_page_token: Option<String>,
        #[command(flatten)]
        response: EmbeddedAndWholeOutputArgs,
    },
    Reply {
        comment_id: String,
        #[arg(
            long,
            required_unless_present = "content_file",
            conflicts_with = "content_file"
        )]
        content: Option<String>,
        #[arg(
            long,
            required_unless_present = "content",
            conflicts_with = "content",
            help = NORMALIZED_CONTENT_FILE_HELP
        )]
        content_file: Option<PathBuf>,
        #[arg(long, value_enum)]
        content_format: ConfluenceContentFormatArg,
        #[command(flatten)]
        response: EmbeddedOutputArgs,
    },
}

#[derive(Debug, Subcommand)]
enum ConfluencePageInlineCommentCommand {
    List {
        page_id: String,
        #[arg(long)]
        body_format: Option<String>,
        #[arg(long)]
        resolution_status: Option<String>,
        #[arg(long)]
        sort: Option<String>,
        #[arg(long)]
        max_results: Option<u32>,
        #[arg(long)]
        next_page_token: Option<String>,
        #[command(flatten)]
        response: EmbeddedAndWholeOutputArgs,
    },
    View {
        comment_id: String,
        #[arg(long)]
        body_format: Option<String>,
        #[command(flatten)]
        response: EmbeddedAndWholeOutputArgs,
    },
    Update {
        comment_id: String,
        #[arg(long)]
        base_version: u64,
        #[arg(
            long,
            required_unless_present = "content_file",
            conflicts_with = "content_file"
        )]
        content: Option<String>,
        #[arg(
            long,
            required_unless_present = "content",
            conflicts_with = "content",
            help = NORMALIZED_CONTENT_FILE_HELP
        )]
        content_file: Option<PathBuf>,
        #[arg(long, value_enum)]
        content_format: ConfluenceContentFormatArg,
        #[command(flatten)]
        response: EmbeddedOutputArgs,
    },
    Delete {
        comment_id: String,
    },
    Replies {
        comment_id: String,
        #[arg(long)]
        body_format: Option<String>,
        #[arg(long)]
        max_results: Option<u32>,
        #[arg(long)]
        next_page_token: Option<String>,
        #[command(flatten)]
        response: EmbeddedAndWholeOutputArgs,
    },
    Reply {
        comment_id: String,
        #[arg(
            long,
            required_unless_present = "content_file",
            conflicts_with = "content_file"
        )]
        content: Option<String>,
        #[arg(
            long,
            required_unless_present = "content",
            conflicts_with = "content",
            help = NORMALIZED_CONTENT_FILE_HELP
        )]
        content_file: Option<PathBuf>,
        #[arg(long, value_enum)]
        content_format: ConfluenceContentFormatArg,
        #[command(flatten)]
        response: EmbeddedOutputArgs,
    },
}

#[derive(Debug, Subcommand)]
enum ConfluenceBlogCommand {
    View {
        blog_id: Option<String>,
        #[arg(long)]
        blog_url: Option<String>,
        #[command(flatten)]
        response: EmbeddedAndWholeOutputArgs,
    },
    Search {
        /// CQL filter and/or ordering; empty browses the authorized content scope.
        #[arg(long)]
        cql: Option<String>,
        #[arg(long)]
        text: Option<String>,
        /// Optional space narrowing; omission uses effective broker authorization.
        #[arg(long = "space")]
        spaces: Vec<String>,
        #[arg(long)]
        max_results: Option<u32>,
        #[arg(long)]
        next_page_token: Option<String>,
        #[command(flatten)]
        response: WholeOutputArgs,
    },
    Create {
        #[arg(long)]
        space: String,
        #[arg(long)]
        title: String,
        #[arg(
            long,
            required_unless_present = "content_file",
            conflicts_with = "content_file"
        )]
        content: Option<String>,
        #[arg(
            long,
            required_unless_present = "content",
            conflicts_with = "content",
            help = NORMALIZED_CONTENT_FILE_HELP
        )]
        content_file: Option<PathBuf>,
        #[arg(long, value_enum)]
        content_format: ConfluenceContentFormatArg,
    },
    Update {
        blog_id: String,
        #[arg(long)]
        base_version: u64,
        #[arg(long)]
        title: Option<String>,
        #[arg(
            long,
            required_unless_present = "content_file",
            conflicts_with = "content_file"
        )]
        content: Option<String>,
        #[arg(
            long,
            required_unless_present = "content",
            conflicts_with = "content",
            help = NORMALIZED_CONTENT_FILE_HELP
        )]
        content_file: Option<PathBuf>,
        #[arg(long, value_enum)]
        content_format: ConfluenceContentFormatArg,
        #[arg(long)]
        version_message: Option<String>,
    },
    Attach {
        blog_id: String,
        #[arg(required = true)]
        files: Vec<PathBuf>,
        #[arg(long)]
        content_type: Option<String>,
    },
    Attachment {
        #[command(subcommand)]
        command: ConfluenceBlogAttachmentCommand,
    },
    Draft {
        #[command(subcommand)]
        command: ConfluenceBlogDraftCommand,
    },
    FooterComment {
        #[command(subcommand)]
        command: ConfluenceBlogCommentCommand,
    },
    InlineComment {
        #[command(subcommand)]
        command: ConfluenceBlogInlineCommentCommand,
    },
    Verify {
        blog_id: String,
        #[arg(long)]
        expect_version: Option<u64>,
        #[arg(long)]
        expect_title: Option<String>,
        #[arg(long)]
        expect_attachment_id: Option<String>,
        #[command(flatten)]
        response: WholeOutputArgs,
    },
}

#[derive(Debug, Subcommand)]
enum ConfluenceBlogDraftCommand {
    Create {
        #[arg(long)]
        space: String,
        #[arg(long)]
        title: String,
        #[arg(
            long,
            required_unless_present = "content_file",
            conflicts_with = "content_file"
        )]
        content: Option<String>,
        #[arg(
            long,
            required_unless_present = "content",
            conflicts_with = "content",
            help = NORMALIZED_CONTENT_FILE_HELP
        )]
        content_file: Option<PathBuf>,
        #[arg(long, value_enum)]
        content_format: ConfluenceContentFormatArg,
    },
    Stage {
        blog_id: String,
        #[arg(long)]
        base_version: u64,
        #[arg(long)]
        title: Option<String>,
        #[arg(
            long,
            required_unless_present = "content_file",
            conflicts_with = "content_file"
        )]
        content: Option<String>,
        #[arg(
            long,
            required_unless_present = "content",
            conflicts_with = "content",
            help = NORMALIZED_CONTENT_FILE_HELP
        )]
        content_file: Option<PathBuf>,
        #[arg(long, value_enum)]
        content_format: ConfluenceContentFormatArg,
    },
    View {
        blog_id: String,
        #[arg(long)]
        draft_handle: String,
        #[arg(long)]
        body_format: String,
        #[command(flatten)]
        response: EmbeddedAndWholeOutputArgs,
    },
    Update {
        blog_id: String,
        #[arg(long)]
        draft_handle: String,
        #[arg(long)]
        title: Option<String>,
        #[arg(
            long,
            required_unless_present = "content_file",
            conflicts_with = "content_file"
        )]
        content: Option<String>,
        #[arg(
            long,
            required_unless_present = "content",
            conflicts_with = "content",
            help = NORMALIZED_CONTENT_FILE_HELP
        )]
        content_file: Option<PathBuf>,
        #[arg(long, value_enum)]
        content_format: ConfluenceContentFormatArg,
    },
    Publish {
        blog_id: String,
        #[arg(long)]
        draft_handle: String,
        #[arg(long)]
        body_format: String,
    },
    Discard {
        blog_id: String,
        #[arg(long)]
        draft_handle: String,
    },
    Verify {
        blog_id: String,
        #[arg(long)]
        draft_handle: String,
        #[arg(long)]
        expect_version: Option<u64>,
        #[arg(long)]
        expect_title: Option<String>,
        #[arg(long)]
        expect_attachment_id: Option<String>,
        #[command(flatten)]
        response: WholeOutputArgs,
    },
    Attach {
        blog_id: String,
        #[arg(long)]
        draft_handle: String,
        #[arg(required = true)]
        files: Vec<PathBuf>,
        #[arg(long)]
        content_type: Option<String>,
    },
    Attachment {
        #[command(subcommand)]
        command: ConfluenceBlogDraftAttachmentCommand,
    },
}

#[derive(Debug, Subcommand)]
enum ConfluenceBlogDraftAttachmentCommand {
    List {
        blog_id: String,
        #[arg(long)]
        draft_handle: String,
        #[arg(long)]
        max_results: Option<u32>,
        #[arg(long)]
        next_page_token: Option<String>,
        #[command(flatten)]
        response: WholeOutputArgs,
    },
    Download {
        blog_id: String,
        #[arg(long)]
        draft_handle: String,
        #[arg(long)]
        attachment_id: String,
    },
}

#[derive(Debug, Subcommand)]
enum ConfluenceBlogAttachmentCommand {
    List {
        blog_id: Option<String>,
        #[arg(long)]
        blog_url: Option<String>,
        #[arg(long)]
        max_results: Option<u32>,
        #[arg(long)]
        next_page_token: Option<String>,
        #[command(flatten)]
        response: WholeOutputArgs,
    },
    Download {
        blog_id: String,
        #[arg(long)]
        attachment_id: String,
    },
}

#[derive(Debug, Subcommand)]
enum ConfluenceBlogCommentCommand {
    List {
        blog_id: String,
        #[arg(long)]
        body_format: Option<String>,
        #[arg(long)]
        sort: Option<String>,
        #[arg(long)]
        max_results: Option<u32>,
        #[arg(long)]
        next_page_token: Option<String>,
        #[command(flatten)]
        response: EmbeddedAndWholeOutputArgs,
    },
    View {
        comment_id: String,
        #[arg(long)]
        body_format: Option<String>,
        #[command(flatten)]
        response: EmbeddedAndWholeOutputArgs,
    },
    Add {
        blog_id: String,
        #[arg(
            long,
            required_unless_present = "content_file",
            conflicts_with = "content_file"
        )]
        content: Option<String>,
        #[arg(
            long,
            required_unless_present = "content",
            conflicts_with = "content",
            help = NORMALIZED_CONTENT_FILE_HELP
        )]
        content_file: Option<PathBuf>,
        #[arg(long, value_enum)]
        content_format: ConfluenceContentFormatArg,
        #[command(flatten)]
        response: EmbeddedOutputArgs,
    },
    Update {
        comment_id: String,
        #[arg(long)]
        base_version: u64,
        #[arg(
            long,
            required_unless_present = "content_file",
            conflicts_with = "content_file"
        )]
        content: Option<String>,
        #[arg(
            long,
            required_unless_present = "content",
            conflicts_with = "content",
            help = NORMALIZED_CONTENT_FILE_HELP
        )]
        content_file: Option<PathBuf>,
        #[arg(long, value_enum)]
        content_format: ConfluenceContentFormatArg,
        #[command(flatten)]
        response: EmbeddedOutputArgs,
    },
    Delete {
        comment_id: String,
    },
    Replies {
        comment_id: String,
        #[arg(long)]
        body_format: Option<String>,
        #[arg(long)]
        max_results: Option<u32>,
        #[arg(long)]
        next_page_token: Option<String>,
        #[command(flatten)]
        response: EmbeddedAndWholeOutputArgs,
    },
    Reply {
        comment_id: String,
        #[arg(
            long,
            required_unless_present = "content_file",
            conflicts_with = "content_file"
        )]
        content: Option<String>,
        #[arg(
            long,
            required_unless_present = "content",
            conflicts_with = "content",
            help = NORMALIZED_CONTENT_FILE_HELP
        )]
        content_file: Option<PathBuf>,
        #[arg(long, value_enum)]
        content_format: ConfluenceContentFormatArg,
        #[command(flatten)]
        response: EmbeddedOutputArgs,
    },
}

#[derive(Debug, Subcommand)]
enum ConfluenceBlogInlineCommentCommand {
    List {
        blog_id: String,
        #[arg(long)]
        body_format: Option<String>,
        #[arg(long)]
        resolution_status: Option<String>,
        #[arg(long)]
        sort: Option<String>,
        #[arg(long)]
        max_results: Option<u32>,
        #[arg(long)]
        next_page_token: Option<String>,
        #[command(flatten)]
        response: EmbeddedAndWholeOutputArgs,
    },
    View {
        comment_id: String,
        #[arg(long)]
        body_format: Option<String>,
        #[command(flatten)]
        response: EmbeddedAndWholeOutputArgs,
    },
    Update {
        comment_id: String,
        #[arg(long)]
        base_version: u64,
        #[arg(
            long,
            required_unless_present = "content_file",
            conflicts_with = "content_file"
        )]
        content: Option<String>,
        #[arg(
            long,
            required_unless_present = "content",
            conflicts_with = "content",
            help = NORMALIZED_CONTENT_FILE_HELP
        )]
        content_file: Option<PathBuf>,
        #[arg(long, value_enum)]
        content_format: ConfluenceContentFormatArg,
        #[command(flatten)]
        response: EmbeddedOutputArgs,
    },
    Delete {
        comment_id: String,
    },
    Replies {
        comment_id: String,
        #[arg(long)]
        body_format: Option<String>,
        #[arg(long)]
        max_results: Option<u32>,
        #[arg(long)]
        next_page_token: Option<String>,
        #[command(flatten)]
        response: EmbeddedAndWholeOutputArgs,
    },
    Reply {
        comment_id: String,
        #[arg(
            long,
            required_unless_present = "content_file",
            conflicts_with = "content_file"
        )]
        content: Option<String>,
        #[arg(
            long,
            required_unless_present = "content",
            conflicts_with = "content",
            help = NORMALIZED_CONTENT_FILE_HELP
        )]
        content_file: Option<PathBuf>,
        #[arg(long, value_enum)]
        content_format: ConfluenceContentFormatArg,
        #[command(flatten)]
        response: EmbeddedOutputArgs,
    },
}

#[derive(Debug, Subcommand)]
enum CloudbeesCiCommand {
    /// Read job metadata.
    Job {
        #[command(subcommand)]
        command: CloudbeesCiJobCommand,
    },
    /// Read builds, logs, tests, Pipelines, and artifacts, or trigger a build.
    Build {
        #[command(subcommand)]
        command: CloudbeesCiBuildCommand,
    },
    /// Inspect queued builds.
    Queue {
        #[command(subcommand)]
        command: CloudbeesCiQueueCommand,
    },
}

#[derive(Subcommand, Debug)]
enum TeamsCommand {
    Notification {
        #[command(subcommand)]
        command: TeamsNotificationCommand,
    },
}

#[derive(Debug, Subcommand)]
enum TeamsNotificationCommand {
    /// Acceptance confirms only that the Workflow endpoint accepted the request.
    Send {
        destination: String,
        #[arg(
            long,
            required_unless_present = "content_file",
            conflicts_with = "content_file"
        )]
        text: Option<String>,
        #[arg(long, requires = "text", conflicts_with = "content_file")]
        title: Option<String>,
        /// Full Microsoft Adaptive Card envelope or MessageCard JSON file.
        #[arg(long, conflicts_with_all = ["text", "title"])]
        content_file: Option<PathBuf>,
    },
}

fn teams_invocation(command: &TeamsCommand) -> serde_json::Value {
    let TeamsCommand::Notification {
        command:
            TeamsNotificationCommand::Send {
                destination,
                text,
                title,
                content_file,
            },
    } = command;
    let (format, content) = if let Some(path) = content_file {
        ("microsoft", read_json_file(path))
    } else {
        let mut content = serde_json::json!({"text":text.as_deref().expect("clap requires text")});
        if let Some(title) = title {
            content["title"] = serde_json::json!(title);
        }
        ("simple", content)
    };
    serde_json::json!({"destination":destination,"contentFormat":format,"content":content})
}

#[derive(Debug, Subcommand)]
enum GmailCommand {
    /// Connected mailbox profile.
    Account,
    /// List mailbox labels.
    Labels,
    Message {
        #[command(subcommand)]
        command: GmailMessageCommand,
    },
    Thread {
        #[command(subcommand)]
        command: GmailThreadCommand,
    },
}
#[derive(Subcommand, Debug)]
enum GmailMessageCommand {
    Search {
        #[arg(long)]
        query: Option<String>,
        #[arg(long, default_value_t = 20)]
        max_results: u32,
        #[arg(long)]
        page_token: Option<String>,
        #[arg(long)]
        include_spam_trash: bool,
    },
    View {
        id: String,
    },
    Archive {
        id: String,
    },
    Trash {
        id: String,
    },
    Restore {
        id: String,
    },
}
#[derive(Subcommand, Debug)]
enum GmailThreadCommand {
    View { id: String },
    Archive { id: String },
    Trash { id: String },
    Restore { id: String },
}
fn gmail_invocation(command: &GmailCommand) -> (&'static str, serde_json::Value) {
    use GmailMessageCommand as M;
    use GmailThreadCommand as T;
    let (action, id) = match command {
        GmailCommand::Account => return ("gmail.account.view", serde_json::json!({})),
        GmailCommand::Labels => return ("gmail.label.list", serde_json::json!({})),
        GmailCommand::Message {
            command:
                M::Search {
                    query,
                    max_results,
                    page_token,
                    include_spam_trash,
                },
        } => {
            let mut inputs =
                serde_json::json!({"maxResults":max_results,"includeSpamTrash":include_spam_trash});
            if let Some(query) = query {
                inputs["query"] = query.as_str().into();
            }
            if let Some(token) = page_token {
                inputs["pageToken"] = token.as_str().into();
            }
            return ("gmail.message.search", inputs);
        }
        GmailCommand::Message { command } => match command {
            M::View { id } => ("gmail.message.view", id),
            M::Archive { id } => ("gmail.message.archive", id),
            M::Trash { id } => ("gmail.message.trash", id),
            M::Restore { id } => ("gmail.message.restore", id),
            M::Search { .. } => unreachable!(),
        },
        GmailCommand::Thread { command } => match command {
            T::View { id } => ("gmail.thread.view", id),
            T::Archive { id } => ("gmail.thread.archive", id),
            T::Trash { id } => ("gmail.thread.trash", id),
            T::Restore { id } => ("gmail.thread.restore", id),
        },
    };
    (action, serde_json::json!({"id":id}))
}

#[derive(Debug, Subcommand)]
enum OAuthStubCommand {
    Record {
        #[command(subcommand)]
        command: OAuthStubRecordCommand,
    },
    /// Read the connected account identity.
    Account,
}

#[derive(Debug, Subcommand)]
enum OAuthStubRecordCommand {
    List {
        #[arg(long)]
        collection: String,
    },
    View {
        id: String,
        #[arg(long)]
        collection: String,
    },
}

/// Jenkins permalinks `--build-selector` accepts.
const CLOUDBEES_CI_BUILD_SELECTORS: [&str; 7] = [
    "lastBuild",
    "lastCompletedBuild",
    "lastFailedBuild",
    "lastSuccessfulBuild",
    "lastStableBuild",
    "lastUnstableBuild",
    "lastUnsuccessfulBuild",
];

/// A job, by controller alias and full name or by a Jenkins URL. The URL
/// flag is `--job-url` because `--url` selects the broker.
#[derive(Debug, Args)]
struct CloudbeesCiJobArgs {
    /// Configured controller alias: the first segment of a cloudbees_ci_job resource value (see resource-access describe inputs or coverage).
    #[arg(required_unless_present = "job_url")]
    controller: Option<String>,
    /// Jenkins full name below the controller, such as payments/build-api; not a display name or URL.
    #[arg(required_unless_present = "job_url")]
    job: Option<String>,
    /// Jenkins job or build URL on a configured controller, instead of CONTROLLER and JOB; sent as the url input. Parsed, never fetched; give any build in the URL or with --build-selector.
    #[arg(long, conflicts_with_all = ["controller", "job"])]
    job_url: Option<String>,
}

impl CloudbeesCiJobArgs {
    fn inputs(&self) -> serde_json::Map<String, serde_json::Value> {
        [
            ("controller", &self.controller),
            ("job", &self.job),
            ("url", &self.job_url),
        ]
        .into_iter()
        .filter_map(|(name, value)| Some((name.to_owned(), serde_json::json!(value.as_ref()?))))
        .collect()
    }
}

/// One build of a job: a number, a permalink, or the build in `--job-url`.
#[derive(Debug, Args)]
struct CloudbeesCiBuildArgs {
    #[command(flatten)]
    job: CloudbeesCiJobArgs,
    /// Build number. Alternatively pass --build-selector, or a build URL with --job-url.
    #[arg(
        required_unless_present_any = ["build_selector", "job_url"],
        conflicts_with = "build_selector"
    )]
    build_number: Option<u64>,
    /// Jenkins permalink resolved to a build number after authorization, such as lastFailedBuild. Results report the resolved buildNumber.
    #[arg(long, value_parser = clap::builder::PossibleValuesParser::new(CLOUDBEES_CI_BUILD_SELECTORS))]
    build_selector: Option<String>,
}

impl CloudbeesCiBuildArgs {
    fn inputs(&self) -> serde_json::Map<String, serde_json::Value> {
        let mut inputs = self.job.inputs();
        if let Some(number) = self.build_number {
            inputs.insert("buildNumber".into(), serde_json::json!(number));
        }
        if let Some(selector) = &self.build_selector {
            inputs.insert("buildSelector".into(), serde_json::json!(selector));
        }
        inputs
    }
}

#[derive(Debug, Subcommand)]
enum CloudbeesCiJobCommand {
    /// Recursively list live jobs and folders within effective grants (one JSON page).
    List {
        /// Configured controller alias.
        controller: String,
        /// Canonical folder path below the controller; defaults to its root.
        #[arg(long)]
        folder: Option<String>,
        #[arg(long)]
        max_results: Option<u32>,
        #[arg(long)]
        page_token: Option<String>,
    },
    /// Read a job's metadata, recent builds, and queue state.
    View {
        #[command(flatten)]
        job: CloudbeesCiJobArgs,
        #[command(flatten)]
        response: WholeOutputArgs,
    },
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum CloudbeesCiLogMode {
    Head,
    Tail,
    Search,
}

impl CloudbeesCiLogMode {
    fn as_str(self) -> &'static str {
        match self {
            Self::Head => "head",
            Self::Tail => "tail",
            Self::Search => "search",
        }
    }
}

#[derive(Debug, Subcommand)]
enum CloudbeesCiBuildCommand {
    /// Read Pipeline stages and steps of a build.
    Pipeline {
        #[command(subcommand)]
        command: CloudbeesCiPipelineCommand,
    },
    /// Download the full console text currently available for a build.
    LogDownload {
        #[command(flatten)]
        build: CloudbeesCiBuildArgs,
    },
    /// Read detailed test cases, including failure messages and captured output.
    TestsDetails {
        #[command(flatten)]
        build: CloudbeesCiBuildArgs,
        /// Most test cases to return.
        #[arg(long)]
        max_results: Option<u32>,
        #[command(flatten)]
        response: WholeOutputArgs,
    },
    /// Download the detailed test report as JSON.
    TestsDownload {
        #[command(flatten)]
        build: CloudbeesCiBuildArgs,
    },
    /// Read pending Pipeline input prompts.
    PendingInputs {
        #[command(flatten)]
        build: CloudbeesCiBuildArgs,
        #[command(flatten)]
        response: WholeOutputArgs,
    },
    /// List or download a build's archived artifacts.
    Artifact {
        #[command(subcommand)]
        command: CloudbeesCiBuildArtifactCommand,
    },
    /// List a job's recent builds.
    List {
        #[command(flatten)]
        job: CloudbeesCiJobArgs,
        /// Most builds to return.
        #[arg(long)]
        max_results: Option<u32>,
        #[command(flatten)]
        response: WholeOutputArgs,
    },
    /// Read one build's status, causes, and parameters.
    View {
        #[command(flatten)]
        build: CloudbeesCiBuildArgs,
        #[command(flatten)]
        response: WholeOutputArgs,
    },
    /// Read a bounded beginning, ending, or literal-search excerpt of a build log.
    Log {
        #[command(flatten)]
        build: CloudbeesCiBuildArgs,
        /// Excerpt mode (defaults to tail). All modes obey the provider scan budget.
        #[arg(long, value_enum)]
        mode: Option<CloudbeesCiLogMode>,
        /// Continue a head/search read with the same query and output settings; pass the returned BUILD_NUMBER, not --build-selector.
        #[arg(long)]
        cursor: Option<String>,
        /// Case-sensitive literal to find in search mode (at most 256 UTF-8 bytes).
        #[arg(long)]
        query: Option<String>,
        /// Search-only match limit (defaults to 20).
        #[arg(long, value_parser = clap::value_parser!(u32).range(1..=100))]
        max_matches: Option<u32>,
        /// Returned text budget (defaults to 16384 bytes); does not raise the scan budget.
        #[arg(long, value_parser = clap::value_parser!(u64).range(1024..=65536))]
        max_bytes: Option<u64>,
        #[command(flatten)]
        response: WholeOutputArgs,
    },
    /// Read a build's test report summary.
    Tests {
        #[command(flatten)]
        build: CloudbeesCiBuildArgs,
        #[command(flatten)]
        response: WholeOutputArgs,
    },
    /// Queue a parameterless build; do not retry an unverified trigger.
    Trigger {
        #[command(flatten)]
        job: CloudbeesCiJobArgs,
        #[command(flatten)]
        response: WholeOutputArgs,
    },
}

#[derive(Debug, Subcommand)]
enum CloudbeesCiPipelineCommand {
    /// Read a build's Pipeline stages.
    View {
        #[command(flatten)]
        build: CloudbeesCiBuildArgs,
        #[command(flatten)]
        response: WholeOutputArgs,
    },
    /// Read one Pipeline node and its steps.
    Node {
        #[command(flatten)]
        build: CloudbeesCiBuildArgs,
        /// Pipeline node ID from build pipeline view.
        #[arg(long)]
        node_id: String,
        #[command(flatten)]
        response: WholeOutputArgs,
    },
    /// Read one Pipeline node's log.
    Log {
        #[command(flatten)]
        build: CloudbeesCiBuildArgs,
        /// Pipeline node ID from build pipeline view.
        #[arg(long)]
        node_id: String,
        #[command(flatten)]
        response: WholeOutputArgs,
    },
}

#[derive(Debug, Subcommand)]
enum CloudbeesCiBuildArtifactCommand {
    /// List a build's archived artifacts.
    List {
        #[command(flatten)]
        build: CloudbeesCiBuildArgs,
        #[command(flatten)]
        response: WholeOutputArgs,
    },
    /// Download one archived artifact; requires --output.
    Download {
        #[command(flatten)]
        build: CloudbeesCiBuildArgs,
        /// Artifact relative path from build artifact list, such as reports/results.zip.
        #[arg(long)]
        artifact_path: String,
    },
}

#[derive(Debug, Subcommand)]
enum CloudbeesCiQueueCommand {
    /// Read a queue item the job's trigger returned.
    View {
        #[command(flatten)]
        job: CloudbeesCiJobArgs,
        /// Queue item ID from build trigger.
        #[arg(long)]
        queue_id: u64,
        #[command(flatten)]
        response: WholeOutputArgs,
    },
}

#[derive(Debug, Subcommand)]
enum GitlabCommand {
    /// Search native GitLab content across authorized repositories or one project.
    Search {
        #[command(subcommand)]
        command: gitlab_search::SearchCommand,
    },
    ServiceAccount {
        #[command(subcommand)]
        command: gitlab_provisioning::ServiceAccountCommand,
    },
    Project {
        #[command(subcommand)]
        command: GitlabProjectCommand,
    },
    Issue {
        #[command(subcommand)]
        command: GitlabIssueCommand,
    },
    MergeRequest {
        #[command(subcommand)]
        command: GitlabMergeRequestCommand,
    },
    Branch {
        #[command(subcommand)]
        command: GitlabBranchCommand,
    },
    ProtectedBranch {
        #[command(subcommand)]
        command: GitlabProtectedBranchCommand,
    },
    File {
        #[command(subcommand)]
        command: GitlabFileCommand,
    },
    Commit {
        #[command(subcommand)]
        command: GitlabCommitCommand,
    },
    Pipeline {
        #[command(subcommand)]
        command: GitlabPipelineCommand,
    },
    Job {
        #[command(subcommand)]
        command: GitlabJobCommand,
    },
    Webhook {
        #[command(subcommand)]
        command: GitlabWebhookCommand,
    },
}

#[derive(Debug, Subcommand)]
enum GitlabProjectCommand {
    /// List live projects within effective repository grants, one page per call.
    List(gitlab_search::ProjectListArgs),
    /// Discover or browse authorized repositories by name, path, or description.
    Search(gitlab_search::ProjectSearchArgs),
    AccessToken {
        #[command(subcommand)]
        command: gitlab_provisioning::ProjectTokenCommand,
    },
    Upload {
        #[arg(
            required_unless_present = "project_url",
            conflicts_with = "project_url"
        )]
        project: Option<String>,
        #[arg(long)]
        project_url: Option<String>,
        #[arg(long)]
        file: PathBuf,
        #[arg(long)]
        content_type: Option<String>,
    },
    View {
        project: Option<String>,
        #[arg(long)]
        project_url: Option<String>,
        #[command(flatten)]
        response: WholeOutputArgs,
    },
}

#[derive(Debug, Subcommand)]
#[allow(clippy::large_enum_variant)]
enum GitlabIssueCommand {
    View {
        project: Option<String>,
        iid: Option<u64>,
        #[arg(long)]
        issue_url: Option<String>,
        #[command(flatten)]
        response: EmbeddedAndWholeOutputArgs,
    },
    /// List and filter issues within one required project.
    Search {
        project: String,
        #[arg(long)]
        state: Option<String>,
        #[arg(long = "label")]
        labels: Vec<String>,
        #[arg(long)]
        milestone: Option<String>,
        #[arg(long)]
        assignee: Option<String>,
        #[arg(long)]
        author: Option<String>,
        #[arg(long)]
        search: Option<String>,
        #[arg(long)]
        created_after: Option<String>,
        #[arg(long)]
        updated_after: Option<String>,
        #[arg(long)]
        sort: Option<String>,
        #[arg(long)]
        order_by: Option<String>,
        #[arg(long)]
        max_results: Option<u32>,
        #[arg(long)]
        page_token: Option<String>,
        #[command(flatten)]
        response: EmbeddedAndWholeOutputArgs,
    },
    Create {
        project: String,
        #[arg(long)]
        title: String,
        #[arg(long, group = "content_source", requires = "content_format")]
        content: Option<String>,
        #[arg(long, group = "content_source", requires = "content_format", help = NORMALIZED_CONTENT_FILE_HELP)]
        content_file: Option<PathBuf>,
        #[arg(long, value_enum, requires = "content_source")]
        content_format: Option<GitlabContentFormatArg>,
        #[arg(long = "label")]
        labels: Vec<String>,
        #[arg(long)]
        milestone: Option<String>,
        #[arg(long = "assignee-id")]
        assignee_ids: Vec<u64>,
        #[arg(long)]
        confidential: Option<bool>,
        #[command(flatten)]
        response: EmbeddedOutputArgs,
    },
    Update {
        project: String,
        iid: u64,
        #[arg(long)]
        title: Option<String>,
        #[arg(long, group = "content_source", requires = "content_format")]
        content: Option<String>,
        #[arg(long, group = "content_source", requires = "content_format", help = NORMALIZED_CONTENT_FILE_HELP)]
        content_file: Option<PathBuf>,
        #[arg(long, value_enum, requires = "content_source")]
        content_format: Option<GitlabContentFormatArg>,
        #[arg(long)]
        state_event: Option<String>,
        #[arg(long = "label")]
        labels: Vec<String>,
        #[arg(long = "add-label")]
        add_labels: Vec<String>,
        #[arg(long = "remove-label")]
        remove_labels: Vec<String>,
        #[arg(long)]
        milestone: Option<String>,
        #[arg(long = "assignee-id")]
        assignee_ids: Vec<u64>,
        #[arg(long)]
        confidential: Option<bool>,
        #[command(flatten)]
        response: EmbeddedOutputArgs,
    },
    Comment {
        project: String,
        iid: u64,
        #[arg(
            long,
            group = "content_source",
            requires = "content_format",
            required_unless_present = "content_file"
        )]
        content: Option<String>,
        #[arg(long, group = "content_source", requires = "content_format", required_unless_present = "content", help = NORMALIZED_CONTENT_FILE_HELP)]
        content_file: Option<PathBuf>,
        #[arg(long, value_enum, requires = "content_source")]
        content_format: Option<GitlabContentFormatArg>,
        #[arg(long)]
        confidential: Option<bool>,
        #[command(flatten)]
        response: EmbeddedOutputArgs,
    },
    UpdateComment {
        project: String,
        iid: u64,
        note_id: u64,
        #[arg(
            long,
            group = "content_source",
            requires = "content_format",
            required_unless_present = "content_file"
        )]
        content: Option<String>,
        #[arg(long, group = "content_source", requires = "content_format", required_unless_present = "content", help = NORMALIZED_CONTENT_FILE_HELP)]
        content_file: Option<PathBuf>,
        #[arg(long, value_enum, requires = "content_source")]
        content_format: Option<GitlabContentFormatArg>,
        #[command(flatten)]
        response: EmbeddedOutputArgs,
    },
    DeleteComment {
        project: String,
        iid: u64,
        note_id: u64,
    },
    ViewComment {
        project: String,
        iid: u64,
        note_id: u64,
        #[command(flatten)]
        response: EmbeddedAndWholeOutputArgs,
    },
    ListComments {
        project: String,
        iid: u64,
        #[arg(long)]
        max_results: Option<u32>,
        #[arg(long)]
        sort: Option<String>,
        #[arg(long)]
        order_by: Option<String>,
        #[arg(long)]
        page_token: Option<String>,
        #[arg(long, value_enum, default_value = "full")]
        projection: GitlabProjectionArg,
        #[command(flatten)]
        response: EmbeddedAndWholeOutputArgs,
    },
}

#[derive(Debug, Subcommand)]
#[allow(clippy::large_enum_variant)]
enum GitlabMergeRequestCommand {
    View {
        project: Option<String>,
        iid: Option<u64>,
        #[arg(long)]
        merge_request_url: Option<String>,
        #[command(flatten)]
        response: EmbeddedAndWholeOutputArgs,
    },
    /// List and filter merge requests within one required project.
    Search {
        project: String,
        #[arg(long)]
        state: Option<String>,
        #[arg(long)]
        source_branch: Option<String>,
        #[arg(long)]
        target_branch: Option<String>,
        #[arg(long = "label")]
        labels: Vec<String>,
        #[arg(long)]
        milestone: Option<String>,
        #[arg(long)]
        assignee: Option<String>,
        #[arg(long)]
        author: Option<String>,
        #[arg(long)]
        reviewer: Option<String>,
        #[arg(long)]
        search: Option<String>,
        #[arg(long)]
        created_after: Option<String>,
        #[arg(long)]
        updated_after: Option<String>,
        #[arg(long)]
        sort: Option<String>,
        #[arg(long)]
        order_by: Option<String>,
        #[arg(long)]
        max_results: Option<u32>,
        #[arg(long)]
        page_token: Option<String>,
        #[command(flatten)]
        response: EmbeddedAndWholeOutputArgs,
    },
    ListReviewers {
        project: String,
        iid: u64,
        #[arg(long)]
        max_results: Option<u32>,
        #[arg(long)]
        page_token: Option<String>,
        #[command(flatten)]
        response: WholeOutputArgs,
    },
    ListCommits {
        project: String,
        iid: u64,
        #[arg(long)]
        max_results: Option<u32>,
        #[arg(long)]
        page_token: Option<String>,
        #[command(flatten)]
        response: WholeOutputArgs,
    },
    ListPipelines {
        project: String,
        iid: u64,
        #[arg(long)]
        max_results: Option<u32>,
        #[arg(long)]
        page_token: Option<String>,
        #[command(flatten)]
        response: WholeOutputArgs,
    },
    ListDiffs {
        project: String,
        iid: u64,
        #[arg(long)]
        unidiff: bool,
        #[arg(long)]
        max_results: Option<u32>,
        #[arg(long)]
        page_token: Option<String>,
        #[command(flatten)]
        response: WholeOutputArgs,
    },
    DiffRaw {
        project: String,
        iid: u64,
    },
    ListDiffVersions {
        project: String,
        iid: u64,
        #[arg(long)]
        max_results: Option<u32>,
        #[arg(long)]
        page_token: Option<String>,
        #[command(flatten)]
        response: WholeOutputArgs,
    },
    ViewDiffVersion {
        project: String,
        iid: u64,
        version_id: u64,
        #[arg(long)]
        unidiff: bool,
        #[command(flatten)]
        response: WholeOutputArgs,
    },
    ViewDiscussion {
        project: String,
        iid: u64,
        discussion_id: String,
        #[command(flatten)]
        response: EmbeddedAndWholeOutputArgs,
    },
    InlineDiscussion {
        project: String,
        iid: u64,
        #[arg(long, requires = "position_source")]
        expected_head_sha: String,
        #[command(flatten)]
        position: GitlabPositionArgs,
        #[command(flatten)]
        body: GitlabRequiredContentArgs,
        #[command(flatten)]
        response: EmbeddedOutputArgs,
    },
    ReplyDiscussion {
        project: String,
        iid: u64,
        discussion_id: String,
        #[command(flatten)]
        body: GitlabRequiredContentArgs,
        #[command(flatten)]
        response: EmbeddedOutputArgs,
    },
    ListDraftNotes {
        project: String,
        iid: u64,
        #[arg(long)]
        max_results: Option<u32>,
        #[arg(long)]
        page_token: Option<String>,
        #[arg(long, value_enum, default_value = "full")]
        projection: GitlabProjectionArg,
        #[command(flatten)]
        response: EmbeddedAndWholeOutputArgs,
    },
    ViewDraftNote {
        project: String,
        iid: u64,
        draft_note_id: u64,
        #[command(flatten)]
        response: EmbeddedAndWholeOutputArgs,
    },
    AddDraftNote {
        project: String,
        iid: u64,
        #[arg(
            long,
            requires = "position_source",
            conflicts_with = "in_reply_to_discussion_id"
        )]
        expected_head_sha: Option<String>,
        #[arg(long, conflicts_with = "position_source")]
        in_reply_to_discussion_id: Option<String>,
        #[arg(long, requires = "in_reply_to_discussion_id")]
        resolve_discussion: Option<bool>,
        #[command(flatten)]
        position: GitlabPositionArgs,
        #[command(flatten)]
        body: GitlabRequiredContentArgs,
        #[command(flatten)]
        response: EmbeddedOutputArgs,
    },
    UpdateDraftNote {
        project: String,
        iid: u64,
        draft_note_id: u64,
        #[arg(long, requires = "position_source")]
        expected_head_sha: Option<String>,
        #[command(flatten)]
        position: GitlabPositionArgs,
        #[command(flatten)]
        body: GitlabOptionalContentArgs,
        #[command(flatten)]
        response: EmbeddedOutputArgs,
    },
    DeleteDraftNote {
        project: String,
        iid: u64,
        draft_note_id: u64,
    },
    PublishDraftNote {
        project: String,
        iid: u64,
        draft_note_id: u64,
    },
    PublishAll {
        project: String,
        iid: u64,
        #[command(flatten)]
        summary: GitlabOptionalContentArgs,
        #[arg(long, requires = "content_source")]
        internal: Option<bool>,
    },
    SubmitReview {
        project: String,
        iid: u64,
        #[arg(long, value_enum)]
        reviewer_state: GitlabReviewerStateArg,
        #[command(flatten)]
        summary: GitlabOptionalContentArgs,
        #[arg(long, requires = "content_source")]
        internal: Option<bool>,
    },
    ViewApproval {
        project: String,
        iid: u64,
        #[command(flatten)]
        response: WholeOutputArgs,
    },
    ViewApprovalState {
        project: String,
        iid: u64,
        #[command(flatten)]
        response: WholeOutputArgs,
    },
    ListApprovalRules {
        project: String,
        iid: u64,
        #[arg(long)]
        max_results: Option<u32>,
        #[arg(long)]
        page_token: Option<String>,
        #[command(flatten)]
        response: WholeOutputArgs,
    },
    ViewApprovalRule {
        project: String,
        iid: u64,
        approval_rule_id: u64,
        #[command(flatten)]
        response: WholeOutputArgs,
    },
    Approve {
        project: String,
        iid: u64,
        #[arg(long)]
        head_sha: String,
    },
    Unapprove {
        project: String,
        iid: u64,
    },
    ApplySuggestion {
        project: String,
        iid: u64,
        discussion_id: String,
        note_id: u64,
        suggestion_id: u64,
        #[arg(long)]
        expected_head_sha: String,
        #[command(flatten)]
        commit: GitlabOptionalCommitMessageArgs,
    },
    ApplySuggestions {
        project: String,
        iid: u64,
        #[arg(long)]
        suggestions_file: PathBuf,
        #[arg(long)]
        expected_head_sha: String,
        #[command(flatten)]
        commit: GitlabOptionalCommitMessageArgs,
    },
    Create {
        project: String,
        #[arg(long)]
        source_branch: String,
        #[arg(long)]
        target_branch: String,
        #[arg(long)]
        title: String,
        #[arg(long, group = "content_source", requires = "content_format")]
        content: Option<String>,
        #[arg(long, group = "content_source", requires = "content_format", help = NORMALIZED_CONTENT_FILE_HELP)]
        content_file: Option<PathBuf>,
        #[arg(long, value_enum, requires = "content_source")]
        content_format: Option<GitlabContentFormatArg>,
        #[arg(long = "label")]
        labels: Vec<String>,
        #[arg(long = "assignee-id")]
        assignee_ids: Vec<u64>,
        #[arg(long = "reviewer-id")]
        reviewer_ids: Vec<u64>,
        #[arg(long)]
        remove_source_branch: Option<bool>,
        #[arg(long)]
        squash: Option<bool>,
        #[arg(long)]
        draft: Option<bool>,
        #[command(flatten)]
        response: EmbeddedOutputArgs,
    },
    Update {
        project: String,
        iid: u64,
        #[arg(long)]
        title: Option<String>,
        #[arg(long, group = "content_source", requires = "content_format")]
        content: Option<String>,
        #[arg(long, group = "content_source", requires = "content_format", help = NORMALIZED_CONTENT_FILE_HELP)]
        content_file: Option<PathBuf>,
        #[arg(long, value_enum, requires = "content_source")]
        content_format: Option<GitlabContentFormatArg>,
        #[arg(long)]
        state_event: Option<String>,
        #[arg(long = "label")]
        labels: Vec<String>,
        #[arg(long = "add-label")]
        add_labels: Vec<String>,
        #[arg(long = "remove-label")]
        remove_labels: Vec<String>,
        #[arg(long = "assignee-id")]
        assignee_ids: Vec<u64>,
        #[arg(long = "reviewer-id")]
        reviewer_ids: Vec<u64>,
        #[arg(long)]
        target_branch: Option<String>,
        #[arg(long)]
        remove_source_branch: Option<bool>,
        #[arg(long)]
        squash: Option<bool>,
        #[command(flatten)]
        response: EmbeddedOutputArgs,
    },
    Comment {
        project: String,
        iid: u64,
        #[arg(
            long,
            group = "content_source",
            requires = "content_format",
            required_unless_present = "content_file"
        )]
        content: Option<String>,
        #[arg(long, group = "content_source", requires = "content_format", required_unless_present = "content", help = NORMALIZED_CONTENT_FILE_HELP)]
        content_file: Option<PathBuf>,
        #[arg(long, value_enum, requires = "content_source")]
        content_format: Option<GitlabContentFormatArg>,
        #[command(flatten)]
        response: EmbeddedOutputArgs,
    },
    UpdateComment {
        project: String,
        iid: u64,
        note_id: u64,
        #[arg(
            long,
            group = "content_source",
            requires = "content_format",
            required_unless_present = "content_file"
        )]
        content: Option<String>,
        #[arg(long, group = "content_source", requires = "content_format", required_unless_present = "content", help = NORMALIZED_CONTENT_FILE_HELP)]
        content_file: Option<PathBuf>,
        #[arg(long, value_enum, requires = "content_source")]
        content_format: Option<GitlabContentFormatArg>,
        #[command(flatten)]
        response: EmbeddedOutputArgs,
    },
    DeleteComment {
        project: String,
        iid: u64,
        note_id: u64,
    },
    ViewComment {
        project: String,
        iid: u64,
        note_id: u64,
        #[command(flatten)]
        response: EmbeddedAndWholeOutputArgs,
    },
    ListComments {
        project: String,
        iid: u64,
        #[arg(long)]
        max_results: Option<u32>,
        #[arg(long)]
        sort: Option<String>,
        #[arg(long)]
        order_by: Option<String>,
        #[arg(long)]
        page_token: Option<String>,
        #[arg(long, value_enum, default_value = "full")]
        projection: GitlabProjectionArg,
        #[command(flatten)]
        response: EmbeddedAndWholeOutputArgs,
    },
    Discussion {
        project: String,
        iid: u64,
        #[arg(
            long,
            group = "content_source",
            requires = "content_format",
            required_unless_present = "content_file"
        )]
        content: Option<String>,
        #[arg(long, group = "content_source", requires = "content_format", required_unless_present = "content", help = NORMALIZED_CONTENT_FILE_HELP)]
        content_file: Option<PathBuf>,
        #[arg(long, value_enum, requires = "content_source")]
        content_format: Option<GitlabContentFormatArg>,
        #[command(flatten)]
        response: EmbeddedOutputArgs,
    },
    UpdateDiscussionNote {
        project: String,
        iid: u64,
        discussion_id: String,
        note_id: u64,
        #[arg(
            long,
            group = "content_source",
            requires = "content_format",
            required_unless_present = "content_file"
        )]
        content: Option<String>,
        #[arg(long, group = "content_source", requires = "content_format", required_unless_present = "content", help = NORMALIZED_CONTENT_FILE_HELP)]
        content_file: Option<PathBuf>,
        #[arg(long, value_enum, requires = "content_source")]
        content_format: Option<GitlabContentFormatArg>,
        #[command(flatten)]
        response: EmbeddedOutputArgs,
    },
    DeleteDiscussionNote {
        project: String,
        iid: u64,
        discussion_id: String,
        note_id: u64,
    },
    ResolveDiscussion {
        project: String,
        iid: u64,
        discussion_id: String,
        #[command(flatten)]
        response: EmbeddedOutputArgs,
    },
    ReopenDiscussion {
        project: String,
        iid: u64,
        discussion_id: String,
        #[command(flatten)]
        response: EmbeddedOutputArgs,
    },
    ListDiscussions {
        project: String,
        iid: u64,
        #[arg(long)]
        max_results: Option<u32>,
        #[arg(long)]
        page_token: Option<String>,
        #[arg(long, value_enum, default_value = "full")]
        projection: GitlabProjectionArg,
        #[command(flatten)]
        response: EmbeddedAndWholeOutputArgs,
    },
    Merge {
        project: String,
        iid: u64,
        #[arg(long)]
        sha: String,
        #[arg(long)]
        squash: Option<bool>,
        #[arg(long)]
        should_remove_source_branch: Option<bool>,
        #[arg(long)]
        merge_commit_message_file: Option<PathBuf>,
        #[arg(long)]
        squash_commit_message_file: Option<PathBuf>,
    },
}

#[derive(Debug, Subcommand)]
enum GitlabBranchCommand {
    List {
        project: String,
        #[arg(long)]
        search: Option<String>,
        #[arg(long)]
        regex: Option<String>,
        #[arg(long)]
        max_results: Option<u32>,
        #[command(flatten)]
        response: WholeOutputArgs,
    },
    View {
        project: String,
        branch: String,
        #[command(flatten)]
        response: WholeOutputArgs,
    },
    Create {
        project: String,
        branch: String,
        #[arg(long = "ref")]
        ref_name: String,
    },
}

#[derive(Debug, Subcommand)]
enum GitlabProtectedBranchCommand {
    List {
        project: String,
        #[arg(long)]
        search: Option<String>,
        #[arg(long)]
        max_results: Option<u32>,
        #[command(flatten)]
        response: WholeOutputArgs,
    },
    View {
        project: String,
        branch_or_wildcard_name: String,
        #[command(flatten)]
        response: WholeOutputArgs,
    },
    Verify {
        project: String,
        #[arg(long = "required-pattern")]
        required_patterns: Vec<String>,
        #[command(flatten)]
        response: WholeOutputArgs,
    },
}

#[derive(Debug, Subcommand)]
enum GitlabFileCommand {
    View {
        project: String,
        #[arg(long)]
        path: String,
        #[arg(long = "ref")]
        ref_name: String,
        #[command(flatten)]
        response: WholeOutputArgs,
    },
    Raw {
        project: String,
        #[arg(long)]
        path: String,
        #[arg(long = "ref")]
        ref_name: String,
    },
    Create {
        project: String,
        #[arg(long)]
        path: String,
        #[arg(long)]
        branch: String,
        #[arg(long)]
        content_file: PathBuf,
        #[arg(long = "message")]
        commit_message: String,
        #[arg(long)]
        start_branch: Option<String>,
        #[arg(long)]
        author_name: Option<String>,
        #[arg(long)]
        author_email: Option<String>,
        #[arg(long)]
        execute_filemode: Option<bool>,
    },
    Update {
        project: String,
        #[arg(long)]
        path: String,
        #[arg(long)]
        branch: String,
        #[arg(long)]
        content_file: PathBuf,
        #[arg(long = "message")]
        commit_message: String,
        #[arg(long)]
        last_commit_id: Option<String>,
        #[arg(long)]
        start_branch: Option<String>,
        #[arg(long)]
        author_name: Option<String>,
        #[arg(long)]
        author_email: Option<String>,
        #[arg(long)]
        execute_filemode: Option<bool>,
    },
    Delete {
        project: String,
        #[arg(long)]
        path: String,
        #[arg(long)]
        branch: String,
        #[arg(long = "message")]
        commit_message: String,
        #[arg(long)]
        last_commit_id: Option<String>,
        #[arg(long)]
        start_branch: Option<String>,
        #[arg(long)]
        author_name: Option<String>,
        #[arg(long)]
        author_email: Option<String>,
    },
}

#[derive(Debug, Subcommand)]
enum GitlabCommitCommand {
    List {
        project: String,
        #[arg(long)]
        ref_name: Option<String>,
        #[arg(long)]
        path: Option<String>,
        #[arg(long)]
        since: Option<String>,
        #[arg(long)]
        until: Option<String>,
        #[arg(long)]
        first_parent: Option<bool>,
        #[arg(long)]
        max_results: Option<u32>,
        #[command(flatten)]
        response: WholeOutputArgs,
    },
    View {
        project: String,
        sha: String,
        #[command(flatten)]
        response: WholeOutputArgs,
    },
    Create {
        project: String,
        #[arg(long)]
        branch: String,
        #[arg(long = "message")]
        commit_message: String,
        #[arg(long)]
        actions_file: PathBuf,
        #[arg(long)]
        start_branch: Option<String>,
        #[arg(long)]
        start_sha: Option<String>,
        #[arg(long)]
        author_name: Option<String>,
        #[arg(long)]
        author_email: Option<String>,
    },
}

#[derive(Debug, Subcommand)]
enum GitlabPipelineCommand {
    List {
        project: String,
        #[arg(long = "ref")]
        ref_name: Option<String>,
        #[arg(long)]
        sha: Option<String>,
        #[arg(long)]
        status: Option<String>,
        #[arg(long)]
        source: Option<String>,
        #[arg(long)]
        updated_after: Option<String>,
        #[arg(long)]
        updated_before: Option<String>,
        #[arg(long)]
        max_results: Option<u32>,
        #[command(flatten)]
        response: WholeOutputArgs,
    },
    View {
        project: String,
        pipeline_id: u64,
        #[command(flatten)]
        response: WholeOutputArgs,
    },
    Run {
        project: String,
        #[arg(long = "ref")]
        ref_name: String,
    },
    Retry {
        project: String,
        pipeline_id: u64,
    },
    Cancel {
        project: String,
        pipeline_id: u64,
    },
}

#[derive(Debug, Subcommand)]
enum GitlabJobCommand {
    List {
        project: String,
        #[arg(long)]
        pipeline_id: Option<u64>,
        #[arg(long)]
        scope: Option<String>,
        #[arg(long)]
        max_results: Option<u32>,
        #[command(flatten)]
        response: WholeOutputArgs,
    },
    View {
        project: String,
        job_id: u64,
        #[command(flatten)]
        response: WholeOutputArgs,
    },
    Trace {
        project: String,
        job_id: u64,
    },
    Retry {
        project: String,
        job_id: u64,
    },
    Cancel {
        project: String,
        job_id: u64,
    },
    Play {
        project: String,
        job_id: u64,
    },
}

#[derive(Debug, Subcommand)]
enum GitlabWebhookCommand {
    List {
        project: String,
        #[arg(long)]
        max_results: Option<u32>,
        #[arg(long)]
        page_token: Option<String>,
    },
    View {
        project: String,
        #[arg(value_parser = clap::value_parser!(u64).range(1..))]
        webhook_id: u64,
    },
    Create {
        project: String,
        #[arg(long = "destination-url")]
        destination_url: String,
        #[arg(long = "event")]
        events: Vec<GitlabWebhookEventArg>,
        #[arg(long)]
        name: Option<String>,
        #[arg(long)]
        description: Option<String>,
        #[arg(long)]
        enable_ssl_verification: Option<bool>,
        #[arg(long)]
        branch_filter_strategy: Option<GitlabWebhookBranchFilterStrategyArg>,
        #[arg(long)]
        push_events_branch_filter: Option<String>,
        #[arg(long)]
        custom_webhook_template: Option<String>,
        #[arg(long, conflicts_with_all = ["secret_token_file", "secret_token_stdin"])]
        secret_token_env: Option<String>,
        #[arg(long, conflicts_with_all = ["secret_token_env", "secret_token_stdin"])]
        secret_token_file: Option<PathBuf>,
        #[arg(long, conflicts_with_all = ["secret_token_env", "secret_token_file"])]
        secret_token_stdin: bool,
        #[arg(long, conflicts_with_all = ["signing_token_file", "signing_token_stdin"])]
        signing_token_env: Option<String>,
        #[arg(long, conflicts_with_all = ["signing_token_env", "signing_token_stdin"])]
        signing_token_file: Option<PathBuf>,
        #[arg(long, conflicts_with_all = ["signing_token_env", "signing_token_file"])]
        signing_token_stdin: bool,
    },
    Update {
        project: String,
        #[arg(value_parser = clap::value_parser!(u64).range(1..))]
        webhook_id: u64,
        #[arg(long = "destination-url")]
        destination_url: Option<String>,
        #[arg(long = "event", conflicts_with = "clear_events")]
        events: Vec<GitlabWebhookEventArg>,
        #[arg(long, conflicts_with = "events")]
        clear_events: bool,
        #[arg(long, conflicts_with = "clear_name")]
        name: Option<String>,
        #[arg(long, conflicts_with = "name")]
        clear_name: bool,
        #[arg(long, conflicts_with = "clear_description")]
        description: Option<String>,
        #[arg(long, conflicts_with = "description")]
        clear_description: bool,
        #[arg(long)]
        enable_ssl_verification: Option<bool>,
        #[arg(long)]
        branch_filter_strategy: Option<GitlabWebhookBranchFilterStrategyArg>,
        #[arg(long)]
        push_events_branch_filter: Option<String>,
        #[arg(long, conflicts_with = "clear_custom_webhook_template")]
        custom_webhook_template: Option<String>,
        #[arg(long, conflicts_with = "custom_webhook_template")]
        clear_custom_webhook_template: bool,
        #[arg(long, conflicts_with_all = ["secret_token_file", "secret_token_stdin", "clear_token"])]
        secret_token_env: Option<String>,
        #[arg(long, conflicts_with_all = ["secret_token_env", "secret_token_stdin", "clear_token"])]
        secret_token_file: Option<PathBuf>,
        #[arg(long, conflicts_with_all = ["secret_token_env", "secret_token_file", "clear_token"])]
        secret_token_stdin: bool,
        #[arg(long, conflicts_with_all = ["secret_token_env", "secret_token_file", "secret_token_stdin"])]
        clear_token: bool,
        #[arg(long, conflicts_with_all = ["signing_token_file", "signing_token_stdin"])]
        signing_token_env: Option<String>,
        #[arg(long, conflicts_with_all = ["signing_token_env", "signing_token_stdin"])]
        signing_token_file: Option<PathBuf>,
        #[arg(long, conflicts_with_all = ["signing_token_env", "signing_token_file"])]
        signing_token_stdin: bool,
        #[arg(long)]
        confirm_destination_reset: bool,
    },
    Delete {
        project: String,
        #[arg(value_parser = clap::value_parser!(u64).range(1..))]
        webhook_id: u64,
    },
    Test {
        project: String,
        #[arg(value_parser = clap::value_parser!(u64).range(1..))]
        webhook_id: u64,
        #[arg(long)]
        event: GitlabWebhookTestEventArg,
    },
    Event {
        #[command(subcommand)]
        command: GitlabWebhookEventCommand,
    },
    CustomHeader {
        #[command(subcommand)]
        command: GitlabWebhookCustomHeaderCommand,
    },
}

#[derive(Debug, Subcommand)]
enum GitlabWebhookEventCommand {
    List {
        project: String,
        #[arg(value_parser = clap::value_parser!(u64).range(1..))]
        webhook_id: u64,
        #[arg(long, value_parser = parse_gitlab_webhook_delivery_status)]
        status: Option<String>,
        #[arg(long, value_parser = clap::value_parser!(u32).range(1..=20))]
        max_results: Option<u32>,
        #[arg(long)]
        page_token: Option<String>,
    },
    Resend {
        project: String,
        #[arg(value_parser = clap::value_parser!(u64).range(1..))]
        webhook_id: u64,
        #[arg(value_parser = clap::value_parser!(u64).range(1..))]
        webhook_event_id: u64,
    },
}

#[derive(Debug, Subcommand)]
enum GitlabWebhookCustomHeaderCommand {
    Set {
        project: String,
        #[arg(value_parser = clap::value_parser!(u64).range(1..))]
        webhook_id: u64,
        key: String,
        #[arg(
            long,
            conflicts_with_all = ["value_file", "value_stdin"],
            required_unless_present_any = ["value_file", "value_stdin"]
        )]
        value_env: Option<String>,
        #[arg(long, conflicts_with_all = ["value_env", "value_stdin"])]
        value_file: Option<PathBuf>,
        #[arg(long, conflicts_with_all = ["value_env", "value_file"])]
        value_stdin: bool,
    },
    Delete {
        project: String,
        #[arg(value_parser = clap::value_parser!(u64).range(1..))]
        webhook_id: u64,
        key: String,
    },
}

struct CliContext<'a> {
    settings: &'a ResolvedCliSettings,
    output: Option<&'a Path>,
}

#[derive(Debug, Subcommand)]
enum McpCommand {
    /// Serve caller-filtered tools over stdin/stdout using the CLI broker settings.
    Serve {
        /// Expose one canonical service with its original tool names.
        #[arg(long, value_parser = mcp::parse_service)]
        service: Option<String>,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    require_cli_input(validate_output_command(&cli));
    let config = cli.config.clone().unwrap_or_else(default_config_path);
    if let Command::Mcp {
        command: McpCommand::Serve { service },
    } = &cli.command
    {
        let view = service
            .clone()
            .map(agent_access_core::mcp::McpView::Service)
            .unwrap_or_default();
        return mcp::serve(cli, config, view).await;
    }
    let result = match &cli.command {
        Command::Auth {
            command: AuthCommand::Token { command },
        } => {
            require_cli_input(run_auth_token_command(&cli, &config, command));
            Ok(())
        }
        Command::Auth {
            command: AuthCommand::GitCredential { operation },
        } => run_git_credential_command(
            &cli,
            &config,
            *operation,
            std::io::stdin().lock(),
            std::io::stdout().lock(),
            std::io::stderr().lock(),
        ),
        Command::Config {
            command: ConfigCommand::Validate,
        } => match validate_cli_config_file(&config) {
            Ok(()) => {
                println!("cli config valid: {}", config.display());
                Ok(())
            }
            Err(error) => exit_config_error(error),
        },
        command => {
            reject_literal_identity_token_for_management_command(&cli, command);
            let settings = require_cli_input(resolve_cli_settings(&cli, &config));
            require_cli_input(validate_transport(&settings));
            let ctx = CliContext {
                settings: &settings,
                output: cli.output.as_deref(),
            };
            run_cli_command(&ctx, command).await
        }
    };
    if let Err(error) = &result
        && let Some(error) = error.downcast_ref::<DeferredCliError>()
    {
        eprintln!("{}", error.message);
        std::process::exit(error.code);
    }
    if let Err(error) = &result
        && let Some(failure) = error.downcast_ref::<output::LocalOutputFailure>()
    {
        eprintln!("{}", serde_json::to_string_pretty(&failure.details)?);
        std::process::exit(failure.exit_code);
    }
    result
}

/// Defer process exit until output reservations have been dropped.
#[derive(Debug)]
struct DeferredCliError {
    code: i32,
    message: String,
}
impl DeferredCliError {
    fn malformed(error: impl std::fmt::Display) -> Self {
        Self {
            code: 5,
            message: format!("malformed broker response: {error:#}"),
        }
    }
    fn input(error: impl std::fmt::Display) -> Self {
        Self {
            code: 3,
            message: format!("{error:#}"),
        }
    }
    fn remote(error: impl std::fmt::Display) -> Self {
        Self {
            code: 5,
            message: format!("{error:#}"),
        }
    }
}
impl std::fmt::Display for DeferredCliError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(&self.message)
    }
}
impl std::error::Error for DeferredCliError {}

fn validate_output_command(cli: &Cli) -> Result<()> {
    let download = match &cli.command {
        Command::CloudbeesCi { command } => matches!(
            cloudbees_ci_invocation(command),
            CloudbeesCiInvocation::Download { .. }
        ),
        Command::Jira {
            command:
                JiraCommand::Issue {
                    command:
                        JiraIssueCommand::Attachment {
                            command: JiraAttachmentCommand::Download { .. },
                        },
                },
        } => true,
        Command::Confluence { command } => matches!(
            command,
            ConfluenceCommand::Page {
                command: ConfluencePageCommand::Attachment {
                    command: ConfluenceAttachmentCommand::Download { .. }
                }
            } | ConfluenceCommand::Blog {
                command: ConfluenceBlogCommand::Attachment {
                    command: ConfluenceBlogAttachmentCommand::Download { .. }
                }
            } | ConfluenceCommand::Page {
                command: ConfluencePageCommand::Draft {
                    command: ConfluencePageDraftCommand::Attachment {
                        command: ConfluencePageDraftAttachmentCommand::Download { .. }
                    }
                }
            } | ConfluenceCommand::Blog {
                command: ConfluenceBlogCommand::Draft {
                    command: ConfluenceBlogDraftCommand::Attachment {
                        command: ConfluenceBlogDraftAttachmentCommand::Download { .. }
                    }
                }
            }
        ),
        Command::Gitlab { command } => matches!(
            command,
            GitlabCommand::MergeRequest {
                command: GitlabMergeRequestCommand::DiffRaw { .. }
            } | GitlabCommand::File {
                command: GitlabFileCommand::Raw { .. }
            } | GitlabCommand::Job {
                command: GitlabJobCommand::Trace { .. }
            }
        ),
        _ => false,
    };
    if download && cli.output.is_none() {
        anyhow::bail!("download requires --output PATH (or --output - for stdout)");
    }
    if cli.output.is_some()
        && !matches!(
            cli.command,
            Command::Jira { .. }
                | Command::Confluence { .. }
                | Command::Gitlab { .. }
                | Command::CloudbeesCi { .. }
                | Command::OAuthStub { .. }
                | Command::Gmail { .. }
                | Command::Teams { .. }
                | Command::Invoke { .. }
                | Command::Send { .. }
                | Command::Spec { .. }
                | Command::Services { .. }
                | Command::ResourceAccess { .. }
                | Command::Actions { .. }
                | Command::Broker {
                    command: BrokerCommand::Status
                }
        )
    {
        anyhow::bail!(
            "--output is supported only for provider actions, downloads, discovery, and specification commands"
        );
    }
    Ok(())
}

fn required_output<'a>(ctx: &'a CliContext<'_>) -> &'a Path {
    ctx.output.unwrap_or_else(|| {
        exit_cli_input_error(anyhow::anyhow!(
            "download requires --output PATH (or --output - for stdout)"
        ))
    })
}

/// Saving a response is a client-side capability, not a new broker permission.
async fn output_action_spec(
    ctx: &CliContext<'_>,
    service: &str,
    action: &str,
) -> Result<ApiActionSpec> {
    let catalog = fetch_runtime_catalog(ctx).await.unwrap_or_else(|error| {
        exit_malformed_broker_response(format!("invalid runtime catalog: {error:#}"))
    });
    let spec = catalog_action(&catalog, service, action)?.clone();
    if !spec.supports_json_file_output() {
        anyhow::bail!(
            "action {service}.{action} does not support JSON file output; use its dedicated download command"
        );
    }
    Ok(spec)
}

fn write_local_response(
    ctx: &CliContext<'_>,
    status: u16,
    value: &serde_json::Value,
    format: ResponseFormat,
    reserved: Option<output::ResponseOutput>,
) -> Result<Option<serde_json::Value>> {
    if !(200..300).contains(&status)
        || value
            .get("decision")
            .is_some_and(|decision| decision != "allow")
    {
        return Ok(None);
    }
    let reserved = match reserved {
        Some(reserved) => Some(reserved),
        None => output::ResponseOutput::prepare(ctx.output, &[]).map_err(|error| {
            output::LocalOutputFailure::response(
                value,
                ctx.output.expect("preparation failed for selected output"),
                error,
                &[],
            )
        })?,
    };
    let Some(reserved) = reserved else {
        return Ok(None);
    };
    let (bytes, content_type) = if format == ResponseFormat::Markdown {
        let markdown =
            markdown_result_value(value)?.context("formatted response has no Markdown result")?;
        (markdown.as_bytes().to_vec(), "text/markdown")
    } else {
        let mut bytes = serde_json::to_vec_pretty(value)?;
        bytes.push(b'\n');
        (bytes, "application/json")
    };
    Ok(Some(reserved.save(value, &bytes, content_type)?))
}

fn print_local_response(ctx: &CliContext<'_>, status: u16, value: serde_json::Value) -> Result<()> {
    if let Some(receipt) = write_local_response(ctx, status, &value, ResponseFormat::Json, None)? {
        print_value_and_exit(status, receipt);
    }
    print_value_and_exit(status, value);
}

fn reject_literal_identity_token_for_management_command(cli: &Cli, command: &Command) {
    if matches!(
        command,
        Command::Credentials { .. }
            | Command::Tokens { .. }
            | Command::Audit { .. }
            | Command::Admin { .. }
    ) {
        reject_literal_identity_token_for_management(cli);
    }
}

async fn run_cli_command(ctx: &CliContext<'_>, command: &Command) -> Result<()> {
    match command {
        Command::Mcp { .. } => unreachable!("handled before resolved CLI dispatch"),
        Command::Auth {
            command: AuthCommand::Status,
        } => run_broker_get(ctx, "/v1/me", ResponseShape::Object).await,
        Command::Broker {
            command: BrokerCommand::Status,
        } => run_broker_get(ctx, "/v1/broker/status", ResponseShape::Object).await,
        Command::Auth {
            command: AuthCommand::Token { .. },
        }
        | Command::Auth {
            command: AuthCommand::GitCredential { .. },
        }
        | Command::Config {
            command: ConfigCommand::Validate,
        } => unreachable!("handled before resolved CLI dispatch"),
        Command::Services { command } => match command {
            ServicesCommand::List { projection } => run_services_list(ctx, projection).await,
            ServicesCommand::Describe { service } => render_discovery(
                ctx,
                discovery::service_describe(ctx.settings, service).await,
            ),
        },
        Command::ResourceAccess {
            command:
                ResourceAccessCommand::Describe {
                    service,
                    action,
                    resource_type,
                    prefix,
                    limit,
                    cursor,
                },
        } => render_discovery(
            ctx,
            discovery::resource_access_describe(
                ctx.settings,
                service,
                action.as_deref(),
                resource_type.as_deref(),
                prefix.as_deref(),
                *limit,
                cursor.as_deref(),
            )
            .await,
        ),
        Command::Actions { command } => match command {
            ActionsCommand::List {
                service,
                resource,
                resource_type,
                projection,
            } => {
                run_actions_list(
                    ctx,
                    service,
                    resource.as_deref(),
                    resource_type.as_deref(),
                    projection,
                )
                .await
            }
            ActionsCommand::Describe { service, action } => {
                run_action_describe(ctx, service, action).await
            }
        },
        Command::Credentials { command } => run_credentials_command(ctx, command).await,
        Command::Tokens { command } => run_tokens_command(ctx, command).await,
        Command::Audit { command } => audit_commands::run_audit(ctx, command).await,
        Command::Admin { command } => run_admin_command(ctx, command).await,
        Command::Jira { command } => run_jira_command(ctx, command).await,
        Command::Confluence { command } => run_confluence_command(ctx, command).await,
        Command::Gitlab { command } => run_gitlab_command(ctx, command).await,
        Command::CloudbeesCi { command } => run_cloudbees_ci_command(ctx, command).await,
        Command::Gmail { command } => {
            let (action, inputs) = gmail_invocation(command);
            run_typed_invoke_value(ctx, action, inputs, None, None).await
        }
        Command::Teams { command } => {
            run_typed_invoke_value(
                ctx,
                "teams.notification.send",
                teams_invocation(command),
                None,
                None,
            )
            .await
        }
        Command::OAuthStub { command } => {
            let (action, inputs) = match command {
                OAuthStubCommand::Record {
                    command: OAuthStubRecordCommand::List { collection },
                } => (
                    "oauth_stub.record.list",
                    serde_json::json!({"collection":collection}),
                ),
                OAuthStubCommand::Record {
                    command: OAuthStubRecordCommand::View { id, collection },
                } => (
                    "oauth_stub.record.view",
                    serde_json::json!({"collection":collection,"id":id}),
                ),
                OAuthStubCommand::Account => ("oauth_stub.account.view", serde_json::json!({})),
            };
            run_typed_invoke_value(ctx, action, inputs, None, None).await
        }
        Command::Spec { command } => run_spec_command(ctx, command).await,
        Command::Send {
            request_json,
            request_file,
            request_stdin,
        } => run_send_command(ctx, request_json, request_file, *request_stdin).await,
        Command::Invoke {
            service_action,
            input_json,
            input_file,
            input_stdin,
            read_content_format,
            output_format,
        } => {
            run_invoke(
                ctx,
                service_action,
                input_json,
                input_file,
                *input_stdin,
                *read_content_format,
                *output_format,
            )
            .await
        }
    }
}

async fn run_confluence_command(ctx: &CliContext<'_>, command: &ConfluenceCommand) -> Result<()> {
    match command {
        ConfluenceCommand::Space {
            command:
                ConfluenceSpaceCommand::List {
                    max_results,
                    page_token,
                    output_format,
                },
        } => {
            let mut inputs = serde_json::Map::new();
            if let Some(max_results) = max_results {
                inputs.insert("maxResults".to_string(), serde_json::json!(max_results));
            }
            if let Some(page_token) = page_token {
                inputs.insert("pageToken".to_string(), serde_json::json!(page_token));
            }
            run_typed_invoke_value(
                ctx,
                "confluence.space.list",
                inputs.into(),
                None,
                *output_format,
            )
            .await
        }

        ConfluenceCommand::Page { command } => match command {
            ConfluencePageCommand::View {
                page_id,
                page_url,
                response,
            } => {
                let inputs = match (page_id.as_deref(), page_url.as_deref()) {
                    (Some(page_id), None) => serde_json::json!({ "pageId": page_id }),
                    (None, Some(url)) => serde_json::json!({ "url": url }),
                    _ => require_cli_input(Err(anyhow::anyhow!(
                        "confluence page view requires exactly one page id or --page-url"
                    ))),
                };
                run_typed_invoke_value(
                    ctx,
                    "confluence.page.view",
                    inputs,
                    response.read_content_format,
                    response.output_format,
                )
                .await
            }
            ConfluencePageCommand::Search {
                cql,
                text,
                spaces,
                max_results,
                next_page_token,
                response,
            } => {
                let mut inputs = serde_json::Map::new();
                inputs.insert(
                    "query".to_string(),
                    exclusive_search_query(
                        "cql",
                        cql.as_ref(),
                        text.as_ref(),
                        "confluence page search",
                    ),
                );
                if !spaces.is_empty() {
                    inputs.insert("spaces".to_string(), serde_json::json!(spaces));
                }
                if let Some(max_results) = max_results {
                    inputs.insert("maxResults".to_string(), serde_json::json!(max_results));
                }
                if let Some(next_page_token) = next_page_token {
                    inputs.insert(
                        "nextPageToken".to_string(),
                        serde_json::json!(next_page_token),
                    );
                }
                run_typed_invoke_value(
                    ctx,
                    "confluence.search",
                    serde_json::Value::Object(inputs),
                    None,
                    response.output_format,
                )
                .await
            }
            ConfluencePageCommand::Create {
                space,
                title,
                parent,
                parent_url,
                content,
                content_file,
                content_format,
            } => {
                let mut inputs = serde_json::Map::new();
                inputs.insert("space".to_string(), serde_json::json!(space));
                inputs.insert("title".to_string(), serde_json::json!(title));
                insert_confluence_content_inputs(
                    &mut inputs,
                    content.as_deref(),
                    content_file.as_deref(),
                    *content_format,
                    "confluence page create",
                )?;
                confluence_optional_parent_locator_inputs(
                    &mut inputs,
                    parent.as_deref(),
                    parent_url.as_deref(),
                    "confluence page create",
                );
                run_invoke_value(
                    ctx,
                    "confluence.page.create",
                    serde_json::Value::Object(inputs),
                )
                .await
            }
            ConfluencePageCommand::Update {
                page_id,
                base_version,
                title,
                content,
                content_file,
                content_format,
            } => {
                let mut inputs = serde_json::Map::new();
                inputs.insert("pageId".to_string(), serde_json::json!(page_id));
                inputs.insert("baseVersion".to_string(), serde_json::json!(base_version));
                insert_confluence_content_inputs(
                    &mut inputs,
                    content.as_deref(),
                    content_file.as_deref(),
                    *content_format,
                    "confluence page update",
                )?;
                if let Some(title) = title {
                    inputs.insert("title".to_string(), serde_json::json!(title));
                }
                run_invoke_value(
                    ctx,
                    "confluence.page.update",
                    serde_json::Value::Object(inputs),
                )
                .await
            }
            ConfluencePageCommand::Move {
                page_id,
                page_url,
                position,
                target,
                target_url,
            } => {
                let mut inputs = confluence_page_argument_locator_inputs(
                    page_id.as_deref(),
                    page_url.as_deref(),
                    "confluence page move",
                );
                inputs.insert("position".to_string(), serde_json::json!(position.as_str()));
                confluence_move_target_locator_inputs(
                    &mut inputs,
                    target.as_deref(),
                    target_url.as_deref(),
                    "confluence page move",
                );
                run_invoke_value(
                    ctx,
                    "confluence.page.move",
                    serde_json::Value::Object(inputs),
                )
                .await
            }
            ConfluencePageCommand::Attach {
                page_id,
                files,
                content_type,
            } => run_confluence_attachment_add(ctx, page_id, files, content_type.as_deref()).await,
            ConfluencePageCommand::Attachment { command } => match command {
                ConfluenceAttachmentCommand::List {
                    page_id,
                    page_url,
                    max_results,
                    next_page_token,
                    response,
                } => {
                    let mut inputs = match (page_id.as_deref(), page_url.as_deref()) {
                        (Some(page_id), None) => {
                            let mut inputs = serde_json::Map::new();
                            inputs.insert("pageId".to_string(), serde_json::json!(page_id));
                            inputs
                        }
                        (None, Some(url)) => {
                            let mut inputs = serde_json::Map::new();
                            inputs.insert("url".to_string(), serde_json::json!(url));
                            inputs
                        }
                        _ => require_cli_input(Err(anyhow::anyhow!(
                            "confluence page attachment list requires exactly one page id or --page-url"
                        ))),
                    };
                    if let Some(max_results) = max_results {
                        inputs.insert("maxResults".to_string(), serde_json::json!(max_results));
                    }
                    if let Some(next_page_token) = next_page_token {
                        inputs.insert(
                            "nextPageToken".to_string(),
                            serde_json::json!(next_page_token),
                        );
                    }
                    run_typed_invoke_value(
                        ctx,
                        "confluence.attachment.list",
                        serde_json::Value::Object(inputs),
                        None,
                        response.output_format,
                    )
                    .await
                }
                ConfluenceAttachmentCommand::Download {
                    page_id,
                    attachment_id,
                } => {
                    run_confluence_attachment_download(
                        ctx,
                        page_id,
                        attachment_id,
                        required_output(ctx),
                    )
                    .await
                }
            },
            ConfluencePageCommand::Draft { command } => {
                run_confluence_page_draft_command(ctx, command).await
            }
            ConfluencePageCommand::FooterComment { command } => {
                run_confluence_page_comment_command(ctx, "footer_comment", "pageId", command).await
            }
            ConfluencePageCommand::InlineComment { command } => {
                run_confluence_page_inline_comment_command(ctx, "inline_comment", "pageId", command)
                    .await
            }
            ConfluencePageCommand::Verify {
                page_id,
                expect_version,
                expect_title,
                expect_attachment_id,
                response,
            } => {
                if expect_version.is_none()
                    && expect_title.is_none()
                    && expect_attachment_id.is_none()
                {
                    require_cli_input::<()>(Err(anyhow::anyhow!(
                        "confluence page verify requires at least one expected value"
                    )));
                }
                let mut inputs = serde_json::Map::new();
                inputs.insert("pageId".to_string(), serde_json::json!(page_id));
                if let Some(version) = expect_version {
                    inputs.insert("expectVersion".to_string(), serde_json::json!(version));
                }
                if let Some(title) = expect_title {
                    inputs.insert("expectTitle".to_string(), serde_json::json!(title));
                }
                if let Some(attachment_id) = expect_attachment_id {
                    inputs.insert(
                        "expectAttachmentId".to_string(),
                        serde_json::json!(attachment_id),
                    );
                }
                run_typed_invoke_value(
                    ctx,
                    "confluence.verify",
                    serde_json::Value::Object(inputs),
                    None,
                    response.output_format,
                )
                .await
            }
        },
        ConfluenceCommand::Blog { command } => match command {
            ConfluenceBlogCommand::View {
                blog_id,
                blog_url,
                response,
            } => {
                let inputs = match (blog_id.as_deref(), blog_url.as_deref()) {
                    (Some(blog_id), None) => serde_json::json!({ "blogId": blog_id }),
                    (None, Some(url)) => serde_json::json!({ "url": url }),
                    _ => require_cli_input(Err(anyhow::anyhow!(
                        "confluence blog view requires exactly one blog id or --blog-url"
                    ))),
                };
                run_typed_invoke_value(
                    ctx,
                    "confluence.blog.view",
                    inputs,
                    response.read_content_format,
                    response.output_format,
                )
                .await
            }
            ConfluenceBlogCommand::Search {
                cql,
                text,
                spaces,
                max_results,
                next_page_token,
                response,
            } => {
                let mut inputs = serde_json::Map::new();
                inputs.insert(
                    "query".to_string(),
                    exclusive_search_query(
                        "cql",
                        cql.as_ref(),
                        text.as_ref(),
                        "confluence blog search",
                    ),
                );
                if !spaces.is_empty() {
                    inputs.insert("spaces".to_string(), serde_json::json!(spaces));
                }
                if let Some(max_results) = max_results {
                    inputs.insert("maxResults".to_string(), serde_json::json!(max_results));
                }
                if let Some(next_page_token) = next_page_token {
                    inputs.insert(
                        "nextPageToken".to_string(),
                        serde_json::json!(next_page_token),
                    );
                }
                run_typed_invoke_value(
                    ctx,
                    "confluence.blog.search",
                    serde_json::Value::Object(inputs),
                    None,
                    response.output_format,
                )
                .await
            }
            ConfluenceBlogCommand::Create {
                space,
                title,
                content,
                content_file,
                content_format,
            } => {
                let mut inputs = serde_json::Map::new();
                inputs.insert("space".to_string(), serde_json::json!(space));
                inputs.insert("title".to_string(), serde_json::json!(title));
                insert_confluence_content_inputs(
                    &mut inputs,
                    content.as_deref(),
                    content_file.as_deref(),
                    *content_format,
                    "confluence blog create",
                )?;
                run_invoke_value(
                    ctx,
                    "confluence.blog.create",
                    serde_json::Value::Object(inputs),
                )
                .await
            }
            ConfluenceBlogCommand::Update {
                blog_id,
                base_version,
                title,
                content,
                content_file,
                content_format,
                version_message,
            } => {
                let mut inputs = serde_json::Map::new();
                inputs.insert("blogId".to_string(), serde_json::json!(blog_id));
                inputs.insert("baseVersion".to_string(), serde_json::json!(base_version));
                insert_confluence_content_inputs(
                    &mut inputs,
                    content.as_deref(),
                    content_file.as_deref(),
                    *content_format,
                    "confluence blog update",
                )?;
                if let Some(title) = title {
                    inputs.insert("title".to_string(), serde_json::json!(title));
                }
                if let Some(message) = version_message {
                    inputs.insert("versionMessage".to_string(), serde_json::json!(message));
                }
                run_invoke_value(
                    ctx,
                    "confluence.blog.update",
                    serde_json::Value::Object(inputs),
                )
                .await
            }
            ConfluenceBlogCommand::Attach {
                blog_id,
                files,
                content_type,
            } => {
                run_confluence_blog_attachment_add(ctx, blog_id, files, content_type.as_deref())
                    .await
            }
            ConfluenceBlogCommand::Attachment { command } => match command {
                ConfluenceBlogAttachmentCommand::List {
                    blog_id,
                    blog_url,
                    max_results,
                    next_page_token,
                    response,
                } => {
                    let mut inputs = match (blog_id.as_deref(), blog_url.as_deref()) {
                        (Some(blog_id), None) => {
                            let mut inputs = serde_json::Map::new();
                            inputs.insert("blogId".to_string(), serde_json::json!(blog_id));
                            inputs
                        }
                        (None, Some(url)) => {
                            let mut inputs = serde_json::Map::new();
                            inputs.insert("url".to_string(), serde_json::json!(url));
                            inputs
                        }
                        _ => require_cli_input(Err(anyhow::anyhow!(
                            "confluence blog attachment list requires exactly one blog id or --blog-url"
                        ))),
                    };
                    if let Some(max_results) = max_results {
                        inputs.insert("maxResults".to_string(), serde_json::json!(max_results));
                    }
                    if let Some(next_page_token) = next_page_token {
                        inputs.insert(
                            "nextPageToken".to_string(),
                            serde_json::json!(next_page_token),
                        );
                    }
                    run_typed_invoke_value(
                        ctx,
                        "confluence.blog.attachment.list",
                        serde_json::Value::Object(inputs),
                        None,
                        response.output_format,
                    )
                    .await
                }
                ConfluenceBlogAttachmentCommand::Download {
                    blog_id,
                    attachment_id,
                } => {
                    run_confluence_blog_attachment_download(
                        ctx,
                        blog_id,
                        attachment_id,
                        required_output(ctx),
                    )
                    .await
                }
            },
            ConfluenceBlogCommand::Draft { command } => {
                run_confluence_blog_draft_command(ctx, command).await
            }
            ConfluenceBlogCommand::FooterComment { command } => {
                run_confluence_blog_comment_command(ctx, "footer_comment", "blogId", command).await
            }
            ConfluenceBlogCommand::InlineComment { command } => {
                run_confluence_blog_inline_comment_command(ctx, "inline_comment", "blogId", command)
                    .await
            }
            ConfluenceBlogCommand::Verify {
                blog_id,
                expect_version,
                expect_title,
                expect_attachment_id,
                response,
            } => {
                if expect_version.is_none()
                    && expect_title.is_none()
                    && expect_attachment_id.is_none()
                {
                    require_cli_input::<()>(Err(anyhow::anyhow!(
                        "confluence blog verify requires at least one expected value"
                    )));
                }
                let mut inputs = serde_json::Map::new();
                inputs.insert("blogId".to_string(), serde_json::json!(blog_id));
                if let Some(version) = expect_version {
                    inputs.insert("expectVersion".to_string(), serde_json::json!(version));
                }
                if let Some(title) = expect_title {
                    inputs.insert("expectTitle".to_string(), serde_json::json!(title));
                }
                if let Some(attachment_id) = expect_attachment_id {
                    inputs.insert(
                        "expectAttachmentId".to_string(),
                        serde_json::json!(attachment_id),
                    );
                }
                run_typed_invoke_value(
                    ctx,
                    "confluence.blog.verify",
                    serde_json::Value::Object(inputs),
                    None,
                    response.output_format,
                )
                .await
            }
        },
    }
}

async fn run_confluence_page_draft_command(
    ctx: &CliContext<'_>,
    command: &ConfluencePageDraftCommand,
) -> Result<()> {
    match command {
        ConfluencePageDraftCommand::Create {
            space,
            title,
            parent,
            parent_url,
            content,
            content_file,
            content_format,
        } => {
            let mut inputs = serde_json::Map::new();
            inputs.insert("space".to_string(), serde_json::json!(space));
            inputs.insert("title".to_string(), serde_json::json!(title));
            insert_confluence_content_inputs(
                &mut inputs,
                content.as_deref(),
                content_file.as_deref(),
                *content_format,
                "confluence page draft create",
            )?;
            confluence_optional_parent_locator_inputs(
                &mut inputs,
                parent.as_deref(),
                parent_url.as_deref(),
                "confluence page draft create",
            );
            run_invoke_value(
                ctx,
                "confluence.page.draft.create",
                serde_json::Value::Object(inputs),
            )
            .await
        }
        ConfluencePageDraftCommand::Stage {
            page_id,
            base_version,
            title,
            content,
            content_file,
            content_format,
        } => {
            let mut inputs = serde_json::Map::new();
            inputs.insert("pageId".to_string(), serde_json::json!(page_id));
            inputs.insert("baseVersion".to_string(), serde_json::json!(base_version));
            insert_confluence_content_inputs(
                &mut inputs,
                content.as_deref(),
                content_file.as_deref(),
                *content_format,
                "confluence page draft stage",
            )?;
            if let Some(title) = title {
                inputs.insert("title".to_string(), serde_json::json!(title));
            }
            run_invoke_value(
                ctx,
                "confluence.page.draft.stage",
                serde_json::Value::Object(inputs),
            )
            .await
        }
        ConfluencePageDraftCommand::View {
            page_id,
            draft_handle,
            body_format,
            response,
        } => {
            run_typed_invoke_value(
                ctx,
                "confluence.page.draft.view",
                serde_json::json!({
                    "pageId": page_id,
                    "draftHandle": draft_handle,
                    "bodyFormat": body_format,
                }),
                response.read_content_format,
                response.output_format,
            )
            .await
        }
        ConfluencePageDraftCommand::Update {
            page_id,
            draft_handle,
            title,
            content,
            content_file,
            content_format,
        } => {
            let mut inputs = serde_json::Map::new();
            inputs.insert("pageId".to_string(), serde_json::json!(page_id));
            inputs.insert("draftHandle".to_string(), serde_json::json!(draft_handle));
            insert_confluence_content_inputs(
                &mut inputs,
                content.as_deref(),
                content_file.as_deref(),
                *content_format,
                "confluence page draft update",
            )?;
            if let Some(title) = title {
                inputs.insert("title".to_string(), serde_json::json!(title));
            }
            run_invoke_value(
                ctx,
                "confluence.page.draft.update",
                serde_json::Value::Object(inputs),
            )
            .await
        }
        ConfluencePageDraftCommand::Publish {
            page_id,
            draft_handle,
            body_format,
        } => {
            run_invoke_value(
                ctx,
                "confluence.page.draft.publish",
                serde_json::json!({
                    "pageId": page_id,
                    "draftHandle": draft_handle,
                    "bodyFormat": body_format,
                }),
            )
            .await
        }
        ConfluencePageDraftCommand::Discard {
            page_id,
            draft_handle,
        } => {
            run_invoke_value(
                ctx,
                "confluence.page.draft.discard",
                serde_json::json!({
                    "pageId": page_id,
                    "draftHandle": draft_handle,
                }),
            )
            .await
        }
        ConfluencePageDraftCommand::Verify {
            page_id,
            draft_handle,
            expect_version,
            expect_title,
            expect_attachment_id,
            response,
        } => {
            let inputs = confluence_draft_verify_inputs(
                "pageId",
                page_id,
                draft_handle,
                *expect_version,
                expect_title.as_deref(),
                expect_attachment_id.as_deref(),
                "confluence page draft verify",
            );
            run_typed_invoke_value(
                ctx,
                "confluence.page.draft.verify",
                inputs,
                None,
                response.output_format,
            )
            .await
        }
        ConfluencePageDraftCommand::Attach {
            page_id,
            draft_handle,
            files,
            content_type,
        } => {
            run_confluence_draft_attachment_add(
                ctx,
                ConfluenceDraftAttachmentAddArgs {
                    service_action: "confluence.page.draft.attachment.add",
                    id_field: "pageId",
                    content_id: page_id,
                    draft_handle,
                    files,
                    content_type: content_type.as_deref(),
                },
            )
            .await
        }
        ConfluencePageDraftCommand::Attachment { command } => match command {
            ConfluencePageDraftAttachmentCommand::List {
                page_id,
                draft_handle,
                max_results,
                next_page_token,
                response,
            } => {
                let inputs = confluence_draft_attachment_list_inputs(
                    "pageId",
                    page_id,
                    draft_handle,
                    *max_results,
                    next_page_token.as_deref(),
                );
                run_typed_invoke_value(
                    ctx,
                    "confluence.page.draft.attachment.list",
                    inputs,
                    None,
                    response.output_format,
                )
                .await
            }
            ConfluencePageDraftAttachmentCommand::Download {
                page_id,
                draft_handle,
                attachment_id,
            } => {
                run_confluence_draft_attachment_download(
                    ctx,
                    ConfluenceDraftAttachmentDownloadArgs {
                        service_action: "confluence.page.draft.attachment.download",
                        id_field: "pageId",
                        content_id: page_id,
                        draft_handle,
                        attachment_id,
                        output: required_output(ctx),
                    },
                )
                .await
            }
        },
    }
}

async fn run_confluence_blog_draft_command(
    ctx: &CliContext<'_>,
    command: &ConfluenceBlogDraftCommand,
) -> Result<()> {
    match command {
        ConfluenceBlogDraftCommand::Create {
            space,
            title,
            content,
            content_file,
            content_format,
        } => {
            let mut inputs = serde_json::Map::new();
            inputs.insert("space".to_string(), serde_json::json!(space));
            inputs.insert("title".to_string(), serde_json::json!(title));
            insert_confluence_content_inputs(
                &mut inputs,
                content.as_deref(),
                content_file.as_deref(),
                *content_format,
                "confluence blog draft create",
            )?;
            run_invoke_value(
                ctx,
                "confluence.blog.draft.create",
                serde_json::Value::Object(inputs),
            )
            .await
        }
        ConfluenceBlogDraftCommand::Stage {
            blog_id,
            base_version,
            title,
            content,
            content_file,
            content_format,
        } => {
            let mut inputs = serde_json::Map::new();
            inputs.insert("blogId".to_string(), serde_json::json!(blog_id));
            inputs.insert("baseVersion".to_string(), serde_json::json!(base_version));
            insert_confluence_content_inputs(
                &mut inputs,
                content.as_deref(),
                content_file.as_deref(),
                *content_format,
                "confluence blog draft stage",
            )?;
            if let Some(title) = title {
                inputs.insert("title".to_string(), serde_json::json!(title));
            }
            run_invoke_value(
                ctx,
                "confluence.blog.draft.stage",
                serde_json::Value::Object(inputs),
            )
            .await
        }
        ConfluenceBlogDraftCommand::View {
            blog_id,
            draft_handle,
            body_format,
            response,
        } => {
            run_typed_invoke_value(
                ctx,
                "confluence.blog.draft.view",
                serde_json::json!({
                    "blogId": blog_id,
                    "draftHandle": draft_handle,
                    "bodyFormat": body_format,
                }),
                response.read_content_format,
                response.output_format,
            )
            .await
        }
        ConfluenceBlogDraftCommand::Update {
            blog_id,
            draft_handle,
            title,
            content,
            content_file,
            content_format,
        } => {
            let mut inputs = serde_json::Map::new();
            inputs.insert("blogId".to_string(), serde_json::json!(blog_id));
            inputs.insert("draftHandle".to_string(), serde_json::json!(draft_handle));
            insert_confluence_content_inputs(
                &mut inputs,
                content.as_deref(),
                content_file.as_deref(),
                *content_format,
                "confluence blog draft update",
            )?;
            if let Some(title) = title {
                inputs.insert("title".to_string(), serde_json::json!(title));
            }
            run_invoke_value(
                ctx,
                "confluence.blog.draft.update",
                serde_json::Value::Object(inputs),
            )
            .await
        }
        ConfluenceBlogDraftCommand::Publish {
            blog_id,
            draft_handle,
            body_format,
        } => {
            run_invoke_value(
                ctx,
                "confluence.blog.draft.publish",
                serde_json::json!({
                    "blogId": blog_id,
                    "draftHandle": draft_handle,
                    "bodyFormat": body_format,
                }),
            )
            .await
        }
        ConfluenceBlogDraftCommand::Discard {
            blog_id,
            draft_handle,
        } => {
            run_invoke_value(
                ctx,
                "confluence.blog.draft.discard",
                serde_json::json!({
                    "blogId": blog_id,
                    "draftHandle": draft_handle,
                }),
            )
            .await
        }
        ConfluenceBlogDraftCommand::Verify {
            blog_id,
            draft_handle,
            expect_version,
            expect_title,
            expect_attachment_id,
            response,
        } => {
            let inputs = confluence_draft_verify_inputs(
                "blogId",
                blog_id,
                draft_handle,
                *expect_version,
                expect_title.as_deref(),
                expect_attachment_id.as_deref(),
                "confluence blog draft verify",
            );
            run_typed_invoke_value(
                ctx,
                "confluence.blog.draft.verify",
                inputs,
                None,
                response.output_format,
            )
            .await
        }
        ConfluenceBlogDraftCommand::Attach {
            blog_id,
            draft_handle,
            files,
            content_type,
        } => {
            run_confluence_draft_attachment_add(
                ctx,
                ConfluenceDraftAttachmentAddArgs {
                    service_action: "confluence.blog.draft.attachment.add",
                    id_field: "blogId",
                    content_id: blog_id,
                    draft_handle,
                    files,
                    content_type: content_type.as_deref(),
                },
            )
            .await
        }
        ConfluenceBlogDraftCommand::Attachment { command } => match command {
            ConfluenceBlogDraftAttachmentCommand::List {
                blog_id,
                draft_handle,
                max_results,
                next_page_token,
                response,
            } => {
                let inputs = confluence_draft_attachment_list_inputs(
                    "blogId",
                    blog_id,
                    draft_handle,
                    *max_results,
                    next_page_token.as_deref(),
                );
                run_typed_invoke_value(
                    ctx,
                    "confluence.blog.draft.attachment.list",
                    inputs,
                    None,
                    response.output_format,
                )
                .await
            }
            ConfluenceBlogDraftAttachmentCommand::Download {
                blog_id,
                draft_handle,
                attachment_id,
            } => {
                run_confluence_draft_attachment_download(
                    ctx,
                    ConfluenceDraftAttachmentDownloadArgs {
                        service_action: "confluence.blog.draft.attachment.download",
                        id_field: "blogId",
                        content_id: blog_id,
                        draft_handle,
                        attachment_id,
                        output: required_output(ctx),
                    },
                )
                .await
            }
        },
    }
}

async fn run_confluence_page_comment_command(
    ctx: &CliContext<'_>,
    comment_segment: &str,
    container_field: &str,
    command: &ConfluencePageCommentCommand,
) -> Result<()> {
    match command {
        ConfluencePageCommentCommand::List {
            page_id,
            body_format,
            sort,
            max_results,
            next_page_token,
            response,
        } => {
            run_confluence_comment_list(
                ctx,
                ConfluenceCommentListCliRequest {
                    service_action: format!("confluence.page.{comment_segment}.list"),
                    container_field,
                    container_id: page_id,
                    body_format: body_format.as_deref(),
                    resolution_status: None,
                    sort: sort.as_deref(),
                    max_results: *max_results,
                    next_page_token: next_page_token.as_deref(),
                    read_content_format: response.read_content_format,
                    output_format: response.output_format,
                },
            )
            .await
        }
        ConfluencePageCommentCommand::View {
            comment_id,
            body_format,
            response,
        } => {
            run_confluence_comment_view(
                ctx,
                &format!("confluence.page.{comment_segment}.view"),
                comment_id,
                body_format.as_deref(),
                response,
            )
            .await
        }
        ConfluencePageCommentCommand::Add {
            page_id,
            content,
            content_file,
            content_format,
            response,
        } => {
            run_confluence_comment_add(
                ctx,
                ConfluenceCommentAddCliRequest {
                    service_action: format!("confluence.page.{comment_segment}.add"),
                    container_field,
                    container_id: page_id,
                    content: content.as_deref(),
                    content_file: content_file.as_deref(),
                    content_format: *content_format,
                    read_content_format: response.read_content_format,
                },
            )
            .await
        }
        ConfluencePageCommentCommand::Update {
            comment_id,
            base_version,
            content,
            content_file,
            content_format,
            response,
        } => {
            run_confluence_comment_update(
                ctx,
                ConfluenceCommentUpdateCliRequest {
                    service_action: format!("confluence.page.{comment_segment}.update"),
                    comment_id,
                    base_version: *base_version,
                    content: content.as_deref(),
                    content_file: content_file.as_deref(),
                    content_format: *content_format,
                    read_content_format: response.read_content_format,
                },
            )
            .await
        }
        ConfluencePageCommentCommand::Delete { comment_id } => {
            run_confluence_comment_delete(
                ctx,
                &format!("confluence.page.{comment_segment}.delete"),
                comment_id,
            )
            .await
        }
        ConfluencePageCommentCommand::Replies {
            comment_id,
            body_format,
            max_results,
            next_page_token,
            response,
        } => {
            run_confluence_comment_replies(
                ctx,
                &format!("confluence.page.{comment_segment}.reply.list"),
                comment_id,
                body_format.as_deref(),
                *max_results,
                next_page_token.as_deref(),
                response,
            )
            .await
        }
        ConfluencePageCommentCommand::Reply {
            comment_id,
            content,
            content_file,
            content_format,
            response,
        } => {
            run_confluence_comment_reply(
                ctx,
                &format!("confluence.page.{comment_segment}.reply.add"),
                comment_id,
                content.as_deref(),
                content_file.as_deref(),
                *content_format,
                response,
            )
            .await
        }
    }
}

async fn run_confluence_page_inline_comment_command(
    ctx: &CliContext<'_>,
    comment_segment: &str,
    container_field: &str,
    command: &ConfluencePageInlineCommentCommand,
) -> Result<()> {
    match command {
        ConfluencePageInlineCommentCommand::List {
            page_id,
            body_format,
            resolution_status,
            sort,
            max_results,
            next_page_token,
            response,
        } => {
            run_confluence_comment_list(
                ctx,
                ConfluenceCommentListCliRequest {
                    service_action: format!("confluence.page.{comment_segment}.list"),
                    container_field,
                    container_id: page_id,
                    body_format: body_format.as_deref(),
                    resolution_status: resolution_status.as_deref(),
                    sort: sort.as_deref(),
                    max_results: *max_results,
                    next_page_token: next_page_token.as_deref(),
                    read_content_format: response.read_content_format,
                    output_format: response.output_format,
                },
            )
            .await
        }
        ConfluencePageInlineCommentCommand::View {
            comment_id,
            body_format,
            response,
        } => {
            run_confluence_comment_view(
                ctx,
                &format!("confluence.page.{comment_segment}.view"),
                comment_id,
                body_format.as_deref(),
                response,
            )
            .await
        }
        ConfluencePageInlineCommentCommand::Update {
            comment_id,
            base_version,
            content,
            content_file,
            content_format,
            response,
        } => {
            run_confluence_comment_update(
                ctx,
                ConfluenceCommentUpdateCliRequest {
                    service_action: format!("confluence.page.{comment_segment}.update"),
                    comment_id,
                    base_version: *base_version,
                    content: content.as_deref(),
                    content_file: content_file.as_deref(),
                    content_format: *content_format,
                    read_content_format: response.read_content_format,
                },
            )
            .await
        }
        ConfluencePageInlineCommentCommand::Delete { comment_id } => {
            run_confluence_comment_delete(
                ctx,
                &format!("confluence.page.{comment_segment}.delete"),
                comment_id,
            )
            .await
        }
        ConfluencePageInlineCommentCommand::Replies {
            comment_id,
            body_format,
            max_results,
            next_page_token,
            response,
        } => {
            run_confluence_comment_replies(
                ctx,
                &format!("confluence.page.{comment_segment}.reply.list"),
                comment_id,
                body_format.as_deref(),
                *max_results,
                next_page_token.as_deref(),
                response,
            )
            .await
        }
        ConfluencePageInlineCommentCommand::Reply {
            comment_id,
            content,
            content_file,
            content_format,
            response,
        } => {
            run_confluence_comment_reply(
                ctx,
                &format!("confluence.page.{comment_segment}.reply.add"),
                comment_id,
                content.as_deref(),
                content_file.as_deref(),
                *content_format,
                response,
            )
            .await
        }
    }
}

async fn run_confluence_blog_comment_command(
    ctx: &CliContext<'_>,
    comment_segment: &str,
    container_field: &str,
    command: &ConfluenceBlogCommentCommand,
) -> Result<()> {
    match command {
        ConfluenceBlogCommentCommand::List {
            blog_id,
            body_format,
            sort,
            max_results,
            next_page_token,
            response,
        } => {
            run_confluence_comment_list(
                ctx,
                ConfluenceCommentListCliRequest {
                    service_action: format!("confluence.blog.{comment_segment}.list"),
                    container_field,
                    container_id: blog_id,
                    body_format: body_format.as_deref(),
                    resolution_status: None,
                    sort: sort.as_deref(),
                    max_results: *max_results,
                    next_page_token: next_page_token.as_deref(),
                    read_content_format: response.read_content_format,
                    output_format: response.output_format,
                },
            )
            .await
        }
        ConfluenceBlogCommentCommand::View {
            comment_id,
            body_format,
            response,
        } => {
            run_confluence_comment_view(
                ctx,
                &format!("confluence.blog.{comment_segment}.view"),
                comment_id,
                body_format.as_deref(),
                response,
            )
            .await
        }
        ConfluenceBlogCommentCommand::Add {
            blog_id,
            content,
            content_file,
            content_format,
            response,
        } => {
            run_confluence_comment_add(
                ctx,
                ConfluenceCommentAddCliRequest {
                    service_action: format!("confluence.blog.{comment_segment}.add"),
                    container_field,
                    container_id: blog_id,
                    content: content.as_deref(),
                    content_file: content_file.as_deref(),
                    content_format: *content_format,
                    read_content_format: response.read_content_format,
                },
            )
            .await
        }
        ConfluenceBlogCommentCommand::Update {
            comment_id,
            base_version,
            content,
            content_file,
            content_format,
            response,
        } => {
            run_confluence_comment_update(
                ctx,
                ConfluenceCommentUpdateCliRequest {
                    service_action: format!("confluence.blog.{comment_segment}.update"),
                    comment_id,
                    base_version: *base_version,
                    content: content.as_deref(),
                    content_file: content_file.as_deref(),
                    content_format: *content_format,
                    read_content_format: response.read_content_format,
                },
            )
            .await
        }
        ConfluenceBlogCommentCommand::Delete { comment_id } => {
            run_confluence_comment_delete(
                ctx,
                &format!("confluence.blog.{comment_segment}.delete"),
                comment_id,
            )
            .await
        }
        ConfluenceBlogCommentCommand::Replies {
            comment_id,
            body_format,
            max_results,
            next_page_token,
            response,
        } => {
            run_confluence_comment_replies(
                ctx,
                &format!("confluence.blog.{comment_segment}.reply.list"),
                comment_id,
                body_format.as_deref(),
                *max_results,
                next_page_token.as_deref(),
                response,
            )
            .await
        }
        ConfluenceBlogCommentCommand::Reply {
            comment_id,
            content,
            content_file,
            content_format,
            response,
        } => {
            run_confluence_comment_reply(
                ctx,
                &format!("confluence.blog.{comment_segment}.reply.add"),
                comment_id,
                content.as_deref(),
                content_file.as_deref(),
                *content_format,
                response,
            )
            .await
        }
    }
}

async fn run_confluence_blog_inline_comment_command(
    ctx: &CliContext<'_>,
    comment_segment: &str,
    container_field: &str,
    command: &ConfluenceBlogInlineCommentCommand,
) -> Result<()> {
    match command {
        ConfluenceBlogInlineCommentCommand::List {
            blog_id,
            body_format,
            resolution_status,
            sort,
            max_results,
            next_page_token,
            response,
        } => {
            run_confluence_comment_list(
                ctx,
                ConfluenceCommentListCliRequest {
                    service_action: format!("confluence.blog.{comment_segment}.list"),
                    container_field,
                    container_id: blog_id,
                    body_format: body_format.as_deref(),
                    resolution_status: resolution_status.as_deref(),
                    sort: sort.as_deref(),
                    max_results: *max_results,
                    next_page_token: next_page_token.as_deref(),
                    read_content_format: response.read_content_format,
                    output_format: response.output_format,
                },
            )
            .await
        }
        ConfluenceBlogInlineCommentCommand::View {
            comment_id,
            body_format,
            response,
        } => {
            run_confluence_comment_view(
                ctx,
                &format!("confluence.blog.{comment_segment}.view"),
                comment_id,
                body_format.as_deref(),
                response,
            )
            .await
        }
        ConfluenceBlogInlineCommentCommand::Update {
            comment_id,
            base_version,
            content,
            content_file,
            content_format,
            response,
        } => {
            run_confluence_comment_update(
                ctx,
                ConfluenceCommentUpdateCliRequest {
                    service_action: format!("confluence.blog.{comment_segment}.update"),
                    comment_id,
                    base_version: *base_version,
                    content: content.as_deref(),
                    content_file: content_file.as_deref(),
                    content_format: *content_format,
                    read_content_format: response.read_content_format,
                },
            )
            .await
        }
        ConfluenceBlogInlineCommentCommand::Delete { comment_id } => {
            run_confluence_comment_delete(
                ctx,
                &format!("confluence.blog.{comment_segment}.delete"),
                comment_id,
            )
            .await
        }
        ConfluenceBlogInlineCommentCommand::Replies {
            comment_id,
            body_format,
            max_results,
            next_page_token,
            response,
        } => {
            run_confluence_comment_replies(
                ctx,
                &format!("confluence.blog.{comment_segment}.reply.list"),
                comment_id,
                body_format.as_deref(),
                *max_results,
                next_page_token.as_deref(),
                response,
            )
            .await
        }
        ConfluenceBlogInlineCommentCommand::Reply {
            comment_id,
            content,
            content_file,
            content_format,
            response,
        } => {
            run_confluence_comment_reply(
                ctx,
                &format!("confluence.blog.{comment_segment}.reply.add"),
                comment_id,
                content.as_deref(),
                content_file.as_deref(),
                *content_format,
                response,
            )
            .await
        }
    }
}

struct ConfluenceCommentListCliRequest<'a> {
    service_action: String,
    container_field: &'a str,
    container_id: &'a str,
    body_format: Option<&'a str>,
    resolution_status: Option<&'a str>,
    sort: Option<&'a str>,
    max_results: Option<u32>,
    next_page_token: Option<&'a str>,
    read_content_format: Option<ReadContentFormatArg>,
    output_format: Option<OutputFormatArg>,
}

async fn run_confluence_comment_list(
    ctx: &CliContext<'_>,
    request: ConfluenceCommentListCliRequest<'_>,
) -> Result<()> {
    let mut inputs = serde_json::Map::new();
    inputs.insert(
        request.container_field.to_string(),
        serde_json::json!(request.container_id),
    );
    if let Some(body_format) = request.body_format {
        inputs.insert("bodyFormat".to_string(), serde_json::json!(body_format));
    }
    if let Some(resolution_status) = request.resolution_status {
        inputs.insert(
            "resolutionStatus".to_string(),
            serde_json::json!(resolution_status),
        );
    }
    if let Some(sort) = request.sort {
        inputs.insert("sort".to_string(), serde_json::json!(sort));
    }
    if let Some(max_results) = request.max_results {
        inputs.insert("maxResults".to_string(), serde_json::json!(max_results));
    }
    if let Some(next_page_token) = request.next_page_token {
        inputs.insert(
            "nextPageToken".to_string(),
            serde_json::json!(next_page_token),
        );
    }
    run_typed_invoke_value(
        ctx,
        &request.service_action,
        serde_json::Value::Object(inputs),
        request.read_content_format,
        request.output_format,
    )
    .await
}

async fn run_confluence_comment_view(
    ctx: &CliContext<'_>,
    service_action: &str,
    comment_id: &str,
    body_format: Option<&str>,
    response: &EmbeddedAndWholeOutputArgs,
) -> Result<()> {
    let mut inputs = serde_json::Map::new();
    inputs.insert("commentId".to_string(), serde_json::json!(comment_id));
    if let Some(body_format) = body_format {
        inputs.insert("bodyFormat".to_string(), serde_json::json!(body_format));
    }
    run_typed_invoke_value(
        ctx,
        service_action,
        serde_json::Value::Object(inputs),
        response.read_content_format,
        response.output_format,
    )
    .await
}

struct ConfluenceCommentAddCliRequest<'a> {
    service_action: String,
    container_field: &'a str,
    container_id: &'a str,
    content: Option<&'a str>,
    content_file: Option<&'a Path>,
    content_format: ConfluenceContentFormatArg,
    read_content_format: Option<ReadContentFormatArg>,
}

async fn run_confluence_comment_add(
    ctx: &CliContext<'_>,
    request: ConfluenceCommentAddCliRequest<'_>,
) -> Result<()> {
    let mut inputs = serde_json::Map::new();
    inputs.insert(
        request.container_field.to_string(),
        serde_json::json!(request.container_id),
    );
    insert_confluence_content_inputs(
        &mut inputs,
        request.content,
        request.content_file,
        request.content_format,
        &request.service_action,
    )?;
    run_typed_invoke_value(
        ctx,
        &request.service_action,
        serde_json::Value::Object(inputs),
        request.read_content_format,
        None,
    )
    .await
}

async fn run_confluence_comment_replies(
    ctx: &CliContext<'_>,
    service_action: &str,
    comment_id: &str,
    body_format: Option<&str>,
    max_results: Option<u32>,
    next_page_token: Option<&str>,
    response: &EmbeddedAndWholeOutputArgs,
) -> Result<()> {
    let mut inputs = serde_json::Map::new();
    inputs.insert("commentId".to_string(), serde_json::json!(comment_id));
    if let Some(body_format) = body_format {
        inputs.insert("bodyFormat".to_string(), serde_json::json!(body_format));
    }
    if let Some(max_results) = max_results {
        inputs.insert("maxResults".to_string(), serde_json::json!(max_results));
    }
    if let Some(next_page_token) = next_page_token {
        inputs.insert(
            "nextPageToken".to_string(),
            serde_json::json!(next_page_token),
        );
    }
    run_typed_invoke_value(
        ctx,
        service_action,
        serde_json::Value::Object(inputs),
        response.read_content_format,
        response.output_format,
    )
    .await
}

async fn run_confluence_comment_reply(
    ctx: &CliContext<'_>,
    service_action: &str,
    comment_id: &str,
    content: Option<&str>,
    content_file: Option<&Path>,
    content_format: ConfluenceContentFormatArg,
    response: &EmbeddedOutputArgs,
) -> Result<()> {
    let mut inputs = serde_json::Map::new();
    inputs.insert("commentId".to_string(), serde_json::json!(comment_id));
    insert_confluence_content_inputs(
        &mut inputs,
        content,
        content_file,
        content_format,
        service_action,
    )?;
    run_typed_invoke_value(
        ctx,
        service_action,
        serde_json::Value::Object(inputs),
        response.read_content_format,
        None,
    )
    .await
}

struct ConfluenceCommentUpdateCliRequest<'a> {
    service_action: String,
    comment_id: &'a str,
    base_version: u64,
    content: Option<&'a str>,
    content_file: Option<&'a Path>,
    content_format: ConfluenceContentFormatArg,
    read_content_format: Option<ReadContentFormatArg>,
}

async fn run_confluence_comment_update(
    ctx: &CliContext<'_>,
    request: ConfluenceCommentUpdateCliRequest<'_>,
) -> Result<()> {
    let mut inputs = serde_json::Map::new();
    inputs.insert(
        "commentId".to_string(),
        serde_json::json!(request.comment_id),
    );
    inputs.insert(
        "baseVersion".to_string(),
        serde_json::json!(request.base_version),
    );
    insert_confluence_content_inputs(
        &mut inputs,
        request.content,
        request.content_file,
        request.content_format,
        &request.service_action,
    )?;
    run_typed_invoke_value(
        ctx,
        &request.service_action,
        serde_json::Value::Object(inputs),
        request.read_content_format,
        None,
    )
    .await
}

async fn run_confluence_comment_delete(
    ctx: &CliContext<'_>,
    service_action: &str,
    comment_id: &str,
) -> Result<()> {
    run_invoke_value(
        ctx,
        service_action,
        serde_json::json!({
            "commentId": comment_id,
        }),
    )
    .await
}

async fn run_cloudbees_ci_command(
    ctx: &CliContext<'_>,
    command: &CloudbeesCiCommand,
) -> Result<()> {
    match cloudbees_ci_invocation(command) {
        CloudbeesCiInvocation::Json {
            action,
            inputs,
            format,
        } => {
            run_typed_invoke_value(ctx, &format!("cloudbees_ci.{action}"), inputs, None, format)
                .await
        }
        CloudbeesCiInvocation::Download { action, inputs } => {
            run_attachment_download(
                ctx,
                &format!("cloudbees_ci.{action}"),
                inputs,
                required_output(ctx),
            )
            .await
        }
    }
}

enum CloudbeesCiInvocation {
    Json {
        action: &'static str,
        inputs: serde_json::Value,
        format: Option<OutputFormatArg>,
    },
    Download {
        action: &'static str,
        inputs: serde_json::Value,
    },
}

fn cloudbees_ci_invocation(command: &CloudbeesCiCommand) -> CloudbeesCiInvocation {
    use CloudbeesCiBuildArtifactCommand as Artifact;
    use CloudbeesCiBuildCommand as Build;
    use CloudbeesCiPipelineCommand as Pipeline;
    let with = |mut inputs: serde_json::Map<String, serde_json::Value>,
                extra: &[(&str, Option<serde_json::Value>)]| {
        for (name, value) in extra {
            if let Some(value) = value {
                inputs.insert((*name).to_owned(), value.clone());
            }
        }
        serde_json::Value::Object(inputs)
    };
    let download = |action, inputs| CloudbeesCiInvocation::Download { action, inputs };
    let list_response = WholeOutputArgs {
        output_format: None,
    };
    let (action, inputs, response) = match command {
        CloudbeesCiCommand::Job {
            command:
                CloudbeesCiJobCommand::List {
                    controller,
                    folder,
                    max_results,
                    page_token,
                },
        } => (
            "job.list",
            with(
                serde_json::Map::from_iter([("controller".into(), serde_json::json!(controller))]),
                &[
                    ("folder", folder.clone().map(serde_json::Value::String)),
                    ("maxResults", max_results.map(|n| serde_json::json!(n))),
                    (
                        "pageToken",
                        page_token.clone().map(serde_json::Value::String),
                    ),
                ],
            ),
            &list_response,
        ),
        CloudbeesCiCommand::Job {
            command: CloudbeesCiJobCommand::View { job, response },
        } => ("job.view", with(job.inputs(), &[]), response),
        CloudbeesCiCommand::Queue {
            command:
                CloudbeesCiQueueCommand::View {
                    job,
                    queue_id,
                    response,
                },
        } => (
            "queue.view",
            with(
                job.inputs(),
                &[("queueId", Some(serde_json::json!(queue_id)))],
            ),
            response,
        ),
        CloudbeesCiCommand::Build { command } => match command {
            Build::Artifact {
                command: Artifact::List { build, response },
            } => ("build.artifact.list", with(build.inputs(), &[]), response),
            Build::Artifact {
                command:
                    Artifact::Download {
                        build,
                        artifact_path,
                    },
            } => {
                return download(
                    "build.artifact.download",
                    with(
                        build.inputs(),
                        &[("artifactPath", Some(serde_json::json!(artifact_path)))],
                    ),
                );
            }
            Build::LogDownload { build } => {
                return download("build.log.download", with(build.inputs(), &[]));
            }
            Build::TestsDownload { build } => {
                return download("build.tests.download", with(build.inputs(), &[]));
            }
            Build::TestsDetails {
                build,
                max_results,
                response,
            } => (
                "build.tests.details",
                with(
                    build.inputs(),
                    &[(
                        "maxResults",
                        max_results.map(|value| serde_json::json!(value)),
                    )],
                ),
                response,
            ),
            Build::PendingInputs { build, response } => (
                "build.pending-inputs.list",
                with(build.inputs(), &[]),
                response,
            ),
            Build::Pipeline {
                command: Pipeline::View { build, response },
            } => ("build.pipeline.view", with(build.inputs(), &[]), response),
            Build::Pipeline {
                command:
                    Pipeline::Node {
                        build,
                        node_id,
                        response,
                    },
            } => (
                "build.pipeline.node.view",
                with(
                    build.inputs(),
                    &[("nodeId", Some(serde_json::json!(node_id)))],
                ),
                response,
            ),
            Build::Pipeline {
                command:
                    Pipeline::Log {
                        build,
                        node_id,
                        response,
                    },
            } => (
                "build.pipeline.node.log.read",
                with(
                    build.inputs(),
                    &[("nodeId", Some(serde_json::json!(node_id)))],
                ),
                response,
            ),
            Build::List {
                job,
                max_results,
                response,
            } => (
                "build.list",
                with(
                    job.inputs(),
                    &[(
                        "maxResults",
                        max_results.map(|value| serde_json::json!(value)),
                    )],
                ),
                response,
            ),
            Build::View { build, response } => ("build.view", with(build.inputs(), &[]), response),
            Build::Log {
                build,
                mode,
                cursor,
                query,
                max_matches,
                max_bytes,
                response,
            } => (
                "build.log.read",
                with(
                    build.inputs(),
                    &[
                        ("mode", mode.map(|mode| serde_json::json!(mode.as_str()))),
                        (
                            "cursor",
                            cursor.as_ref().map(|value| serde_json::json!(value)),
                        ),
                        (
                            "query",
                            query.as_ref().map(|value| serde_json::json!(value)),
                        ),
                        (
                            "maxMatches",
                            max_matches.map(|value| serde_json::json!(value)),
                        ),
                        ("maxBytes", max_bytes.map(|value| serde_json::json!(value))),
                    ],
                ),
                response,
            ),
            Build::Tests { build, response } => {
                ("build.tests.view", with(build.inputs(), &[]), response)
            }
            Build::Trigger { job, response } => {
                ("build.trigger", with(job.inputs(), &[]), response)
            }
        },
    };
    CloudbeesCiInvocation::Json {
        action,
        inputs,
        format: response.output_format,
    }
}

async fn run_gitlab_command(ctx: &CliContext<'_>, command: &GitlabCommand) -> Result<()> {
    match command {
        GitlabCommand::Search { command } => gitlab_search::run_content(ctx, command).await,
        GitlabCommand::ServiceAccount { command } => {
            gitlab_provisioning::run_service_account(ctx, command).await
        }
        GitlabCommand::Project { command } => match command {
            GitlabProjectCommand::List(args) => gitlab_search::run_project_list(ctx, args).await,
            GitlabProjectCommand::Search(args) => gitlab_search::run_project(ctx, args).await,
            GitlabProjectCommand::AccessToken { command } => {
                gitlab_provisioning::run_project_token(ctx, command).await
            }
            GitlabProjectCommand::Upload {
                project,
                project_url,
                file,
                content_type,
            } => {
                let inputs = gitlab_project_locator_inputs(
                    project.as_deref(),
                    project_url.as_deref(),
                    "gitlab project upload",
                );
                // Like the Jira and Confluence attachment commands, this typed
                // wrapper builds its request directly; the broker stays authoritative.
                let plan =
                    agent_access_provider::attachment_upload_plan(&["project", "url"], Some(1));
                run_upload_with_plan(
                    ctx,
                    "gitlab",
                    "project.upload",
                    inputs,
                    vec![SendFileDescriptor {
                        role: plan.role.clone(),
                        path: file.clone(),
                        filename: None,
                        content_type: content_type.clone(),
                    }],
                    &plan,
                    ResponseOptions::default(),
                )
                .await
            }
            GitlabProjectCommand::View {
                project,
                project_url,
                response,
            } => {
                let inputs = gitlab_project_locator_inputs(
                    project.as_deref(),
                    project_url.as_deref(),
                    "gitlab project view",
                );
                run_typed_invoke_value(
                    ctx,
                    "gitlab.project.view",
                    inputs,
                    None,
                    response.output_format,
                )
                .await
            }
        },
        GitlabCommand::Issue { command } => match command {
            GitlabIssueCommand::View {
                project,
                iid,
                issue_url,
                response,
            } => {
                let inputs = gitlab_numbered_locator_inputs(
                    project.as_deref(),
                    *iid,
                    issue_url.as_deref(),
                    "gitlab issue view",
                    "--issue-url",
                );
                run_typed_invoke_value(
                    ctx,
                    "gitlab.issue.view",
                    inputs,
                    response.read_content_format,
                    response.output_format,
                )
                .await
            }
            GitlabIssueCommand::Search {
                project,
                state,
                labels,
                milestone,
                assignee,
                author,
                search,
                created_after,
                updated_after,
                sort,
                order_by,
                max_results,
                page_token,
                response,
            } => {
                let mut inputs = serde_json::Map::new();
                inputs.insert("project".to_string(), serde_json::json!(project));
                insert_optional_json_string(&mut inputs, "state", state);
                insert_optional_json_array(&mut inputs, "labels", labels);
                insert_optional_json_string(&mut inputs, "milestone", milestone);
                insert_optional_json_string(&mut inputs, "assignee", assignee);
                insert_optional_json_string(&mut inputs, "author", author);
                insert_optional_json_string(&mut inputs, "search", search);
                insert_optional_json_string(&mut inputs, "createdAfter", created_after);
                insert_optional_json_string(&mut inputs, "updatedAfter", updated_after);
                insert_optional_json_string(&mut inputs, "sort", sort);
                insert_optional_json_string(&mut inputs, "orderBy", order_by);
                insert_optional_json_u32(&mut inputs, "maxResults", *max_results);
                insert_optional_json_string(&mut inputs, "pageToken", page_token);
                run_typed_invoke_value(
                    ctx,
                    "gitlab.issue.search",
                    serde_json::Value::Object(inputs),
                    response.read_content_format,
                    response.output_format,
                )
                .await
            }
            GitlabIssueCommand::Create {
                project,
                title,
                content,
                content_file,
                content_format,
                labels,
                milestone,
                assignee_ids,
                confidential,
                response,
            } => {
                let mut inputs = serde_json::Map::new();
                inputs.insert("project".to_string(), serde_json::json!(project));
                inputs.insert("title".to_string(), serde_json::json!(title));
                require_cli_input(insert_gitlab_content_inputs(
                    &mut inputs,
                    content.as_deref(),
                    content_file.as_deref(),
                    *content_format,
                    false,
                    "gitlab issue create",
                ));
                insert_optional_json_array(&mut inputs, "labels", labels);
                insert_optional_json_string(&mut inputs, "milestone", milestone);
                insert_optional_json_u64_array(&mut inputs, "assignees", assignee_ids);
                insert_optional_json_bool(&mut inputs, "confidential", *confidential);
                run_typed_invoke_value(
                    ctx,
                    "gitlab.issue.create",
                    serde_json::Value::Object(inputs),
                    response.read_content_format,
                    None,
                )
                .await
            }
            GitlabIssueCommand::Update {
                project,
                iid,
                title,
                content,
                content_file,
                content_format,
                state_event,
                labels,
                add_labels,
                remove_labels,
                milestone,
                assignee_ids,
                confidential,
                response,
            } => {
                let mut inputs = serde_json::Map::new();
                inputs.insert("project".to_string(), serde_json::json!(project));
                inputs.insert("iid".to_string(), serde_json::json!(iid));
                insert_optional_json_string(&mut inputs, "title", title);
                require_cli_input(insert_gitlab_content_inputs(
                    &mut inputs,
                    content.as_deref(),
                    content_file.as_deref(),
                    *content_format,
                    false,
                    "gitlab issue update",
                ));
                insert_optional_json_string(&mut inputs, "stateEvent", state_event);
                insert_optional_json_array(&mut inputs, "labels", labels);
                insert_optional_json_array(&mut inputs, "addLabels", add_labels);
                insert_optional_json_array(&mut inputs, "removeLabels", remove_labels);
                insert_optional_json_string(&mut inputs, "milestone", milestone);
                insert_optional_json_u64_array(&mut inputs, "assignees", assignee_ids);
                insert_optional_json_bool(&mut inputs, "confidential", *confidential);
                run_typed_invoke_value(
                    ctx,
                    "gitlab.issue.update",
                    serde_json::Value::Object(inputs),
                    response.read_content_format,
                    None,
                )
                .await
            }
            GitlabIssueCommand::Comment {
                project,
                iid,
                content,
                content_file,
                content_format,
                confidential,
                response,
            } => {
                let mut inputs = serde_json::Map::new();
                inputs.insert("project".to_string(), serde_json::json!(project));
                inputs.insert("iid".to_string(), serde_json::json!(iid));
                require_cli_input(insert_gitlab_content_inputs(
                    &mut inputs,
                    content.as_deref(),
                    content_file.as_deref(),
                    *content_format,
                    true,
                    "gitlab issue comment",
                ));
                insert_optional_json_bool(&mut inputs, "confidential", *confidential);
                run_typed_invoke_value(
                    ctx,
                    "gitlab.issue.note.add",
                    serde_json::Value::Object(inputs),
                    response.read_content_format,
                    None,
                )
                .await
            }
            GitlabIssueCommand::UpdateComment {
                project,
                iid,
                note_id,
                content,
                content_file,
                content_format,
                response,
            } => {
                run_gitlab_note_content_command(
                    ctx,
                    GitlabNoteContentCommandArgs {
                        action: "gitlab.issue.note.update",
                        project,
                        iid: *iid,
                        note_id: *note_id,
                        content: content.as_deref(),
                        content_file: content_file.as_deref(),
                        content_format: *content_format,
                        command: "gitlab issue update-comment",
                        read_content_format: response.read_content_format,
                    },
                )
                .await
            }
            GitlabIssueCommand::DeleteComment {
                project,
                iid,
                note_id,
            } => {
                run_gitlab_note_delete_command(
                    ctx,
                    "gitlab.issue.note.delete",
                    project,
                    *iid,
                    *note_id,
                )
                .await
            }
            GitlabIssueCommand::ViewComment {
                project,
                iid,
                note_id,
                response,
            } => {
                run_typed_invoke_value(
                    ctx,
                    "gitlab.issue.note.view",
                    serde_json::json!({"project": project, "iid": iid, "noteId": note_id}),
                    response.read_content_format,
                    response.output_format,
                )
                .await
            }
            GitlabIssueCommand::ListComments {
                project,
                iid,
                max_results,
                sort,
                order_by,
                page_token,
                projection,
                response,
            } => {
                let mut inputs = serde_json::Map::new();
                inputs.insert("project".to_string(), serde_json::json!(project));
                inputs.insert("iid".to_string(), serde_json::json!(iid));
                insert_optional_json_u32(&mut inputs, "maxResults", *max_results);
                insert_optional_json_string(&mut inputs, "sort", sort);
                insert_optional_json_string(&mut inputs, "orderBy", order_by);
                insert_optional_json_string(&mut inputs, "pageToken", page_token);
                inputs.insert(
                    "projection".to_string(),
                    serde_json::json!(projection.as_str()),
                );
                run_typed_invoke_value(
                    ctx,
                    "gitlab.issue.note.list",
                    serde_json::Value::Object(inputs),
                    response.read_content_format,
                    response.output_format,
                )
                .await
            }
        },
        GitlabCommand::MergeRequest { command } => match command {
            GitlabMergeRequestCommand::View {
                project,
                iid,
                merge_request_url,
                response,
            } => {
                let inputs = gitlab_numbered_locator_inputs(
                    project.as_deref(),
                    *iid,
                    merge_request_url.as_deref(),
                    "gitlab merge-request view",
                    "--merge-request-url",
                );
                run_typed_invoke_value(
                    ctx,
                    "gitlab.merge_request.view",
                    inputs,
                    response.read_content_format,
                    response.output_format,
                )
                .await
            }
            GitlabMergeRequestCommand::Search {
                project,
                state,
                source_branch,
                target_branch,
                labels,
                milestone,
                assignee,
                author,
                reviewer,
                search,
                created_after,
                updated_after,
                sort,
                order_by,
                max_results,
                page_token,
                response,
            } => {
                let mut inputs = serde_json::Map::new();
                inputs.insert("project".to_string(), serde_json::json!(project));
                insert_optional_json_string(&mut inputs, "state", state);
                insert_optional_json_string(&mut inputs, "sourceBranch", source_branch);
                insert_optional_json_string(&mut inputs, "targetBranch", target_branch);
                insert_optional_json_array(&mut inputs, "labels", labels);
                insert_optional_json_string(&mut inputs, "milestone", milestone);
                insert_optional_json_string(&mut inputs, "assignee", assignee);
                insert_optional_json_string(&mut inputs, "author", author);
                insert_optional_json_string(&mut inputs, "reviewer", reviewer);
                insert_optional_json_string(&mut inputs, "search", search);
                insert_optional_json_string(&mut inputs, "createdAfter", created_after);
                insert_optional_json_string(&mut inputs, "updatedAfter", updated_after);
                insert_optional_json_string(&mut inputs, "sort", sort);
                insert_optional_json_string(&mut inputs, "orderBy", order_by);
                insert_optional_json_u32(&mut inputs, "maxResults", *max_results);
                insert_optional_json_string(&mut inputs, "pageToken", page_token);
                run_typed_invoke_value(
                    ctx,
                    "gitlab.merge_request.search",
                    serde_json::Value::Object(inputs),
                    response.read_content_format,
                    response.output_format,
                )
                .await
            }
            GitlabMergeRequestCommand::ListReviewers {
                project,
                iid,
                max_results,
                page_token,
                response,
            } => {
                run_typed_invoke_value(
                    ctx,
                    "gitlab.merge_request.reviewer.list",
                    gitlab_merge_request_list_inputs(
                        project,
                        *iid,
                        *max_results,
                        page_token.as_deref(),
                    ),
                    None,
                    response.output_format,
                )
                .await
            }
            GitlabMergeRequestCommand::ListCommits {
                project,
                iid,
                max_results,
                page_token,
                response,
            } => {
                run_typed_invoke_value(
                    ctx,
                    "gitlab.merge_request.commit.list",
                    gitlab_merge_request_list_inputs(
                        project,
                        *iid,
                        *max_results,
                        page_token.as_deref(),
                    ),
                    None,
                    response.output_format,
                )
                .await
            }
            GitlabMergeRequestCommand::ListPipelines {
                project,
                iid,
                max_results,
                page_token,
                response,
            } => {
                run_typed_invoke_value(
                    ctx,
                    "gitlab.merge_request.pipeline.list",
                    gitlab_merge_request_list_inputs(
                        project,
                        *iid,
                        *max_results,
                        page_token.as_deref(),
                    ),
                    None,
                    response.output_format,
                )
                .await
            }
            GitlabMergeRequestCommand::ListDiffs {
                project,
                iid,
                unidiff,
                max_results,
                page_token,
                response,
            } => {
                run_typed_invoke_value(
                    ctx,
                    "gitlab.merge_request.diff.list",
                    gitlab_merge_request_diff_list_inputs(
                        project,
                        *iid,
                        *unidiff,
                        *max_results,
                        page_token.as_deref(),
                    ),
                    None,
                    response.output_format,
                )
                .await
            }
            GitlabMergeRequestCommand::DiffRaw { project, iid } => {
                run_attachment_download(
                    ctx,
                    "gitlab.merge_request.diff.raw.download",
                    gitlab_merge_request_inputs(project, *iid),
                    required_output(ctx),
                )
                .await
            }
            GitlabMergeRequestCommand::ListDiffVersions {
                project,
                iid,
                max_results,
                page_token,
                response,
            } => {
                run_typed_invoke_value(
                    ctx,
                    "gitlab.merge_request.diff_version.list",
                    gitlab_merge_request_list_inputs(
                        project,
                        *iid,
                        *max_results,
                        page_token.as_deref(),
                    ),
                    None,
                    response.output_format,
                )
                .await
            }
            GitlabMergeRequestCommand::ViewDiffVersion {
                project,
                iid,
                version_id,
                unidiff,
                response,
            } => {
                run_typed_invoke_value(
                    ctx,
                    "gitlab.merge_request.diff_version.view",
                    gitlab_merge_request_diff_version_inputs(project, *iid, *version_id, *unidiff),
                    None,
                    response.output_format,
                )
                .await
            }
            GitlabMergeRequestCommand::ViewDiscussion {
                project,
                iid,
                discussion_id,
                response,
            } => {
                run_typed_invoke_value(
                    ctx,
                    "gitlab.merge_request.discussion.view",
                    gitlab_merge_request_discussion_view_inputs(project, *iid, discussion_id),
                    response.read_content_format,
                    response.output_format,
                )
                .await
            }
            GitlabMergeRequestCommand::InlineDiscussion {
                project,
                iid,
                expected_head_sha,
                position,
                body,
                response,
            } => {
                let inputs = require_cli_input(gitlab_inline_discussion_inputs(
                    project,
                    *iid,
                    expected_head_sha,
                    position,
                    body,
                ));
                run_typed_invoke_value(
                    ctx,
                    "gitlab.merge_request.discussion.inline.add",
                    inputs,
                    response.read_content_format,
                    None,
                )
                .await
            }
            GitlabMergeRequestCommand::ReplyDiscussion {
                project,
                iid,
                discussion_id,
                body,
                response,
            } => {
                let inputs = require_cli_input(gitlab_discussion_reply_inputs(
                    project,
                    *iid,
                    discussion_id,
                    body,
                ));
                run_typed_invoke_value(
                    ctx,
                    "gitlab.merge_request.discussion.note.add",
                    inputs,
                    response.read_content_format,
                    None,
                )
                .await
            }
            GitlabMergeRequestCommand::ListDraftNotes {
                project,
                iid,
                max_results,
                page_token,
                projection,
                response,
            } => {
                let mut inputs = gitlab_merge_request_list_inputs(
                    project,
                    *iid,
                    *max_results,
                    page_token.as_deref(),
                );
                inputs["projection"] = serde_json::json!(projection.as_str());
                run_typed_invoke_value(
                    ctx,
                    "gitlab.merge_request.draft_note.list",
                    inputs,
                    response.read_content_format,
                    response.output_format,
                )
                .await
            }
            GitlabMergeRequestCommand::ViewDraftNote {
                project,
                iid,
                draft_note_id,
                response,
            } => {
                run_typed_invoke_value(
                    ctx,
                    "gitlab.merge_request.draft_note.view",
                    gitlab_draft_note_object_inputs(project, *iid, *draft_note_id),
                    response.read_content_format,
                    response.output_format,
                )
                .await
            }
            GitlabMergeRequestCommand::AddDraftNote {
                project,
                iid,
                expected_head_sha,
                in_reply_to_discussion_id,
                resolve_discussion,
                position,
                body,
                response,
            } => {
                let inputs = require_cli_input(gitlab_draft_note_add_inputs(
                    project,
                    *iid,
                    expected_head_sha.as_deref(),
                    in_reply_to_discussion_id.as_deref(),
                    *resolve_discussion,
                    position,
                    body,
                ));
                run_typed_invoke_value(
                    ctx,
                    "gitlab.merge_request.draft_note.add",
                    inputs,
                    response.read_content_format,
                    None,
                )
                .await
            }
            GitlabMergeRequestCommand::UpdateDraftNote {
                project,
                iid,
                draft_note_id,
                expected_head_sha,
                position,
                body,
                response,
            } => {
                let inputs = require_cli_input(gitlab_draft_note_update_inputs(
                    project,
                    *iid,
                    *draft_note_id,
                    expected_head_sha.as_deref(),
                    position,
                    body,
                ));
                run_typed_invoke_value(
                    ctx,
                    "gitlab.merge_request.draft_note.update",
                    inputs,
                    response.read_content_format,
                    None,
                )
                .await
            }
            GitlabMergeRequestCommand::DeleteDraftNote {
                project,
                iid,
                draft_note_id,
            } => {
                run_invoke_value(
                    ctx,
                    "gitlab.merge_request.draft_note.delete",
                    gitlab_draft_note_object_inputs(project, *iid, *draft_note_id),
                )
                .await
            }
            GitlabMergeRequestCommand::PublishDraftNote {
                project,
                iid,
                draft_note_id,
            } => {
                run_invoke_value(
                    ctx,
                    "gitlab.merge_request.draft_note.publish",
                    gitlab_draft_note_object_inputs(project, *iid, *draft_note_id),
                )
                .await
            }
            GitlabMergeRequestCommand::PublishAll {
                project,
                iid,
                summary,
                internal,
            } => {
                let inputs = require_cli_input(gitlab_publish_all_inputs(
                    project, *iid, None, summary, *internal,
                ));
                run_invoke_value(ctx, "gitlab.merge_request.draft_note.publish_all", inputs).await
            }
            GitlabMergeRequestCommand::SubmitReview {
                project,
                iid,
                reviewer_state,
                summary,
                internal,
            } => {
                let inputs = require_cli_input(gitlab_publish_all_inputs(
                    project,
                    *iid,
                    Some(*reviewer_state),
                    summary,
                    *internal,
                ));
                run_invoke_value(ctx, "gitlab.merge_request.review.submit", inputs).await
            }
            GitlabMergeRequestCommand::ViewApproval {
                project,
                iid,
                response,
            } => {
                run_typed_invoke_value(
                    ctx,
                    "gitlab.merge_request.approval.view",
                    gitlab_merge_request_inputs(project, *iid),
                    None,
                    response.output_format,
                )
                .await
            }
            GitlabMergeRequestCommand::ViewApprovalState {
                project,
                iid,
                response,
            } => {
                run_typed_invoke_value(
                    ctx,
                    "gitlab.merge_request.approval_state.view",
                    gitlab_merge_request_inputs(project, *iid),
                    None,
                    response.output_format,
                )
                .await
            }
            GitlabMergeRequestCommand::ListApprovalRules {
                project,
                iid,
                max_results,
                page_token,
                response,
            } => {
                run_typed_invoke_value(
                    ctx,
                    "gitlab.merge_request.approval_rule.list",
                    gitlab_merge_request_list_inputs(
                        project,
                        *iid,
                        *max_results,
                        page_token.as_deref(),
                    ),
                    None,
                    response.output_format,
                )
                .await
            }
            GitlabMergeRequestCommand::ViewApprovalRule {
                project,
                iid,
                approval_rule_id,
                response,
            } => {
                run_typed_invoke_value(
                    ctx,
                    "gitlab.merge_request.approval_rule.view",
                    gitlab_approval_rule_inputs(project, *iid, *approval_rule_id),
                    None,
                    response.output_format,
                )
                .await
            }
            GitlabMergeRequestCommand::Approve {
                project,
                iid,
                head_sha,
            } => {
                run_invoke_value(
                    ctx,
                    "gitlab.merge_request.approve",
                    gitlab_approve_inputs(project, *iid, head_sha),
                )
                .await
            }
            GitlabMergeRequestCommand::Unapprove { project, iid } => {
                run_invoke_value(
                    ctx,
                    "gitlab.merge_request.unapprove",
                    gitlab_merge_request_inputs(project, *iid),
                )
                .await
            }
            GitlabMergeRequestCommand::ApplySuggestion {
                project,
                iid,
                discussion_id,
                note_id,
                suggestion_id,
                expected_head_sha,
                commit,
            } => {
                let inputs = gitlab_suggestion_apply_inputs(
                    project,
                    *iid,
                    expected_head_sha,
                    discussion_id,
                    *note_id,
                    *suggestion_id,
                    commit,
                );
                run_invoke_value(ctx, "gitlab.merge_request.suggestion.apply", inputs).await
            }
            GitlabMergeRequestCommand::ApplySuggestions {
                project,
                iid,
                suggestions_file,
                expected_head_sha,
                commit,
            } => {
                let inputs = require_cli_input(gitlab_suggestion_batch_apply_inputs(
                    project,
                    *iid,
                    expected_head_sha,
                    suggestions_file,
                    commit,
                ));
                run_invoke_value(ctx, "gitlab.merge_request.suggestion.batch_apply", inputs).await
            }
            GitlabMergeRequestCommand::Create {
                project,
                source_branch,
                target_branch,
                title,
                content,
                content_file,
                content_format,
                labels,
                assignee_ids,
                reviewer_ids,
                remove_source_branch,
                squash,
                draft,
                response,
            } => {
                let mut inputs = serde_json::Map::new();
                inputs.insert("project".to_string(), serde_json::json!(project));
                inputs.insert("sourceBranch".to_string(), serde_json::json!(source_branch));
                inputs.insert("targetBranch".to_string(), serde_json::json!(target_branch));
                inputs.insert("title".to_string(), serde_json::json!(title));
                require_cli_input(insert_gitlab_content_inputs(
                    &mut inputs,
                    content.as_deref(),
                    content_file.as_deref(),
                    *content_format,
                    false,
                    "gitlab merge-request create",
                ));
                insert_optional_json_array(&mut inputs, "labels", labels);
                insert_optional_json_u64_array(&mut inputs, "assignees", assignee_ids);
                insert_optional_json_u64_array(&mut inputs, "reviewers", reviewer_ids);
                insert_optional_json_bool(&mut inputs, "removeSourceBranch", *remove_source_branch);
                insert_optional_json_bool(&mut inputs, "squash", *squash);
                insert_optional_json_bool(&mut inputs, "draft", *draft);
                run_typed_invoke_value(
                    ctx,
                    "gitlab.merge_request.create",
                    serde_json::Value::Object(inputs),
                    response.read_content_format,
                    None,
                )
                .await
            }
            GitlabMergeRequestCommand::Update {
                project,
                iid,
                title,
                content,
                content_file,
                content_format,
                state_event,
                labels,
                add_labels,
                remove_labels,
                assignee_ids,
                reviewer_ids,
                target_branch,
                remove_source_branch,
                squash,
                response,
            } => {
                let mut inputs = serde_json::Map::new();
                inputs.insert("project".to_string(), serde_json::json!(project));
                inputs.insert("iid".to_string(), serde_json::json!(iid));
                insert_optional_json_string(&mut inputs, "title", title);
                require_cli_input(insert_gitlab_content_inputs(
                    &mut inputs,
                    content.as_deref(),
                    content_file.as_deref(),
                    *content_format,
                    false,
                    "gitlab merge-request update",
                ));
                insert_optional_json_string(&mut inputs, "stateEvent", state_event);
                insert_optional_json_array(&mut inputs, "labels", labels);
                insert_optional_json_array(&mut inputs, "addLabels", add_labels);
                insert_optional_json_array(&mut inputs, "removeLabels", remove_labels);
                insert_optional_json_u64_array(&mut inputs, "assignees", assignee_ids);
                insert_optional_json_u64_array(&mut inputs, "reviewers", reviewer_ids);
                insert_optional_json_string(&mut inputs, "targetBranch", target_branch);
                insert_optional_json_bool(&mut inputs, "removeSourceBranch", *remove_source_branch);
                insert_optional_json_bool(&mut inputs, "squash", *squash);
                run_typed_invoke_value(
                    ctx,
                    "gitlab.merge_request.update",
                    serde_json::Value::Object(inputs),
                    response.read_content_format,
                    None,
                )
                .await
            }
            GitlabMergeRequestCommand::Comment {
                project,
                iid,
                content,
                content_file,
                content_format,
                response,
            } => {
                run_gitlab_content_command(
                    ctx,
                    GitlabContentCommandArgs {
                        action: "gitlab.merge_request.note.add",
                        project,
                        iid: *iid,
                        content: content.as_deref(),
                        content_file: content_file.as_deref(),
                        content_format: *content_format,
                        command: "gitlab merge-request comment",
                        read_content_format: response.read_content_format,
                    },
                )
                .await
            }
            GitlabMergeRequestCommand::UpdateComment {
                project,
                iid,
                note_id,
                content,
                content_file,
                content_format,
                response,
            } => {
                run_gitlab_note_content_command(
                    ctx,
                    GitlabNoteContentCommandArgs {
                        action: "gitlab.merge_request.note.update",
                        project,
                        iid: *iid,
                        note_id: *note_id,
                        content: content.as_deref(),
                        content_file: content_file.as_deref(),
                        content_format: *content_format,
                        command: "gitlab merge-request update-comment",
                        read_content_format: response.read_content_format,
                    },
                )
                .await
            }
            GitlabMergeRequestCommand::DeleteComment {
                project,
                iid,
                note_id,
            } => {
                run_gitlab_note_delete_command(
                    ctx,
                    "gitlab.merge_request.note.delete",
                    project,
                    *iid,
                    *note_id,
                )
                .await
            }
            GitlabMergeRequestCommand::ViewComment {
                project,
                iid,
                note_id,
                response,
            } => {
                run_typed_invoke_value(
                    ctx,
                    "gitlab.merge_request.note.view",
                    serde_json::json!({"project": project, "iid": iid, "noteId": note_id}),
                    response.read_content_format,
                    response.output_format,
                )
                .await
            }
            GitlabMergeRequestCommand::ListComments {
                project,
                iid,
                max_results,
                sort,
                order_by,
                page_token,
                projection,
                response,
            } => {
                let mut inputs = serde_json::Map::new();
                inputs.insert("project".to_string(), serde_json::json!(project));
                inputs.insert("iid".to_string(), serde_json::json!(iid));
                insert_optional_json_u32(&mut inputs, "maxResults", *max_results);
                insert_optional_json_string(&mut inputs, "sort", sort);
                insert_optional_json_string(&mut inputs, "orderBy", order_by);
                insert_optional_json_string(&mut inputs, "pageToken", page_token);
                inputs.insert(
                    "projection".to_string(),
                    serde_json::json!(projection.as_str()),
                );
                run_typed_invoke_value(
                    ctx,
                    "gitlab.merge_request.note.list",
                    serde_json::Value::Object(inputs),
                    response.read_content_format,
                    response.output_format,
                )
                .await
            }
            GitlabMergeRequestCommand::Discussion {
                project,
                iid,
                content,
                content_file,
                content_format,
                response,
            } => {
                run_gitlab_content_command(
                    ctx,
                    GitlabContentCommandArgs {
                        action: "gitlab.merge_request.discussion.add",
                        project,
                        iid: *iid,
                        content: content.as_deref(),
                        content_file: content_file.as_deref(),
                        content_format: *content_format,
                        command: "gitlab merge-request discussion",
                        read_content_format: response.read_content_format,
                    },
                )
                .await
            }
            GitlabMergeRequestCommand::UpdateDiscussionNote {
                project,
                iid,
                discussion_id,
                note_id,
                content,
                content_file,
                content_format,
                response,
            } => {
                run_gitlab_discussion_note_content_command(
                    ctx,
                    GitlabDiscussionNoteContentArgs {
                        action: "gitlab.merge_request.discussion.note.update",
                        project,
                        iid: *iid,
                        discussion_id,
                        note_id: *note_id,
                        content: content.as_deref(),
                        content_file: content_file.as_deref(),
                        content_format: *content_format,
                        command: "gitlab merge-request update-discussion-note",
                        read_content_format: response.read_content_format,
                    },
                )
                .await
            }
            GitlabMergeRequestCommand::DeleteDiscussionNote {
                project,
                iid,
                discussion_id,
                note_id,
            } => {
                run_gitlab_discussion_note_delete_command(
                    ctx,
                    "gitlab.merge_request.discussion.note.delete",
                    project,
                    *iid,
                    discussion_id,
                    *note_id,
                )
                .await
            }
            GitlabMergeRequestCommand::ResolveDiscussion {
                project,
                iid,
                discussion_id,
                response,
            } => {
                run_gitlab_discussion_state_command(
                    ctx,
                    "gitlab.merge_request.discussion.resolve",
                    project,
                    *iid,
                    discussion_id,
                    response.read_content_format,
                )
                .await
            }
            GitlabMergeRequestCommand::ReopenDiscussion {
                project,
                iid,
                discussion_id,
                response,
            } => {
                run_gitlab_discussion_state_command(
                    ctx,
                    "gitlab.merge_request.discussion.reopen",
                    project,
                    *iid,
                    discussion_id,
                    response.read_content_format,
                )
                .await
            }
            GitlabMergeRequestCommand::ListDiscussions {
                project,
                iid,
                max_results,
                page_token,
                projection,
                response,
            } => {
                let mut inputs = gitlab_merge_request_list_inputs(
                    project,
                    *iid,
                    *max_results,
                    page_token.as_deref(),
                );
                inputs["projection"] = serde_json::json!(projection.as_str());
                run_typed_invoke_value(
                    ctx,
                    "gitlab.merge_request.discussion.list",
                    inputs,
                    response.read_content_format,
                    response.output_format,
                )
                .await
            }
            GitlabMergeRequestCommand::Merge {
                project,
                iid,
                sha,
                squash,
                should_remove_source_branch,
                merge_commit_message_file,
                squash_commit_message_file,
            } => {
                let mut inputs = serde_json::Map::new();
                inputs.insert("project".to_string(), serde_json::json!(project));
                inputs.insert("iid".to_string(), serde_json::json!(iid));
                inputs.insert("sha".to_string(), serde_json::json!(sha));
                insert_optional_json_bool(&mut inputs, "squash", *squash);
                insert_optional_json_bool(
                    &mut inputs,
                    "shouldRemoveSourceBranch",
                    *should_remove_source_branch,
                );
                insert_optional_text_file(
                    &mut inputs,
                    "mergeCommitMessage",
                    merge_commit_message_file,
                );
                insert_optional_text_file(
                    &mut inputs,
                    "squashCommitMessage",
                    squash_commit_message_file,
                );
                run_invoke_value(
                    ctx,
                    "gitlab.merge_request.merge",
                    serde_json::Value::Object(inputs),
                )
                .await
            }
        },
        GitlabCommand::Branch { command } => match command {
            GitlabBranchCommand::List {
                project,
                search,
                regex,
                max_results,
                response,
            } => {
                let mut inputs = serde_json::Map::new();
                inputs.insert("project".to_string(), serde_json::json!(project));
                insert_optional_json_string(&mut inputs, "search", search);
                insert_optional_json_string(&mut inputs, "regex", regex);
                insert_optional_json_u32(&mut inputs, "maxResults", *max_results);
                run_typed_invoke_value(
                    ctx,
                    "gitlab.branch.list",
                    serde_json::Value::Object(inputs),
                    None,
                    response.output_format,
                )
                .await
            }
            GitlabBranchCommand::View {
                project,
                branch,
                response,
            } => {
                run_typed_invoke_value(
                    ctx,
                    "gitlab.branch.view",
                    serde_json::json!({
                        "project": project,
                        "branch": branch,
                    }),
                    None,
                    response.output_format,
                )
                .await
            }
            GitlabBranchCommand::Create {
                project,
                branch,
                ref_name,
            } => {
                run_invoke_value(
                    ctx,
                    "gitlab.branch.create",
                    serde_json::json!({
                        "project": project,
                        "branch": branch,
                        "ref": ref_name,
                    }),
                )
                .await
            }
        },
        GitlabCommand::ProtectedBranch { command } => match command {
            GitlabProtectedBranchCommand::List {
                project,
                search,
                max_results,
                response,
            } => {
                let mut inputs = serde_json::Map::new();
                inputs.insert("project".to_string(), serde_json::json!(project));
                insert_optional_json_string(&mut inputs, "search", search);
                insert_optional_json_u32(&mut inputs, "maxResults", *max_results);
                run_typed_invoke_value(
                    ctx,
                    "gitlab.protected_branch.list",
                    serde_json::Value::Object(inputs),
                    None,
                    response.output_format,
                )
                .await
            }
            GitlabProtectedBranchCommand::View {
                project,
                branch_or_wildcard_name,
                response,
            } => {
                run_typed_invoke_value(
                    ctx,
                    "gitlab.protected_branch.view",
                    serde_json::json!({
                        "project": project,
                        "branchOrWildcardName": branch_or_wildcard_name,
                    }),
                    None,
                    response.output_format,
                )
                .await
            }
            GitlabProtectedBranchCommand::Verify {
                project,
                required_patterns,
                response,
            } => {
                let mut inputs = serde_json::Map::new();
                inputs.insert("project".to_string(), serde_json::json!(project));
                insert_optional_json_array(&mut inputs, "requiredPatterns", required_patterns);
                run_typed_invoke_value(
                    ctx,
                    "gitlab.protected_branch.verify",
                    serde_json::Value::Object(inputs),
                    None,
                    response.output_format,
                )
                .await
            }
        },
        GitlabCommand::File { command } => match command {
            GitlabFileCommand::View {
                project,
                path,
                ref_name,
                response,
            } => {
                run_typed_invoke_value(
                    ctx,
                    "gitlab.file.view",
                    serde_json::json!({
                        "project": project,
                        "path": path,
                        "ref": ref_name,
                    }),
                    None,
                    response.output_format,
                )
                .await
            }
            GitlabFileCommand::Raw {
                project,
                path,
                ref_name,
            } => {
                run_attachment_download(
                    ctx,
                    "gitlab.file.raw.download",
                    serde_json::json!({
                        "project": project,
                        "path": path,
                        "ref": ref_name,
                    }),
                    required_output(ctx),
                )
                .await
            }
            GitlabFileCommand::Create {
                project,
                path,
                branch,
                content_file,
                commit_message,
                start_branch,
                author_name,
                author_email,
                execute_filemode,
            } => {
                let inputs = gitlab_file_write_inputs(GitlabFileWriteCliInput {
                    project,
                    path,
                    branch,
                    content_file,
                    commit_message,
                    start_branch,
                    author_name,
                    author_email,
                    execute_filemode,
                });
                run_invoke_value(ctx, "gitlab.file.create", serde_json::Value::Object(inputs)).await
            }
            GitlabFileCommand::Update {
                project,
                path,
                branch,
                content_file,
                commit_message,
                last_commit_id,
                start_branch,
                author_name,
                author_email,
                execute_filemode,
            } => {
                let mut inputs = gitlab_file_write_inputs(GitlabFileWriteCliInput {
                    project,
                    path,
                    branch,
                    content_file,
                    commit_message,
                    start_branch,
                    author_name,
                    author_email,
                    execute_filemode,
                });
                insert_optional_json_string(&mut inputs, "lastCommitId", last_commit_id);
                run_invoke_value(ctx, "gitlab.file.update", serde_json::Value::Object(inputs)).await
            }
            GitlabFileCommand::Delete {
                project,
                path,
                branch,
                commit_message,
                last_commit_id,
                start_branch,
                author_name,
                author_email,
            } => {
                let mut inputs = serde_json::Map::new();
                inputs.insert("project".to_string(), serde_json::json!(project));
                inputs.insert("path".to_string(), serde_json::json!(path));
                inputs.insert("branch".to_string(), serde_json::json!(branch));
                inputs.insert(
                    "commitMessage".to_string(),
                    serde_json::json!(commit_message),
                );
                insert_optional_json_string(&mut inputs, "lastCommitId", last_commit_id);
                insert_optional_json_string(&mut inputs, "startBranch", start_branch);
                insert_optional_json_string(&mut inputs, "authorName", author_name);
                insert_optional_json_string(&mut inputs, "authorEmail", author_email);
                run_invoke_value(ctx, "gitlab.file.delete", serde_json::Value::Object(inputs)).await
            }
        },
        GitlabCommand::Commit { command } => match command {
            GitlabCommitCommand::List {
                project,
                ref_name,
                path,
                since,
                until,
                first_parent,
                max_results,
                response,
            } => {
                let mut inputs = serde_json::Map::new();
                inputs.insert("project".to_string(), serde_json::json!(project));
                insert_optional_json_string(&mut inputs, "refName", ref_name);
                insert_optional_json_string(&mut inputs, "path", path);
                insert_optional_json_string(&mut inputs, "since", since);
                insert_optional_json_string(&mut inputs, "until", until);
                if let Some(first_parent) = first_parent {
                    inputs.insert("firstParent".to_string(), serde_json::json!(first_parent));
                }
                insert_optional_json_u32(&mut inputs, "maxResults", *max_results);
                run_typed_invoke_value(
                    ctx,
                    "gitlab.commit.list",
                    serde_json::Value::Object(inputs),
                    None,
                    response.output_format,
                )
                .await
            }
            GitlabCommitCommand::View {
                project,
                sha,
                response,
            } => {
                run_typed_invoke_value(
                    ctx,
                    "gitlab.commit.view",
                    serde_json::json!({
                        "project": project,
                        "sha": sha,
                    }),
                    None,
                    response.output_format,
                )
                .await
            }
            GitlabCommitCommand::Create {
                project,
                branch,
                commit_message,
                actions_file,
                start_branch,
                start_sha,
                author_name,
                author_email,
            } => {
                let mut inputs = serde_json::Map::new();
                inputs.insert("project".to_string(), serde_json::json!(project));
                inputs.insert("branch".to_string(), serde_json::json!(branch));
                inputs.insert(
                    "commitMessage".to_string(),
                    serde_json::json!(commit_message),
                );
                inputs.insert("actions".to_string(), read_json_file(actions_file));
                insert_optional_json_string(&mut inputs, "startBranch", start_branch);
                insert_optional_json_string(&mut inputs, "startSha", start_sha);
                insert_optional_json_string(&mut inputs, "authorName", author_name);
                insert_optional_json_string(&mut inputs, "authorEmail", author_email);
                run_invoke_value(
                    ctx,
                    "gitlab.commit.create",
                    serde_json::Value::Object(inputs),
                )
                .await
            }
        },
        GitlabCommand::Pipeline { command } => match command {
            GitlabPipelineCommand::List {
                project,
                ref_name,
                sha,
                status,
                source,
                updated_after,
                updated_before,
                max_results,
                response,
            } => {
                let mut inputs = serde_json::Map::new();
                inputs.insert("project".to_string(), serde_json::json!(project));
                insert_optional_json_string(&mut inputs, "ref", ref_name);
                insert_optional_json_string(&mut inputs, "sha", sha);
                insert_optional_json_string(&mut inputs, "status", status);
                insert_optional_json_string(&mut inputs, "source", source);
                insert_optional_json_string(&mut inputs, "updatedAfter", updated_after);
                insert_optional_json_string(&mut inputs, "updatedBefore", updated_before);
                insert_optional_json_u32(&mut inputs, "maxResults", *max_results);
                run_typed_invoke_value(
                    ctx,
                    "gitlab.pipeline.list",
                    serde_json::Value::Object(inputs),
                    None,
                    response.output_format,
                )
                .await
            }
            GitlabPipelineCommand::View {
                project,
                pipeline_id,
                response,
            } => {
                run_typed_invoke_value(
                    ctx,
                    "gitlab.pipeline.view",
                    serde_json::json!({
                        "project": project,
                        "pipelineId": pipeline_id,
                    }),
                    None,
                    response.output_format,
                )
                .await
            }
            GitlabPipelineCommand::Run { project, ref_name } => {
                run_invoke_value(
                    ctx,
                    "gitlab.pipeline.run",
                    serde_json::json!({
                        "project": project,
                        "ref": ref_name,
                    }),
                )
                .await
            }
            GitlabPipelineCommand::Retry {
                project,
                pipeline_id,
            } => {
                run_invoke_value(
                    ctx,
                    "gitlab.pipeline.retry",
                    serde_json::json!({
                        "project": project,
                        "pipelineId": pipeline_id,
                    }),
                )
                .await
            }
            GitlabPipelineCommand::Cancel {
                project,
                pipeline_id,
            } => {
                run_invoke_value(
                    ctx,
                    "gitlab.pipeline.cancel",
                    serde_json::json!({
                        "project": project,
                        "pipelineId": pipeline_id,
                    }),
                )
                .await
            }
        },
        GitlabCommand::Job { command } => match command {
            GitlabJobCommand::List {
                project,
                pipeline_id,
                scope,
                max_results,
                response,
            } => {
                let mut inputs = serde_json::Map::new();
                inputs.insert("project".to_string(), serde_json::json!(project));
                if let Some(pipeline_id) = pipeline_id {
                    inputs.insert("pipelineId".to_string(), serde_json::json!(pipeline_id));
                }
                insert_optional_json_string(&mut inputs, "scope", scope);
                insert_optional_json_u32(&mut inputs, "maxResults", *max_results);
                run_typed_invoke_value(
                    ctx,
                    "gitlab.job.list",
                    serde_json::Value::Object(inputs),
                    None,
                    response.output_format,
                )
                .await
            }
            GitlabJobCommand::View {
                project,
                job_id,
                response,
            } => {
                run_typed_invoke_value(
                    ctx,
                    "gitlab.job.view",
                    serde_json::json!({
                        "project": project,
                        "jobId": job_id,
                    }),
                    None,
                    response.output_format,
                )
                .await
            }
            GitlabJobCommand::Trace { project, job_id } => {
                run_attachment_download(
                    ctx,
                    "gitlab.job.trace.download",
                    serde_json::json!({
                        "project": project,
                        "jobId": job_id,
                    }),
                    required_output(ctx),
                )
                .await
            }
            GitlabJobCommand::Retry { project, job_id } => {
                run_invoke_value(
                    ctx,
                    "gitlab.job.retry",
                    serde_json::json!({
                        "project": project,
                        "jobId": job_id,
                    }),
                )
                .await
            }
            GitlabJobCommand::Cancel { project, job_id } => {
                run_invoke_value(
                    ctx,
                    "gitlab.job.cancel",
                    serde_json::json!({
                        "project": project,
                        "jobId": job_id,
                    }),
                )
                .await
            }
            GitlabJobCommand::Play { project, job_id } => {
                run_invoke_value(
                    ctx,
                    "gitlab.job.play",
                    serde_json::json!({
                        "project": project,
                        "jobId": job_id,
                    }),
                )
                .await
            }
        },
        GitlabCommand::Webhook { command } => match command {
            GitlabWebhookCommand::List {
                project,
                max_results,
                page_token,
            } => {
                let mut inputs = serde_json::Map::new();
                inputs.insert("project".to_string(), serde_json::json!(project));
                insert_optional_json_u32(&mut inputs, "maxResults", *max_results);
                insert_optional_json_string(&mut inputs, "pageToken", page_token);
                run_invoke_value(
                    ctx,
                    "gitlab.webhook.list",
                    serde_json::Value::Object(inputs),
                )
                .await
            }
            GitlabWebhookCommand::View {
                project,
                webhook_id,
            } => {
                run_invoke_value(
                    ctx,
                    "gitlab.webhook.view",
                    serde_json::json!({
                        "project": project,
                        "webhookId": webhook_id,
                    }),
                )
                .await
            }
            GitlabWebhookCommand::Create {
                project,
                destination_url,
                events,
                name,
                description,
                enable_ssl_verification,
                branch_filter_strategy,
                push_events_branch_filter,
                custom_webhook_template,
                secret_token_env,
                secret_token_file,
                secret_token_stdin,
                signing_token_env,
                signing_token_file,
                signing_token_stdin,
            } => {
                ensure_single_webhook_secret_stdin(*secret_token_stdin, *signing_token_stdin)?;
                let token = read_webhook_secret_source(
                    "secret token",
                    secret_token_env.as_deref(),
                    secret_token_file.as_deref(),
                    *secret_token_stdin,
                )?;
                let signing_token = read_webhook_secret_source(
                    "signing token",
                    signing_token_env.as_deref(),
                    signing_token_file.as_deref(),
                    *signing_token_stdin,
                )?;
                let mut inputs = serde_json::Map::new();
                inputs.insert("project".to_string(), serde_json::json!(project));
                inputs.insert("url".to_string(), serde_json::json!(destination_url));
                inputs.insert(
                    "events".to_string(),
                    serde_json::json!(
                        events
                            .iter()
                            .map(|event| event.as_str())
                            .collect::<Vec<_>>()
                    ),
                );
                insert_optional_json_string(&mut inputs, "name", name);
                insert_optional_json_string(&mut inputs, "description", description);
                insert_optional_json_bool(
                    &mut inputs,
                    "enableSslVerification",
                    *enable_ssl_verification,
                );
                if let Some(strategy) = branch_filter_strategy {
                    inputs.insert(
                        "branchFilterStrategy".to_string(),
                        serde_json::json!(strategy.as_str()),
                    );
                }
                insert_optional_json_string(
                    &mut inputs,
                    "pushEventsBranchFilter",
                    push_events_branch_filter,
                );
                insert_optional_json_string(
                    &mut inputs,
                    "customWebhookTemplate",
                    custom_webhook_template,
                );
                insert_optional_owned_json_string(&mut inputs, "token", token);
                insert_optional_owned_json_string(&mut inputs, "signingToken", signing_token);
                run_invoke_value(
                    ctx,
                    "gitlab.webhook.create",
                    serde_json::Value::Object(inputs),
                )
                .await
            }
            GitlabWebhookCommand::Update {
                project,
                webhook_id,
                destination_url,
                events,
                clear_events,
                name,
                clear_name,
                description,
                clear_description,
                enable_ssl_verification,
                branch_filter_strategy,
                push_events_branch_filter,
                custom_webhook_template,
                clear_custom_webhook_template,
                secret_token_env,
                secret_token_file,
                secret_token_stdin,
                clear_token,
                signing_token_env,
                signing_token_file,
                signing_token_stdin,
                confirm_destination_reset,
            } => {
                ensure_single_webhook_secret_stdin(*secret_token_stdin, *signing_token_stdin)?;
                let token = read_webhook_secret_source(
                    "secret token",
                    secret_token_env.as_deref(),
                    secret_token_file.as_deref(),
                    *secret_token_stdin,
                )?;
                let signing_token = read_webhook_secret_source(
                    "signing token",
                    signing_token_env.as_deref(),
                    signing_token_file.as_deref(),
                    *signing_token_stdin,
                )?;
                let mut inputs = serde_json::Map::new();
                inputs.insert("project".to_string(), serde_json::json!(project));
                inputs.insert("webhookId".to_string(), serde_json::json!(webhook_id));
                insert_optional_json_string(&mut inputs, "url", destination_url);
                if *clear_events {
                    inputs.insert("events".to_string(), serde_json::json!([]));
                } else if !events.is_empty() {
                    inputs.insert(
                        "events".to_string(),
                        serde_json::json!(
                            events
                                .iter()
                                .map(|event| event.as_str())
                                .collect::<Vec<_>>()
                        ),
                    );
                }
                insert_optional_or_null_json_string(&mut inputs, "name", name, *clear_name);
                insert_optional_or_null_json_string(
                    &mut inputs,
                    "description",
                    description,
                    *clear_description,
                );
                insert_optional_json_bool(
                    &mut inputs,
                    "enableSslVerification",
                    *enable_ssl_verification,
                );
                if let Some(strategy) = branch_filter_strategy {
                    inputs.insert(
                        "branchFilterStrategy".to_string(),
                        serde_json::json!(strategy.as_str()),
                    );
                }
                insert_optional_json_string(
                    &mut inputs,
                    "pushEventsBranchFilter",
                    push_events_branch_filter,
                );
                insert_optional_or_null_json_string(
                    &mut inputs,
                    "customWebhookTemplate",
                    custom_webhook_template,
                    *clear_custom_webhook_template,
                );
                insert_optional_owned_json_string(&mut inputs, "token", token);
                insert_optional_owned_json_string(&mut inputs, "signingToken", signing_token);
                if *clear_token {
                    inputs.insert("clearToken".to_string(), serde_json::json!(true));
                }
                if *confirm_destination_reset {
                    inputs.insert(
                        "confirmDestinationReset".to_string(),
                        serde_json::json!(true),
                    );
                }
                ensure_webhook_update_has_changes(&inputs)?;
                run_invoke_value(
                    ctx,
                    "gitlab.webhook.update",
                    serde_json::Value::Object(inputs),
                )
                .await
            }
            GitlabWebhookCommand::Delete {
                project,
                webhook_id,
            } => {
                run_invoke_value(
                    ctx,
                    "gitlab.webhook.delete",
                    serde_json::json!({
                        "project": project,
                        "webhookId": webhook_id,
                    }),
                )
                .await
            }
            GitlabWebhookCommand::Test {
                project,
                webhook_id,
                event,
            } => {
                run_invoke_value(
                    ctx,
                    "gitlab.webhook.test",
                    serde_json::json!({
                        "project": project,
                        "webhookId": webhook_id,
                        "event": event.as_str(),
                    }),
                )
                .await
            }
            GitlabWebhookCommand::Event { command } => match command {
                GitlabWebhookEventCommand::List {
                    project,
                    webhook_id,
                    status,
                    max_results,
                    page_token,
                } => {
                    let mut inputs = serde_json::Map::new();
                    inputs.insert("project".to_string(), serde_json::json!(project));
                    inputs.insert("webhookId".to_string(), serde_json::json!(webhook_id));
                    insert_optional_json_string(&mut inputs, "status", status);
                    insert_optional_json_u32(&mut inputs, "maxResults", *max_results);
                    insert_optional_json_string(&mut inputs, "pageToken", page_token);
                    run_invoke_value(
                        ctx,
                        "gitlab.webhook.event.list",
                        serde_json::Value::Object(inputs),
                    )
                    .await
                }
                GitlabWebhookEventCommand::Resend {
                    project,
                    webhook_id,
                    webhook_event_id,
                } => {
                    run_invoke_value(
                        ctx,
                        "gitlab.webhook.event.resend",
                        serde_json::json!({
                            "project": project,
                            "webhookId": webhook_id,
                            "webhookEventId": webhook_event_id,
                        }),
                    )
                    .await
                }
            },
            GitlabWebhookCommand::CustomHeader { command } => match command {
                GitlabWebhookCustomHeaderCommand::Set {
                    project,
                    webhook_id,
                    key,
                    value_env,
                    value_file,
                    value_stdin,
                } => {
                    let value = read_webhook_secret_source(
                        "custom header value",
                        value_env.as_deref(),
                        value_file.as_deref(),
                        *value_stdin,
                    )?
                    .ok_or_else(|| {
                        anyhow::anyhow!(
                            "custom-header set requires one of --value-env, --value-file, or --value-stdin"
                        )
                    })?;
                    run_invoke_value(
                        ctx,
                        "gitlab.webhook.custom_header.set",
                        serde_json::json!({
                            "project": project,
                            "webhookId": webhook_id,
                            "key": key,
                            "value": value,
                        }),
                    )
                    .await
                }
                GitlabWebhookCustomHeaderCommand::Delete {
                    project,
                    webhook_id,
                    key,
                } => {
                    run_invoke_value(
                        ctx,
                        "gitlab.webhook.custom_header.delete",
                        serde_json::json!({
                            "project": project,
                            "webhookId": webhook_id,
                            "key": key,
                        }),
                    )
                    .await
                }
            },
        },
    }
}

fn gitlab_project_locator_inputs(
    project: Option<&str>,
    url: Option<&str>,
    label: &str,
) -> serde_json::Value {
    match (project, url) {
        (Some(project), None) => serde_json::json!({ "project": project }),
        (None, Some(url)) => serde_json::json!({ "url": url }),
        _ => require_cli_input(Err(anyhow::anyhow!(
            "{label} requires exactly one project argument or --project-url"
        ))),
    }
}

fn gitlab_numbered_locator_inputs(
    project: Option<&str>,
    iid: Option<u64>,
    url: Option<&str>,
    label: &str,
    url_flag: &str,
) -> serde_json::Value {
    match (project, iid, url) {
        (Some(project), Some(iid), None) => serde_json::json!({
            "project": project,
            "iid": iid,
        }),
        (None, None, Some(url)) => serde_json::json!({ "url": url }),
        _ => require_cli_input(Err(anyhow::anyhow!(
            "{label} requires either project and iid arguments or {url_flag}"
        ))),
    }
}

fn gitlab_merge_request_input_map(
    project: &str,
    iid: u64,
) -> serde_json::Map<String, serde_json::Value> {
    let mut inputs = serde_json::Map::new();
    inputs.insert("project".to_string(), serde_json::json!(project));
    inputs.insert("iid".to_string(), serde_json::json!(iid));
    inputs
}

fn gitlab_merge_request_list_input_map(
    project: &str,
    iid: u64,
    max_results: Option<u32>,
    page_token: Option<&str>,
) -> serde_json::Map<String, serde_json::Value> {
    let mut inputs = gitlab_merge_request_input_map(project, iid);
    insert_optional_json_u32(&mut inputs, "maxResults", max_results);
    if let Some(page_token) = page_token {
        inputs.insert("pageToken".to_string(), serde_json::json!(page_token));
    }
    inputs
}

fn gitlab_merge_request_inputs(project: &str, iid: u64) -> serde_json::Value {
    serde_json::json!({
        "project": project,
        "iid": iid,
    })
}

fn gitlab_merge_request_list_inputs(
    project: &str,
    iid: u64,
    max_results: Option<u32>,
    page_token: Option<&str>,
) -> serde_json::Value {
    serde_json::Value::Object(gitlab_merge_request_list_input_map(
        project,
        iid,
        max_results,
        page_token,
    ))
}

fn gitlab_approval_rule_inputs(
    project: &str,
    iid: u64,
    approval_rule_id: u64,
) -> serde_json::Value {
    serde_json::json!({
        "project": project,
        "iid": iid,
        "approvalRuleId": approval_rule_id,
    })
}

fn gitlab_approve_inputs(project: &str, iid: u64, head_sha: &str) -> serde_json::Value {
    serde_json::json!({
        "project": project,
        "iid": iid,
        "headSha": head_sha,
    })
}

fn insert_gitlab_commit_message(
    inputs: &mut serde_json::Map<String, serde_json::Value>,
    commit: &GitlabOptionalCommitMessageArgs,
) {
    let message = commit.commit_message.clone().or_else(|| {
        commit
            .commit_message_file
            .as_deref()
            .map(read_gitlab_text_file)
    });
    if let Some(message) = message {
        inputs.insert("commitMessage".to_string(), serde_json::json!(message));
    }
}

fn gitlab_suggestion_apply_inputs(
    project: &str,
    iid: u64,
    expected_head_sha: &str,
    discussion_id: &str,
    note_id: u64,
    suggestion_id: u64,
    commit: &GitlabOptionalCommitMessageArgs,
) -> serde_json::Value {
    let mut inputs = gitlab_merge_request_input_map(project, iid);
    inputs.insert(
        "expectedHeadSha".to_string(),
        serde_json::json!(expected_head_sha),
    );
    inputs.insert("discussionId".to_string(), serde_json::json!(discussion_id));
    inputs.insert("noteId".to_string(), serde_json::json!(note_id));
    inputs.insert("suggestionId".to_string(), serde_json::json!(suggestion_id));
    insert_gitlab_commit_message(&mut inputs, commit);
    serde_json::Value::Object(inputs)
}

fn gitlab_suggestion_batch_apply_inputs(
    project: &str,
    iid: u64,
    expected_head_sha: &str,
    suggestions_file: &Path,
    commit: &GitlabOptionalCommitMessageArgs,
) -> Result<serde_json::Value> {
    let suggestions = read_json_file(suggestions_file);
    if !suggestions.is_array() {
        anyhow::bail!(
            "gitlab merge-request apply-suggestions --suggestions-file must contain one JSON array"
        );
    }
    let mut inputs = gitlab_merge_request_input_map(project, iid);
    inputs.insert(
        "expectedHeadSha".to_string(),
        serde_json::json!(expected_head_sha),
    );
    inputs.insert("suggestions".to_string(), suggestions);
    insert_gitlab_commit_message(&mut inputs, commit);
    Ok(serde_json::Value::Object(inputs))
}

fn gitlab_merge_request_diff_list_inputs(
    project: &str,
    iid: u64,
    unidiff: bool,
    max_results: Option<u32>,
    page_token: Option<&str>,
) -> serde_json::Value {
    let mut inputs = gitlab_merge_request_list_input_map(project, iid, max_results, page_token);
    insert_optional_json_bool(&mut inputs, "unidiff", unidiff.then_some(true));
    serde_json::Value::Object(inputs)
}

fn gitlab_merge_request_diff_version_inputs(
    project: &str,
    iid: u64,
    diff_version_id: u64,
    unidiff: bool,
) -> serde_json::Value {
    let mut inputs = serde_json::Map::new();
    inputs.insert("project".to_string(), serde_json::json!(project));
    inputs.insert("iid".to_string(), serde_json::json!(iid));
    inputs.insert(
        "diffVersionId".to_string(),
        serde_json::json!(diff_version_id),
    );
    insert_optional_json_bool(&mut inputs, "unidiff", unidiff.then_some(true));
    serde_json::Value::Object(inputs)
}

fn gitlab_merge_request_discussion_view_inputs(
    project: &str,
    iid: u64,
    discussion_id: &str,
) -> serde_json::Value {
    serde_json::json!({
        "project": project,
        "iid": iid,
        "discussionId": discussion_id,
    })
}

fn gitlab_draft_note_object_inputs(
    project: &str,
    iid: u64,
    draft_note_id: u64,
) -> serde_json::Value {
    serde_json::json!({
        "project": project,
        "iid": iid,
        "draftNoteId": draft_note_id,
    })
}

fn gitlab_position_coordinate(
    old_line: Option<u64>,
    new_line: Option<u64>,
    label: &str,
) -> Result<serde_json::Value> {
    if old_line == Some(0) || new_line == Some(0) {
        anyhow::bail!("{label} line numbers must be positive");
    }
    if old_line.is_none() && new_line.is_none() {
        anyhow::bail!("{label} requires --old-line, --new-line, or both");
    }
    let mut coordinate = serde_json::Map::new();
    if let Some(old_line) = old_line {
        coordinate.insert("oldLine".to_string(), serde_json::json!(old_line));
    }
    if let Some(new_line) = new_line {
        coordinate.insert("newLine".to_string(), serde_json::json!(new_line));
    }
    Ok(serde_json::Value::Object(coordinate))
}

fn gitlab_position_value(
    args: &GitlabPositionArgs,
    required: bool,
    command: &str,
) -> Result<Option<serde_json::Value>> {
    if let Some(path) = &args.position_file {
        let value = read_json_file(path);
        if !value.is_object() {
            anyhow::bail!("{command} --position-file must contain one JSON object");
        }
        return Ok(Some(value));
    }

    let Some(position_type) = args.position_type else {
        if required {
            anyhow::bail!(
                "{command} requires --position-file or --position-type with position fields"
            );
        }
        return Ok(None);
    };
    let old_path = args
        .old_path
        .as_deref()
        .filter(|value| !value.is_empty())
        .ok_or_else(|| anyhow::anyhow!("{command} requires a non-empty --old-path"))?;
    let new_path = args
        .new_path
        .as_deref()
        .filter(|value| !value.is_empty())
        .ok_or_else(|| anyhow::anyhow!("{command} requires a non-empty --new-path"))?;

    let has_scalar_lines = args.old_line.is_some() || args.new_line.is_some();
    let has_range = args.range_start_old_line.is_some()
        || args.range_start_new_line.is_some()
        || args.range_end_old_line.is_some()
        || args.range_end_new_line.is_some();
    let has_image = args.position_width.is_some()
        || args.position_height.is_some()
        || args.position_x.is_some()
        || args.position_y.is_some();
    let mut position = serde_json::Map::new();
    position.insert(
        "positionType".to_string(),
        serde_json::json!(position_type.as_str()),
    );
    position.insert("oldPath".to_string(), serde_json::json!(old_path));
    position.insert("newPath".to_string(), serde_json::json!(new_path));

    match position_type {
        GitlabPositionTypeArg::Text => {
            if has_image {
                anyhow::bail!("{command} text positions reject image coordinate flags");
            }
            if has_range {
                if has_scalar_lines {
                    anyhow::bail!(
                        "{command} multiline positions reject top-level --old-line/--new-line"
                    );
                }
                let start = gitlab_position_coordinate(
                    args.range_start_old_line,
                    args.range_start_new_line,
                    "range start",
                )?;
                let end = gitlab_position_coordinate(
                    args.range_end_old_line,
                    args.range_end_new_line,
                    "range end",
                )?;
                position.insert(
                    "lineRange".to_string(),
                    serde_json::json!({ "start": start, "end": end }),
                );
            } else {
                let coordinate =
                    gitlab_position_coordinate(args.old_line, args.new_line, "text position")?;
                position.extend(coordinate.as_object().cloned().unwrap_or_default());
            }
        }
        GitlabPositionTypeArg::File => {
            if has_scalar_lines || has_range || has_image {
                anyhow::bail!("{command} file positions reject line, range, and image fields");
            }
        }
        GitlabPositionTypeArg::Image => {
            if has_scalar_lines || has_range {
                anyhow::bail!("{command} image positions reject line and range fields");
            }
            let width = args
                .position_width
                .filter(|value| *value > 0)
                .ok_or_else(|| anyhow::anyhow!("{command} requires positive --position-width"))?;
            let height = args
                .position_height
                .filter(|value| *value > 0)
                .ok_or_else(|| anyhow::anyhow!("{command} requires positive --position-height"))?;
            let x = args
                .position_x
                .ok_or_else(|| anyhow::anyhow!("{command} requires --position-x"))?;
            let y = args
                .position_y
                .ok_or_else(|| anyhow::anyhow!("{command} requires --position-y"))?;
            position.insert("width".to_string(), serde_json::json!(width));
            position.insert("height".to_string(), serde_json::json!(height));
            position.insert("x".to_string(), serde_json::json!(x));
            position.insert("y".to_string(), serde_json::json!(y));
        }
    }
    Ok(Some(serde_json::Value::Object(position)))
}

fn gitlab_inline_discussion_inputs(
    project: &str,
    iid: u64,
    expected_head_sha: &str,
    position: &GitlabPositionArgs,
    body: &GitlabRequiredContentArgs,
) -> Result<serde_json::Value> {
    let mut inputs = gitlab_merge_request_input_map(project, iid);
    inputs.insert(
        "expectedHeadSha".to_string(),
        serde_json::json!(expected_head_sha),
    );
    inputs.insert(
        "position".to_string(),
        gitlab_position_value(position, true, "gitlab merge-request inline-discussion")?
            .expect("required position was validated"),
    );
    insert_gitlab_content_inputs(
        &mut inputs,
        body.content.as_deref(),
        body.content_file.as_deref(),
        body.content_format,
        true,
        "gitlab merge-request inline-discussion",
    )?;
    Ok(serde_json::Value::Object(inputs))
}

fn gitlab_discussion_reply_inputs(
    project: &str,
    iid: u64,
    discussion_id: &str,
    body: &GitlabRequiredContentArgs,
) -> Result<serde_json::Value> {
    let mut inputs = gitlab_merge_request_input_map(project, iid);
    inputs.insert("discussionId".to_string(), serde_json::json!(discussion_id));
    insert_gitlab_content_inputs(
        &mut inputs,
        body.content.as_deref(),
        body.content_file.as_deref(),
        body.content_format,
        true,
        "gitlab merge-request reply-discussion",
    )?;
    Ok(serde_json::Value::Object(inputs))
}

fn gitlab_draft_note_add_inputs(
    project: &str,
    iid: u64,
    expected_head_sha: Option<&str>,
    in_reply_to_discussion_id: Option<&str>,
    resolve_discussion: Option<bool>,
    position: &GitlabPositionArgs,
    body: &GitlabRequiredContentArgs,
) -> Result<serde_json::Value> {
    let position = gitlab_position_value(position, false, "gitlab merge-request add-draft-note")?;
    if expected_head_sha.is_some() != position.is_some() {
        anyhow::bail!(
            "gitlab merge-request add-draft-note requires --expected-head-sha and position together"
        );
    }
    if position.is_some() && in_reply_to_discussion_id.is_some() {
        anyhow::bail!(
            "gitlab merge-request add-draft-note accepts a position or reply target, not both"
        );
    }
    if resolve_discussion.is_some() && in_reply_to_discussion_id.is_none() {
        anyhow::bail!("--resolve-discussion requires --in-reply-to-discussion-id");
    }
    let mut inputs = gitlab_merge_request_input_map(project, iid);
    if let Some(expected_head_sha) = expected_head_sha {
        inputs.insert(
            "expectedHeadSha".to_string(),
            serde_json::json!(expected_head_sha),
        );
    }
    if let Some(position) = position {
        inputs.insert("position".to_string(), position);
    }
    if let Some(discussion_id) = in_reply_to_discussion_id {
        inputs.insert(
            "inReplyToDiscussionId".to_string(),
            serde_json::json!(discussion_id),
        );
    }
    insert_optional_json_bool(&mut inputs, "resolveDiscussion", resolve_discussion);
    insert_gitlab_content_inputs(
        &mut inputs,
        body.content.as_deref(),
        body.content_file.as_deref(),
        body.content_format,
        true,
        "gitlab merge-request add-draft-note",
    )?;
    Ok(serde_json::Value::Object(inputs))
}

fn gitlab_draft_note_update_inputs(
    project: &str,
    iid: u64,
    draft_note_id: u64,
    expected_head_sha: Option<&str>,
    position: &GitlabPositionArgs,
    body: &GitlabOptionalContentArgs,
) -> Result<serde_json::Value> {
    let position =
        gitlab_position_value(position, false, "gitlab merge-request update-draft-note")?;
    if expected_head_sha.is_some() != position.is_some() {
        anyhow::bail!(
            "gitlab merge-request update-draft-note requires --expected-head-sha and position together"
        );
    }
    let mut inputs = gitlab_merge_request_input_map(project, iid);
    inputs.insert("draftNoteId".to_string(), serde_json::json!(draft_note_id));
    if let Some(expected_head_sha) = expected_head_sha {
        inputs.insert(
            "expectedHeadSha".to_string(),
            serde_json::json!(expected_head_sha),
        );
    }
    if let Some(position) = position {
        inputs.insert("position".to_string(), position);
    }
    let has_content = insert_gitlab_content_inputs(
        &mut inputs,
        body.content.as_deref(),
        body.content_file.as_deref(),
        body.content_format,
        false,
        "gitlab merge-request update-draft-note",
    )?;
    if !has_content && expected_head_sha.is_none() {
        anyhow::bail!(
            "gitlab merge-request update-draft-note requires content or a replacement position"
        );
    }
    Ok(serde_json::Value::Object(inputs))
}

fn gitlab_publish_all_inputs(
    project: &str,
    iid: u64,
    reviewer_state: Option<GitlabReviewerStateArg>,
    summary: &GitlabOptionalContentArgs,
    internal: Option<bool>,
) -> Result<serde_json::Value> {
    let mut inputs = gitlab_merge_request_input_map(project, iid);
    let has_summary = insert_gitlab_content_inputs(
        &mut inputs,
        summary.content.as_deref(),
        summary.content_file.as_deref(),
        summary.content_format,
        false,
        "gitlab merge-request publish-all/submit-review",
    )?;
    if internal.is_some() && !has_summary {
        anyhow::bail!("--internal requires summary content");
    }
    insert_optional_json_bool(&mut inputs, "internal", internal);
    if let Some(reviewer_state) = reviewer_state {
        inputs.insert(
            "reviewerState".to_string(),
            serde_json::json!(reviewer_state.as_str()),
        );
    }
    Ok(serde_json::Value::Object(inputs))
}

struct GitlabFileWriteCliInput<'a> {
    project: &'a str,
    path: &'a str,
    branch: &'a str,
    content_file: &'a Path,
    commit_message: &'a str,
    start_branch: &'a Option<String>,
    author_name: &'a Option<String>,
    author_email: &'a Option<String>,
    execute_filemode: &'a Option<bool>,
}

fn gitlab_file_write_inputs(
    input: GitlabFileWriteCliInput<'_>,
) -> serde_json::Map<String, serde_json::Value> {
    let mut inputs = serde_json::Map::new();
    inputs.insert("project".to_string(), serde_json::json!(input.project));
    inputs.insert("path".to_string(), serde_json::json!(input.path));
    inputs.insert("branch".to_string(), serde_json::json!(input.branch));
    inputs.insert(
        "content".to_string(),
        serde_json::json!(read_gitlab_text_file(input.content_file)),
    );
    inputs.insert(
        "commitMessage".to_string(),
        serde_json::json!(input.commit_message),
    );
    insert_optional_json_string(&mut inputs, "startBranch", input.start_branch);
    insert_optional_json_string(&mut inputs, "authorName", input.author_name);
    insert_optional_json_string(&mut inputs, "authorEmail", input.author_email);
    insert_optional_json_bool(&mut inputs, "executeFilemode", *input.execute_filemode);
    inputs
}

fn insert_optional_json_string(
    inputs: &mut serde_json::Map<String, serde_json::Value>,
    key: &str,
    value: &Option<String>,
) {
    if let Some(value) = value {
        inputs.insert(key.to_string(), serde_json::json!(value));
    }
}

fn insert_optional_owned_json_string(
    inputs: &mut serde_json::Map<String, serde_json::Value>,
    key: &str,
    value: Option<String>,
) {
    if let Some(value) = value {
        inputs.insert(key.to_string(), serde_json::Value::String(value));
    }
}

fn insert_optional_or_null_json_string(
    inputs: &mut serde_json::Map<String, serde_json::Value>,
    key: &str,
    value: &Option<String>,
    clear: bool,
) {
    if clear {
        inputs.insert(key.to_string(), serde_json::Value::Null);
    } else {
        insert_optional_json_string(inputs, key, value);
    }
}

fn ensure_single_webhook_secret_stdin(first: bool, second: bool) -> Result<()> {
    if first && second {
        anyhow::bail!("only one webhook secret source may read from stdin");
    }
    Ok(())
}

fn parse_gitlab_webhook_delivery_status(value: &str) -> std::result::Result<String, String> {
    if matches!(value, "successful" | "client_failure" | "server_failure") {
        return Ok(value.to_string());
    }
    if value.len() == 3
        && value.bytes().all(|byte| byte.is_ascii_digit())
        && matches!(value.parse::<u16>(), Ok(100..=599))
    {
        return Ok(value.to_string());
    }
    Err(
        "status must be successful, client_failure, server_failure, or a three-digit HTTP status"
            .to_string(),
    )
}

fn ensure_webhook_update_has_changes(
    inputs: &serde_json::Map<String, serde_json::Value>,
) -> Result<()> {
    if inputs
        .keys()
        .all(|key| key == "project" || key == "webhookId" || key == "confirmDestinationReset")
    {
        anyhow::bail!("gitlab webhook update requires at least one change");
    }
    Ok(())
}

fn read_webhook_secret_source(
    label: &str,
    env_name: Option<&str>,
    file: Option<&Path>,
    stdin: bool,
) -> Result<Option<String>> {
    let count = usize::from(env_name.is_some()) + usize::from(file.is_some()) + usize::from(stdin);
    if count > 1 {
        anyhow::bail!("{label} accepts only one env, file, or stdin source");
    }
    if let Some(env_name) = env_name {
        let value = env::var(env_name)
            .with_context(|| format!("{label} environment variable is not set or is not UTF-8"))?;
        return Ok(Some(value));
    }
    if let Some(path) = file {
        return fs::read_to_string(path)
            .with_context(|| format!("failed to read {label} as UTF-8 from file"))
            .map(Some);
    }
    if stdin {
        let mut value = String::new();
        std::io::stdin()
            .read_to_string(&mut value)
            .with_context(|| format!("failed to read {label} as UTF-8 from stdin"))?;
        return Ok(Some(value));
    }
    Ok(None)
}

fn insert_optional_json_array(
    inputs: &mut serde_json::Map<String, serde_json::Value>,
    key: &str,
    values: &[String],
) {
    if !values.is_empty() {
        inputs.insert(key.to_string(), serde_json::json!(values));
    }
}

fn insert_optional_json_u32(
    inputs: &mut serde_json::Map<String, serde_json::Value>,
    key: &str,
    value: Option<u32>,
) {
    if let Some(value) = value {
        inputs.insert(key.to_string(), serde_json::json!(value));
    }
}

fn insert_optional_json_u64_array(
    inputs: &mut serde_json::Map<String, serde_json::Value>,
    key: &str,
    values: &[u64],
) {
    if !values.is_empty() {
        inputs.insert(key.to_string(), serde_json::json!(values));
    }
}

fn insert_optional_json_bool(
    inputs: &mut serde_json::Map<String, serde_json::Value>,
    key: &str,
    value: Option<bool>,
) {
    if let Some(value) = value {
        inputs.insert(key.to_string(), serde_json::json!(value));
    }
}

fn insert_optional_text_file(
    inputs: &mut serde_json::Map<String, serde_json::Value>,
    key: &str,
    path: &Option<PathBuf>,
) {
    if let Some(path) = path {
        inputs.insert(
            key.to_string(),
            serde_json::json!(read_gitlab_text_file(path)),
        );
    }
}

fn insert_gitlab_content_inputs(
    inputs: &mut serde_json::Map<String, serde_json::Value>,
    content: Option<&str>,
    content_file: Option<&Path>,
    content_format: Option<GitlabContentFormatArg>,
    required: bool,
    command: &str,
) -> Result<bool> {
    let Some((content, content_format)) =
        resolve_content_input(content, content_file, content_format, required, command)?
    else {
        return Ok(false);
    };
    inputs.insert("content".to_string(), content);
    inputs.insert(
        "contentFormat".to_string(),
        serde_json::json!(content_format.as_str()),
    );
    Ok(true)
}

struct GitlabContentCommandArgs<'a> {
    action: &'a str,
    project: &'a str,
    iid: u64,
    content: Option<&'a str>,
    content_file: Option<&'a Path>,
    content_format: Option<GitlabContentFormatArg>,
    command: &'a str,
    read_content_format: Option<ReadContentFormatArg>,
}

async fn run_gitlab_content_command(
    ctx: &CliContext<'_>,
    args: GitlabContentCommandArgs<'_>,
) -> Result<()> {
    let mut inputs = serde_json::Map::new();
    inputs.insert("project".to_string(), serde_json::json!(args.project));
    inputs.insert("iid".to_string(), serde_json::json!(args.iid));
    require_cli_input(insert_gitlab_content_inputs(
        &mut inputs,
        args.content,
        args.content_file,
        args.content_format,
        true,
        args.command,
    ));
    run_typed_invoke_value(
        ctx,
        args.action,
        serde_json::Value::Object(inputs),
        args.read_content_format,
        None,
    )
    .await
}

struct GitlabNoteContentCommandArgs<'a> {
    action: &'a str,
    project: &'a str,
    iid: u64,
    note_id: u64,
    content: Option<&'a str>,
    content_file: Option<&'a Path>,
    content_format: Option<GitlabContentFormatArg>,
    command: &'a str,
    read_content_format: Option<ReadContentFormatArg>,
}

async fn run_gitlab_note_content_command(
    ctx: &CliContext<'_>,
    args: GitlabNoteContentCommandArgs<'_>,
) -> Result<()> {
    let mut inputs = serde_json::Map::new();
    inputs.insert("project".to_string(), serde_json::json!(args.project));
    inputs.insert("iid".to_string(), serde_json::json!(args.iid));
    inputs.insert("noteId".to_string(), serde_json::json!(args.note_id));
    require_cli_input(insert_gitlab_content_inputs(
        &mut inputs,
        args.content,
        args.content_file,
        args.content_format,
        true,
        args.command,
    ));
    run_typed_invoke_value(
        ctx,
        args.action,
        serde_json::Value::Object(inputs),
        args.read_content_format,
        None,
    )
    .await
}

async fn run_gitlab_note_delete_command(
    ctx: &CliContext<'_>,
    action: &str,
    project: &str,
    iid: u64,
    note_id: u64,
) -> Result<()> {
    let mut inputs = serde_json::Map::new();
    inputs.insert("project".to_string(), serde_json::json!(project));
    inputs.insert("iid".to_string(), serde_json::json!(iid));
    inputs.insert("noteId".to_string(), serde_json::json!(note_id));
    run_invoke_value(ctx, action, serde_json::Value::Object(inputs)).await
}

struct GitlabDiscussionNoteContentArgs<'a> {
    action: &'a str,
    project: &'a str,
    iid: u64,
    discussion_id: &'a str,
    note_id: u64,
    content: Option<&'a str>,
    content_file: Option<&'a Path>,
    content_format: Option<GitlabContentFormatArg>,
    command: &'a str,
    read_content_format: Option<ReadContentFormatArg>,
}

async fn run_gitlab_discussion_note_content_command(
    ctx: &CliContext<'_>,
    args: GitlabDiscussionNoteContentArgs<'_>,
) -> Result<()> {
    let mut inputs = serde_json::Map::new();
    inputs.insert("project".to_string(), serde_json::json!(args.project));
    inputs.insert("iid".to_string(), serde_json::json!(args.iid));
    inputs.insert(
        "discussionId".to_string(),
        serde_json::json!(args.discussion_id),
    );
    inputs.insert("noteId".to_string(), serde_json::json!(args.note_id));
    require_cli_input(insert_gitlab_content_inputs(
        &mut inputs,
        args.content,
        args.content_file,
        args.content_format,
        true,
        args.command,
    ));
    run_typed_invoke_value(
        ctx,
        args.action,
        serde_json::Value::Object(inputs),
        args.read_content_format,
        None,
    )
    .await
}

async fn run_gitlab_discussion_note_delete_command(
    ctx: &CliContext<'_>,
    action: &str,
    project: &str,
    iid: u64,
    discussion_id: &str,
    note_id: u64,
) -> Result<()> {
    let mut inputs = serde_json::Map::new();
    inputs.insert("project".to_string(), serde_json::json!(project));
    inputs.insert("iid".to_string(), serde_json::json!(iid));
    inputs.insert("discussionId".to_string(), serde_json::json!(discussion_id));
    inputs.insert("noteId".to_string(), serde_json::json!(note_id));
    run_invoke_value(ctx, action, serde_json::Value::Object(inputs)).await
}

async fn run_gitlab_discussion_state_command(
    ctx: &CliContext<'_>,
    action: &str,
    project: &str,
    iid: u64,
    discussion_id: &str,
    read_content_format: Option<ReadContentFormatArg>,
) -> Result<()> {
    let mut inputs = serde_json::Map::new();
    inputs.insert("project".to_string(), serde_json::json!(project));
    inputs.insert("iid".to_string(), serde_json::json!(iid));
    inputs.insert("discussionId".to_string(), serde_json::json!(discussion_id));
    run_typed_invoke_value(
        ctx,
        action,
        serde_json::Value::Object(inputs),
        read_content_format,
        None,
    )
    .await
}

async fn run_broker_get(ctx: &CliContext<'_>, path: &str, shape: ResponseShape) -> Result<()> {
    let (status, value) = send_broker_get(ctx, path, shape).await?;
    print_local_response(ctx, status, value)
}

fn render_discovery(ctx: &CliContext<'_>, result: Result<serde_json::Value>) -> Result<()> {
    match result {
        Ok(value) => print_local_response(ctx, 200, value),
        Err(error) => {
            if let Some(failure) = error.downcast_ref::<discovery::BrokerFailure>() {
                print_value_and_exit(failure.status, failure.body.clone());
            }
            if error.is::<discovery::InputError>() {
                exit_cli_input_error(error);
            }
            exit_network_error(error)
        }
    }
}

async fn run_services_list(ctx: &CliContext<'_>, projection: &DiscoveryListArgs) -> Result<()> {
    render_discovery(
        ctx,
        discovery::services_list(
            ctx.settings,
            projection.prefix.as_deref(),
            projection.verbose,
        )
        .await,
    )
}

async fn run_actions_list(
    ctx: &CliContext<'_>,
    service: &str,
    resource: Option<&str>,
    resource_type: Option<&str>,
    projection: &DiscoveryListArgs,
) -> Result<()> {
    render_discovery(
        ctx,
        discovery::actions_list(
            ctx.settings,
            service,
            resource,
            resource_type,
            projection.prefix.as_deref(),
            projection.verbose,
        )
        .await,
    )
}

async fn run_action_describe(ctx: &CliContext<'_>, service: &str, action: &str) -> Result<()> {
    render_discovery(
        ctx,
        discovery::action_describe(
            ctx.settings,
            &agent_access_core::mcp::McpView::Aggregate,
            service,
            action,
        )
        .await,
    )
}

fn validate_discovery_prefix(prefix: Option<&str>) -> Result<()> {
    if prefix == Some("") {
        anyhow::bail!("prefix must not be empty");
    }
    Ok(())
}

fn validate_action_argument(action: &str) -> Result<()> {
    if agent_access_provider::is_action_name(action) {
        Ok(())
    } else {
        anyhow::bail!("action name is invalid")
    }
}

fn project_service_list(
    value: serde_json::Value,
    projection: &DiscoveryListArgs,
) -> Result<serde_json::Value> {
    Ok(agent_access_core::mcp::project_service_list(
        value,
        projection.prefix.as_deref(),
        projection.verbose,
    )?)
}

fn parse_discovery_service(
    value: serde_json::Value,
) -> Result<agent_access_core::mcp::DiscoveryServiceValue> {
    Ok(agent_access_core::mcp::parse_discovery_service(value)?)
}

fn discovery_actions(
    service: agent_access_core::mcp::DiscoveryServiceValue,
) -> Result<Vec<(agent_access_provider::ActionCapabilities, serde_json::Value)>> {
    Ok(agent_access_core::mcp::discovery_actions(service)?)
}

async fn send_broker_get(
    ctx: &CliContext<'_>,
    path: &str,
    shape: ResponseShape,
) -> Result<(u16, serde_json::Value)> {
    let resolved = ctx.settings;
    let endpoint = require_cli_input(endpoint(&resolved.url, path));
    let client = require_cli_input(http_client(resolved));
    let response = request_builder(client.get(endpoint), resolved)
        .send()
        .await
        .context("broker request failed")
        .unwrap_or_else(|error| exit_network_error(error));
    response_value(response, shape).await
}

async fn run_broker_json_method(
    ctx: &CliContext<'_>,
    method: reqwest::Method,
    path: &str,
    body: Option<serde_json::Value>,
) -> Result<()> {
    let (status, value) = send_broker_json_method(ctx, method, path, body).await?;
    print_value_and_exit(status, value);
}

async fn send_broker_json_method(
    ctx: &CliContext<'_>,
    method: reqwest::Method,
    path: &str,
    body: Option<serde_json::Value>,
) -> Result<(u16, serde_json::Value)> {
    send_broker_json_method_shape(ctx, method, path, body, ResponseShape::Object).await
}

async fn send_broker_json_method_shape(
    ctx: &CliContext<'_>,
    method: reqwest::Method,
    path: &str,
    body: Option<serde_json::Value>,
    shape: ResponseShape,
) -> Result<(u16, serde_json::Value)> {
    let resolved = ctx.settings;
    let endpoint = require_cli_input(endpoint(&resolved.url, path));
    let client = require_cli_input(http_client(resolved));
    let mut request = request_builder(client.request(method, endpoint), resolved);
    if let Some(body) = body {
        request = request.json(&body);
    }
    let response = request
        .send()
        .await
        .context("broker request failed")
        .unwrap_or_else(|error| exit_network_error(error));
    response_value(response, shape).await
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum JsonInputSourceKind {
    Argv,
    File,
    Stdin,
}

#[derive(Debug, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
enum SendRequest {
    Invoke {
        version: String,
        service: String,
        action: String,
        #[serde(default = "empty_json_object_for_cli")]
        inputs: serde_json::Value,
        #[serde(default)]
        files: Vec<SendFileDescriptor>,
        #[serde(default, rename = "secretSources")]
        secret_sources: Vec<SecretSourceBinding>,
        #[serde(rename = "responseMode")]
        response_mode: Option<String>,
        #[serde(default, rename = "readContentFormat")]
        read_content_format: ReadContentFormat,
        #[serde(default, rename = "responseFormat")]
        response_format: ResponseFormat,
        output: Option<SendOutput>,
        #[serde(rename = "metadataOutput")]
        metadata_output: Option<SendMetadataOutput>,
    },
    Http {
        version: String,
        method: String,
        route: String,
        #[serde(default, rename = "pathParams")]
        path_params: BTreeMap<String, String>,
        #[serde(default)]
        query: BTreeMap<String, serde_json::Value>,
        body: Option<serde_json::Value>,
        #[serde(default, rename = "secretSources")]
        secret_sources: Vec<SecretSourceBinding>,
    },
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct SendFileDescriptor {
    role: String,
    path: PathBuf,
    filename: Option<String>,
    content_type: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct SecretSourceBinding {
    pointer: String,
    source: LocalSecretSource,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
enum LocalSecretSource {
    Env { name: String },
    File { path: PathBuf },
    Stdin,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
enum SendOutput {
    File { path: PathBuf },
    Stdout,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
enum SendMetadataOutput {
    Stderr,
    File { path: PathBuf },
}

fn empty_json_object_for_cli() -> serde_json::Value {
    serde_json::json!({})
}

async fn run_spec_command(ctx: &CliContext<'_>, command: &SpecCommand) -> Result<()> {
    match command {
        SpecCommand::Catalog {
            auth,
            visibility,
            output_format: _,
        } => run_spec_fetch(ctx, "/v1/spec/catalog", *auth, *visibility).await,
        SpecCommand::Openapi {
            auth,
            visibility,
            output_format: _,
        } => run_spec_fetch(ctx, "/v1/spec/openapi.json", *auth, *visibility).await,
        SpecCommand::SendSchema {
            auth,
            visibility,
            output_format: _,
            offline,
        } => {
            if *offline {
                return print_local_response(ctx, 200, generic_send_schema());
            }
            run_spec_fetch(ctx, "/v1/spec/send-schema.json", *auth, *visibility).await
        }
    }
}

async fn run_spec_fetch(
    ctx: &CliContext<'_>,
    route: &str,
    auth: SpecAuthArg,
    visibility: SpecVisibilityArg,
) -> Result<()> {
    let mut serializer = form_urlencoded::Serializer::new(String::new());
    serializer.append_pair("auth", auth.as_str());
    serializer.append_pair("visibility", visibility.as_str());
    serializer.append_pair("format", "json");
    let path = format!("{route}?{}", serializer.finish());
    run_broker_get(ctx, &path, ResponseShape::Object).await
}

async fn fetch_runtime_catalog(ctx: &CliContext<'_>) -> Result<ApiCatalog> {
    let (status, value) = send_broker_get(ctx, "/v1/spec/catalog", ResponseShape::Object).await?;
    if status >= 400 {
        print_value_and_exit(status, value);
    }
    parse_runtime_catalog(value)
}

fn parse_runtime_catalog(value: serde_json::Value) -> Result<ApiCatalog> {
    let version = value
        .get("version")
        .and_then(serde_json::Value::as_str)
        .context("runtime catalog response is invalid")?;
    if version != API_CATALOG_VERSION {
        anyhow::bail!("runtime catalog version {version} is not supported");
    }
    let catalog: ApiCatalog =
        serde_json::from_value(value).context("runtime catalog response is invalid")?;
    if catalog.send.version != SEND_SCHEMA_VERSION || !catalog.send.catalog_required {
        anyhow::bail!("runtime catalog send metadata is unsupported");
    }
    Ok(catalog)
}

async fn run_send_command(
    ctx: &CliContext<'_>,
    request_json: &Option<String>,
    request_file: &Option<PathBuf>,
    request_stdin: bool,
) -> Result<()> {
    let (mut request_value, source_kind) =
        read_json_request_source(request_json, request_file, request_stdin, "send")?;
    if let Some(path) = ctx.output {
        if request_value
            .get("kind")
            .and_then(serde_json::Value::as_str)
            != Some("invoke")
        {
            exit_cli_input_error(anyhow::anyhow!(
                "--output for send requires kind=invoke; management/HTTP route output is not supported"
            ));
        }
        if request_value.get("output").is_some() {
            exit_cli_input_error(anyhow::anyhow!(
                "choose either --output or the send envelope output, not both"
            ));
        }
        request_value["output"] = if path == Path::new("-") {
            serde_json::json!({"type":"stdout"})
        } else {
            serde_json::json!({"type":"file","path":path.to_str().unwrap_or_else(|| exit_cli_input_error(anyhow::anyhow!("--output path must be valid UTF-8 for send")))})
        };
    }
    require_cli_input(validate_send_envelope_shape(&request_value));
    let catalog = fetch_runtime_catalog(ctx).await.unwrap_or_else(|error| {
        eprintln!("{error:#}");
        std::process::exit(5);
    });
    let sensitive_pointers = send_sensitive_pointers(&catalog, &request_value)?;
    reject_literal_identity_token_for_send_management(ctx, &catalog, &request_value)?;
    if source_kind == JsonInputSourceKind::Argv {
        reject_inline_sensitive_values(&request_value, &sensitive_pointers)?;
    }
    apply_secret_sources(&mut request_value, source_kind, &sensitive_pointers)?;
    let request = require_cli_input(parse_send_request(request_value));
    match request {
        SendRequest::Invoke {
            version,
            service,
            action,
            inputs,
            files,
            secret_sources,
            response_mode,
            read_content_format,
            response_format,
            output,
            metadata_output,
        } => {
            ensure_send_version(&version)?;
            drop(secret_sources);
            run_send_invoke(
                ctx,
                &catalog,
                SendInvokeDispatch {
                    service,
                    action,
                    inputs,
                    files,
                    response_mode,
                    response_options: ResponseOptions::new(read_content_format, response_format),
                    output,
                    metadata_output,
                },
            )
            .await
        }
        SendRequest::Http {
            version,
            method,
            route,
            path_params,
            query,
            body,
            secret_sources,
        } => {
            ensure_send_version(&version)?;
            drop(secret_sources);
            run_send_http(ctx, &catalog, &method, &route, path_params, query, body).await
        }
    }
}

struct SendInvokeDispatch {
    service: String,
    action: String,
    inputs: serde_json::Value,
    files: Vec<SendFileDescriptor>,
    response_mode: Option<String>,
    response_options: ResponseOptions,
    output: Option<SendOutput>,
    metadata_output: Option<SendMetadataOutput>,
}

struct PreparedSendOutput {
    body: Option<output::ResponseOutput>,
    metadata: Option<output::AtomicOutput>,
}

impl PreparedSendOutput {
    fn new(
        body: Option<&SendOutput>,
        metadata: Option<&SendMetadataOutput>,
        sensitive: &[String],
    ) -> Result<Self> {
        let body = match body {
            Some(SendOutput::File { path }) => {
                output::ResponseOutput::prepare(Some(path), sensitive)?
            }
            _ => None,
        };
        let metadata = match metadata {
            Some(SendMetadataOutput::File { path }) => Some(output::AtomicOutput::new(path)?),
            _ => None,
        };
        Ok(Self { body, metadata })
    }
}

fn read_json_request_source(
    request_json: &Option<String>,
    request_file: &Option<PathBuf>,
    request_stdin: bool,
    command_name: &str,
) -> Result<(serde_json::Value, JsonInputSourceKind)> {
    let count = request_json.is_some() as u8 + request_file.is_some() as u8 + request_stdin as u8;
    if count != 1 {
        anyhow::bail!("{command_name} requires exactly one request source");
    }
    if let Some(raw) = request_json {
        let value = serde_json::from_str(raw)
            .map_err(|error| anyhow::anyhow!("--request-json must be JSON: {error}"))?;
        return Ok((value, JsonInputSourceKind::Argv));
    }
    if let Some(path) = request_file {
        let value = read_json_file(path);
        return Ok((value, JsonInputSourceKind::File));
    }
    let mut raw = String::new();
    std::io::stdin()
        .read_to_string(&mut raw)
        .context("failed to read request JSON from stdin")?;
    let value = serde_json::from_str(&raw)
        .map_err(|error| anyhow::anyhow!("--request-stdin must provide JSON: {error}"))?;
    Ok((value, JsonInputSourceKind::Stdin))
}

fn validate_send_version(value: &serde_json::Value) -> Result<()> {
    let version = value
        .get("version")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| anyhow::anyhow!("send request requires version"))?;
    ensure_send_version(version)
}

fn ensure_send_version(version: &str) -> Result<()> {
    if version != SEND_SCHEMA_VERSION {
        anyhow::bail!("send request version {version} is not supported");
    }
    Ok(())
}

fn validate_send_envelope_shape(value: &serde_json::Value) -> Result<()> {
    validate_send_version(value)?;
    if value.get("kind").and_then(serde_json::Value::as_str) == Some("http")
        && value.get("body").is_some_and(serde_json::Value::is_null)
    {
        anyhow::bail!("kind=http body cannot be null");
    }
    let request = parse_send_request(value.clone())?;
    match &request {
        SendRequest::Invoke { version, .. } | SendRequest::Http { version, .. } => {
            ensure_send_version(version)
        }
    }
}

fn parse_send_request(value: serde_json::Value) -> Result<SendRequest> {
    serde_json::from_value(value)
        .map_err(|error| anyhow::anyhow!("send request is invalid: {error}"))
}

fn send_sensitive_pointers(
    catalog: &ApiCatalog,
    request: &serde_json::Value,
) -> Result<Vec<String>> {
    match request.get("kind").and_then(serde_json::Value::as_str) {
        Some("invoke") => {
            let service = required_str_field(request, "service")?;
            let action = required_str_field(request, "action")?;
            let action = catalog_action(catalog, service, action)?;
            Ok(action.sensitive_input_pointers.clone())
        }
        Some("http") => {
            let method = required_str_field(request, "method")?;
            let route = required_str_field(request, "route")?;
            let route = catalog_route(catalog, method, route)?;
            Ok(route.sensitive_request_pointers.clone())
        }
        Some(other) => anyhow::bail!("send request kind {other} is not supported"),
        None => anyhow::bail!("send request requires kind"),
    }
}

fn required_str_field<'a>(value: &'a serde_json::Value, field: &str) -> Result<&'a str> {
    value
        .get(field)
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| anyhow::anyhow!("send request requires string field {field}"))
}

fn reject_inline_sensitive_values(
    request: &serde_json::Value,
    sensitive_pointers: &[String],
) -> Result<()> {
    for pointer in sensitive_pointers {
        if json_pointer_or_descendant_exists(request, pointer) {
            anyhow::bail!(
                "--request-json cannot include sensitive field {pointer}; use secretSources"
            );
        }
    }
    Ok(())
}

fn json_pointer_or_descendant_exists(value: &serde_json::Value, pointer: &str) -> bool {
    if value.pointer(pointer).is_some() {
        return true;
    }
    let Some(header) = input_header_pointer_name(pointer) else {
        return false;
    };
    value
        .pointer("/inputs/headers")
        .and_then(serde_json::Value::as_object)
        .is_some_and(|headers| {
            headers
                .keys()
                .any(|candidate| candidate.eq_ignore_ascii_case(&header))
        })
}

fn reject_literal_identity_token_for_send_management(
    ctx: &CliContext<'_>,
    catalog: &ApiCatalog,
    request: &serde_json::Value,
) -> Result<()> {
    if !ctx.settings.token_from_literal_arg {
        return Ok(());
    }
    if request.get("kind").and_then(serde_json::Value::as_str) != Some("http") {
        return Ok(());
    }
    let method = required_str_field(request, "method")?;
    let route = required_str_field(request, "route")?;
    let route = catalog_route(catalog, method, route)?;
    if matches!(
        route.access,
        RouteAccess::UserManagement
            | RouteAccess::BrowserManagement
            | RouteAccess::UserTokenManagement
            | RouteAccess::PolicyRead
            | RouteAccess::PolicyWrite
            | RouteAccess::AdminRead
            | RouteAccess::AdminWrite
    ) {
        anyhow::bail!(
            "management routes do not accept --token-value; use --token-env, --token-file, config, or AGENT_ACCESS_TOKEN"
        );
    }
    Ok(())
}

fn apply_secret_sources(
    request: &mut serde_json::Value,
    source_kind: JsonInputSourceKind,
    sensitive_pointers: &[String],
) -> Result<()> {
    let sources = request
        .get("secretSources")
        .cloned()
        .unwrap_or_else(|| serde_json::json!([]));
    let bindings: Vec<SecretSourceBinding> = serde_json::from_value(sources)
        .map_err(|error| anyhow::anyhow!("secretSources is invalid: {error}"))?;
    let stdin_count = bindings
        .iter()
        .filter(|binding| matches!(binding.source, LocalSecretSource::Stdin))
        .count();
    if stdin_count > 1 {
        anyhow::bail!("only one stdin secret source may be used");
    }
    if stdin_count == 1 && source_kind == JsonInputSourceKind::Stdin {
        anyhow::bail!("stdin secret source cannot be used with --request-stdin");
    }
    for binding in bindings {
        if !sensitive_pointer_allowed(&binding.pointer, sensitive_pointers) {
            anyhow::bail!(
                "secret source pointer {} is not declared sensitive by the runtime catalog",
                binding.pointer
            );
        }
        let secret = match binding.source {
            LocalSecretSource::Env { name } => env::var(&name)
                .map_err(|_| anyhow::anyhow!("secret source environment variable is not set"))?,
            LocalSecretSource::File { path } => fs::read_to_string(&path)
                .with_context(|| format!("failed to read secret source {}", path.display()))?,
            LocalSecretSource::Stdin => {
                let mut value = String::new();
                std::io::stdin()
                    .read_to_string(&mut value)
                    .context("failed to read secret from stdin")?;
                value
            }
        };
        set_json_pointer(request, &binding.pointer, serde_json::Value::String(secret))?;
    }
    Ok(())
}

fn sensitive_pointer_allowed(pointer: &str, sensitive_pointers: &[String]) -> bool {
    sensitive_pointers.iter().any(|allowed| {
        pointer == allowed
            || pointer
                .strip_prefix(allowed)
                .is_some_and(|suffix| suffix.starts_with('/'))
            || input_header_pointer_matches(pointer, allowed)
    })
}

fn input_header_pointer_matches(candidate: &str, allowed: &str) -> bool {
    let Some(candidate_header) = input_header_pointer_name(candidate) else {
        return false;
    };
    let Some(allowed_header) = input_header_pointer_name(allowed) else {
        return false;
    };
    candidate_header.eq_ignore_ascii_case(&allowed_header)
}

fn input_header_pointer_name(pointer: &str) -> Option<String> {
    let suffix = pointer.strip_prefix("/inputs/headers/")?;
    if suffix.contains('/') {
        return None;
    }
    Some(json_pointer_unescape(suffix))
}

fn json_pointer_unescape(value: &str) -> String {
    value.replace("~1", "/").replace("~0", "~")
}

fn set_json_pointer(
    value: &mut serde_json::Value,
    pointer: &str,
    replacement: serde_json::Value,
) -> Result<()> {
    set_json_pointer_value(value, pointer, replacement, "secret source pointer")
}

fn set_json_pointer_value(
    value: &mut serde_json::Value,
    pointer: &str,
    replacement: serde_json::Value,
    pointer_label: &str,
) -> Result<()> {
    if !pointer.starts_with('/') {
        anyhow::bail!("{pointer_label} must be a JSON pointer");
    }
    let tokens = pointer
        .trim_start_matches('/')
        .split('/')
        .map(|token| token.replace("~1", "/").replace("~0", "~"))
        .collect::<Vec<_>>();
    let mut current = value;
    for token in &tokens[..tokens.len().saturating_sub(1)] {
        if !current.is_object() {
            *current = serde_json::Value::Object(serde_json::Map::new());
        }
        current = current
            .as_object_mut()
            .expect("object just inserted")
            .entry(token.clone())
            .or_insert_with(|| serde_json::Value::Object(serde_json::Map::new()));
    }
    let Some(last) = tokens.last() else {
        anyhow::bail!("secret source pointer cannot target the document root");
    };
    if !current.is_object() {
        *current = serde_json::Value::Object(serde_json::Map::new());
    }
    current
        .as_object_mut()
        .expect("object just inserted")
        .insert(last.clone(), replacement);
    Ok(())
}

fn set_upload_metadata(
    inputs: &mut serde_json::Value,
    plan: &MultipartUploadSpec,
    metadata: Vec<serde_json::Value>,
) -> Result<()> {
    set_json_pointer_value(
        inputs,
        &plan.metadata_pointer,
        serde_json::Value::Array(metadata),
        "upload metadata pointer",
    )
}

async fn run_send_invoke(
    ctx: &CliContext<'_>,
    catalog: &ApiCatalog,
    request: SendInvokeDispatch,
) -> Result<()> {
    let service = request.service.clone();
    let action = request.action.clone();
    let action_spec = catalog_action(catalog, &service, &action)?.clone();
    if !action_spec.supports_io() {
        exit_cli_input_error(anyhow::anyhow!(
            "this client does not support the action's input and output kind"
        ));
    }
    if (request.output.is_some() || request.metadata_output.is_some())
        && !action_spec.supports_file_output()
    {
        exit_cli_input_error(anyhow::anyhow!(
            "this action does not accept output or metadataOutput"
        ));
    }
    if request.metadata_output.is_some() && request.output.is_none() {
        exit_cli_input_error(anyhow::anyhow!("metadataOutput requires output"));
    }
    require_cli_input(validate_send_destinations(
        request.output.as_ref(),
        request.metadata_output.as_ref(),
    ));
    let prepared = PreparedSendOutput::new(
        request.output.as_ref(),
        request.metadata_output.as_ref(),
        &action_spec.sensitive_output_pointers,
    )
    .map_err(DeferredCliError::input)?;
    let invoke_ctx = CliContext {
        settings: ctx.settings,
        output: None,
    };

    match request.response_mode.as_deref().unwrap_or("json") {
        "json" => {
            if matches!(action_spec.io, ActionIo::RawDownload { .. }) {
                return Err(DeferredCliError::input(format!(
                    "download action {service}.{action} requires responseMode=stream"
                ))
                .into());
            }
            if !request.files.is_empty() {
                return run_send_upload(ctx, &action_spec, request, prepared).await;
            }
            if matches!(action_spec.io, ActionIo::MultipartUpload { .. }) {
                return Err(DeferredCliError::input(format!(
                    "upload action {service}.{action} requires files"
                ))
                .into());
            }
            let (status, value) = send_invoke_parts_with_options(
                &invoke_ctx,
                &service,
                &action,
                request.inputs,
                request.response_options,
            )
            .await?;
            validate_embedded_invoke_result(
                &value,
                request.response_options.read_content_format,
                &action_spec.rendered_body_owners,
                &action_spec.optional_rendered_body_owner_prefixes,
            )
            .map_err(DeferredCliError::malformed)?;
            if request.response_options.response_format == ResponseFormat::Markdown {
                markdown_result_value(&value).map_err(DeferredCliError::malformed)?;
            }
            finish_send_json(
                status,
                value,
                request.output,
                request.metadata_output,
                &action_spec.sensitive_output_pointers,
                prepared,
            )
        }
        "stream" => {
            if !matches!(action_spec.io, ActionIo::RawDownload { .. }) {
                return Err(DeferredCliError::input(
                    "responseMode=stream is valid only for raw download actions",
                )
                .into());
            }
            if !request.files.is_empty() {
                return Err(
                    DeferredCliError::input("stream downloads cannot include files").into(),
                );
            }
            run_send_download(
                ctx,
                request,
                &action_spec.sensitive_output_pointers,
                prepared,
            )
            .await
        }
        other => {
            Err(DeferredCliError::input(format!("responseMode {other} is not supported")).into())
        }
    }
}

async fn run_send_upload(
    ctx: &CliContext<'_>,
    action_spec: &ApiActionSpec,
    request: SendInvokeDispatch,
    prepared: PreparedSendOutput,
) -> Result<()> {
    let SendInvokeDispatch {
        service,
        action,
        inputs,
        files,
        response_options,
        output,
        metadata_output,
        ..
    } = request;
    let ActionIo::MultipartUpload { plan } = &action_spec.io else {
        return Err(DeferredCliError::input(format!(
            "action {service}.{action} does not accept files"
        ))
        .into());
    };
    let (status, value) = send_upload_with_plan(
        ctx,
        &service,
        &action,
        inputs,
        files,
        plan,
        response_options,
    )
    .await?;
    validate_embedded_invoke_result(
        &value,
        response_options.read_content_format,
        &action_spec.rendered_body_owners,
        &action_spec.optional_rendered_body_owner_prefixes,
    )
    .map_err(DeferredCliError::malformed)?;
    if response_options.response_format == ResponseFormat::Markdown {
        markdown_result_value(&value).map_err(DeferredCliError::malformed)?;
    }
    finish_send_json(
        status,
        value,
        output,
        metadata_output,
        &action_spec.sensitive_output_pointers,
        prepared,
    )
}

async fn run_upload_with_plan(
    ctx: &CliContext<'_>,
    service: &str,
    action: &str,
    inputs: serde_json::Value,
    files: Vec<SendFileDescriptor>,
    plan: &MultipartUploadSpec,
    response_options: ResponseOptions,
) -> Result<()> {
    let spec = if ctx.output.is_some() {
        Some(
            output_action_spec(ctx, service, action)
                .await
                .unwrap_or_else(|error| exit_cli_input_error(error)),
        )
    } else {
        None
    };
    let reserved = output::ResponseOutput::prepare(
        ctx.output,
        spec.as_ref()
            .map(|spec| spec.sensitive_output_pointers.as_slice())
            .unwrap_or_default(),
    )
    .map_err(DeferredCliError::input)?;
    let (status, value) =
        send_upload_with_plan(ctx, service, action, inputs, files, plan, response_options).await?;
    if let Some(spec) = spec {
        validate_embedded_invoke_result(
            &value,
            response_options.read_content_format,
            &spec.rendered_body_owners,
            &spec.optional_rendered_body_owner_prefixes,
        )
        .map_err(DeferredCliError::malformed)?;
    }
    if response_options.response_format == ResponseFormat::Markdown {
        markdown_result_value(&value).map_err(DeferredCliError::malformed)?;
    }
    if let Some(receipt) = write_local_response(
        ctx,
        status,
        &value,
        response_options.response_format,
        reserved,
    )? {
        print_value_and_exit(status, receipt);
    }
    print_invoke_value_and_exit(status, value, response_options.response_format);
}

async fn send_upload_with_plan(
    ctx: &CliContext<'_>,
    service: &str,
    action: &str,
    inputs: serde_json::Value,
    files: Vec<SendFileDescriptor>,
    plan: &MultipartUploadSpec,
    response_options: ResponseOptions,
) -> Result<(u16, serde_json::Value)> {
    let inputs = inputs
        .as_object()
        .cloned()
        .ok_or_else(|| DeferredCliError::input("multipart invoke inputs must be a JSON object"))?;
    validate_upload_files(plan, &files, service, action).map_err(DeferredCliError::input)?;
    let mut form = reqwest::multipart::Form::new();
    let mut upload_metadata = Vec::new();
    let mut file_parts = Vec::new();
    for (index, file) in files.iter().enumerate() {
        let size = upload_file_metadata(&file.path)
            .map_err(DeferredCliError::input)?
            .len();
        let filename = file.filename.clone().map(Ok).unwrap_or_else(|| {
            file.path
                .file_name()
                .and_then(|name| name.to_str())
                .map(str::to_owned)
                .ok_or_else(|| DeferredCliError::input("upload filename must be UTF-8"))
        })?;
        let content_type = file.content_type.clone().unwrap_or_else(|| {
            mime_guess::from_path(&file.path)
                .first_or_octet_stream()
                .essence_str()
                .to_string()
        });
        let field = format!("{}{}", plan.field_name_prefix, index);
        let sha256 = {
            let mut source = fs::File::open(&file.path)
                .with_context(|| format!("failed to open {} for upload", file.path.display()))
                .map_err(DeferredCliError::input)?;
            let mut digest = Sha256::new();
            let mut buffer = [0_u8; 64 * 1024];
            loop {
                let count = source
                    .read(&mut buffer)
                    .with_context(|| format!("failed to read {} for upload", file.path.display()))
                    .map_err(DeferredCliError::input)?;
                if count == 0 {
                    break;
                }
                digest.update(&buffer[..count]);
            }
            finalize_sha256(digest)
        };
        upload_metadata.push(
            upload_metadata_entry(
                plan,
                UploadFileMetadata {
                    field: &field,
                    filename: &filename,
                    content_type: &content_type,
                    size,
                    sha256: &sha256,
                },
                &format!("{service}.{action}"),
            )
            .map_err(DeferredCliError::input)?,
        );
        file_parts.push((field, file.path.clone(), filename, content_type));
    }
    let mut inputs = serde_json::Value::Object(inputs);
    set_upload_metadata(&mut inputs, plan, upload_metadata).map_err(DeferredCliError::input)?;
    let request_json = serde_json::to_string(&InvokeRequest {
        inputs,
        read_content_format: response_options.read_content_format,
        response_format: response_options.response_format,
        body_parts: vec![],
    })?;
    form = form.part(
        "request",
        reqwest::multipart::Part::text(request_json).mime_str("application/json")?,
    );
    for (field, path, filename, content_type) in file_parts {
        let part = reqwest::multipart::Part::file(&path)
            .await
            .with_context(|| format!("failed to open {} for upload", path.display()))?
            .file_name(filename)
            .mime_str(&content_type)?;
        form = form.part(field, part);
    }
    let service_action = format!("{service}.{action}");
    send_invoke_multipart(ctx, &service_action, form).await
}

fn validate_upload_files(
    plan: &MultipartUploadSpec,
    files: &[SendFileDescriptor],
    service: &str,
    action: &str,
) -> Result<()> {
    if files.len() < plan.min_files {
        anyhow::bail!(
            "action {service}.{action} requires at least {} file(s)",
            plan.min_files
        );
    }
    if let Some(max_files) = plan.max_files
        && files.len() > max_files
    {
        anyhow::bail!("action {service}.{action} accepts at most {max_files} file(s)");
    }
    for file in files {
        if file.role != plan.role {
            anyhow::bail!(
                "file role {} is not valid for {service}.{action}",
                file.role
            );
        }
        if !plan.caller_content_type_allowed && file.content_type.is_some() {
            anyhow::bail!("file contentType is not valid for {service}.{action}");
        }
    }
    Ok(())
}

struct UploadFileMetadata<'a> {
    field: &'a str,
    filename: &'a str,
    content_type: &'a str,
    size: u64,
    sha256: &'a str,
}

fn upload_metadata_entry(
    plan: &MultipartUploadSpec,
    metadata: UploadFileMetadata<'_>,
    action_label: &str,
) -> Result<serde_json::Value> {
    let mut object = serde_json::Map::new();
    for metadata_field in &plan.metadata_fields {
        let value = match metadata_field.as_str() {
            "field" => serde_json::json!(metadata.field),
            "filename" => serde_json::json!(metadata.filename),
            "contentType" => serde_json::json!(metadata.content_type),
            "size" => serde_json::json!(metadata.size),
            "sha256" => serde_json::json!(metadata.sha256),
            other => {
                anyhow::bail!(
                    "upload action {action_label} declares unsupported metadata field {other}"
                );
            }
        };
        object.insert(metadata_field.clone(), value);
    }
    Ok(serde_json::Value::Object(object))
}

async fn run_send_download(
    ctx: &CliContext<'_>,
    request: SendInvokeDispatch,
    sensitive_outputs: &[String],
    mut prepared: PreparedSendOutput,
) -> Result<()> {
    let SendInvokeDispatch {
        service,
        action,
        inputs,
        output,
        metadata_output,
        ..
    } = request;
    let output =
        output.ok_or_else(|| DeferredCliError::input("stream send request requires output"))?;
    let output_path = match &output {
        SendOutput::File { path } => path.clone(),
        SendOutput::Stdout => PathBuf::from("-"),
    };
    let (status, metadata) = send_download_parts(
        ctx,
        &service,
        &action,
        inputs,
        &output_path,
        prepared.body.take().map(output::ResponseOutput::into_file),
        sensitive_outputs,
    )
    .await
    .map_err(DownloadResponseError::into_error)?;
    if status >= 400 {
        drop(prepared);
        print_value_and_exit(status, metadata);
    }
    match output {
        SendOutput::Stdout => {
            write_send_metadata(metadata_output, &metadata, prepared.metadata.take())?;
            std::process::exit(cli_exit_code_for_http_status(status));
        }
        SendOutput::File { .. } => {
            if let Some(metadata_output) = metadata_output {
                write_send_metadata(Some(metadata_output), &metadata, prepared.metadata.take())?;
            } else {
                println!("{}", serde_json::to_string_pretty(&metadata)?);
            }
            std::process::exit(cli_exit_code_for_http_status(status));
        }
    }
}

fn validate_send_destinations(
    output: Option<&SendOutput>,
    metadata: Option<&SendMetadataOutput>,
) -> Result<()> {
    if matches!(output, Some(SendOutput::File { path }) if path == Path::new("-")) {
        anyhow::bail!(
            "file output path '-' is ambiguous; use type=stdout or './-' for a literal filename"
        );
    }
    if let (
        Some(SendOutput::File { path: body }),
        Some(SendMetadataOutput::File { path: metadata }),
    ) = (output, metadata)
    {
        fn destination(path: &Path) -> Result<PathBuf> {
            let parent = path
                .parent()
                .filter(|p| !p.as_os_str().is_empty())
                .unwrap_or(Path::new("."));
            Ok(parent
                .canonicalize()
                .with_context(|| format!("cannot resolve output parent for {}", path.display()))?
                .join(path.file_name().context("output path needs a file name")?))
        }
        if destination(body)? == destination(metadata)? {
            anyhow::bail!("output and metadataOutput must name different destinations");
        }
    }
    Ok(())
}

fn finish_send_json(
    status: u16,
    value: serde_json::Value,
    sink: Option<SendOutput>,
    metadata: Option<SendMetadataOutput>,
    sensitive_outputs: &[String],
    mut prepared: PreparedSendOutput,
) -> Result<()> {
    if !(200..300).contains(&status)
        || value.get("decision").and_then(serde_json::Value::as_str) != Some("allow")
    {
        drop(prepared);
        print_value_and_exit(status, value);
    }
    match sink {
        Some(SendOutput::File { .. }) => {
            let receipt = prepared
                .body
                .take()
                .expect("file output was reserved")
                .save_json(&value)?;
            if metadata.is_some() {
                write_send_metadata(metadata, &receipt, prepared.metadata.take())?;
            } else {
                print_value_and_exit(status, receipt);
            }
        }
        Some(SendOutput::Stdout) => {
            // Preserve the complete send envelope; metadata never repeats result content.
            if metadata.is_some() {
                let mut bytes = serde_json::to_vec_pretty(&value)?;
                bytes.push(b'\n');
                let summary = output::FileOutput::new(
                    Path::new("-"),
                    bytes.len() as u64,
                    format!("{:x}", Sha256::digest(&bytes)),
                    "application/json",
                    !sensitive_outputs.is_empty(),
                );
                let receipt = output::receipt(&value, &summary, false, sensitive_outputs);
                {
                    let mut stdout = std::io::stdout().lock();
                    stdout
                        .write_all(&bytes)
                        .and_then(|()| stdout.flush())
                        .context("failed to write response to stdout")
                        .map_err(|error| {
                            output::LocalOutputFailure::response(
                                &value,
                                Path::new("-"),
                                error,
                                sensitive_outputs,
                            )
                        })?;
                }
                write_send_metadata(metadata, &receipt, prepared.metadata.take())?;
                exit_for_broker_status(status, &value);
            }
            print_value_and_exit(status, value);
        }
        None => {
            drop(prepared);
            print_value_and_exit(status, value)
        }
    }
    Ok(())
}

fn write_send_metadata(
    metadata_output: Option<SendMetadataOutput>,
    metadata: &serde_json::Value,
    reserved: Option<output::AtomicOutput>,
) -> Result<()> {
    let Some(metadata_output) = metadata_output else {
        return Ok(());
    };
    let formatted = serde_json::to_string_pretty(metadata)?;
    match metadata_output {
        SendMetadataOutput::Stderr => {
            eprintln!("{formatted}");
        }
        SendMetadataOutput::File { path } => {
            let reserved = match reserved {
                Some(reserved) => reserved,
                None => output::AtomicOutput::new(&path)?,
            };
            reserved
                .write_response(formatted.as_bytes(), "application/json", false)
                .map_err(|error| output::LocalOutputFailure::metadata(metadata, &path, error))?;
        }
    }
    Ok(())
}

async fn run_send_http(
    ctx: &CliContext<'_>,
    catalog: &ApiCatalog,
    method: &str,
    route: &str,
    path_params: BTreeMap<String, String>,
    query: BTreeMap<String, serde_json::Value>,
    body: Option<serde_json::Value>,
) -> Result<()> {
    let route_spec = catalog_route(catalog, method, route)?.clone();
    if let Some(serde_json::Value::Null) = body {
        require_cli_input::<()>(Err(anyhow::anyhow!("kind=http body cannot be null")));
    }
    if body.is_some() && !route_spec.body_allowed {
        require_cli_input::<()>(Err(anyhow::anyhow!(
            "route {} {} does not accept a JSON body",
            route_spec.method,
            route_spec.route
        )));
    }
    let path = resolve_route_path(&route_spec, path_params, query)?;
    let method = reqwest::Method::from_bytes(route_spec.method.as_bytes())
        .map_err(|error| anyhow::anyhow!("catalog method is invalid: {error}"))?;
    let response_shape = response_shape_for_route(&route_spec);
    let (status, value) =
        send_broker_json_method_shape(ctx, method, &path, body, response_shape).await?;
    println!("{}", serde_json::to_string_pretty(&value)?);
    exit_for_broker_status(status, &value);
}

fn response_shape_for_route(route: &HttpRouteSpec) -> ResponseShape {
    match route.response_kind {
        agent_access_core::ResponseKind::ManagementEnvelope => ResponseShape::ManagementObject,
        agent_access_core::ResponseKind::ResponseEnvelope => ResponseShape::Envelope,
        agent_access_core::ResponseKind::RawJson
        | agent_access_core::ResponseKind::AuthEnvelope
        | agent_access_core::ResponseKind::RawStream => ResponseShape::Json,
    }
}

fn catalog_action<'a>(
    catalog: &'a ApiCatalog,
    service: &str,
    action: &str,
) -> Result<&'a ApiActionSpec> {
    catalog
        .services
        .iter()
        .find(|candidate| candidate.service == service)
        .and_then(|service| {
            service
                .actions
                .iter()
                .find(|candidate| candidate.action == action)
        })
        .ok_or_else(|| anyhow::anyhow!("runtime catalog does not expose action {service}.{action}; run agent-access services describe {service} to check availability and setup requirements"))
}

fn catalog_route<'a>(
    catalog: &'a ApiCatalog,
    method: &str,
    route: &str,
) -> Result<&'a HttpRouteSpec> {
    let method = method.to_ascii_uppercase();
    if !route.starts_with("/v1/") {
        anyhow::bail!("send HTTP route must start with /v1/");
    }
    let route_spec = catalog
        .routes
        .iter()
        .find(|candidate| candidate.method == method && candidate.route == route)
        .ok_or_else(|| anyhow::anyhow!("runtime catalog does not expose route {method} {route}"))?;
    if !matches!(
        route_spec.request_body_kind,
        agent_access_core::RequestBodyKind::Json
    ) {
        let guidance = if route_spec.operation == "admin.imports.document.upload" {
            "use agent-access admin imports upload-document to preserve the original document bytes"
        } else {
            "use a client that supports the route's request body format"
        };
        return Err(DeferredCliError::input(anyhow::anyhow!(
            "route {method} {route} requires a request body format unsupported by kind=http; {guidance}"
        ))
        .into());
    }
    Ok(route_spec)
}

fn resolve_route_path(
    route: &HttpRouteSpec,
    path_params: BTreeMap<String, String>,
    query: BTreeMap<String, serde_json::Value>,
) -> Result<String> {
    let expected_path = route
        .path_params
        .iter()
        .map(|param| param.name.clone())
        .collect::<std::collections::BTreeSet<_>>();
    for key in path_params.keys() {
        if !expected_path.contains(key) {
            anyhow::bail!("route {} has no path parameter {key}", route.route);
        }
    }
    let mut path = route.route.clone();
    for param in &route.path_params {
        let value = path_params.get(&param.name).ok_or_else(|| {
            anyhow::anyhow!(
                "route {} requires path parameter {}",
                route.route,
                param.name
            )
        })?;
        let encoded = utf8_percent_encode(value, PATH_SEGMENT_ENCODE_SET).to_string();
        path = path.replace(&format!("{{{}}}", param.name), &encoded);
    }

    let allowed_query = route
        .query_params
        .iter()
        .map(|param| param.name.clone())
        .collect::<std::collections::BTreeSet<_>>();
    for key in query.keys() {
        if !allowed_query.contains(key) {
            anyhow::bail!("route {} has no query parameter {key}", route.route);
        }
    }
    if query.is_empty() {
        return Ok(path);
    }
    let mut serializer = form_urlencoded::Serializer::new(String::new());
    for (key, value) in query {
        append_query_value(&mut serializer, &key, &value)?;
    }
    let query = serializer.finish();
    Ok(format!("{path}?{query}"))
}

fn append_query_value(
    serializer: &mut form_urlencoded::Serializer<'_, String>,
    key: &str,
    value: &serde_json::Value,
) -> Result<()> {
    match value {
        serde_json::Value::String(value) => {
            serializer.append_pair(key, value);
        }
        serde_json::Value::Number(value) => {
            serializer.append_pair(key, &value.to_string());
        }
        serde_json::Value::Bool(value) => {
            serializer.append_pair(key, if *value { "true" } else { "false" });
        }
        serde_json::Value::Array(values) => {
            for value in values {
                append_query_value(serializer, key, value)?;
            }
        }
        serde_json::Value::Null | serde_json::Value::Object(_) => {
            anyhow::bail!("query parameter {key} must be a scalar or array of scalars");
        }
    }
    Ok(())
}

/// The input form of a credential connection's token, as its input-schema
/// route returns it for the chosen (or only accepted) profile: the profile
/// to store and the fields it takes.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
struct CredentialInputSchema {
    profile: String,
    credential_kind: String,
    fields: Vec<CredentialInputField>,
    #[serde(default, deserialize_with = "deserialize_credential_input_policy")]
    input_policy: Option<ImportedCredentialInputPolicy>,
}

fn deserialize_credential_input_policy<'de, D>(
    deserializer: D,
) -> std::result::Result<Option<ImportedCredentialInputPolicy>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    ImportedCredentialInputPolicy::deserialize(deserializer).map(Some)
}

async fn fetch_credential_input_schema(
    ctx: &CliContext<'_>,
    path: &str,
) -> Result<CredentialInputSchema> {
    let (status, value) = send_broker_get(ctx, path, ResponseShape::ManagementObject).await?;
    if status >= 400 {
        print_value_and_exit(status, value);
    }
    let result = value
        .get("result")
        .cloned()
        .ok_or_else(|| anyhow::anyhow!("malformed broker response: input schema result missing"))?;
    serde_json::from_value(result).context("malformed broker response: input schema is invalid")
}

fn reject_literal_identity_token_for_management(cli: &Cli) {
    if cli.token_value.is_some() {
        require_cli_input::<()>(Err(anyhow::anyhow!(
            "management commands do not accept --token-value; use --token-env, --token-file, config, or AGENT_ACCESS_TOKEN"
        )));
    }
}

fn reject_token_source_flags_for_auth_token(cli: &Cli) -> Result<()> {
    if cli.token_value.is_some() {
        anyhow::bail!("auth token commands do not accept --token-value");
    }
    if cli.token_file.is_some() {
        anyhow::bail!("auth token commands do not accept --token-file");
    }
    if cli.token_env.is_some() {
        anyhow::bail!("auth token commands do not accept --token-env");
    }
    Ok(())
}

#[derive(Debug, Default, PartialEq, Eq)]
struct GitCredentialRequest {
    protocol: Option<String>,
    host: Option<String>,
}

fn read_git_credential_request(mut input: impl BufRead) -> Result<GitCredentialRequest> {
    let mut request = GitCredentialRequest::default();
    let mut line = String::new();
    loop {
        line.clear();
        if input
            .read_line(&mut line)
            .context("failed to read Git credential input")?
            == 0
        {
            break;
        }
        let record = line.trim_end_matches(['\r', '\n']);
        if record.is_empty() {
            break;
        }
        let Some((key, value)) = record.split_once('=') else {
            anyhow::bail!("credential record is not key=value");
        };
        match key {
            "protocol" => request.protocol = Some(value.to_string()),
            "host" => request.host = Some(value.to_string()),
            // Git may send these fields, and newer clients may add more. The helper only
            // needs the logical destination to reject malformed requests fail-closed.
            "path" | "username" | "password" => {}
            _ => {}
        }
    }
    Ok(request)
}

fn consume_git_credential_request(mut input: impl BufRead) -> Result<()> {
    let mut line = Vec::new();
    loop {
        line.clear();
        if input
            .read_until(b'\n', &mut line)
            .context("failed to consume Git credential input")?
            == 0
        {
            break;
        }
        if line.iter().all(|byte| matches!(byte, b'\r' | b'\n')) {
            break;
        }
    }
    Ok(())
}

fn write_git_credential_failure(
    mut output: impl Write,
    mut error_output: impl Write,
    message: &str,
) -> Result<()> {
    writeln!(error_output, "agent-access: {message}")?;
    write!(output, "quit=true\n\n")?;
    Ok(())
}

fn run_git_credential_command(
    cli: &Cli,
    config_path: &PathBuf,
    operation: GitCredentialOperation,
    input: impl BufRead,
    mut output: impl Write,
    error_output: impl Write,
) -> Result<()> {
    match operation {
        GitCredentialOperation::Capability => Ok(()),
        GitCredentialOperation::Store | GitCredentialOperation::Erase => {
            // Consume the request without parsing or retaining credentials. Token lifecycle is
            // intentionally owned only by `auth token set` and `auth token clear`.
            consume_git_credential_request(input)
        }
        GitCredentialOperation::Get => {
            let request = match read_git_credential_request(input) {
                Ok(request) => request,
                Err(_) => {
                    return write_git_credential_failure(
                        output,
                        error_output,
                        "malformed credential input: expected key=value records",
                    );
                }
            };
            if request
                .protocol
                .as_deref()
                .is_none_or(|value| value.trim().is_empty())
            {
                return write_git_credential_failure(
                    output,
                    error_output,
                    "malformed credential input: missing protocol",
                );
            }
            if request
                .host
                .as_deref()
                .is_none_or(|value| value.trim().is_empty())
            {
                return write_git_credential_failure(
                    output,
                    error_output,
                    "malformed credential input: missing host",
                );
            }

            if cli.token_value.is_some() {
                return write_git_credential_failure(
                    output,
                    error_output,
                    "Git credential helper does not accept --token-value; use --token-file, --token-env, or configured token sources",
                );
            }
            let explicit_config = cli.config.is_some();
            let config_exists = config_path.exists();
            let resolution = load_config_or_default(config_path, explicit_config)
                .map(|config| resolve_identity_token_report(cli, config_exists, &config));
            let token = match resolution {
                Ok(IdentityTokenResolution {
                    token: Some(token),
                    error: None,
                    ..
                }) if !token.contains(['\0', '\r', '\n']) => token,
                _ => {
                    return write_git_credential_failure(
                        output,
                        error_output,
                        "no usable broker token is configured; run `agent-access auth token set --token-stdin`",
                    );
                }
            };
            write!(output, "username=agent-access\npassword={token}\n\n")?;
            Ok(())
        }
    }
}

fn run_auth_token_command(
    cli: &Cli,
    config_path: &PathBuf,
    command: &AuthTokenCommand,
) -> Result<()> {
    reject_token_source_flags_for_auth_token(cli)?;
    let explicit_config = cli.config.is_some();
    let config_exists = config_path.exists();
    let config = load_config_or_default(config_path, explicit_config)?;

    match command {
        AuthTokenCommand::Status => run_auth_token_status(cli, config_exists, &config),
        AuthTokenCommand::Set { token_stdin } => {
            let path = configured_token_file_for_write(cli, config_exists, &config, true)?;
            let token = read_token_input(*token_stdin)?;
            write_managed_token_file(&path, &format!("{token}\n"))?;
            println!("configured token file updated: {}", path.display());
            Ok(())
        }
        AuthTokenCommand::Clear => {
            let path = configured_token_file_for_write(cli, config_exists, &config, false)?;
            if path.exists() {
                truncate_existing_token_file(&path)?;
                println!("configured token file cleared: {}", path.display());
            } else {
                println!("configured token file already absent: {}", path.display());
            }
            Ok(())
        }
    }
}

fn run_auth_token_status(cli: &Cli, config_exists: bool, config: &CliConfig) -> Result<()> {
    let disabled = identity_resolution_disabled(cli, config_exists, config);
    println!(
        "identity: {}",
        if disabled { "disabled" } else { "enabled" }
    );

    let configured_status = match configured_token_file_path(config_exists, config)? {
        Some(path) => {
            let status = configured_token_file_status(&path);
            println!("configured token file: {}", path.display());
            println!("configured token file status: {}", status.as_str());
            Some(status)
        }
        None => {
            println!("configured token file: none");
            println!("configured token file status: not configured");
            None
        }
    };

    if configured_status == Some(ConfiguredTokenFileStatus::Unreadable) {
        anyhow::bail!("configured token file is unreadable");
    }

    let resolution = resolve_identity_token_report(cli, config_exists, config);
    println!("effective token source: {}", resolution.source_label);
    println!("effective token status: {}", resolution.status);
    if let Some(error) = resolution.error {
        anyhow::bail!("{error}");
    }
    Ok(())
}

fn configured_token_file_for_write(
    cli: &Cli,
    config_exists: bool,
    config: &CliConfig,
    reject_disabled: bool,
) -> Result<PathBuf> {
    if !config_exists {
        anyhow::bail!("config file does not exist; identity.token_file is required");
    }
    if reject_disabled && identity_resolution_disabled(cli, config_exists, config) {
        anyhow::bail!("identity token resolution is disabled");
    }
    configured_token_file_path(config_exists, config)
        .map_err(anyhow::Error::from)?
        .ok_or_else(|| anyhow::anyhow!("identity.token_file is not configured"))
}

fn configured_token_file_path(
    config_exists: bool,
    config: &CliConfig,
) -> Result<Option<PathBuf>, agent_access_core::HomeExpansionError> {
    let Some(file) = config_exists
        .then_some(config.identity.token_file.as_ref())
        .flatten()
    else {
        return Ok(None);
    };
    expand_current_user_home(file, "config identity.token_file").map(Some)
}

fn read_token_input(token_stdin: bool) -> Result<String> {
    let mut value = String::new();
    if token_stdin {
        std::io::stdin()
            .read_to_string(&mut value)
            .context("failed to read token from stdin")?;
    } else {
        value = rpassword::prompt_password("Token: ")
            .context("failed to read token from interactive prompt")?;
    }
    let token = value.trim().to_string();
    if token.is_empty() {
        anyhow::bail!("token must not be empty");
    }
    Ok(token)
}

fn write_managed_token_file(path: &Path, contents: &str) -> Result<()> {
    if path.exists() {
        let mut file = fs::OpenOptions::new()
            .write(true)
            .truncate(true)
            .open(path)
            .with_context(|| format!("failed to open token file {}", path.display()))?;
        file.write_all(contents.as_bytes())
            .with_context(|| format!("failed to write token file {}", path.display()))?;
        return Ok(());
    }

    if let Some(parent) = path.parent()
        && !parent.as_os_str().is_empty()
    {
        create_private_parent_dirs(parent)?;
    }

    let mut options = fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    options.mode(0o600);
    match options.open(path) {
        Ok(mut file) => file
            .write_all(contents.as_bytes())
            .with_context(|| format!("failed to write token file {}", path.display())),
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
            let mut file = fs::OpenOptions::new()
                .write(true)
                .truncate(true)
                .open(path)
                .with_context(|| format!("failed to open token file {}", path.display()))?;
            file.write_all(contents.as_bytes())
                .with_context(|| format!("failed to write token file {}", path.display()))
        }
        Err(error) => {
            Err(error).with_context(|| format!("failed to create token file {}", path.display()))
        }
    }
}

fn truncate_existing_token_file(path: &Path) -> Result<()> {
    fs::OpenOptions::new()
        .write(true)
        .truncate(true)
        .open(path)
        .with_context(|| format!("failed to truncate token file {}", path.display()))?;
    Ok(())
}

fn create_private_parent_dirs(path: &Path) -> Result<()> {
    if path.exists() {
        return Ok(());
    }
    if let Some(parent) = path.parent()
        && !parent.as_os_str().is_empty()
    {
        create_private_parent_dirs(parent)?;
    }
    #[cfg(unix)]
    {
        let mut builder = fs::DirBuilder::new();
        builder.mode(0o700);
        builder
            .create(path)
            .with_context(|| format!("failed to create directory {}", path.display()))?;
    }
    #[cfg(not(unix))]
    {
        fs::create_dir(path)
            .with_context(|| format!("failed to create directory {}", path.display()))?;
    }
    Ok(())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ConfiguredTokenFileStatus {
    Missing,
    Empty,
    Present,
    Unreadable,
}

impl ConfiguredTokenFileStatus {
    fn as_str(self) -> &'static str {
        match self {
            Self::Missing => "missing",
            Self::Empty => "empty",
            Self::Present => "present",
            Self::Unreadable => "unreadable",
        }
    }
}

fn configured_token_file_status(path: &Path) -> ConfiguredTokenFileStatus {
    match fs::read_to_string(path) {
        Ok(value) if value.trim().is_empty() => ConfiguredTokenFileStatus::Empty,
        Ok(_) => ConfiguredTokenFileStatus::Present,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            ConfiguredTokenFileStatus::Missing
        }
        Err(_) => ConfiguredTokenFileStatus::Unreadable,
    }
}

fn credential_verify_body(verify: &CredentialVerifyArgs) -> serde_json::Value {
    let mut body = serde_json::Map::new();
    if let Some(service) = &verify.service {
        body.insert("service".to_string(), serde_json::json!(service));
    }
    if let Some(repository) = &verify.repository {
        body.insert("repository".to_string(), serde_json::json!(repository));
    }
    serde_json::Value::Object(body)
}

/// The self-service route of `connection`'s token.
fn self_connection_path(connection: &str) -> String {
    require_cli_input(validate_connection_argument(connection));
    format!("/v1/credentials/connections/{connection}")
}

/// The administrator route of `principal`'s token for `connection`.
fn admin_connection_path(principal: &str, connection: &str) -> String {
    require_cli_input(validate_connection_argument(connection));
    format!(
        "/v1/admin/principals/{}/credentials/connections/{connection}",
        encoded_path_segment(principal)
    )
}

/// Fetches the input schema of `credential_path`, collects the fields from
/// their sources, stores the token, and verifies it when asked.
async fn put_connection_credential(
    ctx: &CliContext<'_>,
    credential_path: &str,
    input: &CredentialPutArgs,
) -> Result<()> {
    let schema = fetch_credential_input_schema(
        ctx,
        &credential_input_schema_path(credential_path, &input.profile),
    )
    .await?;
    let body = require_cli_input(credential_put_body(CredentialPutInput {
        schema: &schema,
        username: &input.username,
        username_env: &input.username_env,
        username_file: &input.username_file,
        field: &input.field,
        field_env: &input.field_env,
        field_file: &input.field_file,
        field_stdin: &input.field_stdin,
        display_name: &input.display_name,
        expires_at: &input.expires_at,
    }));
    let (status, value) =
        send_broker_json_method(ctx, reqwest::Method::PUT, credential_path, Some(body)).await?;
    if status >= 400 || !input.verify {
        print_value_and_exit(status, value);
    }
    let verify = CredentialVerifyArgs {
        service: input.verify_service.clone(),
        repository: input.verify_repository.clone(),
    };
    let (verify_status, verify_value) = send_broker_json_method(
        ctx,
        reqwest::Method::POST,
        &format!("{credential_path}/verify"),
        Some(credential_verify_body(&verify)),
    )
    .await?;
    print_value_and_exit(verify_status, verify_value);
}

async fn run_credentials_command(ctx: &CliContext<'_>, command: &CredentialsCommand) -> Result<()> {
    match command {
        CredentialsCommand::List => {
            run_broker_get(ctx, "/v1/credentials", ResponseShape::Object).await
        }
        CredentialsCommand::Targets => {
            run_broker_get(ctx, "/v1/credentials/targets", ResponseShape::Object).await
        }
        CredentialsCommand::Inspect { connection } => {
            run_broker_get(
                ctx,
                &self_connection_path(connection),
                ResponseShape::Object,
            )
            .await
        }
        CredentialsCommand::Put { connection, input } => {
            put_connection_credential(ctx, &self_connection_path(connection), input).await
        }
        CredentialsCommand::Delete { connection } => {
            run_broker_json_method(
                ctx,
                reqwest::Method::DELETE,
                &self_connection_path(connection),
                None,
            )
            .await
        }
        CredentialsCommand::Verify { connection, verify } => {
            run_broker_json_method(
                ctx,
                reqwest::Method::POST,
                &format!("{}/verify", self_connection_path(connection)),
                Some(credential_verify_body(verify)),
            )
            .await
        }
        CredentialsCommand::DeleteRetained { credential_id } => {
            run_broker_json_method(
                ctx,
                reqwest::Method::DELETE,
                &format!(
                    "/v1/credentials/retained/{}",
                    encoded_path_segment(credential_id)
                ),
                None,
            )
            .await
        }
    }
}

async fn run_tokens_command(ctx: &CliContext<'_>, command: &TokensCommand) -> Result<()> {
    match command {
        TokensCommand::EffectiveAccess { request_file } => {
            run_broker_json_method(
                ctx,
                reqwest::Method::POST,
                "/v1/tokens/effective-access",
                Some(read_json_file(request_file)),
            )
            .await
        }
        TokensCommand::List {
            include_revoked,
            include_expired,
        } => {
            let mut query = form_urlencoded::Serializer::new(String::new());
            if *include_revoked {
                query.append_pair("includeRevoked", "true");
            }
            if *include_expired {
                query.append_pair("includeExpired", "true");
            }
            let query = query.finish();
            let path = if query.is_empty() {
                "/v1/tokens".to_string()
            } else {
                format!("/v1/tokens?{query}")
            };
            run_broker_get(ctx, &path, ResponseShape::Object).await
        }
        TokensCommand::Issue {
            name,
            ttl,
            expires_at,
            never,
            services,
            actions,
            resource_ids,
            resource_group_ids,
            restricted_services,
            service_restrictions_file,
            execution_contexts,
        } => {
            let body =
                require_cli_input(self_agent_token_issue_body(SelfAgentTokenIssueCliInput {
                    name,
                    ttl,
                    expires_at,
                    never: *never,
                    services,
                    actions,
                    resource_ids,
                    resource_group_ids,
                    restricted_services,
                    service_restrictions_file,
                    execution_contexts,
                }));
            run_broker_json_method(ctx, reqwest::Method::POST, "/v1/tokens", Some(body)).await
        }
        TokensCommand::Inspect { token_id } => {
            run_broker_get(
                ctx,
                &format!("/v1/tokens/{token_id}"),
                ResponseShape::Object,
            )
            .await
        }
        TokensCommand::Revoke { token_id } => {
            run_broker_json_method(
                ctx,
                reqwest::Method::DELETE,
                &format!("/v1/tokens/{token_id}"),
                None,
            )
            .await
        }
        TokensCommand::Pause { token_id } => {
            run_broker_json_method(
                ctx,
                reqwest::Method::POST,
                &self_token_action_path(token_id, BrokerTokenAction::Pause),
                None,
            )
            .await
        }
        TokensCommand::Resume { token_id } => {
            run_broker_json_method(
                ctx,
                reqwest::Method::POST,
                &self_token_action_path(token_id, BrokerTokenAction::Resume),
                None,
            )
            .await
        }
    }
}

struct SelfAgentTokenIssueCliInput<'a> {
    name: &'a str,
    ttl: &'a Option<String>,
    expires_at: &'a Option<String>,
    never: bool,
    services: &'a [String],
    actions: &'a [TokenActionRestriction],
    resource_ids: &'a [TokenResourceReference],
    resource_group_ids: &'a [TokenResourceReference],
    restricted_services: &'a [String],
    service_restrictions_file: &'a Option<PathBuf>,
    execution_contexts: &'a [String],
}

fn self_agent_token_issue_body(
    input: SelfAgentTokenIssueCliInput<'_>,
) -> Result<serde_json::Value> {
    let service_restrictions = token_service_restrictions(TokenServiceRestrictionsInput {
        services: input.services,
        actions: input.actions,
        resource_ids: input.resource_ids,
        resource_group_ids: input.resource_group_ids,
        restricted_services: input.restricted_services,
        service_restrictions_file: input.service_restrictions_file,
    })?;
    let mut body = serde_json::Map::new();
    body.insert("name".to_string(), serde_json::json!(input.name));
    body.insert("ttl".to_string(), serde_json::json!(input.ttl));
    body.insert("expiresAt".to_string(), serde_json::json!(input.expires_at));
    body.insert("never".to_string(), serde_json::json!(input.never));
    body.insert(
        "allowedExecutionContexts".to_string(),
        serde_json::json!(input.execution_contexts),
    );
    if !input.services.is_empty() {
        body.insert(
            "allowedServices".to_string(),
            serde_json::json!(input.services),
        );
    }
    if let Some(service_restrictions) = service_restrictions {
        body.insert("serviceRestrictions".to_string(), service_restrictions);
    }
    Ok(serde_json::Value::Object(body))
}

struct TokenServiceRestrictionsInput<'a> {
    services: &'a [String],
    actions: &'a [TokenActionRestriction],
    resource_ids: &'a [TokenResourceReference],
    resource_group_ids: &'a [TokenResourceReference],
    restricted_services: &'a [String],
    service_restrictions_file: &'a Option<PathBuf>,
}

#[derive(Default)]
struct TokenServiceRestrictionDraft {
    action_set: BTreeSet<String>,
    resources: Option<ResourceSelection>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct TokenServiceRestrictionFile {
    actions: Vec<String>,
    #[serde(default, deserialize_with = "deserialize_token_resource_selection")]
    resources: Option<ResourceSelection>,
}

fn deserialize_token_resource_selection<'de, D: serde::Deserializer<'de>>(
    deserializer: D,
) -> std::result::Result<Option<ResourceSelection>, D::Error> {
    ResourceSelection::deserialize(deserializer).map(Some)
}

fn token_service_restrictions(
    input: TokenServiceRestrictionsInput<'_>,
) -> Result<Option<serde_json::Value>> {
    let mut allowed_services = BTreeSet::new();
    for service in input.services {
        validate_service_argument(service)?;
        if !allowed_services.insert(service.as_str()) {
            anyhow::bail!("--service contains duplicate service {service}");
        }
    }

    if let Some(path) = input.service_restrictions_file {
        let restrictions: BTreeMap<String, TokenServiceRestrictionFile> =
            serde_json::from_value(read_json_file(path))?;
        if restrictions.is_empty() {
            anyhow::bail!(
                "--service-restrictions-file must contain at least one service restriction"
            );
        }
        for (service, restriction) in &restrictions {
            validate_token_restriction_service(
                service,
                &allowed_services,
                "--service-restrictions-file",
            )?;
            if restriction.actions.is_empty() {
                anyhow::bail!("service {service} requires at least one action");
            }
            let mut seen = BTreeSet::new();
            for action in &restriction.actions {
                parse_token_action_restriction(&format!("{service}={action}"))
                    .map_err(anyhow::Error::msg)?;
                if !seen.insert(action) {
                    anyhow::bail!("service {service} requires valid unique actions");
                }
            }
            if let Some(selection) = &restriction.resources {
                validate_selection_ids(selection)?;
            }
        }
        let restrictions = restrictions
            .into_iter()
            .map(|(service, restriction)| {
                (
                    service,
                    AgentTokenServiceRestriction {
                        actions: restriction.actions,
                        resources: restriction.resources,
                    },
                )
            })
            .collect::<BTreeMap<_, _>>();
        return Ok(Some(serde_json::to_value(restrictions)?));
    }
    let mut restrictions = BTreeMap::<String, TokenServiceRestrictionDraft>::new();
    for action in input.actions {
        validate_token_restriction_service(&action.service, &allowed_services, "--action")?;
        let restriction = restrictions.entry(action.service.clone()).or_default();
        if !restriction.action_set.insert(action.action.clone()) {
            anyhow::bail!(
                "--action contains duplicate action {}={}",
                action.service,
                action.action
            );
        }
    }
    for service in input.restricted_services {
        validate_token_restriction_service(service, &allowed_services, "--restrict-resources")?;
        restrictions
            .entry(service.clone())
            .or_default()
            .resources
            .get_or_insert_with(ResourceSelection::default);
    }
    for (references, group) in [
        (input.resource_ids, false),
        (input.resource_group_ids, true),
    ] {
        for reference in references {
            validate_token_restriction_service(
                &reference.service,
                &allowed_services,
                "resource selection",
            )?;
            let selection = restrictions
                .entry(reference.service.clone())
                .or_default()
                .resources
                .get_or_insert_with(ResourceSelection::default);
            let ids = if group {
                &mut selection.resource_group_ids
            } else {
                &mut selection.resource_ids
            };
            ids.push(reference.id.clone());
        }
    }
    for (service, restriction) in &restrictions {
        if restriction.action_set.is_empty() {
            anyhow::bail!(
                "token resource restrictions for service {service} require at least one --action {service}=ACTION"
            );
        }
        if let Some(selection) = &restriction.resources {
            validate_selection_ids(selection)?;
        }
    }

    if restrictions.is_empty() {
        return Ok(None);
    }
    let restrictions = restrictions
        .into_iter()
        .map(|(service, restriction)| {
            (
                service,
                AgentTokenServiceRestriction {
                    actions: restriction.action_set.into_iter().collect(),
                    resources: restriction.resources,
                },
            )
        })
        .collect::<BTreeMap<_, _>>();
    Ok(Some(
        serde_json::to_value(restrictions).expect("token service restrictions serialize"),
    ))
}

fn validate_token_restriction_service(
    service: &str,
    allowed_services: &BTreeSet<&str>,
    flag: &str,
) -> Result<()> {
    if allowed_services.contains(service) {
        Ok(())
    } else {
        anyhow::bail!("{flag} references service {service}; add the same service with --service")
    }
}

async fn run_admin_command(ctx: &CliContext<'_>, command: &AdminCommand) -> Result<()> {
    match command {
        AdminCommand::Imports { command } => import_commands::run(ctx, command).await,
        AdminCommand::Store {
            command: AdminStoreCommand::Status,
        } => run_broker_get(ctx, "/v1/admin/store/status", ResponseShape::Object).await,
        AdminCommand::Config { command } => match command {
            AdminConfigCommand::Status => {
                run_broker_get(ctx, "/v1/admin/config/status", ResponseShape::Object).await
            }
            AdminConfigCommand::Reload => {
                run_broker_json_method(ctx, reqwest::Method::POST, "/v1/admin/config/reload", None)
                    .await
            }
        },
        AdminCommand::Principals { command } => run_admin_principals_command(ctx, command).await,
        AdminCommand::Groups { command } => run_admin_groups_command(ctx, command).await,
        AdminCommand::Rights { command } => run_admin_rights_command(ctx, command).await,
        AdminCommand::Tokens { command } => run_admin_tokens_command(ctx, command).await,
        AdminCommand::Credentials { command } => run_admin_credentials_command(ctx, command).await,
        AdminCommand::Policy { command } => run_admin_policy_command(ctx, command).await,
        AdminCommand::Audit { command } => audit_commands::run_admin_audit(ctx, command).await,
    }
}

async fn run_admin_identity_token_command(
    ctx: &CliContext<'_>,
    command: &AdminIdentityTokenCommand,
) -> Result<()> {
    let (principal, method, suffix, body) = match command {
        AdminIdentityTokenCommand::Inspect { principal } => {
            (principal, reqwest::Method::GET, "", None)
        }
        AdminIdentityTokenCommand::Reveal { principal } => {
            (principal, reqwest::Method::POST, "/reveal", None)
        }
        AdminIdentityTokenCommand::Generate { principal } => {
            (principal, reqwest::Method::POST, "/generate", None)
        }
        AdminIdentityTokenCommand::Remove { principal } => {
            (principal, reqwest::Method::DELETE, "", None)
        }
        AdminIdentityTokenCommand::Set {
            principal,
            identity_token_file,
            identity_token_stdin,
        } => {
            // Preserve exact bearer bytes: trimming changes the proxy's fingerprint.
            let token = if let Some(path) = identity_token_file {
                fs::read_to_string(path).context("failed to read identity token file")?
            } else if *identity_token_stdin {
                let mut token = String::new();
                std::io::stdin()
                    .read_to_string(&mut token)
                    .context("failed to read identity token from stdin")?;
                token
            } else {
                anyhow::bail!("use --identity-token-file or --identity-token-stdin");
            };
            (
                principal,
                reqwest::Method::PUT,
                "",
                Some(serde_json::json!({"token": token})),
            )
        }
        AdminIdentityTokenCommand::Update {
            principal,
            settings,
            expected_revision,
        } => (
            principal,
            reqwest::Method::PATCH,
            "",
            Some(settings.body("expectedRevision", *expected_revision)),
        ),
    };
    let path = format!(
        "/v1/admin/principals/{}/identity-token{suffix}",
        encoded_path_segment(principal)
    );
    run_broker_json_method(ctx, method, &path, body).await
}

async fn run_admin_identity_access_command(
    ctx: &CliContext<'_>,
    command: &AdminIdentityAccessCommand,
) -> Result<()> {
    let (principal, method, body) = match command {
        AdminIdentityAccessCommand::Inspect { principal } => {
            (principal, reqwest::Method::GET, None)
        }
        AdminIdentityAccessCommand::Pause {
            principal,
            expected_version,
        }
        | AdminIdentityAccessCommand::Resume {
            principal,
            expected_version,
        } => (
            principal,
            reqwest::Method::PATCH,
            Some(serde_json::json!({
                "paused": matches!(command, AdminIdentityAccessCommand::Pause { .. }),
                "expectedVersion": expected_version,
            })),
        ),
    };
    let path = format!(
        "/v1/admin/principals/{}/identity-access",
        encoded_path_segment(principal)
    );
    run_broker_json_method(ctx, method, &path, body).await
}

async fn run_admin_identity_bindings_command(
    ctx: &CliContext<'_>,
    command: &AdminIdentityBindingsCommand,
) -> Result<()> {
    let (principal, binding, method, body, query) = match command {
        AdminIdentityBindingsCommand::List { principal } => {
            (principal, None, reqwest::Method::GET, None, String::new())
        }
        AdminIdentityBindingsCommand::Create {
            principal,
            namespace,
            username,
            read_only,
        } => (
            principal,
            None,
            reqwest::Method::POST,
            Some(serde_json::json!({
                "namespace": namespace,
                "username": username,
                "readOnly": read_only,
            })),
            String::new(),
        ),
        AdminIdentityBindingsCommand::Update {
            principal,
            binding,
            settings,
            expected_version,
        } => (
            principal,
            Some(binding),
            reqwest::Method::PATCH,
            Some(settings.body("expectedVersion", *expected_version)),
            String::new(),
        ),
        AdminIdentityBindingsCommand::Delete {
            principal,
            binding,
            expected_version,
        } => (
            principal,
            Some(binding),
            reqwest::Method::DELETE,
            None,
            format!("?expectedVersion={expected_version}"),
        ),
    };
    let suffix = binding
        .map(|binding| format!("/{}", encoded_path_segment(binding)))
        .unwrap_or_default();
    let path = format!(
        "/v1/admin/principals/{}/identity-bindings{suffix}{query}",
        encoded_path_segment(principal)
    );
    run_broker_json_method(ctx, method, &path, body).await
}

async fn run_admin_service_limits_command(
    ctx: &CliContext<'_>,
    command: &AdminPrincipalServiceLimitsCommand,
) -> Result<()> {
    match command {
        AdminPrincipalServiceLimitsCommand::List { principal } => {
            run_broker_get(
                ctx,
                &format!(
                    "/v1/admin/principals/{}/service-limits",
                    encoded_path_segment(principal)
                ),
                ResponseShape::Object,
            )
            .await
        }
        AdminPrincipalServiceLimitsCommand::Set {
            principal,
            service,
            requests,
            window,
        } => {
            run_broker_json_method(
                ctx,
                reqwest::Method::PUT,
                &admin_service_limit_path(principal, service),
                Some(serde_json::json!({
                    "requests": requests,
                    "windowSeconds": window,
                })),
            )
            .await
        }
        AdminPrincipalServiceLimitsCommand::Clear { principal, service } => {
            run_broker_json_method(
                ctx,
                reqwest::Method::DELETE,
                &admin_service_limit_path(principal, service),
                None,
            )
            .await
        }
    }
}

fn admin_service_limit_path(principal: &str, service: &str) -> String {
    format!(
        "/v1/admin/principals/{}/service-limits/{}",
        encoded_path_segment(principal),
        encoded_path_segment(service)
    )
}

async fn run_admin_principals_command(
    ctx: &CliContext<'_>,
    command: &AdminPrincipalsCommand,
) -> Result<()> {
    match command {
        AdminPrincipalsCommand::IdentityToken { command } => {
            run_admin_identity_token_command(ctx, command).await
        }
        AdminPrincipalsCommand::IdentityAccess { command } => {
            run_admin_identity_access_command(ctx, command).await
        }
        AdminPrincipalsCommand::IdentityBindings { command } => {
            run_admin_identity_bindings_command(ctx, command).await
        }
        AdminPrincipalsCommand::ServiceLimits { command } => {
            run_admin_service_limits_command(ctx, command).await
        }
        AdminPrincipalsCommand::List => {
            run_broker_get(ctx, "/v1/admin/principals", ResponseShape::Object).await
        }
        AdminPrincipalsCommand::Inspect { principal } => {
            run_broker_get(
                ctx,
                &format!("/v1/admin/principals/{principal}"),
                ResponseShape::Object,
            )
            .await
        }
        AdminPrincipalsCommand::Create {
            principal,
            kind,
            display_name,
            email,
            external_subject,
            role,
            self_service_enabled,
        } => {
            let body = serde_json::json!({
                "principalId": principal,
                "kind": kind,
                "displayName": display_name,
                "email": email,
                "externalSubject": external_subject,
                    "role": role,
                    "selfServiceEnabled": self_service_enabled.unwrap_or(kind != "service_account"),
            });
            run_broker_json_method(
                ctx,
                reqwest::Method::POST,
                "/v1/admin/principals",
                Some(body),
            )
            .await
        }
        AdminPrincipalsCommand::Update {
            principal,
            display_name,
            clear_display_name,
            email,
            clear_email,
        } => {
            let mut body = serde_json::Map::new();
            if *clear_display_name {
                body.insert("displayName".to_string(), serde_json::Value::Null);
            } else if let Some(display_name) = display_name {
                body.insert("displayName".to_string(), serde_json::json!(display_name));
            }
            if *clear_email {
                body.insert("email".to_string(), serde_json::Value::Null);
            } else if let Some(email) = email {
                body.insert("email".to_string(), serde_json::json!(email));
            }
            if body.is_empty() {
                require_cli_input::<()>(Err(anyhow::anyhow!(
                    "admin principals update requires at least one of --display-name, --clear-display-name, --email, or --clear-email"
                )));
            }
            run_broker_json_method(
                ctx,
                reqwest::Method::PATCH,
                &format!("/v1/admin/principals/{principal}"),
                Some(serde_json::Value::Object(body)),
            )
            .await
        }
        AdminPrincipalsCommand::Enable { principal } => {
            patch_principal_status(ctx, principal, "active").await
        }
        AdminPrincipalsCommand::Disable { principal } => {
            patch_principal_status(ctx, principal, "disabled").await
        }
        AdminPrincipalsCommand::Access { command } => match command {
            AdminPrincipalAccessCommand::Set {
                principal,
                role,
                self_service_enabled,
            } => {
                let mut body = serde_json::Map::new();
                if let Some(role) = role {
                    body.insert("role".into(), serde_json::json!(role));
                }
                if let Some(enabled) = self_service_enabled {
                    body.insert("selfServiceEnabled".into(), serde_json::json!(enabled));
                }
                if body.is_empty() {
                    require_cli_input::<()>(Err(anyhow::anyhow!(
                        "access set requires --role or --self-service-enabled"
                    )));
                }
                run_broker_json_method(
                    ctx,
                    reqwest::Method::PATCH,
                    &format!(
                        "/v1/admin/principals/{}/access",
                        encoded_path_segment(principal)
                    ),
                    Some(serde_json::Value::Object(body)),
                )
                .await
            }
        },
        AdminPrincipalsCommand::Groups { command } => match command {
            AdminPrincipalGroupsCommand::Add { principal, group } => {
                run_broker_json_method(
                    ctx,
                    reqwest::Method::PUT,
                    &format!("/v1/admin/principals/{principal}/groups/{group}"),
                    Some(serde_json::json!({})),
                )
                .await
            }
            AdminPrincipalGroupsCommand::Delete { principal, group } => {
                run_broker_json_method(
                    ctx,
                    reqwest::Method::DELETE,
                    &format!("/v1/admin/principals/{principal}/groups/{group}"),
                    None,
                )
                .await
            }
        },
        AdminPrincipalsCommand::LoginMethods { command } => match command {
            AdminPrincipalLoginMethodsCommand::List { principal } => {
                run_broker_get(
                    ctx,
                    &format!(
                        "/v1/admin/principals/{}/login-methods",
                        encoded_path_segment(principal)
                    ),
                    ResponseShape::Object,
                )
                .await
            }
            AdminPrincipalLoginMethodsCommand::Oidc { command } => match command {
                AdminPrincipalOidcCommand::Link {
                    principal,
                    user_object_id,
                } => {
                    run_broker_json_method(
                        ctx,
                        reqwest::Method::PUT,
                        &format!(
                            "/v1/admin/principals/{}/login-methods/oidc/microsoft",
                            encoded_path_segment(principal)
                        ),
                        Some(serde_json::json!({
                            "userObjectId": user_object_id.to_string()
                        })),
                    )
                    .await
                }
                AdminPrincipalOidcCommand::Unlink { principal } => {
                    run_broker_json_method(
                        ctx,
                        reqwest::Method::DELETE,
                        &format!(
                            "/v1/admin/principals/{}/login-methods/oidc/microsoft",
                            encoded_path_segment(principal)
                        ),
                        None,
                    )
                    .await
                }
            },
        },
        AdminPrincipalsCommand::Password { command } => match command {
            AdminPrincipalPasswordCommand::Reset {
                principal,
                password_env,
                password_file,
                password_stdin,
                no_must_change_password,
            } => {
                let password = read_password_input(password_env, password_file, *password_stdin)?;
                let must_change_password = !*no_must_change_password;
                run_broker_json_method(
                    ctx,
                    reqwest::Method::PUT,
                    &format!(
                        "/v1/admin/principals/{}/login-methods/local-password",
                        encoded_path_segment(principal)
                    ),
                    Some(serde_json::json!({
                        "password": password,
                        "mustChangePassword": must_change_password
                    })),
                )
                .await
            }
            AdminPrincipalPasswordCommand::Enable {
                principal,
                acknowledge_separate_sign_in,
                password_env,
                password_file,
                password_stdin,
                no_must_change_password,
            } => {
                let password = read_password_input(password_env, password_file, *password_stdin)?;
                let must_change_password = !*no_must_change_password;
                run_broker_json_method(
                    ctx,
                    reqwest::Method::POST,
                    &format!(
                        "/v1/admin/principals/{}/login-methods/local-password/enable",
                        encoded_path_segment(principal)
                    ),
                    Some(serde_json::json!({
                        "password": password,
                        "mustChangePassword": must_change_password,
                        "acknowledgeSeparateSignIn": acknowledge_separate_sign_in
                    })),
                )
                .await
            }
            AdminPrincipalPasswordCommand::Disable { principal } => {
                run_broker_json_method(
                    ctx,
                    reqwest::Method::DELETE,
                    &format!(
                        "/v1/admin/principals/{}/login-methods/local-password",
                        encoded_path_segment(principal)
                    ),
                    None,
                )
                .await
            }
            AdminPrincipalPasswordCommand::Unlock { principal } => {
                run_broker_json_method(
                    ctx,
                    reqwest::Method::POST,
                    &format!(
                        "/v1/admin/principals/{}/login-methods/local-password/unlock",
                        encoded_path_segment(principal)
                    ),
                    Some(serde_json::json!({})),
                )
                .await
            }
        },
    }
}

async fn run_admin_groups_command(
    ctx: &CliContext<'_>,
    command: &AdminGroupsCommand,
) -> Result<()> {
    match command {
        AdminGroupsCommand::List => {
            run_broker_get(ctx, "/v1/admin/groups", ResponseShape::Object).await
        }
        AdminGroupsCommand::Inspect { group } => {
            run_broker_get(
                ctx,
                &format!("/v1/admin/groups/{group}"),
                ResponseShape::Object,
            )
            .await
        }
        AdminGroupsCommand::Create {
            group,
            display_name,
            description,
            auto_enroll_new_microsoft_users,
        } => {
            let body = serde_json::json!({
                "groupId": group,
                "displayName": display_name,
                "description": description,
                "autoEnrollNewMicrosoftUsers": auto_enroll_new_microsoft_users,
            });
            run_broker_json_method(ctx, reqwest::Method::POST, "/v1/admin/groups", Some(body)).await
        }
        AdminGroupsCommand::Update {
            group,
            display_name,
            clear_display_name,
            description,
            clear_description,
            auto_enroll_new_microsoft_users,
        } => {
            let mut body = serde_json::Map::new();
            if *clear_display_name {
                body.insert("displayName".to_string(), serde_json::Value::Null);
            } else if let Some(display_name) = display_name {
                body.insert("displayName".to_string(), serde_json::json!(display_name));
            }
            if *clear_description {
                body.insert("description".to_string(), serde_json::Value::Null);
            } else if let Some(description) = description {
                body.insert("description".to_string(), serde_json::json!(description));
            }
            if let Some(enabled) = auto_enroll_new_microsoft_users {
                body.insert(
                    "autoEnrollNewMicrosoftUsers".to_string(),
                    serde_json::json!(enabled),
                );
            }
            if body.is_empty() {
                require_cli_input::<()>(Err(anyhow::anyhow!(
                    "admin groups update requires at least one of --display-name, --clear-display-name, --description, --clear-description, or --auto-enroll-new-microsoft-users"
                )));
            }
            run_broker_json_method(
                ctx,
                reqwest::Method::PATCH,
                &format!("/v1/admin/groups/{group}"),
                Some(serde_json::Value::Object(body)),
            )
            .await
        }
        AdminGroupsCommand::Enable { group } => patch_group_status(ctx, group, "active").await,
        AdminGroupsCommand::Disable { group } => patch_group_status(ctx, group, "disabled").await,
        AdminGroupsCommand::Members { command } => match command {
            AdminGroupMembersCommand::List { group } => {
                run_broker_get(
                    ctx,
                    &format!("/v1/admin/groups/{group}/members"),
                    ResponseShape::Object,
                )
                .await
            }
            AdminGroupMembersCommand::Add { group, principal } => {
                run_broker_json_method(
                    ctx,
                    reqwest::Method::PUT,
                    &format!("/v1/admin/groups/{group}/members/{principal}"),
                    Some(serde_json::json!({})),
                )
                .await
            }
            AdminGroupMembersCommand::Delete { group, principal } => {
                run_broker_json_method(
                    ctx,
                    reqwest::Method::DELETE,
                    &format!("/v1/admin/groups/{group}/members/{principal}"),
                    None,
                )
                .await
            }
        },
        AdminGroupsCommand::ExternalGroupBindings { command } => match command {
            AdminExternalGroupBindingsCommand::List { group } => {
                run_broker_get(
                    ctx,
                    &format!(
                        "/v1/admin/groups/{}/external-group-bindings",
                        encoded_path_segment(group)
                    ),
                    ResponseShape::Object,
                )
                .await
            }
            AdminExternalGroupBindingsCommand::Create {
                group,
                external_group_id,
            } => {
                run_broker_json_method(
                    ctx,
                    reqwest::Method::POST,
                    &format!(
                        "/v1/admin/groups/{}/external-group-bindings",
                        encoded_path_segment(group)
                    ),
                    Some(serde_json::json!({
                        "externalGroupId": external_group_id.to_string()
                    })),
                )
                .await
            }
            AdminExternalGroupBindingsCommand::Enable { group, binding_id } => {
                patch_external_group_binding_status(ctx, group, binding_id, "active").await
            }
            AdminExternalGroupBindingsCommand::Disable { group, binding_id } => {
                patch_external_group_binding_status(ctx, group, binding_id, "disabled").await
            }
            AdminExternalGroupBindingsCommand::Delete { group, binding_id } => {
                run_broker_json_method(
                    ctx,
                    reqwest::Method::DELETE,
                    &format!(
                        "/v1/admin/groups/{}/external-group-bindings/{}",
                        encoded_path_segment(group),
                        encoded_path_segment(&binding_id.to_string())
                    ),
                    None,
                )
                .await
            }
        },
    }
}

async fn patch_external_group_binding_status(
    ctx: &CliContext<'_>,
    group: &str,
    binding_id: &Uuid,
    status: &str,
) -> Result<()> {
    run_broker_json_method(
        ctx,
        reqwest::Method::PATCH,
        &format!(
            "/v1/admin/groups/{}/external-group-bindings/{}",
            encoded_path_segment(group),
            encoded_path_segment(&binding_id.to_string())
        ),
        Some(serde_json::json!({ "status": status })),
    )
    .await
}

async fn patch_group_status(ctx: &CliContext<'_>, group: &str, status: &str) -> Result<()> {
    run_broker_json_method(
        ctx,
        reqwest::Method::PATCH,
        &format!("/v1/admin/groups/{group}"),
        Some(serde_json::json!({ "status": status })),
    )
    .await
}

async fn patch_principal_status(ctx: &CliContext<'_>, principal: &str, status: &str) -> Result<()> {
    run_broker_json_method(
        ctx,
        reqwest::Method::PATCH,
        &format!("/v1/admin/principals/{principal}"),
        Some(serde_json::json!({ "status": status })),
    )
    .await
}

async fn run_admin_rights_command(
    ctx: &CliContext<'_>,
    command: &AdminRightsCommand,
) -> Result<()> {
    match command {
        AdminRightsCommand::List => {
            run_broker_get(ctx, "/v1/admin/rights", ResponseShape::Object).await
        }
        AdminRightsCommand::Grant {
            principal,
            right,
            service,
            credential_name,
            expires_at,
            reason,
        } => {
            let body = serde_json::json!({
                "principalId": principal,
                "right": right,
                "service": service,
                "credentialName": credential_name,
                "expiresAt": expires_at,
                "reason": reason,
            });
            run_broker_json_method(ctx, reqwest::Method::POST, "/v1/admin/rights", Some(body)).await
        }
        AdminRightsCommand::Revoke { right_id } => {
            run_broker_json_method(
                ctx,
                reqwest::Method::DELETE,
                &format!("/v1/admin/rights/{right_id}"),
                None,
            )
            .await
        }
    }
}

async fn run_admin_tokens_command(
    ctx: &CliContext<'_>,
    command: &AdminTokensCommand,
) -> Result<()> {
    match command {
        AdminTokensCommand::EffectiveAccess {
            principal,
            request_file,
        } => {
            run_broker_json_method(
                ctx,
                reqwest::Method::POST,
                &format!(
                    "/v1/admin/principals/{}/agent-token-effective-access",
                    encoded_path_segment(principal)
                ),
                Some(read_json_file(request_file)),
            )
            .await
        }
        AdminTokensCommand::List => {
            run_broker_get(ctx, "/v1/admin/tokens", ResponseShape::Object).await
        }
        AdminTokensCommand::Issue {
            principal,
            name,
            token_class,
            ttl,
            expires_at,
            never,
            services,
            actions,
            resource_ids,
            resource_group_ids,
            restricted_services,
            service_restrictions_file,
            execution_contexts,
        } => {
            let body = require_cli_input(admin_token_issue_body(AdminTokenIssueCliInput {
                name,
                token_class,
                ttl,
                expires_at,
                never: *never,
                services,
                actions,
                resource_ids,
                resource_group_ids,
                restricted_services,
                service_restrictions_file,
                execution_contexts,
            }));
            run_broker_json_method(
                ctx,
                reqwest::Method::POST,
                &format!("/v1/admin/principals/{principal}/tokens"),
                Some(body),
            )
            .await
        }
        AdminTokensCommand::Revoke { token_id } => {
            run_broker_json_method(
                ctx,
                reqwest::Method::DELETE,
                &format!("/v1/admin/tokens/{token_id}"),
                None,
            )
            .await
        }
        AdminTokensCommand::Pause { token_id } => {
            run_broker_json_method(
                ctx,
                reqwest::Method::POST,
                &admin_token_action_path(token_id, BrokerTokenAction::Pause),
                None,
            )
            .await
        }
        AdminTokensCommand::Resume { token_id } => {
            run_broker_json_method(
                ctx,
                reqwest::Method::POST,
                &admin_token_action_path(token_id, BrokerTokenAction::Resume),
                None,
            )
            .await
        }
    }
}

struct AdminTokenIssueCliInput<'a> {
    name: &'a str,
    token_class: &'a str,
    ttl: &'a Option<String>,
    expires_at: &'a Option<String>,
    never: bool,
    services: &'a [String],
    actions: &'a [TokenActionRestriction],
    resource_ids: &'a [TokenResourceReference],
    resource_group_ids: &'a [TokenResourceReference],
    restricted_services: &'a [String],
    service_restrictions_file: &'a Option<PathBuf>,
    execution_contexts: &'a [String],
}

fn admin_token_issue_body(input: AdminTokenIssueCliInput<'_>) -> Result<serde_json::Value> {
    let restrictions_present = !input.actions.is_empty()
        || !input.resource_ids.is_empty()
        || !input.resource_group_ids.is_empty()
        || !input.restricted_services.is_empty()
        || input.service_restrictions_file.is_some();

    let scopes = if input.token_class == "agent_invoke" {
        if input.execution_contexts.is_empty() {
            anyhow::bail!(
                "admin tokens issue with --token-class agent_invoke requires at least one --execution-context"
            );
        }
        let service_restrictions = token_service_restrictions(TokenServiceRestrictionsInput {
            services: input.services,
            actions: input.actions,
            resource_ids: input.resource_ids,
            resource_group_ids: input.resource_group_ids,
            restricted_services: input.restricted_services,
            service_restrictions_file: input.service_restrictions_file,
        })?;
        let mut scopes = serde_json::Map::new();
        scopes.insert(
            "allowedExecutionContexts".to_string(),
            serde_json::json!(input.execution_contexts),
        );
        if !input.services.is_empty() {
            scopes.insert(
                "allowedServices".to_string(),
                serde_json::json!(input.services),
            );
        }
        if let Some(service_restrictions) = service_restrictions {
            scopes.insert("serviceRestrictions".to_string(), service_restrictions);
        }
        serde_json::Value::Object(scopes)
    } else {
        if !input.execution_contexts.is_empty()
            || !input.services.is_empty()
            || restrictions_present
        {
            anyhow::bail!(
                "admin tokens issue --execution-context, --service, --action, --resource-id, --resource-group-id, --restrict-resources, and --service-restrictions-file are only valid with --token-class agent_invoke"
            );
        }
        serde_json::json!({})
    };

    Ok(serde_json::json!({
        "name": input.name,
        "tokenClass": input.token_class,
        "ttl": input.ttl,
        "expiresAt": input.expires_at,
        "never": input.never,
        "scopes": scopes,
    }))
}

async fn run_admin_credentials_command(
    ctx: &CliContext<'_>,
    command: &AdminCredentialsCommand,
) -> Result<()> {
    match command {
        AdminCredentialsCommand::List { principal } => {
            run_broker_get(
                ctx,
                &format!(
                    "/v1/admin/principals/{}/credentials",
                    encoded_path_segment(principal)
                ),
                ResponseShape::Object,
            )
            .await
        }
        AdminCredentialsCommand::ListStored { principal } => {
            let path = match principal {
                Some(principal) => {
                    let query = form_urlencoded::Serializer::new(String::new())
                        .append_pair("principal", principal)
                        .finish();
                    format!("/v1/admin/credentials?{query}")
                }
                None => "/v1/admin/credentials".to_string(),
            };
            run_broker_get(ctx, &path, ResponseShape::Object).await
        }
        AdminCredentialsCommand::Targets { principal } => {
            run_broker_get(
                ctx,
                &format!(
                    "/v1/admin/principals/{}/credentials/targets",
                    encoded_path_segment(principal)
                ),
                ResponseShape::Object,
            )
            .await
        }
        AdminCredentialsCommand::Inspect {
            principal,
            connection,
        } => {
            run_broker_get(
                ctx,
                &admin_connection_path(principal, connection),
                ResponseShape::Object,
            )
            .await
        }
        AdminCredentialsCommand::Put {
            principal,
            connection,
            input,
        } => {
            put_connection_credential(ctx, &admin_connection_path(principal, connection), input)
                .await
        }
        AdminCredentialsCommand::Delete {
            principal,
            connection,
        } => {
            run_broker_json_method(
                ctx,
                reqwest::Method::DELETE,
                &admin_connection_path(principal, connection),
                None,
            )
            .await
        }
        AdminCredentialsCommand::Verify {
            principal,
            connection,
            verify,
        } => {
            run_broker_json_method(
                ctx,
                reqwest::Method::POST,
                &format!("{}/verify", admin_connection_path(principal, connection)),
                Some(credential_verify_body(verify)),
            )
            .await
        }
        AdminCredentialsCommand::InspectById { credential_id } => {
            run_broker_get(
                ctx,
                &format!(
                    "/v1/admin/credentials/{}",
                    encoded_path_segment(credential_id)
                ),
                ResponseShape::Object,
            )
            .await
        }
        AdminCredentialsCommand::DeleteById { credential_id } => {
            run_broker_json_method(
                ctx,
                reqwest::Method::DELETE,
                &format!(
                    "/v1/admin/credentials/{}",
                    encoded_path_segment(credential_id)
                ),
                None,
            )
            .await
        }
        AdminCredentialsCommand::Rewrap { from_key, to_key } => {
            run_broker_json_method(
                ctx,
                reqwest::Method::POST,
                "/v1/admin/credentials/rewrap",
                Some(serde_json::json!({
                    "fromKey": from_key,
                    "toKey": to_key,
                })),
            )
            .await
        }
    }
}

async fn run_admin_policy_command(
    ctx: &CliContext<'_>,
    command: &AdminPolicyCommand,
) -> Result<()> {
    match command {
        AdminPolicyCommand::Resources { command } => {
            resource_commands::run_resources(ctx, command).await
        }
        AdminPolicyCommand::ResourceGroups { command } => {
            resource_commands::run_resource_groups(ctx, command).await
        }
        AdminPolicyCommand::EffectiveAccess { request_file } => {
            run_broker_json_method(
                ctx,
                reqwest::Method::POST,
                "/v1/admin/policy/effective-access",
                Some(read_json_file(request_file)),
            )
            .await
        }
        AdminPolicyCommand::Status => {
            run_broker_get(ctx, "/v1/admin/policy/status", ResponseShape::Object).await
        }
        AdminPolicyCommand::Catalog => {
            run_broker_get(ctx, "/v1/admin/policy/catalog", ResponseShape::Object).await
        }
        AdminPolicyCommand::Grants { command } => {
            run_admin_policy_grants_command(ctx, command).await
        }
        AdminPolicyCommand::Managers { command } => {
            run_admin_policy_managers_command(ctx, command).await
        }
    }
}

async fn run_admin_policy_managers_command(
    ctx: &CliContext<'_>,
    command: &AdminPolicyManagersCommand,
) -> Result<()> {
    match command {
        AdminPolicyManagersCommand::List { service } => {
            let path = admin_policy_managers_list_path(service);
            run_broker_get(ctx, &path, ResponseShape::Object).await
        }
        AdminPolicyManagersCommand::Grant { service, principal } => {
            let path = admin_policy_manager_assignment_path(service, principal);
            run_broker_json_method(ctx, reqwest::Method::PUT, &path, None).await
        }
        AdminPolicyManagersCommand::Revoke { service, principal } => {
            let path = admin_policy_manager_assignment_path(service, principal);
            run_broker_json_method(ctx, reqwest::Method::DELETE, &path, None).await
        }
    }
}

async fn run_admin_policy_grants_command(
    ctx: &CliContext<'_>,
    command: &AdminPolicyGrantsCommand,
) -> Result<()> {
    match command {
        AdminPolicyGrantsCommand::List {
            subject,
            service,
            status,
            execution_context,
        } => {
            let path = admin_policy_grants_list_path(subject, service, status, execution_context);
            run_broker_get(ctx, &path, ResponseShape::Object).await
        }
        AdminPolicyGrantsCommand::Inspect { grant_ref } => {
            run_broker_get(
                ctx,
                &format!(
                    "/v1/admin/policy/grants/{}",
                    encoded_path_segment(grant_ref)
                ),
                ResponseShape::Object,
            )
            .await
        }
        AdminPolicyGrantsCommand::Create {
            grant_id,
            subjects,
            service,
            actions,
            execution_contexts,
            resource_ids,
            resource_group_ids,
            resources_json,
            resources_file,
            credential_mode,
            priority,
            status,
            description,
        } => {
            let body = policy_grant_create_body(PolicyGrantCreateCliInput {
                grant_id,
                subjects,
                service,
                actions,
                execution_contexts,
                resource_ids,
                resource_group_ids,
                resources_json,
                resources_file,
                credential_mode,
                priority: *priority,
                status,
                description,
            });
            run_broker_json_method(
                ctx,
                reqwest::Method::POST,
                "/v1/admin/policy/grants",
                Some(body),
            )
            .await
        }
        AdminPolicyGrantsCommand::Update {
            grant_ref,
            expected_version,
            subjects,
            service,
            actions,
            execution_contexts,
            resource_ids,
            resource_group_ids,
            resources_json,
            resources_file,
            credential_mode,
            priority,
            clear_priority,
            status,
            description,
            clear_description,
        } => {
            let body = policy_grant_patch_body(PolicyGrantPatchCliInput {
                expected_version: *expected_version,
                subjects,
                service,
                actions,
                execution_contexts,
                resource_ids,
                resource_group_ids,
                resources_json,
                resources_file,
                credential_mode,
                priority: *priority,
                clear_priority: *clear_priority,
                status,
                description,
                clear_description: *clear_description,
            });
            run_broker_json_method(
                ctx,
                reqwest::Method::PATCH,
                &format!(
                    "/v1/admin/policy/grants/{}",
                    encoded_path_segment(grant_ref)
                ),
                Some(body),
            )
            .await
        }
        AdminPolicyGrantsCommand::Validate {
            grant_id,
            expected_version,
            subjects,
            service,
            actions,
            execution_contexts,
            resource_ids,
            resource_group_ids,
            resources_json,
            resources_file,
            credential_mode,
            priority,
            clear_priority,
            status,
            description,
            clear_description,
        } => {
            let body = policy_grant_validate_body(PolicyGrantValidateCliInput {
                grant_id,
                expected_version: *expected_version,
                subjects,
                service,
                actions,
                execution_contexts,
                resource_ids,
                resource_group_ids,
                resources_json,
                resources_file,
                credential_mode,
                priority: *priority,
                clear_priority: *clear_priority,
                status,
                description,
                clear_description: *clear_description,
            });
            run_broker_json_method(
                ctx,
                reqwest::Method::POST,
                "/v1/admin/policy/grants/validate",
                Some(body),
            )
            .await
        }
        AdminPolicyGrantsCommand::Enable {
            grant_ref,
            expected_version,
        } => {
            run_admin_policy_grant_status_change(ctx, grant_ref, *expected_version, "enable").await
        }
        AdminPolicyGrantsCommand::Disable {
            grant_ref,
            expected_version,
        } => {
            run_admin_policy_grant_status_change(ctx, grant_ref, *expected_version, "disable").await
        }
        AdminPolicyGrantsCommand::Delete {
            grant_ref,
            expected_version,
        } => {
            let query = form_urlencoded::Serializer::new(String::new())
                .append_pair("expectedVersion", &expected_version.to_string())
                .finish();
            run_broker_json_method(
                ctx,
                reqwest::Method::DELETE,
                &format!(
                    "/v1/admin/policy/grants/{}?{}",
                    encoded_path_segment(grant_ref),
                    query
                ),
                None,
            )
            .await
        }
        AdminPolicyGrantsCommand::Subjects { command } => {
            run_admin_policy_grant_subjects_command(ctx, command).await
        }
        AdminPolicyGrantsCommand::Export => {
            run_broker_get(ctx, "/v1/admin/policy/grants/export", ResponseShape::Object).await
        }
    }
}

async fn run_admin_policy_grant_subjects_command(
    ctx: &CliContext<'_>,
    command: &AdminPolicyGrantSubjectsCommand,
) -> Result<()> {
    let (grant_ref, subject, expected_version, operation, last_subject_behavior) = match command {
        AdminPolicyGrantSubjectsCommand::Add {
            grant_ref,
            subject,
            expected_version,
        } => (grant_ref, subject, *expected_version, "subjects", None),
        AdminPolicyGrantSubjectsCommand::Remove {
            grant_ref,
            subject,
            expected_version,
            last_subject_behavior,
        } => (
            grant_ref,
            subject,
            *expected_version,
            "subjects/remove",
            Some(last_subject_behavior.as_str()),
        ),
    };
    let body = policy_grant_subject_mutation_body(subject, expected_version, last_subject_behavior);
    run_broker_json_method(
        ctx,
        reqwest::Method::POST,
        &format!(
            "/v1/admin/policy/grants/{}/{}",
            encoded_path_segment(grant_ref),
            operation
        ),
        Some(body),
    )
    .await
}

async fn run_admin_policy_grant_status_change(
    ctx: &CliContext<'_>,
    grant_ref: &str,
    expected_version: i64,
    change: &str,
) -> Result<()> {
    run_broker_json_method(
        ctx,
        reqwest::Method::POST,
        &format!(
            "/v1/admin/policy/grants/{}/{}",
            encoded_path_segment(grant_ref),
            change
        ),
        Some(serde_json::json!({ "expectedVersion": expected_version })),
    )
    .await
}

struct PolicyGrantCreateCliInput<'a> {
    grant_id: &'a Option<String>,
    subjects: &'a [String],
    service: &'a str,
    actions: &'a [String],
    execution_contexts: &'a [String],
    resource_ids: &'a [String],
    resource_group_ids: &'a [String],
    resources_json: &'a Option<String>,
    resources_file: &'a Option<PathBuf>,
    credential_mode: &'a str,
    priority: Option<i32>,
    status: &'a Option<String>,
    description: &'a Option<String>,
}

struct PolicyGrantPatchCliInput<'a> {
    expected_version: i64,
    subjects: &'a [String],
    service: &'a Option<String>,
    actions: &'a [String],
    execution_contexts: &'a [String],
    resource_ids: &'a [String],
    resource_group_ids: &'a [String],
    resources_json: &'a Option<String>,
    resources_file: &'a Option<PathBuf>,
    credential_mode: &'a Option<String>,
    priority: Option<i32>,
    clear_priority: bool,
    status: &'a Option<String>,
    description: &'a Option<String>,
    clear_description: bool,
}

struct PolicyGrantValidateCliInput<'a> {
    grant_id: &'a Option<String>,
    expected_version: Option<i64>,
    subjects: &'a [String],
    service: &'a Option<String>,
    actions: &'a [String],
    execution_contexts: &'a [String],
    resource_ids: &'a [String],
    resource_group_ids: &'a [String],
    resources_json: &'a Option<String>,
    resources_file: &'a Option<PathBuf>,
    credential_mode: &'a Option<String>,
    priority: Option<i32>,
    clear_priority: bool,
    status: &'a Option<String>,
    description: &'a Option<String>,
    clear_description: bool,
}

fn admin_policy_grants_list_path(
    subject: &Option<String>,
    service: &Option<String>,
    status: &Option<String>,
    execution_context: &Option<String>,
) -> String {
    let mut query = form_urlencoded::Serializer::new(String::new());
    if let Some(subject) = subject {
        query.append_pair("subject", subject);
    }
    if let Some(service) = service {
        query.append_pair("service", service);
    }
    if let Some(status) = status {
        query.append_pair("status", status);
    }
    if let Some(execution_context) = execution_context {
        query.append_pair("executionContext", execution_context);
    }
    let query = query.finish();
    if query.is_empty() {
        "/v1/admin/policy/grants".to_string()
    } else {
        format!("/v1/admin/policy/grants?{query}")
    }
}

fn admin_policy_managers_list_path(service: &Option<String>) -> String {
    match service {
        Some(service) => {
            let query = form_urlencoded::Serializer::new(String::new())
                .append_pair("service", service)
                .finish();
            format!("/v1/admin/policy/service-managers?{query}")
        }
        None => "/v1/admin/policy/service-managers".to_string(),
    }
}

fn admin_policy_manager_assignment_path(service: &str, principal: &str) -> String {
    format!(
        "/v1/admin/policy/services/{}/managers/{}",
        encoded_path_segment(service),
        encoded_path_segment(principal)
    )
}

fn policy_grant_subject_mutation_body(
    subject: &str,
    expected_version: i64,
    last_subject_behavior: Option<&str>,
) -> serde_json::Value {
    let mut body = serde_json::Map::from_iter([
        ("subject".to_string(), serde_json::json!(subject)),
        (
            "expectedVersion".to_string(),
            serde_json::json!(expected_version),
        ),
    ]);
    if let Some(last_subject_behavior) = last_subject_behavior {
        body.insert(
            "lastSubjectBehavior".to_string(),
            serde_json::json!(last_subject_behavior),
        );
    }
    serde_json::Value::Object(body)
}

fn policy_grant_create_body(input: PolicyGrantCreateCliInput<'_>) -> serde_json::Value {
    let mut body = serde_json::Map::new();
    if let Some(grant_id) = input.grant_id {
        body.insert("grantId".to_string(), serde_json::json!(grant_id));
    }
    body.insert("subjects".to_string(), serde_json::json!(input.subjects));
    body.insert("service".to_string(), serde_json::json!(input.service));
    body.insert("actions".to_string(), serde_json::json!(input.actions));
    body.insert(
        "executionContexts".to_string(),
        serde_json::json!(input.execution_contexts),
    );
    body.insert(
        "resources".to_string(),
        policy_resources_value(
            input.resource_ids,
            input.resource_group_ids,
            input.resources_json,
            input.resources_file,
            true,
        )
        .unwrap_or_else(|| serde_json::json!({})),
    );
    body.insert(
        "credentialMode".to_string(),
        serde_json::json!(input.credential_mode),
    );
    if let Some(priority) = input.priority {
        body.insert("priority".to_string(), serde_json::json!(priority));
    }
    if let Some(status) = input.status {
        body.insert("status".to_string(), serde_json::json!(status));
    }
    if let Some(description) = input.description {
        body.insert("description".to_string(), serde_json::json!(description));
    }
    serde_json::Value::Object(body)
}

fn policy_grant_patch_body(input: PolicyGrantPatchCliInput<'_>) -> serde_json::Value {
    let mut body = serde_json::Map::new();
    body.insert(
        "expectedVersion".to_string(),
        serde_json::json!(input.expected_version),
    );
    insert_policy_grant_optional_fields(
        &mut body,
        PolicyGrantOptionalFields {
            subjects: input.subjects,
            service: input.service,
            actions: input.actions,
            execution_contexts: input.execution_contexts,
            resource_ids: input.resource_ids,
            resource_group_ids: input.resource_group_ids,
            resources_json: input.resources_json,
            resources_file: input.resources_file,
            include_empty_resources: false,
            credential_mode: input.credential_mode,
            priority: input.priority,
            clear_priority: input.clear_priority,
            status: input.status,
            description: input.description,
            clear_description: input.clear_description,
        },
    );
    if body.len() == 1 {
        require_cli_input::<()>(Err(anyhow::anyhow!(
            "admin policy grants update requires at least one field besides --expected-version"
        )));
    }
    serde_json::Value::Object(body)
}

fn policy_grant_validate_body(input: PolicyGrantValidateCliInput<'_>) -> serde_json::Value {
    if input.expected_version.is_some() && input.grant_id.is_none() {
        require_cli_input::<()>(Err(anyhow::anyhow!(
            "admin policy grants validate with --expected-version requires --grant-id"
        )));
    }
    if input.expected_version.is_none() && (input.clear_priority || input.clear_description) {
        require_cli_input::<()>(Err(anyhow::anyhow!(
            "admin policy grants validate create mode does not accept --clear-priority or --clear-description; use --grant-id with --expected-version for patch validation"
        )));
    }
    let mut body = serde_json::Map::new();
    if let Some(grant_id) = input.grant_id {
        body.insert("grantId".to_string(), serde_json::json!(grant_id));
    }
    if let Some(expected_version) = input.expected_version {
        body.insert(
            "expectedVersion".to_string(),
            serde_json::json!(expected_version),
        );
    }
    insert_policy_grant_optional_fields(
        &mut body,
        PolicyGrantOptionalFields {
            subjects: input.subjects,
            service: input.service,
            actions: input.actions,
            execution_contexts: input.execution_contexts,
            resource_ids: input.resource_ids,
            resource_group_ids: input.resource_group_ids,
            resources_json: input.resources_json,
            resources_file: input.resources_file,
            include_empty_resources: input.expected_version.is_none(),
            credential_mode: input.credential_mode,
            priority: input.priority,
            clear_priority: input.clear_priority,
            status: input.status,
            description: input.description,
            clear_description: input.clear_description,
        },
    );
    serde_json::Value::Object(body)
}

struct PolicyGrantOptionalFields<'a> {
    subjects: &'a [String],
    service: &'a Option<String>,
    actions: &'a [String],
    execution_contexts: &'a [String],
    resource_ids: &'a [String],
    resource_group_ids: &'a [String],
    resources_json: &'a Option<String>,
    resources_file: &'a Option<PathBuf>,
    include_empty_resources: bool,
    credential_mode: &'a Option<String>,
    priority: Option<i32>,
    clear_priority: bool,
    status: &'a Option<String>,
    description: &'a Option<String>,
    clear_description: bool,
}

fn insert_policy_grant_optional_fields(
    body: &mut serde_json::Map<String, serde_json::Value>,
    fields: PolicyGrantOptionalFields<'_>,
) {
    if !fields.subjects.is_empty() {
        body.insert("subjects".to_string(), serde_json::json!(fields.subjects));
    }
    if let Some(service) = fields.service {
        body.insert("service".to_string(), serde_json::json!(service));
    }
    if !fields.actions.is_empty() {
        body.insert("actions".to_string(), serde_json::json!(fields.actions));
    }
    if !fields.execution_contexts.is_empty() {
        body.insert(
            "executionContexts".to_string(),
            serde_json::json!(fields.execution_contexts),
        );
    }
    if let Some(resources) = policy_resources_value(
        fields.resource_ids,
        fields.resource_group_ids,
        fields.resources_json,
        fields.resources_file,
        fields.include_empty_resources,
    ) {
        body.insert("resources".to_string(), resources);
    }
    if let Some(credential_mode) = fields.credential_mode {
        body.insert(
            "credentialMode".to_string(),
            serde_json::json!(credential_mode),
        );
    }
    if fields.clear_priority {
        body.insert("priority".to_string(), serde_json::Value::Null);
    } else if let Some(priority) = fields.priority {
        body.insert("priority".to_string(), serde_json::json!(priority));
    }
    if let Some(status) = fields.status {
        body.insert("status".to_string(), serde_json::json!(status));
    }
    if fields.clear_description {
        body.insert("description".to_string(), serde_json::Value::Null);
    } else if let Some(description) = fields.description {
        body.insert("description".to_string(), serde_json::json!(description));
    }
}

fn policy_resources_value(
    resource_ids: &[String],
    resource_group_ids: &[String],
    resources_json: &Option<String>,
    resources_file: &Option<PathBuf>,
    include_empty: bool,
) -> Option<serde_json::Value> {
    let value = if let Some(raw) = resources_json {
        require_cli_input(serde_json::from_str(raw).map_err(anyhow::Error::from))
    } else if let Some(path) = resources_file {
        read_json_file(path)
    } else if include_empty || !resource_ids.is_empty() || !resource_group_ids.is_empty() {
        serde_json::json!({"resourceIds": resource_ids, "resourceGroupIds": resource_group_ids})
    } else {
        return None;
    };
    let selection: ResourceSelection =
        require_cli_input(serde_json::from_value(value).map_err(anyhow::Error::from));
    require_cli_input(validate_selection_ids(&selection));
    Some(serde_json::to_value(selection).expect("resource selection serializes"))
}

fn validate_selection_ids(selection: &ResourceSelection) -> Result<()> {
    selection
        .validate_structure()
        .map_err(|errors| anyhow::anyhow!(errors.join("; ")))
}

fn encoded_path_segment(value: &str) -> String {
    utf8_percent_encode(value, PATH_SEGMENT_ENCODE_SET).to_string()
}

struct CredentialPutInput<'a> {
    schema: &'a CredentialInputSchema,
    username: &'a Option<String>,
    username_env: &'a Option<String>,
    username_file: &'a Option<PathBuf>,
    field: &'a [NamedValue],
    field_env: &'a [NamedValue],
    field_file: &'a [NamedPath],
    field_stdin: &'a Option<String>,
    display_name: &'a Option<String>,
    expires_at: &'a Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct CollectedCredentialField {
    value: String,
    source: CredentialFieldSource,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct PlannedCredentialField {
    source: CredentialFieldSource,
    input: CredentialFieldInput,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum CredentialFieldInput {
    Literal(String),
    Env(String),
    File(PathBuf),
    Stdin,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CredentialFieldSource {
    Literal,
    Env,
    File,
    Stdin,
    Prompt,
}

fn credential_put_body(input: CredentialPutInput<'_>) -> Result<serde_json::Value> {
    validate_imported_credential_input_schema(input.schema)?;
    let plans = credential_field_source_plans(&input)?;
    validate_credential_field_plans(input.schema, &plans)?;
    let mut collected = read_planned_credential_fields(&plans, input.schema.input_policy)?;
    for field in &input.schema.fields {
        if field.required && !collected.contains_key(&field.name) {
            if !credential_field_allows_source(field, CredentialFieldSource::Prompt) {
                anyhow::bail!(
                    "missing required credential field {}; use {}",
                    field.name,
                    credential_field_input_hint(field)
                );
            }
            let value = read_prompted_schema_field(field, input.schema.input_policy)?;
            collected.insert(
                field.name.clone(),
                CollectedCredentialField {
                    value,
                    source: CredentialFieldSource::Prompt,
                },
            );
        }
    }
    let mut secret = serde_json::Map::new();
    for field in &input.schema.fields {
        if let Some(value) = collected.get(&field.name) {
            secret.insert(field.name.clone(), serde_json::json!(value.value));
        }
    }
    if input.schema.input_policy == Some(ImportedCredentialInputPolicy::HttpBasic) {
        credential_input::validate_basic_material(&secret)?;
    }
    let mut metadata = serde_json::Map::new();
    if let Some(display_name) = input.display_name {
        metadata.insert("displayName".to_string(), serde_json::json!(display_name));
    }
    if let Some(expires_at) = input.expires_at {
        metadata.insert("expiresAt".to_string(), serde_json::json!(expires_at));
    }
    let mut body = serde_json::Map::new();
    body.insert(
        "profile".to_string(),
        serde_json::json!(input.schema.profile.clone()),
    );
    body.insert("secret".to_string(), serde_json::Value::Object(secret));
    body.insert("metadata".to_string(), serde_json::Value::Object(metadata));
    Ok(serde_json::Value::Object(body))
}

/// Imported field conventions are usable only with a complete, consistent
/// server-derived descriptor. Validate it before consuming any input source.
fn validate_imported_credential_input_schema(schema: &CredentialInputSchema) -> Result<()> {
    let Some(policy) = schema.input_policy else {
        return Ok(());
    };
    let with_username = match (policy, schema.credential_kind.as_str()) {
        (ImportedCredentialInputPolicy::HttpBasic, "basic_api_token") => true,
        (ImportedCredentialInputPolicy::TokenHeader, "bearer_token") => false,
        (ImportedCredentialInputPolicy::CommandStdin, "basic_api_token") => true,
        (ImportedCredentialInputPolicy::CommandStdin, "bearer_token") => false,
        _ => {
            anyhow::bail!("malformed broker response: imported credential policy and kind disagree")
        }
    };
    if schema.fields.len() != if with_username { 2 } else { 1 }
        || !schema
            .fields
            .iter()
            .any(|field| field.name == "token" && field.required && field.secret)
        || (with_username
            && !schema
                .fields
                .iter()
                .any(|field| field.name == "username" && field.required && !field.secret))
    {
        anyhow::bail!("malformed broker response: imported credential fields are invalid");
    }
    Ok(())
}

fn credential_field_source_plans(
    input: &CredentialPutInput<'_>,
) -> Result<BTreeMap<String, PlannedCredentialField>> {
    let mut plans = BTreeMap::<String, PlannedCredentialField>::new();
    insert_named_field_source_plan(
        &mut plans,
        "username",
        "username",
        input.username,
        input.username_env,
        input.username_file,
        false,
    )?;
    for item in input.field {
        insert_credential_field_plan(
            &mut plans,
            &item.name,
            PlannedCredentialField {
                source: CredentialFieldSource::Literal,
                input: CredentialFieldInput::Literal(item.value.clone()),
            },
        )?;
    }
    for item in input.field_env {
        insert_credential_field_plan(
            &mut plans,
            &item.name,
            PlannedCredentialField {
                source: CredentialFieldSource::Env,
                input: CredentialFieldInput::Env(item.value.clone()),
            },
        )?;
    }
    for item in input.field_file {
        insert_credential_field_plan(
            &mut plans,
            &item.name,
            PlannedCredentialField {
                source: CredentialFieldSource::File,
                input: CredentialFieldInput::File(item.path.clone()),
            },
        )?;
    }
    if let Some(field_name) = input.field_stdin {
        insert_credential_field_plan(
            &mut plans,
            field_name,
            PlannedCredentialField {
                source: CredentialFieldSource::Stdin,
                input: CredentialFieldInput::Stdin,
            },
        )?;
    }
    Ok(plans)
}

fn insert_named_field_source_plan(
    plans: &mut BTreeMap<String, PlannedCredentialField>,
    name: &str,
    label: &str,
    literal: &Option<String>,
    env_name: &Option<String>,
    file: &Option<PathBuf>,
    stdin: bool,
) -> Result<()> {
    let sources =
        literal.is_some() as u8 + env_name.is_some() as u8 + file.is_some() as u8 + stdin as u8;
    if sources > 1 {
        anyhow::bail!("{label} accepts only one input source");
    }
    if let Some(value) = literal {
        insert_credential_field_plan(
            plans,
            name,
            PlannedCredentialField {
                source: CredentialFieldSource::Literal,
                input: CredentialFieldInput::Literal(value.clone()),
            },
        )?;
    }
    if let Some(env_name) = env_name {
        insert_credential_field_plan(
            plans,
            name,
            PlannedCredentialField {
                source: CredentialFieldSource::Env,
                input: CredentialFieldInput::Env(env_name.clone()),
            },
        )?;
    }
    if let Some(path) = file {
        insert_credential_field_plan(
            plans,
            name,
            PlannedCredentialField {
                source: CredentialFieldSource::File,
                input: CredentialFieldInput::File(path.clone()),
            },
        )?;
    }
    if stdin {
        insert_credential_field_plan(
            plans,
            name,
            PlannedCredentialField {
                source: CredentialFieldSource::Stdin,
                input: CredentialFieldInput::Stdin,
            },
        )?;
    }
    Ok(())
}

fn insert_credential_field_plan(
    plans: &mut BTreeMap<String, PlannedCredentialField>,
    name: &str,
    field: PlannedCredentialField,
) -> Result<()> {
    validate_credential_field_name(name)?;
    if plans.get(name).is_some_and(|existing| existing == &field) {
        return Ok(());
    }
    if plans.contains_key(name) {
        anyhow::bail!("credential field {name} is provided more than once");
    }
    plans.insert(name.to_string(), field);
    Ok(())
}

fn validate_credential_field_plans(
    schema: &CredentialInputSchema,
    plans: &BTreeMap<String, PlannedCredentialField>,
) -> Result<()> {
    for (name, field) in plans {
        let Some(schema_field) = credential_schema_field(schema, name) else {
            anyhow::bail!(
                "credential field {name} is not supported by profile {}",
                schema.profile
            );
        };
        if schema_field.secret && field.source == CredentialFieldSource::Literal {
            anyhow::bail!(
                "credential field {name} is secret and cannot be provided with --field; use {}",
                credential_field_input_hint(schema_field)
            );
        }
        if !credential_field_allows_source(schema_field, field.source) {
            anyhow::bail!(
                "credential field {name} does not support {}; use {}",
                field.source.input_method(),
                credential_field_input_hint(schema_field)
            );
        }
    }
    Ok(())
}

fn read_planned_credential_fields(
    plans: &BTreeMap<String, PlannedCredentialField>,
    input_policy: Option<ImportedCredentialInputPolicy>,
) -> Result<BTreeMap<String, CollectedCredentialField>> {
    let mut collected = BTreeMap::new();
    let http_basic = input_policy == Some(ImportedCredentialInputPolicy::HttpBasic);
    for (name, plan) in plans {
        let value = match &plan.input {
            CredentialFieldInput::Literal(value) => value.clone(),
            CredentialFieldInput::Env(env_name) => env::var(env_name).map_err(|_| {
                anyhow::anyhow!(
                    "failed to read credential field {name} from environment variable {env_name}"
                )
            })?,
            CredentialFieldInput::File(path) if http_basic => {
                credential_input::read_basic_file(path)?
            }
            CredentialFieldInput::File(path) => read_token_file(path)?,
            CredentialFieldInput::Stdin if http_basic => {
                credential_input::read_basic_reader(std::io::stdin().lock())?
            }
            CredentialFieldInput::Stdin => {
                let mut value = String::new();
                std::io::stdin()
                    .read_to_string(&mut value)
                    .map_err(|error| {
                        anyhow::anyhow!(
                            "failed to read credential field {name} from stdin: {error}"
                        )
                    })?;
                value.trim().to_string()
            }
        };
        if http_basic {
            credential_input::validate_basic_field(name, &value)?;
        }
        collected.insert(
            name.clone(),
            CollectedCredentialField {
                value,
                source: plan.source,
            },
        );
    }
    Ok(collected)
}

fn credential_schema_field<'a>(
    schema: &'a CredentialInputSchema,
    name: &str,
) -> Option<&'a CredentialInputField> {
    schema.fields.iter().find(|field| field.name == name)
}

fn read_prompted_schema_field(
    field: &CredentialInputField,
    input_policy: Option<ImportedCredentialInputPolicy>,
) -> Result<String> {
    if !std::io::stdin().is_terminal() {
        anyhow::bail!(
            "missing required credential field {}; use {}",
            field.name,
            credential_field_input_hint(field)
        );
    }
    read_prompted_field(&field.prompt, &field.name, field.secret, input_policy)
}

fn credential_field_input_hint(field: &CredentialInputField) -> String {
    let mut options = Vec::new();
    if credential_field_allows_source(field, CredentialFieldSource::Literal)
        && field.name == "username"
    {
        options.push("--username VALUE".to_string());
    }
    if credential_field_allows_source(field, CredentialFieldSource::Env) && field.name == "username"
    {
        options.push("--username-env ENV_VAR".to_string());
    }
    if credential_field_allows_source(field, CredentialFieldSource::File)
        && field.name == "username"
    {
        options.push("--username-file PATH".to_string());
    }
    if credential_field_allows_source(field, CredentialFieldSource::Literal) {
        options.push(format!("--field {}=VALUE", field.name));
    }
    if credential_field_allows_source(field, CredentialFieldSource::Env) {
        options.push(format!("--field-env {}=ENV_VAR", field.name));
    }
    if credential_field_allows_source(field, CredentialFieldSource::File) {
        options.push(format!("--field-file {}=PATH", field.name));
    }
    if credential_field_allows_source(field, CredentialFieldSource::Stdin) {
        options.push(format!("--field-stdin {}", field.name));
    }
    options.join(", ")
}

fn credential_field_allows_source(
    field: &CredentialInputField,
    source: CredentialFieldSource,
) -> bool {
    let method = source.input_method();
    match field.input_methods.as_ref() {
        Some(methods) => methods.iter().any(|candidate| candidate == method),
        None => {
            matches!(
                source,
                CredentialFieldSource::Env | CredentialFieldSource::File
            ) || (source == CredentialFieldSource::Literal && !field.secret)
        }
    }
}

impl CredentialFieldSource {
    fn input_method(self) -> &'static str {
        match self {
            Self::Literal => "literal",
            Self::Env => "env",
            Self::File => "file",
            Self::Stdin => "stdin",
            Self::Prompt => "prompt",
        }
    }
}

fn validate_credential_field_name(name: &str) -> Result<()> {
    let mut chars = name.chars();
    if name.len() <= 128
        && matches!(chars.next(), Some(first) if first.is_ascii_lowercase())
        && chars.all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '_' | '-' | '.'))
        && !name.ends_with('.')
        && !name.contains("..")
    {
        Ok(())
    } else {
        anyhow::bail!("credential field name is invalid: {name}")
    }
}

fn parse_named_value(raw: &str) -> std::result::Result<NamedValue, String> {
    let (name, value) = parse_name_equals(raw)?;
    Ok(NamedValue { name, value })
}

fn parse_token_action_restriction(
    raw: &str,
) -> std::result::Result<TokenActionRestriction, String> {
    let Some((service, action)) = raw.split_once('=') else {
        return Err("expected SERVICE=ACTION".to_string());
    };
    if !is_service_name(service) {
        return Err(format!("token action service name is invalid: {service}"));
    }
    if !agent_access_provider::is_action_name(action) {
        return Err(format!("token action name is invalid: {action}"));
    }
    if action.starts_with(&format!("{service}.")) {
        return Err(format!(
            "token action must not repeat its service prefix: {raw}"
        ));
    }
    Ok(TokenActionRestriction {
        service: service.to_string(),
        action: action.to_string(),
    })
}

fn parse_token_resource_reference(
    raw: &str,
) -> std::result::Result<TokenResourceReference, String> {
    let Some((service, id)) = raw.split_once('=') else {
        return Err("expected SERVICE=ID".to_string());
    };
    if !is_service_name(service) || id.trim().is_empty() {
        return Err(
            "resource reference requires a valid service and nonempty catalog ID".to_string(),
        );
    }
    Ok(TokenResourceReference {
        service: service.to_string(),
        id: id.to_string(),
    })
}

fn parse_expected_version(raw: &str) -> std::result::Result<i64, String> {
    let version = raw
        .parse::<i64>()
        .map_err(|_| "expectedVersion must be an integer".to_string())?;
    if version < 1 {
        return Err("expectedVersion must be at least 1".to_string());
    }
    Ok(version)
}

fn parse_uuid(raw: &str) -> std::result::Result<Uuid, String> {
    Uuid::parse_str(raw).map_err(|_| format!("expected a UUID, got {raw:?}"))
}

/// Parses the broker duration syntax (`30s`, `1m`, `2h`, `1d`) into a
/// positive number of seconds. It checks no upper bound: the broker enforces
/// an invocation limit window's 1s to 1d range.
fn parse_broker_duration_seconds(raw: &str) -> std::result::Result<u64, String> {
    agent_access_core::parse_ttl_seconds(raw)
        .ok_or_else(|| format!("expected a duration such as 30s, 1m, 2h, or 1d, got {raw:?}"))
}

fn parse_named_path(raw: &str) -> std::result::Result<NamedPath, String> {
    let (name, value) = parse_name_equals(raw)?;
    Ok(NamedPath {
        name,
        path: PathBuf::from(value),
    })
}

fn parse_name_equals(raw: &str) -> std::result::Result<(String, String), String> {
    let Some((name, value)) = raw.split_once('=') else {
        return Err("expected name=value".to_string());
    };
    if name.is_empty() {
        return Err("field name is required".to_string());
    }
    validate_credential_field_name(name).map_err(|error| format!("{error:#}"))?;
    if value.is_empty() {
        return Err("field value is required".to_string());
    }
    Ok((name.to_string(), value.to_string()))
}

fn credential_input_schema_path(credential_path: &str, profile: &Option<String>) -> String {
    let mut path = format!("{credential_path}/input-schema");
    if let Some(profile) = profile {
        let query = form_urlencoded::Serializer::new(String::new())
            .append_pair("profile", profile)
            .finish();
        path.push('?');
        path.push_str(&query);
    }
    path
}

fn read_prompted_field(
    prompt_label: &str,
    field_name: &str,
    secret: bool,
    input_policy: Option<ImportedCredentialInputPolicy>,
) -> Result<String> {
    let prompt = format!("{prompt_label}: ");
    let value = if secret {
        rpassword::prompt_password(prompt).map_err(|error| {
            anyhow::anyhow!(
                "failed to read credential field {field_name} from interactive prompt: {error}"
            )
        })?
    } else {
        print!("{prompt}");
        std::io::stdout()
            .flush()
            .map_err(|error| anyhow::anyhow!("failed to write {field_name} prompt: {error}"))?;
        let mut value = String::new();
        std::io::stdin()
            .read_line(&mut value)
            .map_err(|error| anyhow::anyhow!("failed to read {field_name} from prompt: {error}"))?;
        value
    };
    if input_policy == Some(ImportedCredentialInputPolicy::HttpBasic) {
        let value = if secret {
            value
        } else {
            credential_input::strip_terminal_newline(value)
        };
        credential_input::validate_basic_field(field_name, &value)?;
        Ok(value)
    } else {
        Ok(value.trim().to_string())
    }
}

fn validate_connection_argument(connection: &str) -> Result<()> {
    if is_service_name(connection) {
        Ok(())
    } else {
        anyhow::bail!("credential connection ID is invalid")
    }
}

fn exclusive_search_query(
    raw_type: &str,
    raw_value: Option<&String>,
    text_value: Option<&String>,
    command: &str,
) -> serde_json::Value {
    match (raw_value, text_value) {
        (Some(value), None) => serde_json::json!({
            "type": raw_type,
            "value": value,
        }),
        (None, Some(value)) => serde_json::json!({
            "type": "text",
            "value": value,
        }),
        _ => require_cli_input(Err(anyhow::anyhow!(
            "{command} requires exactly one of --{raw_type} or --text"
        ))),
    }
}

fn resolve_content_input<F: NormalizedContentFormatArg>(
    content: Option<&str>,
    content_file: Option<&Path>,
    content_format: Option<F>,
    required: bool,
    command: &str,
) -> Result<Option<(serde_json::Value, F)>> {
    let source = match (content, content_file) {
        (Some(_), Some(_)) => {
            anyhow::bail!("{command} accepts exactly one of --content or --content-file")
        }
        (Some(content), None) => Some((content.as_bytes().to_vec(), None)),
        (None, Some(path)) => Some((read_normalized_content_file(path)?, Some(path))),
        (None, None) => None,
    };

    match (source, content_format) {
        (None, None) if required => anyhow::bail!(
            "{command} requires exactly one of --content or --content-file and --content-format"
        ),
        (None, None) => Ok(None),
        (None, Some(_)) => {
            anyhow::bail!("{command} requires --content or --content-file with --content-format")
        }
        (Some(_), None) => {
            anyhow::bail!("{command} requires --content-format with --content or --content-file")
        }
        (Some((bytes, path)), Some(format)) => {
            let value = if format.is_json() {
                serde_json::from_slice(&bytes).map_err(|error| match path {
                    Some(path) => anyhow::anyhow!(
                        "{} must contain valid {} JSON: {error}",
                        path.display(),
                        format.as_str()
                    ),
                    None => anyhow::anyhow!(
                        "--content must contain valid {} JSON: {error}",
                        format.as_str()
                    ),
                })?
            } else {
                serde_json::Value::String(String::from_utf8(bytes).map_err(|error| match path {
                    Some(path) => anyhow::anyhow!(
                        "{} must contain UTF-8 {} content: {error}",
                        path.display(),
                        format.as_str()
                    ),
                    None => anyhow::anyhow!(
                        "--content must contain UTF-8 {} content: {error}",
                        format.as_str()
                    ),
                })?)
            };
            Ok(Some((value, format)))
        }
    }
}

fn insert_confluence_content_inputs<F: NormalizedContentFormatArg>(
    inputs: &mut serde_json::Map<String, serde_json::Value>,
    content: Option<&str>,
    content_file: Option<&Path>,
    content_format: F,
    command: &str,
) -> Result<()> {
    let (content, content_format) = require_cli_input(resolve_content_input(
        content,
        content_file,
        Some(content_format),
        true,
        command,
    ))
    .expect("required Confluence content must resolve");
    inputs.insert("content".to_string(), content);
    inputs.insert(
        "contentFormat".to_string(),
        serde_json::json!(content_format.as_str()),
    );
    Ok(())
}

fn read_normalized_content_file(path: &Path) -> Result<Vec<u8>> {
    let file = fs::File::open(path)
        .map_err(|error| anyhow::anyhow!("failed to open {}: {error}", path.display()))?;
    let metadata = file
        .metadata()
        .map_err(|error| anyhow::anyhow!("failed to stat {}: {error}", path.display()))?;
    if metadata.len() > NORMALIZED_CONTENT_FILE_MAX_BYTES {
        anyhow::bail!(normalized_content_file_size_error(
            &path.display().to_string(),
            NORMALIZED_CONTENT_FILE_MAX_BYTES
        ));
    }
    read_normalized_content_to_limit(
        file,
        &path.display().to_string(),
        NORMALIZED_CONTENT_FILE_MAX_BYTES,
    )
}

fn read_normalized_content_to_limit(
    reader: impl Read,
    source: &str,
    max_bytes: u64,
) -> Result<Vec<u8>> {
    let mut bytes = Vec::new();
    reader
        .take(max_bytes.saturating_add(1))
        .read_to_end(&mut bytes)
        .map_err(|error| anyhow::anyhow!("failed to read {source}: {error}"))?;
    if bytes.len() as u64 > max_bytes {
        anyhow::bail!(normalized_content_file_size_error(source, max_bytes));
    }
    Ok(bytes)
}

fn normalized_content_file_size_error(source: &str, max_bytes: u64) -> String {
    format!(
        "normalized content file {source} exceeds the CLI safety limit of {max_bytes} bytes; provider and server limits may be lower"
    )
}

fn insert_jira_content_inputs(
    inputs: &mut serde_json::Map<String, serde_json::Value>,
    content: Option<&str>,
    content_file: Option<&Path>,
    content_format: Option<JiraContentFormatArg>,
    required: bool,
    command: &str,
) -> Result<bool> {
    let Some((content, content_format)) =
        resolve_content_input(content, content_file, content_format, required, command)?
    else {
        return Ok(false);
    };
    inputs.insert("content".to_string(), content);
    inputs.insert(
        "contentFormat".to_string(),
        serde_json::json!(content_format.as_str()),
    );
    Ok(true)
}

async fn run_jira_command(ctx: &CliContext<'_>, command: &JiraCommand) -> Result<()> {
    match command {
        JiraCommand::Project {
            command:
                JiraProjectCommand::View {
                    project,
                    include,
                    query,
                    output_format,
                },
        } => {
            let mut inputs = serde_json::Map::new();
            inputs.insert("project".to_string(), serde_json::json!(project));
            if let Some(include) = include {
                inputs.insert(
                    "include".to_string(),
                    serde_json::json!(
                        include
                            .iter()
                            .map(|section| section.as_str())
                            .collect::<Vec<_>>()
                    ),
                );
            }
            if let Some(query) = query {
                inputs.insert("query".to_string(), serde_json::json!(query));
            }
            run_typed_invoke_value(
                ctx,
                "jira.project.view",
                inputs.into(),
                None,
                *output_format,
            )
            .await
        }
        JiraCommand::Project {
            command:
                JiraProjectCommand::List {
                    max_results,
                    page_token,
                    output_format,
                },
        } => {
            let mut inputs = serde_json::Map::new();
            if let Some(max_results) = max_results {
                inputs.insert("maxResults".to_string(), serde_json::json!(max_results));
            }
            if let Some(page_token) = page_token {
                inputs.insert("pageToken".to_string(), serde_json::json!(page_token));
            }
            run_typed_invoke_value(
                ctx,
                "jira.project.list",
                inputs.into(),
                None,
                *output_format,
            )
            .await
        }
        JiraCommand::IssueType {
            command:
                JiraIssueTypeCommand::List {
                    project,
                    start_at,
                    max_results,
                    output_format,
                },
        } => {
            let mut inputs = serde_json::Map::new();
            inputs.insert("project".to_string(), serde_json::json!(project));
            if let Some(start_at) = start_at {
                inputs.insert("startAt".to_string(), serde_json::json!(start_at));
            }
            if let Some(max_results) = max_results {
                inputs.insert("maxResults".to_string(), serde_json::json!(max_results));
            }
            run_typed_invoke_value(
                ctx,
                "jira.issue_type.list",
                inputs.into(),
                None,
                *output_format,
            )
            .await
        }
        JiraCommand::Issue { command } => match command {
            JiraIssueCommand::View {
                issue,
                issue_url,
                include_comments,
                read_content_format,
                output_format,
            } => {
                let mut inputs = match (issue.as_deref(), issue_url.as_deref()) {
                    (Some(issue), None) => serde_json::json!({ "issue": issue }),
                    (None, Some(url)) => serde_json::json!({ "url": url }),
                    _ => require_cli_input(Err(anyhow::anyhow!(
                        "jira issue view requires exactly one issue argument or --issue-url"
                    ))),
                };
                if *include_comments {
                    inputs["includeComments"] = serde_json::json!(true);
                }
                run_typed_invoke_value(
                    ctx,
                    "jira.issue.view",
                    inputs,
                    *read_content_format,
                    *output_format,
                )
                .await
            }
            JiraIssueCommand::Create {
                project,
                issue_type_id,
                summary,
                content,
                content_file,
                content_format,
                read_content_format,
            } => {
                let mut inputs = serde_json::Map::new();
                inputs.insert("project".to_string(), serde_json::json!(project));
                inputs.insert("issueTypeId".to_string(), serde_json::json!(issue_type_id));
                inputs.insert("summary".to_string(), serde_json::json!(summary));
                require_cli_input(insert_jira_content_inputs(
                    &mut inputs,
                    content.as_deref(),
                    content_file.as_deref(),
                    *content_format,
                    false,
                    "jira issue create",
                ));
                run_typed_invoke_value(
                    ctx,
                    "jira.issue.create",
                    serde_json::Value::Object(inputs),
                    *read_content_format,
                    None,
                )
                .await
            }
            JiraIssueCommand::Child { command } => match command {
                JiraIssueChildCommand::Create {
                    project,
                    issue_type_id,
                    summary,
                    parent,
                    parent_url,
                    content,
                    content_file,
                    content_format,
                } => {
                    let mut inputs = serde_json::Map::new();
                    inputs.insert("project".to_string(), serde_json::json!(project));
                    inputs.insert("issueTypeId".to_string(), serde_json::json!(issue_type_id));
                    inputs.insert("summary".to_string(), serde_json::json!(summary));
                    jira_parent_locator_inputs(
                        &mut inputs,
                        parent.as_deref(),
                        parent_url.as_deref(),
                        "jira issue child create",
                    );
                    require_cli_input(insert_jira_content_inputs(
                        &mut inputs,
                        content.as_deref(),
                        content_file.as_deref(),
                        *content_format,
                        false,
                        "jira issue child create",
                    ));
                    run_invoke_value(
                        ctx,
                        "jira.issue.child.create",
                        serde_json::Value::Object(inputs),
                    )
                    .await
                }
            },
            JiraIssueCommand::Update {
                issue,
                issue_url,
                summary,
                content,
                content_file,
                content_format,
                read_content_format,
                notify_users,
                suppress_notifications,
            } => {
                let mut inputs = serde_json::Map::new();
                match (issue.as_deref(), issue_url.as_deref()) {
                    (Some(issue), None) => {
                        inputs.insert("issue".to_string(), serde_json::json!(issue));
                    }
                    (None, Some(url)) => {
                        inputs.insert("url".to_string(), serde_json::json!(url));
                    }
                    _ => require_cli_input(Err(anyhow::anyhow!(
                        "jira issue update requires exactly one issue argument or --issue-url"
                    ))),
                };
                let has_content = require_cli_input(insert_jira_content_inputs(
                    &mut inputs,
                    content.as_deref(),
                    content_file.as_deref(),
                    *content_format,
                    false,
                    "jira issue update",
                ));
                if summary.is_none() && !has_content {
                    require_cli_input::<()>(Err(anyhow::anyhow!(
                        "jira issue update requires --summary or content"
                    )));
                }
                if *notify_users && *suppress_notifications {
                    require_cli_input::<()>(Err(anyhow::anyhow!(
                        "jira issue update rejects --notify-users with --suppress-notifications"
                    )));
                }
                if let Some(summary) = summary {
                    inputs.insert("summary".to_string(), serde_json::json!(summary));
                }
                if *notify_users {
                    inputs.insert("notifyUsers".to_string(), serde_json::json!(true));
                } else if *suppress_notifications {
                    inputs.insert("notifyUsers".to_string(), serde_json::json!(false));
                }
                run_typed_invoke_value(
                    ctx,
                    "jira.issue.update",
                    serde_json::Value::Object(inputs),
                    *read_content_format,
                    None,
                )
                .await
            }
            JiraIssueCommand::Parent { command } => match command {
                JiraIssueParentCommand::Set {
                    issue,
                    issue_url,
                    parent,
                    parent_url,
                } => {
                    let mut inputs = jira_issue_argument_locator_inputs(
                        issue.as_deref(),
                        issue_url.as_deref(),
                        "jira issue parent set",
                    );
                    jira_parent_locator_inputs(
                        &mut inputs,
                        parent.as_deref(),
                        parent_url.as_deref(),
                        "jira issue parent set",
                    );
                    run_invoke_value(
                        ctx,
                        "jira.issue.parent.set",
                        serde_json::Value::Object(inputs),
                    )
                    .await
                }
            },
            JiraIssueCommand::Dependency { command } => match command {
                JiraIssueDependencyCommand::Add {
                    blocking,
                    blocking_url,
                    blocked,
                    blocked_url,
                } => {
                    let mut inputs = serde_json::Map::new();
                    jira_dependency_locator_inputs(
                        &mut inputs,
                        "blocking",
                        "blockingIssue",
                        "blockingUrl",
                        blocking.as_deref(),
                        blocking_url.as_deref(),
                    );
                    jira_dependency_locator_inputs(
                        &mut inputs,
                        "blocked",
                        "blockedIssue",
                        "blockedUrl",
                        blocked.as_deref(),
                        blocked_url.as_deref(),
                    );
                    run_invoke_value(
                        ctx,
                        "jira.issue.dependency.add",
                        serde_json::Value::Object(inputs),
                    )
                    .await
                }
            },
            JiraIssueCommand::Search {
                jql,
                text,
                projects,
                max_results,
                next_page_token,
                output_format,
            } => {
                let mut inputs = serde_json::Map::new();
                inputs.insert(
                    "query".to_string(),
                    exclusive_search_query("jql", jql.as_ref(), text.as_ref(), "jira issue search"),
                );
                if !projects.is_empty() {
                    inputs.insert("projects".to_string(), serde_json::json!(projects));
                }
                if let Some(max_results) = max_results {
                    inputs.insert("maxResults".to_string(), serde_json::json!(max_results));
                }
                if let Some(next_page_token) = next_page_token {
                    inputs.insert(
                        "nextPageToken".to_string(),
                        serde_json::json!(next_page_token),
                    );
                }
                run_typed_invoke_value(
                    ctx,
                    "jira.search",
                    serde_json::Value::Object(inputs),
                    None,
                    *output_format,
                )
                .await
            }
            JiraIssueCommand::Comment { command } => run_jira_comment_command(ctx, command).await,
            JiraIssueCommand::Attach {
                issue,
                files,
                content_type,
            } => run_jira_attachment_add(ctx, issue, files, content_type.as_deref()).await,
            JiraIssueCommand::Attachment { command } => match command {
                JiraAttachmentCommand::List {
                    issue,
                    issue_url,
                    output_format,
                } => {
                    let inputs = match (issue.as_deref(), issue_url.as_deref()) {
                        (Some(issue), None) => serde_json::json!({ "issue": issue }),
                        (None, Some(url)) => serde_json::json!({ "url": url }),
                        _ => require_cli_input(Err(anyhow::anyhow!(
                            "jira issue attachment list requires exactly one issue argument or --issue-url"
                        ))),
                    };
                    run_typed_invoke_value(
                        ctx,
                        "jira.attachment.list",
                        inputs,
                        None,
                        *output_format,
                    )
                    .await
                }
                JiraAttachmentCommand::Download {
                    issue,
                    attachment_id,
                } => {
                    run_jira_attachment_download(ctx, issue, attachment_id, required_output(ctx))
                        .await
                }
            },
            JiraIssueCommand::Verify {
                issue,
                expect_comment_id,
                expect_attachment_id,
                output_format,
            } => {
                if expect_comment_id.is_none() && expect_attachment_id.is_none() {
                    require_cli_input::<()>(Err(anyhow::anyhow!(
                        "jira issue verify requires at least one expected object id"
                    )));
                }
                let mut inputs = serde_json::Map::new();
                inputs.insert("issue".to_string(), serde_json::json!(issue));
                if let Some(comment_id) = expect_comment_id {
                    inputs.insert("expectCommentId".to_string(), serde_json::json!(comment_id));
                }
                if let Some(attachment_id) = expect_attachment_id {
                    inputs.insert(
                        "expectAttachmentId".to_string(),
                        serde_json::json!(attachment_id),
                    );
                }
                run_typed_invoke_value(
                    ctx,
                    "jira.verify",
                    serde_json::Value::Object(inputs),
                    None,
                    *output_format,
                )
                .await
            }
        },
    }
}

async fn run_jira_comment_command(
    ctx: &CliContext<'_>,
    command: &JiraCommentCommand,
) -> Result<()> {
    match command {
        JiraCommentCommand::List {
            issue,
            issue_url,
            max_results,
            start_at,
            order_by,
            include_bodies,
            read_content_format,
            output_format,
        } => {
            let mut inputs = jira_issue_locator_inputs(
                issue.as_deref(),
                issue_url.as_deref(),
                "jira issue comment list",
            );
            if let Some(max_results) = max_results {
                inputs.insert("maxResults".to_string(), serde_json::json!(max_results));
            }
            if let Some(start_at) = start_at {
                inputs.insert("startAt".to_string(), serde_json::json!(start_at));
            }
            if let Some(order_by) = order_by {
                inputs.insert("orderBy".to_string(), serde_json::json!(order_by));
            }
            if *include_bodies {
                inputs.insert("includeBodies".to_string(), serde_json::json!(true));
            }
            run_typed_invoke_value(
                ctx,
                "jira.comment.list",
                serde_json::Value::Object(inputs),
                *read_content_format,
                *output_format,
            )
            .await
        }
        JiraCommentCommand::View {
            comment_id,
            issue,
            issue_url,
            read_content_format,
            output_format,
        } => {
            let mut inputs = jira_issue_locator_inputs(
                issue.as_deref(),
                issue_url.as_deref(),
                "jira issue comment view",
            );
            inputs.insert("commentId".to_string(), serde_json::json!(comment_id));
            run_typed_invoke_value(
                ctx,
                "jira.comment.view",
                serde_json::Value::Object(inputs),
                *read_content_format,
                *output_format,
            )
            .await
        }
        JiraCommentCommand::Add {
            issue,
            issue_url,
            content,
            content_file,
            content_format,
            visibility_file,
            read_content_format,
        } => {
            let mut inputs = jira_issue_locator_inputs(
                issue.as_deref(),
                issue_url.as_deref(),
                "jira issue comment add",
            );
            require_cli_input(insert_jira_content_inputs(
                &mut inputs,
                content.as_deref(),
                content_file.as_deref(),
                *content_format,
                true,
                "jira issue comment add",
            ));
            if let Some(visibility_file) = visibility_file {
                inputs.insert("visibility".to_string(), read_json_file(visibility_file));
            }
            run_typed_invoke_value(
                ctx,
                "jira.comment.add",
                serde_json::Value::Object(inputs),
                *read_content_format,
                None,
            )
            .await
        }
        JiraCommentCommand::Reply {
            parent_comment_id,
            issue,
            issue_url,
            content,
            content_file,
            content_format,
            visibility_file,
            read_content_format,
        } => {
            let mut inputs = jira_issue_locator_inputs(
                issue.as_deref(),
                issue_url.as_deref(),
                "jira issue comment reply",
            );
            inputs.insert(
                "parentCommentId".to_string(),
                serde_json::json!(parent_comment_id),
            );
            require_cli_input(insert_jira_content_inputs(
                &mut inputs,
                content.as_deref(),
                content_file.as_deref(),
                *content_format,
                true,
                "jira issue comment reply",
            ));
            if let Some(visibility_file) = visibility_file {
                inputs.insert("visibility".to_string(), read_json_file(visibility_file));
            }
            run_typed_invoke_value(
                ctx,
                "jira.comment.reply",
                serde_json::Value::Object(inputs),
                *read_content_format,
                None,
            )
            .await
        }
        JiraCommentCommand::Update {
            comment_id,
            issue,
            issue_url,
            content,
            content_file,
            content_format,
            visibility_file,
            notify_users,
            read_content_format,
        } => {
            let mut inputs = jira_issue_locator_inputs(
                issue.as_deref(),
                issue_url.as_deref(),
                "jira issue comment update",
            );
            inputs.insert("commentId".to_string(), serde_json::json!(comment_id));
            require_cli_input(insert_jira_content_inputs(
                &mut inputs,
                content.as_deref(),
                content_file.as_deref(),
                *content_format,
                true,
                "jira issue comment update",
            ));
            inputs.insert("notifyUsers".to_string(), serde_json::json!(notify_users));
            if let Some(visibility_file) = visibility_file {
                inputs.insert("visibilityMode".to_string(), serde_json::json!("set"));
                inputs.insert("visibility".to_string(), read_json_file(visibility_file));
            }
            run_typed_invoke_value(
                ctx,
                "jira.comment.update",
                serde_json::Value::Object(inputs),
                *read_content_format,
                None,
            )
            .await
        }
        JiraCommentCommand::Delete {
            comment_id,
            issue,
            issue_url,
        } => {
            let mut inputs = jira_issue_locator_inputs(
                issue.as_deref(),
                issue_url.as_deref(),
                "jira issue comment delete",
            );
            inputs.insert("commentId".to_string(), serde_json::json!(comment_id));
            run_invoke_value(
                ctx,
                "jira.comment.delete",
                serde_json::Value::Object(inputs),
            )
            .await
        }
        JiraCommentCommand::Property { command } => {
            run_jira_comment_property_command(ctx, command).await
        }
    }
}

async fn run_jira_comment_property_command(
    ctx: &CliContext<'_>,
    command: &JiraCommentPropertyCommand,
) -> Result<()> {
    match command {
        JiraCommentPropertyCommand::List {
            comment_id,
            issue,
            issue_url,
            output_format,
        } => {
            let mut inputs = jira_issue_locator_inputs(
                issue.as_deref(),
                issue_url.as_deref(),
                "jira issue comment property list",
            );
            inputs.insert("commentId".to_string(), serde_json::json!(comment_id));
            run_typed_invoke_value(
                ctx,
                "jira.comment.property.list",
                serde_json::Value::Object(inputs),
                None,
                *output_format,
            )
            .await
        }
        JiraCommentPropertyCommand::Get {
            comment_id,
            property_key,
            issue,
            issue_url,
            output_format,
        } => {
            let mut inputs = jira_issue_locator_inputs(
                issue.as_deref(),
                issue_url.as_deref(),
                "jira issue comment property get",
            );
            inputs.insert("commentId".to_string(), serde_json::json!(comment_id));
            inputs.insert("propertyKey".to_string(), serde_json::json!(property_key));
            run_typed_invoke_value(
                ctx,
                "jira.comment.property.get",
                serde_json::Value::Object(inputs),
                None,
                *output_format,
            )
            .await
        }
        JiraCommentPropertyCommand::Set {
            comment_id,
            property_key,
            issue,
            issue_url,
            value_file,
        } => {
            let mut inputs = jira_issue_locator_inputs(
                issue.as_deref(),
                issue_url.as_deref(),
                "jira issue comment property set",
            );
            inputs.insert("commentId".to_string(), serde_json::json!(comment_id));
            inputs.insert("propertyKey".to_string(), serde_json::json!(property_key));
            inputs.insert("value".to_string(), read_json_file(value_file));
            run_invoke_value(
                ctx,
                "jira.comment.property.set",
                serde_json::Value::Object(inputs),
            )
            .await
        }
        JiraCommentPropertyCommand::Delete {
            comment_id,
            property_key,
            issue,
            issue_url,
        } => {
            let mut inputs = jira_issue_locator_inputs(
                issue.as_deref(),
                issue_url.as_deref(),
                "jira issue comment property delete",
            );
            inputs.insert("commentId".to_string(), serde_json::json!(comment_id));
            inputs.insert("propertyKey".to_string(), serde_json::json!(property_key));
            run_invoke_value(
                ctx,
                "jira.comment.property.delete",
                serde_json::Value::Object(inputs),
            )
            .await
        }
    }
}

fn jira_issue_locator_inputs(
    issue: Option<&str>,
    issue_url: Option<&str>,
    command: &str,
) -> serde_json::Map<String, serde_json::Value> {
    let mut inputs = serde_json::Map::new();
    match (issue, issue_url) {
        (Some(issue), None) => {
            inputs.insert("issue".to_string(), serde_json::json!(issue));
        }
        (None, Some(url)) => {
            inputs.insert("url".to_string(), serde_json::json!(url));
        }
        _ => require_cli_input::<()>(Err(anyhow::anyhow!(
            "{command} requires exactly one of --issue or --issue-url"
        ))),
    }
    inputs
}

fn jira_issue_argument_locator_inputs(
    issue: Option<&str>,
    issue_url: Option<&str>,
    command: &str,
) -> serde_json::Map<String, serde_json::Value> {
    let mut inputs = serde_json::Map::new();
    match (issue, issue_url) {
        (Some(issue), None) => {
            inputs.insert("issue".to_string(), serde_json::json!(issue));
        }
        (None, Some(url)) => {
            inputs.insert("url".to_string(), serde_json::json!(url));
        }
        _ => require_cli_input::<()>(Err(anyhow::anyhow!(
            "{command} requires exactly one issue argument or --issue-url"
        ))),
    }
    inputs
}

fn jira_dependency_locator_inputs(
    inputs: &mut serde_json::Map<String, serde_json::Value>,
    label: &str,
    issue_field: &str,
    url_field: &str,
    issue: Option<&str>,
    issue_url: Option<&str>,
) {
    match (issue, issue_url) {
        (Some(issue), None) => {
            inputs.insert(issue_field.to_string(), serde_json::json!(issue));
        }
        (None, Some(url)) => {
            inputs.insert(url_field.to_string(), serde_json::json!(url));
        }
        _ => require_cli_input::<()>(Err(anyhow::anyhow!(
            "jira issue dependency add requires exactly one --{label} or --{label}-url"
        ))),
    };
}

fn jira_parent_locator_inputs(
    inputs: &mut serde_json::Map<String, serde_json::Value>,
    parent: Option<&str>,
    parent_url: Option<&str>,
    command: &str,
) {
    match (parent, parent_url) {
        (Some(parent), None) => {
            inputs.insert("parentIssue".to_string(), serde_json::json!(parent));
        }
        (None, Some(url)) => {
            inputs.insert("parentUrl".to_string(), serde_json::json!(url));
        }
        _ => require_cli_input::<()>(Err(anyhow::anyhow!(
            "{command} requires exactly one --parent or --parent-url"
        ))),
    };
}

async fn run_jira_attachment_add(
    ctx: &CliContext<'_>,
    issue: &str,
    files: &[PathBuf],
    content_type: Option<&str>,
) -> Result<()> {
    require_cli_input(validate_attachment_content_type_override(
        "jira issue attach",
        files,
        content_type,
    ));
    let mut form = reqwest::multipart::Form::new();
    let mut attachments = Vec::new();
    let mut file_parts = Vec::new();
    for (index, path) in files.iter().enumerate() {
        let size = file_size(path);
        let filename = file_name(path);
        let detected_content_type = content_type.map(ToString::to_string).unwrap_or_else(|| {
            mime_guess::from_path(path)
                .first_or_octet_stream()
                .essence_str()
                .to_string()
        });
        let field = format!("file{index}");
        let sha256 = sha256_file(path);
        attachments.push(serde_json::json!({
            "field": field,
            "filename": filename,
            "contentType": detected_content_type,
            "size": size,
            "sha256": sha256,
        }));
        file_parts.push((field, path.clone(), filename, detected_content_type));
    }
    let request_json = serde_json::to_string(&InvokeRequest {
        inputs: serde_json::json!({
            "issue": issue,
            "attachments": attachments,
        }),
        read_content_format: ReadContentFormat::Native,
        response_format: ResponseFormat::Json,
        body_parts: vec![],
    })?;
    form = form.part(
        "request",
        reqwest::multipart::Part::text(request_json).mime_str("application/json")?,
    );
    for (field, path, filename, content_type) in file_parts {
        let part = reqwest::multipart::Part::file(&path)
            .await
            .with_context(|| format!("failed to open {} for upload", path.display()))?
            .file_name(filename)
            .mime_str(&content_type)?;
        form = form.part(field, part);
    }
    run_invoke_multipart(ctx, "jira.attachment.add", form).await
}

fn validate_attachment_content_type_override(
    command: &str,
    files: &[PathBuf],
    content_type: Option<&str>,
) -> Result<()> {
    if content_type.is_some() && files.len() != 1 {
        anyhow::bail!("{command} --content-type requires exactly one file");
    }
    Ok(())
}

async fn run_confluence_attachment_add(
    ctx: &CliContext<'_>,
    page_id: &str,
    files: &[PathBuf],
    content_type: Option<&str>,
) -> Result<()> {
    require_cli_input(validate_attachment_content_type_override(
        "confluence page attach",
        files,
        content_type,
    ));
    let mut form = reqwest::multipart::Form::new();
    let mut attachments = Vec::new();
    let mut file_parts = Vec::new();
    for (index, path) in files.iter().enumerate() {
        let size = file_size(path);
        let filename = file_name(path);
        let detected_content_type = content_type.map(ToString::to_string).unwrap_or_else(|| {
            mime_guess::from_path(path)
                .first_or_octet_stream()
                .essence_str()
                .to_string()
        });
        let field = format!("file{index}");
        let sha256 = sha256_file(path);
        attachments.push(serde_json::json!({
            "field": field,
            "filename": filename,
            "contentType": detected_content_type,
            "size": size,
            "sha256": sha256,
        }));
        file_parts.push((field, path.clone(), filename, detected_content_type));
    }
    let request_json = serde_json::to_string(&InvokeRequest {
        inputs: serde_json::json!({
            "pageId": page_id,
            "attachments": attachments,
        }),
        read_content_format: ReadContentFormat::Native,
        response_format: ResponseFormat::Json,
        body_parts: vec![],
    })?;
    form = form.part(
        "request",
        reqwest::multipart::Part::text(request_json).mime_str("application/json")?,
    );
    for (field, path, filename, content_type) in file_parts {
        let part = reqwest::multipart::Part::file(&path)
            .await
            .with_context(|| format!("failed to open {} for upload", path.display()))?
            .file_name(filename)
            .mime_str(&content_type)?;
        form = form.part(field, part);
    }
    run_invoke_multipart(ctx, "confluence.attachment.add", form).await
}

async fn run_confluence_blog_attachment_add(
    ctx: &CliContext<'_>,
    blog_id: &str,
    files: &[PathBuf],
    content_type: Option<&str>,
) -> Result<()> {
    require_cli_input(validate_attachment_content_type_override(
        "confluence blog attach",
        files,
        content_type,
    ));
    let mut form = reqwest::multipart::Form::new();
    let mut attachments = Vec::new();
    let mut file_parts = Vec::new();
    for (index, path) in files.iter().enumerate() {
        let size = file_size(path);
        let filename = file_name(path);
        let detected_content_type = content_type.map(ToString::to_string).unwrap_or_else(|| {
            mime_guess::from_path(path)
                .first_or_octet_stream()
                .essence_str()
                .to_string()
        });
        let field = format!("file{index}");
        let sha256 = sha256_file(path);
        attachments.push(serde_json::json!({
            "field": field,
            "filename": filename,
            "contentType": detected_content_type,
            "size": size,
            "sha256": sha256,
        }));
        file_parts.push((field, path.clone(), filename, detected_content_type));
    }
    let request_json = serde_json::to_string(&InvokeRequest {
        inputs: serde_json::json!({
            "blogId": blog_id,
            "attachments": attachments,
        }),
        read_content_format: ReadContentFormat::Native,
        response_format: ResponseFormat::Json,
        body_parts: vec![],
    })?;
    form = form.part(
        "request",
        reqwest::multipart::Part::text(request_json).mime_str("application/json")?,
    );
    for (field, path, filename, content_type) in file_parts {
        let part = reqwest::multipart::Part::file(&path)
            .await
            .with_context(|| format!("failed to open {} for upload", path.display()))?
            .file_name(filename)
            .mime_str(&content_type)?;
        form = form.part(field, part);
    }
    run_invoke_multipart(ctx, "confluence.blog.attachment.add", form).await
}

struct ConfluenceDraftAttachmentAddArgs<'a> {
    service_action: &'a str,
    id_field: &'a str,
    content_id: &'a str,
    draft_handle: &'a str,
    files: &'a [PathBuf],
    content_type: Option<&'a str>,
}

async fn run_confluence_draft_attachment_add(
    ctx: &CliContext<'_>,
    args: ConfluenceDraftAttachmentAddArgs<'_>,
) -> Result<()> {
    require_cli_input(validate_attachment_content_type_override(
        args.service_action,
        args.files,
        args.content_type,
    ));
    let mut form = reqwest::multipart::Form::new();
    let mut attachments = Vec::new();
    let mut file_parts = Vec::new();
    for (index, path) in args.files.iter().enumerate() {
        let size = file_size(path);
        let filename = file_name(path);
        let detected_content_type =
            args.content_type
                .map(ToString::to_string)
                .unwrap_or_else(|| {
                    mime_guess::from_path(path)
                        .first_or_octet_stream()
                        .essence_str()
                        .to_string()
                });
        let field = format!("file{index}");
        let sha256 = sha256_file(path);
        attachments.push(serde_json::json!({
            "field": field,
            "filename": filename,
            "contentType": detected_content_type,
            "size": size,
            "sha256": sha256,
        }));
        file_parts.push((field, path.clone(), filename, detected_content_type));
    }
    let mut inputs = serde_json::Map::new();
    inputs.insert(
        args.id_field.to_string(),
        serde_json::json!(args.content_id),
    );
    inputs.insert(
        "draftHandle".to_string(),
        serde_json::json!(args.draft_handle),
    );
    inputs.insert("attachments".to_string(), serde_json::json!(attachments));
    let request_json = serde_json::to_string(&InvokeRequest {
        inputs: serde_json::Value::Object(inputs),
        read_content_format: ReadContentFormat::Native,
        response_format: ResponseFormat::Json,
        body_parts: vec![],
    })?;
    form = form.part(
        "request",
        reqwest::multipart::Part::text(request_json).mime_str("application/json")?,
    );
    for (field, path, filename, content_type) in file_parts {
        let part = reqwest::multipart::Part::file(&path)
            .await
            .with_context(|| format!("failed to open {} for upload", path.display()))?
            .file_name(filename)
            .mime_str(&content_type)?;
        form = form.part(field, part);
    }
    run_invoke_multipart(ctx, args.service_action, form).await
}

async fn run_jira_attachment_download(
    ctx: &CliContext<'_>,
    issue: &str,
    attachment_id: &str,
    output: &Path,
) -> Result<()> {
    run_attachment_download(
        ctx,
        "jira.attachment.download",
        serde_json::json!({
            "issue": issue,
            "attachmentId": attachment_id,
        }),
        output,
    )
    .await
}

async fn run_confluence_attachment_download(
    ctx: &CliContext<'_>,
    page_id: &str,
    attachment_id: &str,
    output: &Path,
) -> Result<()> {
    run_attachment_download(
        ctx,
        "confluence.attachment.download",
        serde_json::json!({
            "pageId": page_id,
            "attachmentId": attachment_id,
        }),
        output,
    )
    .await
}

async fn run_confluence_blog_attachment_download(
    ctx: &CliContext<'_>,
    blog_id: &str,
    attachment_id: &str,
    output: &Path,
) -> Result<()> {
    run_attachment_download(
        ctx,
        "confluence.blog.attachment.download",
        serde_json::json!({
            "blogId": blog_id,
            "attachmentId": attachment_id,
        }),
        output,
    )
    .await
}

struct ConfluenceDraftAttachmentDownloadArgs<'a> {
    service_action: &'a str,
    id_field: &'a str,
    content_id: &'a str,
    draft_handle: &'a str,
    attachment_id: &'a str,
    output: &'a Path,
}

async fn run_confluence_draft_attachment_download(
    ctx: &CliContext<'_>,
    args: ConfluenceDraftAttachmentDownloadArgs<'_>,
) -> Result<()> {
    let mut inputs = serde_json::Map::new();
    inputs.insert(
        args.id_field.to_string(),
        serde_json::json!(args.content_id),
    );
    inputs.insert(
        "draftHandle".to_string(),
        serde_json::json!(args.draft_handle),
    );
    inputs.insert(
        "attachmentId".to_string(),
        serde_json::json!(args.attachment_id),
    );
    run_attachment_download(
        ctx,
        args.service_action,
        serde_json::Value::Object(inputs),
        args.output,
    )
    .await
}

fn confluence_draft_attachment_list_inputs(
    id_field: &str,
    content_id: &str,
    draft_handle: &str,
    max_results: Option<u32>,
    next_page_token: Option<&str>,
) -> serde_json::Value {
    let mut inputs = serde_json::Map::new();
    inputs.insert(id_field.to_string(), serde_json::json!(content_id));
    inputs.insert("draftHandle".to_string(), serde_json::json!(draft_handle));
    if let Some(max_results) = max_results {
        inputs.insert("maxResults".to_string(), serde_json::json!(max_results));
    }
    if let Some(next_page_token) = next_page_token {
        inputs.insert(
            "nextPageToken".to_string(),
            serde_json::json!(next_page_token),
        );
    }
    serde_json::Value::Object(inputs)
}

fn confluence_draft_verify_inputs(
    id_field: &str,
    content_id: &str,
    draft_handle: &str,
    expect_version: Option<u64>,
    expect_title: Option<&str>,
    expect_attachment_id: Option<&str>,
    label: &str,
) -> serde_json::Value {
    if expect_version.is_none() && expect_title.is_none() && expect_attachment_id.is_none() {
        require_cli_input::<()>(Err(anyhow::anyhow!(
            "{label} requires at least one expected value"
        )));
    }
    let mut inputs = serde_json::Map::new();
    inputs.insert(id_field.to_string(), serde_json::json!(content_id));
    inputs.insert("draftHandle".to_string(), serde_json::json!(draft_handle));
    if let Some(version) = expect_version {
        inputs.insert("expectVersion".to_string(), serde_json::json!(version));
    }
    if let Some(title) = expect_title {
        inputs.insert("expectTitle".to_string(), serde_json::json!(title));
    }
    if let Some(attachment_id) = expect_attachment_id {
        inputs.insert(
            "expectAttachmentId".to_string(),
            serde_json::json!(attachment_id),
        );
    }
    serde_json::Value::Object(inputs)
}

async fn run_attachment_download(
    ctx: &CliContext<'_>,
    service_action: &str,
    inputs: serde_json::Value,
    output: &Path,
) -> Result<()> {
    let (status, metadata) = send_download_value(ctx, service_action, inputs, output)
        .await
        .map_err(DownloadResponseError::into_error)?;
    if status < 400 && output == Path::new("-") {
        std::process::exit(cli_exit_code_for_http_status(status));
    }
    println!("{}", serde_json::to_string_pretty(&metadata)?);
    exit_for_broker_status(status, &metadata);
}

async fn run_invoke_multipart(
    ctx: &CliContext<'_>,
    service_action: &str,
    form: reqwest::multipart::Form,
) -> Result<()> {
    let (service, action) =
        require_cli_input(split_service_action(service_action).map_err(anyhow::Error::msg));
    let reserved = if ctx.output.is_some() {
        let spec = output_action_spec(ctx, &service, &action)
            .await
            .unwrap_or_else(|error| exit_cli_input_error(error));
        output::ResponseOutput::prepare(ctx.output, &spec.sensitive_output_pointers)
            .map_err(DeferredCliError::input)?
    } else {
        None
    };
    let (status, value) = send_invoke_multipart(ctx, service_action, form).await?;
    if let Some(receipt) =
        write_local_response(ctx, status, &value, ResponseFormat::Json, reserved)?
    {
        print_value_and_exit(status, receipt);
    }
    print_value_and_exit(status, value);
}

async fn send_invoke_multipart(
    ctx: &CliContext<'_>,
    service_action: &str,
    form: reqwest::multipart::Form,
) -> Result<(u16, serde_json::Value)> {
    let (service, action) =
        split_service_action(service_action).map_err(DeferredCliError::input)?;
    let resolved = ctx.settings;
    let path = format!("/v1/invoke/{service}/{action}");
    let endpoint = endpoint(&resolved.url, &path).map_err(DeferredCliError::input)?;
    let client = http_client(resolved).map_err(DeferredCliError::input)?;
    let response = request_builder(client.post(endpoint), resolved)
        .multipart(form)
        .send()
        .await
        .map_err(|error| invocation_request_error(error, "broker request failed"))
        .map_err(DeferredCliError::remote)?;
    invocation_response_value(response).await
}

fn read_json_file(path: &Path) -> serde_json::Value {
    let bytes = read_bytes_file(path);
    require_cli_input(
        serde_json::from_slice(&bytes)
            .map_err(|error| anyhow::anyhow!("{} must contain JSON: {error}", path.display())),
    )
}

fn confluence_page_argument_locator_inputs(
    page_id: Option<&str>,
    page_url: Option<&str>,
    command: &str,
) -> serde_json::Map<String, serde_json::Value> {
    let mut inputs = serde_json::Map::new();
    match (page_id, page_url) {
        (Some(page_id), None) => {
            inputs.insert("pageId".to_string(), serde_json::json!(page_id));
        }
        (None, Some(url)) => {
            inputs.insert("url".to_string(), serde_json::json!(url));
        }
        _ => require_cli_input::<()>(Err(anyhow::anyhow!(
            "{command} requires exactly one page id argument or --page-url"
        ))),
    }
    inputs
}

fn confluence_optional_parent_locator_inputs(
    inputs: &mut serde_json::Map<String, serde_json::Value>,
    parent: Option<&str>,
    parent_url: Option<&str>,
    command: &str,
) {
    match (parent, parent_url) {
        (Some(parent), None) => {
            inputs.insert("parentPageId".to_string(), serde_json::json!(parent));
        }
        (None, Some(url)) => {
            inputs.insert("parentUrl".to_string(), serde_json::json!(url));
        }
        (None, None) => {}
        (Some(_), Some(_)) => require_cli_input::<()>(Err(anyhow::anyhow!(
            "{command} accepts at most one --parent or --parent-url"
        ))),
    }
}

fn confluence_move_target_locator_inputs(
    inputs: &mut serde_json::Map<String, serde_json::Value>,
    target: Option<&str>,
    target_url: Option<&str>,
    command: &str,
) {
    match (target, target_url) {
        (Some(target), None) => {
            inputs.insert("targetPageId".to_string(), serde_json::json!(target));
        }
        (None, Some(url)) => {
            inputs.insert("targetUrl".to_string(), serde_json::json!(url));
        }
        _ => require_cli_input::<()>(Err(anyhow::anyhow!(
            "{command} requires exactly one --target or --target-url"
        ))),
    }
}

fn read_gitlab_text_file(path: &Path) -> String {
    let bytes = read_bytes_file(path);
    require_cli_input(
        String::from_utf8(bytes).map_err(|error| {
            anyhow::anyhow!("{} must contain UTF-8 text: {error}", path.display())
        }),
    )
}

fn read_bytes_file(path: &Path) -> Vec<u8> {
    require_cli_input(
        fs::read(path)
            .map_err(|error| anyhow::anyhow!("failed to read {}: {error}", path.display())),
    )
}

fn file_size(path: &Path) -> u64 {
    require_cli_input(upload_file_metadata(path)).len()
}

fn upload_file_metadata(path: &Path) -> Result<fs::Metadata> {
    let metadata =
        fs::metadata(path).with_context(|| format!("failed to stat {}", path.display()))?;
    if !metadata.is_file() {
        anyhow::bail!("upload source must be a regular file: {}", path.display());
    }
    Ok(metadata)
}

fn file_name(path: &Path) -> String {
    require_cli_input(
        path.file_name()
            .and_then(|name| name.to_str())
            .map(ToString::to_string)
            .ok_or_else(|| anyhow::anyhow!("{} does not have a valid filename", path.display())),
    )
}

fn sha256_file(path: &Path) -> String {
    let mut file = require_cli_input(
        fs::File::open(path)
            .map_err(|error| anyhow::anyhow!("failed to open {}: {error}", path.display())),
    );
    let mut digest = Sha256::new();
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let count = require_cli_input(
            file.read(&mut buffer)
                .map_err(|error| anyhow::anyhow!("failed to read {}: {error}", path.display())),
        );
        if count == 0 {
            break;
        }
        digest.update(&buffer[..count]);
    }
    let digest = digest.finalize();
    digest.iter().map(|byte| format!("{byte:02x}")).collect()
}

async fn run_invoke(
    ctx: &CliContext<'_>,
    service_action: &str,
    input_json: &Option<String>,
    input_file: &Option<PathBuf>,
    input_stdin: bool,
    read_content_format: Option<ReadContentFormatArg>,
    output_format: Option<OutputFormatArg>,
) -> Result<()> {
    let (service, action) =
        require_cli_input(split_service_action(service_action).map_err(anyhow::Error::msg));
    let inputs = read_invoke_input_source(input_json, input_file, input_stdin);
    let options =
        resolve_generic_invoke_options(ctx, &service, &action, read_content_format, output_format)
            .await
            .unwrap_or_else(|error| exit_cli_input_error(error));
    run_invoke_parts_with_options(ctx, &service, &action, inputs, options).await
}

async fn run_invoke_value(
    ctx: &CliContext<'_>,
    service_action: &str,
    inputs: serde_json::Value,
) -> Result<()> {
    let (service, action) =
        require_cli_input(split_service_action(service_action).map_err(anyhow::Error::msg));
    run_invoke_parts(ctx, &service, &action, inputs).await
}

async fn run_typed_invoke_value(
    ctx: &CliContext<'_>,
    service_action: &str,
    inputs: serde_json::Value,
    read_content_format: Option<ReadContentFormatArg>,
    output_format: Option<OutputFormatArg>,
) -> Result<()> {
    let (service, action) =
        require_cli_input(split_service_action(service_action).map_err(anyhow::Error::msg));
    let options =
        resolve_generic_invoke_options(ctx, &service, &action, read_content_format, output_format)
            .await
            .unwrap_or_else(|error| exit_cli_input_error(error));
    run_invoke_parts_with_options(ctx, &service, &action, inputs, options).await
}

fn resolve_response_options(
    settings: &ResolvedCliSettings,
    explicit_read: Option<ReadContentFormatArg>,
    explicit_output: Option<OutputFormatArg>,
    supports_read_content: bool,
    supports_markdown_output: bool,
    service_action: &str,
) -> Result<ResponseOptions> {
    let requested_read = explicit_read
        .map(ReadContentFormat::from)
        .unwrap_or(settings.read_content_format);
    let requested_output = explicit_output
        .map(ResponseFormat::from)
        .unwrap_or(settings.output_format);

    if explicit_read.is_some()
        && requested_read != ReadContentFormat::Native
        && !supports_read_content
    {
        anyhow::bail!("action {service_action} does not support --read-content-format");
    }
    if explicit_output.is_some()
        && requested_output != ResponseFormat::Json
        && !supports_markdown_output
    {
        anyhow::bail!("action {service_action} does not support --output-format");
    }
    let selected_read = if supports_read_content {
        requested_read
    } else {
        ReadContentFormat::Native
    };
    let selected_output = if supports_markdown_output {
        requested_output
    } else {
        ResponseFormat::Json
    };
    if selected_output == ResponseFormat::Markdown && selected_read != ReadContentFormat::Native {
        // An explicit whole-result selection intentionally overrides an ambient
        // embedded-content default. All other non-native combinations are
        // ambiguous and must be resolved by the caller instead of silently
        // changing one of the configured defaults.
        if explicit_output != Some(OutputFormatArg::Markdown) || explicit_read.is_some() {
            anyhow::bail!(
                "--output-format markdown cannot be combined with a non-native read-content format; explicitly select --output-format markdown to override an ambient read-content default"
            );
        }
    }

    Ok(ResponseOptions::new(
        if selected_output == ResponseFormat::Markdown {
            ReadContentFormat::Native
        } else {
            selected_read
        },
        selected_output,
    ))
}

/// Response options for one invoke and the catalog's `renderedBody` owners
/// for the action, where the CLI checks returned companions.
#[derive(Debug, Clone, Default)]
struct InvokeResponseOptions {
    options: ResponseOptions,
    rendered_body_owners: Vec<String>,
    optional_rendered_body_owner_prefixes: Vec<String>,
    action_spec: Option<ApiActionSpec>,
}

async fn resolve_generic_invoke_options(
    ctx: &CliContext<'_>,
    service: &str,
    action: &str,
    explicit_read: Option<ReadContentFormatArg>,
    explicit_output: Option<OutputFormatArg>,
) -> Result<InvokeResponseOptions> {
    let effective_read = explicit_read
        .map(ReadContentFormat::from)
        .unwrap_or(ctx.settings.read_content_format);
    let effective_output = explicit_output
        .map(ResponseFormat::from)
        .unwrap_or(ctx.settings.output_format);
    if ctx.output.is_none() && !generic_invoke_needs_catalog(effective_read, effective_output) {
        return Ok(InvokeResponseOptions::default());
    }

    let catalog = fetch_runtime_catalog(ctx).await.unwrap_or_else(|error| {
        exit_malformed_broker_response(format!("invalid runtime catalog: {error:#}"))
    });
    let service_action = format!("{service}.{action}");
    let action_spec = if ctx.output.is_some() {
        Some(catalog_action(&catalog, service, action)?)
    } else {
        catalog_action(&catalog, service, action).ok()
    };
    if ctx.output.is_none()
        && action_spec.is_some_and(|spec| matches!(spec.io, ActionIo::RawDownload { .. }))
    {
        anyhow::bail!("download requires --output PATH (or --output - for stdout)");
    }
    let options = resolve_generic_response_options_from_action(
        ctx.settings,
        action_spec,
        explicit_read,
        explicit_output,
        &service_action,
    )?;
    let rendered_body_owners = action_spec
        .map(|action_spec| action_spec.rendered_body_owners.clone())
        .unwrap_or_default();
    if options.read_content_format != ReadContentFormat::Native && rendered_body_owners.is_empty() {
        exit_malformed_broker_response(format!(
            "runtime catalog advertises readContentFormats for {service_action} without renderedBodyOwners"
        ));
    }
    let optional_rendered_body_owner_prefixes = action_spec
        .map(|action_spec| action_spec.optional_rendered_body_owner_prefixes.clone())
        .unwrap_or_default();
    Ok(InvokeResponseOptions {
        options,
        rendered_body_owners,
        optional_rendered_body_owner_prefixes,
        action_spec: action_spec.cloned(),
    })
}

fn resolve_generic_response_options_from_action(
    settings: &ResolvedCliSettings,
    action_spec: Option<&ApiActionSpec>,
    explicit_read: Option<ReadContentFormatArg>,
    explicit_output: Option<OutputFormatArg>,
    service_action: &str,
) -> Result<ResponseOptions> {
    let Some(action_spec) = action_spec else {
        if explicit_read.is_some() || explicit_output.is_some() {
            anyhow::bail!(
                "runtime catalog does not expose action {service_action}; run agent-access services list to check availability and setup requirements"
            );
        }
        // Catalog visibility is caller-filtered. An omitted action therefore
        // cannot safely inherit ambient format defaults; send the protocol
        // defaults and let the Broker make the authoritative action decision.
        return Ok(ResponseOptions::default());
    };
    let raw_download = matches!(action_spec.io, ActionIo::RawDownload { .. });
    let supports_read_content = !raw_download && !action_spec.read_content_formats.is_empty();
    let supports_markdown_output = !raw_download && !action_spec.response_formats.is_empty();
    resolve_response_options(
        settings,
        explicit_read,
        explicit_output,
        supports_read_content,
        supports_markdown_output,
        service_action,
    )
}

fn generic_invoke_needs_catalog(
    read_content_format: ReadContentFormat,
    output_format: ResponseFormat,
) -> bool {
    read_content_format != ReadContentFormat::Native || output_format != ResponseFormat::Json
}

fn read_invoke_input_source(
    input_json: &Option<String>,
    input_file: &Option<PathBuf>,
    input_stdin: bool,
) -> serde_json::Value {
    let count = input_json.is_some() as u8 + input_file.is_some() as u8 + input_stdin as u8;
    if count > 1 {
        return require_cli_input(Err(anyhow::anyhow!(
            "use only one of --input-json, --input-file, or --input-stdin"
        )));
    }
    if let Some(raw) = input_json {
        return require_cli_input(
            serde_json::from_str(raw)
                .map_err(|error| anyhow::anyhow!("--input-json must be a JSON value: {error}")),
        );
    }
    if let Some(path) = input_file {
        return read_json_file(path);
    }
    if input_stdin {
        let mut raw = String::new();
        require_cli_input(
            std::io::stdin()
                .read_to_string(&mut raw)
                .map_err(|error| anyhow::anyhow!("failed to read --input-stdin: {error}")),
        );
        return require_cli_input(
            serde_json::from_str(&raw)
                .map_err(|error| anyhow::anyhow!("--input-stdin must be a JSON value: {error}")),
        );
    }
    serde_json::json!({})
}

async fn send_download_value(
    ctx: &CliContext<'_>,
    service_action: &str,
    inputs: serde_json::Value,
    output: &Path,
) -> DownloadResponseResult<(u16, serde_json::Value)> {
    let (service, action) =
        require_cli_input(split_service_action(service_action).map_err(anyhow::Error::msg));
    send_download_parts(ctx, &service, &action, inputs, output, None, &[]).await
}

async fn run_invoke_parts(
    ctx: &CliContext<'_>,
    service: &str,
    action: &str,
    inputs: serde_json::Value,
) -> Result<()> {
    run_invoke_parts_with_options(
        ctx,
        service,
        action,
        inputs,
        InvokeResponseOptions::default(),
    )
    .await
}

async fn run_invoke_parts_with_options(
    ctx: &CliContext<'_>,
    service: &str,
    action: &str,
    inputs: serde_json::Value,
    response_options: InvokeResponseOptions,
) -> Result<()> {
    let InvokeResponseOptions {
        options,
        rendered_body_owners,
        optional_rendered_body_owner_prefixes,
        action_spec,
    } = response_options;
    let reserved = if let Some(output) = ctx.output {
        let spec = match action_spec {
            Some(spec) => spec,
            None => {
                let catalog = fetch_runtime_catalog(ctx)
                    .await
                    .map_err(DeferredCliError::remote)?;
                catalog_action(&catalog, service, action)
                    .map_err(DeferredCliError::input)?
                    .clone()
            }
        };
        if !spec.supports_io() || !spec.supports_file_output() {
            return Err(DeferredCliError::input(
                "this client does not support the action's input and output kind",
            )
            .into());
        }
        if matches!(spec.io, ActionIo::RawDownload { .. }) {
            let (status, metadata) = send_download_parts(
                ctx,
                service,
                action,
                inputs,
                output,
                None,
                &spec.sensitive_output_pointers,
            )
            .await
            .map_err(DownloadResponseError::into_error)?;
            if status < 400 && output == Path::new("-") {
                std::process::exit(cli_exit_code_for_http_status(status));
            }
            print_value_and_exit(status, metadata);
        }
        output::ResponseOutput::prepare(ctx.output, &spec.sensitive_output_pointers)
            .map_err(DeferredCliError::input)?
    } else {
        None
    };
    let invoke_ctx = CliContext {
        settings: ctx.settings,
        output: None,
    };
    let response =
        send_invoke_parts_with_options(&invoke_ctx, service, action, inputs, options).await?;
    validate_embedded_invoke_result(
        &response.1,
        options.read_content_format,
        &rendered_body_owners,
        &optional_rendered_body_owner_prefixes,
    )
    .map_err(DeferredCliError::malformed)?;
    if options.response_format == ResponseFormat::Markdown {
        markdown_result_value(&response.1).map_err(DeferredCliError::malformed)?;
    }
    if let Some(receipt) = write_local_response(
        ctx,
        response.0,
        &response.1,
        options.response_format,
        reserved,
    )? {
        print_value_and_exit(response.0, receipt);
    }
    print_invoke_value_and_exit(response.0, response.1, options.response_format);
}

async fn send_invoke_parts_with_options(
    ctx: &CliContext<'_>,
    service: &str,
    action: &str,
    inputs: serde_json::Value,
    response_options: ResponseOptions,
) -> Result<(u16, serde_json::Value)> {
    if ctx.output.is_some() {
        output_action_spec(ctx, service, action)
            .await
            .unwrap_or_else(|error| exit_cli_input_error(error));
    }
    let resolved = ctx.settings;
    let path = format!("/v1/invoke/{service}/{action}");
    let endpoint = endpoint(&resolved.url, &path).map_err(DeferredCliError::input)?;
    let client = http_client(resolved).map_err(DeferredCliError::input)?;
    let response = request_builder(client.post(endpoint), resolved)
        .json(&InvokeRequest {
            inputs,
            read_content_format: response_options.read_content_format,
            response_format: response_options.response_format,
            body_parts: vec![],
        })
        .send()
        .await
        .map_err(|error| invocation_request_error(error, "broker request failed"))
        .map_err(DeferredCliError::remote)?;
    invocation_response_value(response).await
}

async fn send_download_parts(
    ctx: &CliContext<'_>,
    service: &str,
    action: &str,
    inputs: serde_json::Value,
    output: &Path,
    reserved: Option<output::AtomicOutput>,
    sensitive_outputs: &[String],
) -> DownloadResponseResult<(u16, serde_json::Value)> {
    let reserved = DownloadOutput::prepare(output, reserved)
        .map_err(DeferredCliError::input)
        .map_err(|error| DownloadResponseError::Local(error.into()))?;
    let resolved = ctx.settings;
    let path = format!("/v1/invoke/{service}/{action}");
    let endpoint = endpoint(&resolved.url, &path)
        .map_err(|error| DownloadResponseError::Local(DeferredCliError::input(error).into()))?;
    let client = streaming_http_client(resolved)
        .map_err(|error| DownloadResponseError::Local(DeferredCliError::input(error).into()))?;
    let response = tokio::time::timeout(
        resolved.request_timeout(),
        request_builder(client.post(endpoint), resolved)
            .header("Accept", "application/octet-stream")
            .json(&InvokeRequest {
                inputs,
                read_content_format: ReadContentFormat::Native,
                response_format: ResponseFormat::Json,
                body_parts: vec![],
            })
            .send(),
    )
    .await
    .map_err(|_| anyhow::anyhow!(INVOCATION_TIMEOUT_MESSAGE))
    .map_err(DownloadResponseError::Remote)?
    .map_err(|error| invocation_request_error(error, "broker request failed"))
    .map_err(DownloadResponseError::Remote)?;
    download_response_value(
        response,
        output,
        reserved,
        sensitive_outputs,
        RESULT_METADATA_HEADER,
    )
    .await
}

fn http_client(settings: &ResolvedCliSettings) -> Result<reqwest::Client> {
    let builder = reqwest::Client::builder().timeout(settings.request_timeout());
    build_http_client(builder, &settings.tls)
}

fn streaming_http_client(settings: &ResolvedCliSettings) -> Result<reqwest::Client> {
    build_http_client(reqwest::Client::builder(), &settings.tls)
}

fn build_http_client(
    builder: reqwest::ClientBuilder,
    tls: &CliTlsConfig,
) -> Result<reqwest::Client> {
    apply_broker_tls_config(builder, tls)?
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .context("failed to build HTTP client")
}

fn apply_broker_tls_config(
    mut builder: reqwest::ClientBuilder,
    tls: &CliTlsConfig,
) -> Result<reqwest::ClientBuilder> {
    if !tls.verify_certificates {
        return Ok(builder.danger_accept_invalid_certs(true));
    }
    for certificate in load_cli_tls_certificates(tls)? {
        builder = builder.add_root_certificate(certificate);
    }
    Ok(builder)
}

fn request_builder(
    mut builder: reqwest::RequestBuilder,
    settings: &ResolvedCliSettings,
) -> reqwest::RequestBuilder {
    builder = builder.header(REQUEST_ID_HEADER, Uuid::new_v4().to_string());
    if let Some(token) = &settings.token {
        let value = if settings.identity_scheme == "Bearer" {
            format!("Bearer {token}")
        } else {
            token.clone()
        };
        builder = builder.header(&settings.identity_header, value);
    }
    builder
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ResponseShape {
    Json,
    Array,
    Object,
    Envelope,
    ManagementObject,
}

fn print_value_and_exit(status: u16, value: serde_json::Value) -> ! {
    match serde_json::to_string_pretty(&value) {
        Ok(output) => println!("{output}"),
        Err(error) => {
            eprintln!("failed to format broker response: {error}");
            std::process::exit(5);
        }
    }
    exit_for_broker_status(status, &value);
}

/// Exits with the code for a broker HTTP status. A broker or upstream rate
/// limit first writes the broker's message as one stderr line, so the wait is
/// visible without parsing stdout. Nothing is retried.
fn exit_for_broker_status(status: u16, value: &serde_json::Value) -> ! {
    if let Some(notice) = rate_limit_notice(status, value) {
        eprintln!("{notice}");
    }
    std::process::exit(cli_exit_code_for_http_status(status));
}

/// The stderr line for a `rate_limited` or `upstream_rate_limited` error: the
/// broker's message collapsed onto one line. Whitespace and control
/// characters separate words; Unicode format characters (general category
/// Cf: bidirectional overrides and isolates, zero-width characters, and the
/// like) are dropped, so upstream text cannot reorder or hide the line.
fn rate_limit_notice(status: u16, value: &serde_json::Value) -> Option<String> {
    let message = rate_limit_message(status, value)?
        .split(|character: char| character.is_whitespace() || character.is_control())
        .map(|word| {
            word.chars()
                .filter(|character| !is_unicode_format_character(*character))
                .collect::<String>()
        })
        .filter(|word| !word.is_empty())
        .collect::<Vec<_>>()
        .join(" ");
    Some(format!("rate limited: {message}"))
}

fn is_unicode_format_character(character: char) -> bool {
    unicode_general_category::get_general_category(character)
        == unicode_general_category::GeneralCategory::Format
}

/// The broker's message for a `rate_limited` or `upstream_rate_limited` error
/// response. The broker builds it complete, naming the service and the wait,
/// so clients surface it rather than rebuilding it from `result`. Falls back
/// to the reason code when a response carries no message.
pub(crate) fn rate_limit_message(status: u16, value: &serde_json::Value) -> Option<&str> {
    if status < 400 {
        return None;
    }
    let reason_code = value
        .get("reasonCode")
        .and_then(serde_json::Value::as_str)?;
    if !matches!(reason_code, "rate_limited" | "upstream_rate_limited") {
        return None;
    }
    let message = ["/error/message", "/reason", "/message"]
        .into_iter()
        .filter_map(|pointer| value.pointer(pointer).and_then(serde_json::Value::as_str))
        .find(|message| !message.trim().is_empty());
    Some(message.unwrap_or(reason_code))
}

fn print_invoke_value_and_exit(
    status: u16,
    value: serde_json::Value,
    response_format: ResponseFormat,
) -> ! {
    if status >= 400 && is_mutation_verification_failure(&value) {
        match serde_json::to_string_pretty(&value) {
            Ok(output) => eprintln!("{output}"),
            Err(error) => {
                eprintln!("failed to format broker response: {error}");
                std::process::exit(5);
            }
        }
        exit_for_broker_status(status, &value);
    }
    if response_format == ResponseFormat::Markdown {
        match markdown_result_value(&value) {
            Ok(Some(markdown)) => {
                let mut stdout = std::io::stdout().lock();
                if let Err(error) = stdout
                    .write_all(markdown.as_bytes())
                    .and_then(|()| stdout.flush())
                {
                    exit_malformed_broker_response(format!(
                        "failed to write formatted broker response: {error}"
                    ));
                }
            }
            Ok(None) => match serde_json::to_string_pretty(&value) {
                Ok(output) => println!("{output}"),
                Err(error) => exit_malformed_broker_response(format!(
                    "failed to format broker response: {error}"
                )),
            },
            Err(error) => exit_malformed_broker_response(error.to_string()),
        }
        exit_for_broker_status(status, &value);
    }
    print_value_and_exit(status, value);
}

fn is_mutation_verification_failure(value: &serde_json::Value) -> bool {
    value.get("reasonCode").and_then(serde_json::Value::as_str)
        == Some("mutation_verification_failed")
        && value.get("decision").and_then(serde_json::Value::as_str) == Some("error")
}

fn markdown_result_value(value: &serde_json::Value) -> Result<Option<&str>> {
    let Some(object) = value.as_object() else {
        anyhow::bail!("unexpected JSON shape");
    };
    if object.get("decision").and_then(serde_json::Value::as_str) != Some("allow") {
        return Ok(None);
    }
    let result = object
        .get("result")
        .and_then(serde_json::Value::as_object)
        .ok_or_else(|| anyhow::anyhow!("formatted allow response is missing result"))?;
    if result.get("format").and_then(serde_json::Value::as_str) != Some("markdown") {
        anyhow::bail!("formatted allow response has an invalid result format");
    }
    result
        .get("value")
        .and_then(serde_json::Value::as_str)
        .map(Some)
        .ok_or_else(|| anyhow::anyhow!("formatted allow response is missing result.value"))
}

/// Checks the `renderedBody` companions of a normalized allow result at the
/// owners the runtime catalog declares for the action: each owner must be
/// present and an object unless its path has an explicitly optional missing
/// field. A companion must be an object carrying the
/// requested format and a string value. The rest of the result, including
/// the preserved native bodies, is upstream content and is not inspected.
fn validate_embedded_invoke_result(
    envelope: &serde_json::Value,
    format: ReadContentFormat,
    rendered_body_owners: &[String],
    optional_rendered_body_owner_prefixes: &[String],
) -> Result<()> {
    if format == ReadContentFormat::Native {
        return Ok(());
    }
    let object = envelope
        .as_object()
        .ok_or_else(|| anyhow::anyhow!("unexpected JSON shape"))?;
    if object.get("decision").and_then(serde_json::Value::as_str) != Some("allow") {
        return Ok(());
    }
    for pointer in rendered_body_owners {
        let segments = pointer
            .strip_prefix('/')
            .ok_or_else(|| anyhow::anyhow!("invalid renderedBody owner pointer {pointer:?}"))?
            .split('/')
            .collect::<Vec<_>>();
        validate_rendered_body_owners(
            envelope,
            &segments,
            "",
            optional_rendered_body_owner_prefixes,
            format,
        )?;
    }
    Ok(())
}

fn validate_rendered_body_owners(
    value: &serde_json::Value,
    segments: &[&str],
    pointer: &str,
    optional_prefixes: &[String],
    format: ReadContentFormat,
) -> Result<()> {
    let Some((segment, rest)) = segments.split_first() else {
        return validate_rendered_body_owner(value, format);
    };
    let child_pointer = format!("{pointer}/{segment}");
    if *segment == "*" {
        let items = value
            .as_array()
            .ok_or_else(|| anyhow::anyhow!("normalized result body collection is not an array"))?;
        return items.iter().try_for_each(|item| {
            validate_rendered_body_owners(item, rest, &child_pointer, optional_prefixes, format)
        });
    }
    let field = segment.replace("~1", "/").replace("~0", "~");
    let object = value
        .as_object()
        .ok_or_else(|| anyhow::anyhow!("normalized result body owner parent is not an object"))?;
    let Some(child) = object.get(&field) else {
        if optional_prefixes.contains(&child_pointer) {
            return Ok(());
        }
        anyhow::bail!("normalized result is missing body owner field {field}");
    };
    validate_rendered_body_owners(child, rest, &child_pointer, optional_prefixes, format)
}

fn validate_rendered_body_owner(
    owner: &serde_json::Value,
    format: ReadContentFormat,
) -> Result<()> {
    let owner = owner
        .as_object()
        .ok_or_else(|| anyhow::anyhow!("normalized result body owner is not an object"))?;
    let Some(rendered) = owner.get("renderedBody") else {
        return Ok(());
    };
    let rendered = rendered.as_object().ok_or_else(|| {
        anyhow::anyhow!("normalized result has a renderedBody that is not an object")
    })?;
    if rendered.get("format").and_then(serde_json::Value::as_str) != Some(format.as_str()) {
        anyhow::bail!("normalized result has an invalid renderedBody format");
    }
    if !rendered
        .get("value")
        .is_some_and(serde_json::Value::is_string)
    {
        anyhow::bail!("normalized result is missing renderedBody.value");
    }
    Ok(())
}

// Redirect locations can contain credentials or other private material. Report
// only the status and require callers to configure the final broker URL.
fn reject_broker_redirect(response: &reqwest::Response) -> Result<()> {
    if response.status().is_redirection() {
        return Err(DeferredCliError::remote(format!(
            "broker returned HTTP {}; redirects are disabled; configure the final broker URL",
            response.status().as_u16()
        ))
        .into());
    }
    Ok(())
}

fn invocation_request_error(error: reqwest::Error, fallback: &'static str) -> anyhow::Error {
    if error.is_timeout() {
        anyhow::anyhow!(INVOCATION_TIMEOUT_MESSAGE)
    } else {
        anyhow::Error::new(error).context(fallback)
    }
}

async fn invocation_response_value(
    response: reqwest::Response,
) -> Result<(u16, serde_json::Value)> {
    response_value_with_timeout_message(
        response,
        ResponseShape::Envelope,
        INVOCATION_TIMEOUT_MESSAGE,
    )
    .await
}

async fn response_value(
    response: reqwest::Response,
    shape: ResponseShape,
) -> Result<(u16, serde_json::Value)> {
    response_value_with_timeout_message(response, shape, "failed to read broker response").await
}

async fn response_value_with_timeout_message(
    response: reqwest::Response,
    shape: ResponseShape,
    timeout_message: &'static str,
) -> Result<(u16, serde_json::Value)> {
    reject_broker_redirect(&response)?;
    let status = response.status().as_u16();
    let body = response
        .text()
        .await
        .map_err(|error| {
            if error.is_timeout() {
                anyhow::anyhow!(timeout_message)
            } else {
                anyhow::Error::new(error).context("failed to read broker response")
            }
        })
        .map_err(DeferredCliError::remote)?;
    let value =
        serde_json::from_str::<serde_json::Value>(&body).map_err(DeferredCliError::malformed)?;
    if !response_shape_valid(status, shape, &value) {
        return Err(DeferredCliError::malformed("unexpected JSON shape").into());
    }
    Ok((status, value))
}

async fn download_response_value(
    mut response: reqwest::Response,
    output: &Path,
    reserved: DownloadOutput,
    sensitive_outputs: &[String],
    metadata_header: &str,
) -> DownloadResponseResult<(u16, serde_json::Value)> {
    reject_broker_redirect(&response).map_err(DownloadResponseError::Remote)?;
    let status = response.status().as_u16();
    if status >= 400 {
        let (status, value) = response_value(response, ResponseShape::Envelope)
            .await
            .map_err(DownloadResponseError::Remote)?;
        return Ok((status, value));
    }
    let metadata_header = response
        .headers()
        .get(metadata_header)
        .and_then(|value| value.to_str().ok())
        .map(ToString::to_string);
    let metadata = parse_download_metadata_header(metadata_header.as_deref()).map_err(|error| {
        DownloadResponseError::Remote(DeferredCliError::malformed(error).into())
    })?;
    if !response_shape_valid(status, ResponseShape::Envelope, &metadata) {
        return Err(DownloadResponseError::Remote(
            DeferredCliError::malformed("unexpected JSON metadata shape").into(),
        ));
    }
    if metadata.get("decision").and_then(serde_json::Value::as_str) != Some("allow") {
        return Err(DownloadResponseError::Remote(
            DeferredCliError::malformed("download metadata does not authorize a download").into(),
        ));
    }
    let content_type = response
        .headers()
        .get(reqwest::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("application/octet-stream")
        .to_owned();
    let summary = write_download_body(
        &mut response,
        output,
        &metadata,
        reserved,
        sensitive_outputs,
    )
    .await?;
    let saved = output::FileOutput::new(
        output,
        summary.size,
        summary.sha256,
        &content_type,
        !sensitive_outputs.is_empty(),
    );
    Ok((
        status,
        output::receipt(&metadata, &saved, true, sensitive_outputs),
    ))
}

type DownloadResponseResult<T> = std::result::Result<T, DownloadResponseError>;

#[derive(Debug)]
enum DownloadResponseError {
    Remote(anyhow::Error),
    Local(anyhow::Error),
}

impl DownloadResponseError {
    fn into_error(self) -> anyhow::Error {
        match self {
            Self::Remote(error) if !error.is::<output::LocalOutputFailure>() => {
                DeferredCliError::remote(error).into()
            }
            Self::Remote(error) | Self::Local(error) => error,
        }
    }

    fn with_outcome(
        self,
        metadata: &serde_json::Value,
        path: &Path,
        sensitive_outputs: &[String],
        verified: bool,
    ) -> Self {
        if !verified && !output::has_mutation_outcome(metadata) {
            return self;
        }
        match self {
            Self::Remote(error) => Self::Remote(
                output::LocalOutputFailure::download(
                    metadata,
                    path,
                    error,
                    sensitive_outputs,
                    true,
                )
                .into(),
            ),
            Self::Local(error) => Self::Local(
                output::LocalOutputFailure::download(
                    metadata,
                    path,
                    error,
                    sensitive_outputs,
                    false,
                )
                .into(),
            ),
        }
    }
}

impl std::fmt::Display for DownloadResponseError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Remote(error) | Self::Local(error) => write!(formatter, "{error:#}"),
        }
    }
}

#[derive(Debug, Clone)]
struct DownloadExpectations {
    size: Option<u64>,
    sha256: Option<String>,
}

#[derive(Debug, Clone)]
struct DownloadWriteSummary {
    size: u64,
    sha256: String,
}

/// Reserve all local resources before dispatch, including the verified stdout spool.
enum DownloadOutput {
    File(output::AtomicOutput),
    Stdout(tempfile::NamedTempFile),
}

impl DownloadOutput {
    fn prepare(path: &Path, reserved: Option<output::AtomicOutput>) -> Result<Self> {
        if path == Path::new("-") {
            return Ok(Self::Stdout(
                tempfile::NamedTempFile::new()
                    .context("failed to create temporary download file for stdout")?,
            ));
        }
        Ok(Self::File(match reserved {
            Some(file) => file,
            None => output::AtomicOutput::new(path)?,
        }))
    }

    fn finish(self) -> Result<()> {
        match self {
            Self::File(file) => file.commit(),
            Self::Stdout(mut file) => {
                file.as_file_mut()
                    .seek(SeekFrom::Start(0))
                    .context("failed to read temporary download file for stdout")?;
                let mut stdout = std::io::stdout().lock();
                std::io::copy(file.as_file_mut(), &mut stdout)
                    .context("failed to write download bytes to stdout")?;
                stdout
                    .flush()
                    .context("failed to flush download bytes to stdout")
            }
        }
    }
}

impl Write for DownloadOutput {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        match self {
            Self::File(file) => file.write(bytes),
            Self::Stdout(file) => file.write(bytes),
        }
    }

    fn flush(&mut self) -> std::io::Result<()> {
        match self {
            Self::File(file) => file.flush(),
            Self::Stdout(file) => file.flush(),
        }
    }
}

async fn write_download_body(
    response: &mut reqwest::Response,
    output: &Path,
    metadata: &serde_json::Value,
    mut reserved: DownloadOutput,
    sensitive_outputs: &[String],
) -> DownloadResponseResult<DownloadWriteSummary> {
    let summary = receive_download_body(response, metadata, &mut reserved)
        .await
        .map_err(|error| error.with_outcome(metadata, output, sensitive_outputs, false))?;
    reserved.finish().map_err(|error| {
        DownloadResponseError::Local(error).with_outcome(metadata, output, sensitive_outputs, true)
    })?;
    Ok(summary)
}

async fn receive_download_body(
    response: &mut reqwest::Response,
    metadata: &serde_json::Value,
    output: &mut impl Write,
) -> DownloadResponseResult<DownloadWriteSummary> {
    let expectations = download_expectations(metadata).map_err(DownloadResponseError::Remote)?;
    let mut digest = Sha256::new();
    let mut size = 0_u64;
    while let Some(chunk) = next_download_chunk(response)
        .await
        .map_err(DownloadResponseError::Remote)?
    {
        size = next_download_size(size, chunk.len(), expectations.size)
            .map_err(DownloadResponseError::Remote)?;
        digest.update(&chunk);
        output
            .write_all(&chunk)
            .context("failed to write download output")
            .map_err(DownloadResponseError::Local)?;
    }
    let summary = DownloadWriteSummary {
        size,
        sha256: finalize_sha256(digest),
    };
    verify_download_summary(&summary, &expectations).map_err(DownloadResponseError::Remote)?;
    Ok(summary)
}

async fn next_download_chunk(response: &mut reqwest::Response) -> Result<Option<bytes::Bytes>> {
    tokio::time::timeout(CLI_STREAMING_IDLE_TIMEOUT, response.chunk())
        .await
        .context("broker download stream stalled")?
        .context("failed to read broker download bytes")
}

fn download_expectations(metadata: &serde_json::Value) -> Result<DownloadExpectations> {
    let result = metadata
        .get("result")
        .and_then(serde_json::Value::as_object)
        .context("download metadata result is missing")?;
    let size = result
        .get("size")
        .filter(|value| !value.is_null())
        .map(|value| {
            value
                .as_u64()
                .context("download metadata size must be an unsigned integer")
        });
    let sha256 = result.get("sha256").map(|value| {
        let sha256 = value
            .as_str()
            .context("download metadata sha256 must be a string")?;
        if sha256.len() != 64 || !sha256.chars().all(|ch| ch.is_ascii_hexdigit()) {
            anyhow::bail!("download metadata sha256 is invalid");
        }
        Ok::<String, anyhow::Error>(sha256.to_ascii_lowercase())
    });
    Ok(DownloadExpectations {
        size: size.transpose()?,
        sha256: sha256.transpose()?,
    })
}

fn next_download_size(current: u64, chunk_len: usize, expected_size: Option<u64>) -> Result<u64> {
    let next = current
        .checked_add(chunk_len as u64)
        .context("download size overflowed")?;
    if let Some(expected_size) = expected_size
        && next > expected_size
    {
        anyhow::bail!(
            "download size mismatch: expected {expected_size} bytes, received more than {expected_size} bytes"
        );
    }
    Ok(next)
}

fn verify_download_summary(
    summary: &DownloadWriteSummary,
    expectations: &DownloadExpectations,
) -> Result<()> {
    if let Some(expected_size) = expectations.size
        && summary.size != expected_size
    {
        anyhow::bail!(
            "download size mismatch: expected {} bytes, received {} bytes",
            expected_size,
            summary.size
        );
    }
    if let Some(expected_sha256) = &expectations.sha256
        && &summary.sha256 != expected_sha256
    {
        anyhow::bail!("download sha256 mismatch");
    }
    Ok(())
}

fn finalize_sha256(digest: Sha256) -> String {
    digest
        .finalize()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn parse_download_metadata_header(header: Option<&str>) -> Result<serde_json::Value, String> {
    let header = header.ok_or_else(|| "download metadata is missing".to_string())?;
    if header.len() > 16_384 {
        return Err("download metadata exceeds the header limit".into());
    }
    let metadata_bytes = BASE64
        .decode(header)
        .map_err(|error| format!("download metadata is invalid: {error}"))?;
    serde_json::from_slice::<serde_json::Value>(&metadata_bytes)
        .map_err(|error| format!("download metadata is not JSON: {error}"))
}

fn response_shape_valid(status: u16, shape: ResponseShape, value: &serde_json::Value) -> bool {
    if status >= 400 {
        return match shape {
            ResponseShape::ManagementObject => management_envelope_shape_valid(value),
            ResponseShape::Object => {
                value.is_object()
                    && (envelope_shape_valid(value) || management_envelope_shape_valid(value))
            }
            _ => envelope_shape_valid(value),
        };
    }
    match shape {
        ResponseShape::Json => true,
        ResponseShape::Array => value.is_array(),
        ResponseShape::Object => value.is_object(),
        ResponseShape::Envelope => envelope_shape_valid(value),
        ResponseShape::ManagementObject => management_envelope_shape_valid(value),
    }
}

fn envelope_shape_valid(value: &serde_json::Value) -> bool {
    value.as_object().is_some_and(|object| {
        object.contains_key("agentRequestId")
            && object.contains_key("brokerRequestId")
            && object.contains_key("decision")
    })
}

fn management_envelope_shape_valid(value: &serde_json::Value) -> bool {
    value.as_object().is_some_and(|object| {
        object.contains_key("requestId")
            && object.contains_key("brokerRequestId")
            && object.contains_key("decision")
    })
}

fn exit_network_error(error: anyhow::Error) -> ! {
    eprintln!("{error}");
    std::process::exit(5);
}

fn exit_malformed_broker_response(message: String) -> ! {
    eprintln!("malformed broker response: {message}");
    std::process::exit(5);
}

fn exit_cli_input_error(error: anyhow::Error) -> ! {
    eprintln!("{error:#}");
    std::process::exit(3);
}

fn require_cli_input<T>(result: Result<T>) -> T {
    match result {
        Ok(value) => value,
        Err(error) => exit_cli_input_error(error),
    }
}

#[derive(Debug)]
struct ResolvedCliSettings {
    url: String,
    request_timeout_ms: u64,
    tls: CliTlsConfig,
    token: Option<String>,
    token_from_literal_arg: bool,
    identity_header: String,
    identity_scheme: String,
    allow_insecure_broker_http: bool,
    read_content_format: ReadContentFormat,
    output_format: ResponseFormat,
}

impl ResolvedCliSettings {
    fn request_timeout(&self) -> Duration {
        Duration::from_millis(self.request_timeout_ms)
    }
}

fn resolve_cli_settings(cli: &Cli, config_path: &PathBuf) -> Result<ResolvedCliSettings> {
    let explicit_config = cli.config.is_some();
    let config_exists = config_path.exists();
    let config = load_config_or_default(config_path, explicit_config)?;

    let url = cli
        .url
        .clone()
        .or_else(|| config_exists.then_some(config.service.url.clone()))
        .or_else(|| env::var("AGENT_ACCESS_URL").ok())
        .unwrap_or_else(|| "http://127.0.0.1:8787".to_string());
    let tls = if config_exists {
        config.service.tls.clone()
    } else {
        CliTlsConfig::default()
    };

    let identity_header = cli
        .identity_header
        .clone()
        .or_else(|| config_exists.then_some(config.identity.header.clone()))
        .or_else(|| env::var("AGENT_ACCESS_IDENTITY_HEADER").ok())
        .unwrap_or_else(|| "X-Agent-Access-Identity-Token".to_string());
    let identity_scheme = cli
        .identity_scheme
        .clone()
        .or_else(|| config_exists.then_some(config.identity.scheme.clone()))
        .or_else(|| env::var("AGENT_ACCESS_IDENTITY_SCHEME").ok())
        .unwrap_or_else(|| "raw".to_string());
    let token_resolution = resolve_identity_token_report(cli, config_exists, &config);
    let token_from_literal_arg = token_resolution.source_label == "--token-value";
    if let Some(error) = token_resolution.error {
        anyhow::bail!("{error}");
    }
    let token = token_resolution.token;

    let allow_insecure_broker_http = cli.allow_insecure_broker_http
        || env::var("AGENT_ACCESS_ALLOW_INSECURE_BROKER_HTTP")
            .map(|value| value.eq_ignore_ascii_case("true"))
            .unwrap_or(false);

    let read_content_format = resolve_read_content_format_default(
        config_path,
        config_exists,
        config.defaults.read_content_format,
    )?;
    let output_format =
        resolve_output_format_default(config_path, config_exists, config.defaults.output_format)?;

    let resolved = ResolvedCliSettings {
        url,
        request_timeout_ms: config.service.request_timeout_ms,
        tls,
        token,
        token_from_literal_arg,
        identity_header,
        identity_scheme,
        allow_insecure_broker_http,
        read_content_format,
        output_format,
    };
    validate_cli_config(&CliConfig {
        service: agent_access_core::CliServiceConfig {
            url: resolved.url.clone(),
            request_timeout_ms: resolved.request_timeout_ms,
            tls: resolved.tls.clone(),
        },
        identity: agent_access_core::CliIdentityConfig {
            token_env: None,
            token_file: None,
            header: resolved.identity_header.clone(),
            scheme: resolved.identity_scheme.clone(),
            disabled: resolved.token.is_none() || resolved.allow_insecure_broker_http,
        },
        defaults: agent_access_core::CliDefaultsConfig {
            read_content_format: resolved.read_content_format,
            output_format: resolved.output_format,
        },
    })?;
    Ok(resolved)
}

fn resolve_read_content_format_default(
    config_path: &Path,
    config_exists: bool,
    config_value: ReadContentFormat,
) -> Result<ReadContentFormat> {
    if config_exists && cli_default_key_is_present(config_path, "read_content_format")? {
        return Ok(config_value);
    }
    match env::var("AGENT_ACCESS_READ_CONTENT_FORMAT") {
        Ok(value) => parse_read_content_format(&value, "AGENT_ACCESS_READ_CONTENT_FORMAT"),
        Err(env::VarError::NotPresent) => Ok(ReadContentFormat::Native),
        Err(error) => Err(anyhow::anyhow!(
            "failed to read AGENT_ACCESS_READ_CONTENT_FORMAT: {error}"
        )),
    }
}

fn resolve_output_format_default(
    config_path: &Path,
    config_exists: bool,
    config_value: ResponseFormat,
) -> Result<ResponseFormat> {
    if config_exists && cli_default_key_is_present(config_path, "output_format")? {
        return Ok(config_value);
    }
    match env::var("AGENT_ACCESS_OUTPUT_FORMAT") {
        Ok(value) => parse_output_format(&value, "AGENT_ACCESS_OUTPUT_FORMAT"),
        Err(env::VarError::NotPresent) => Ok(ResponseFormat::Json),
        Err(error) => Err(anyhow::anyhow!(
            "failed to read AGENT_ACCESS_OUTPUT_FORMAT: {error}"
        )),
    }
}

fn parse_read_content_format(value: &str, source: &str) -> Result<ReadContentFormat> {
    match value {
        "native" => Ok(ReadContentFormat::Native),
        "markdown" => Ok(ReadContentFormat::Markdown),
        "text" => Ok(ReadContentFormat::Text),
        _ => anyhow::bail!("{source} must be one of native, markdown, or text"),
    }
}

fn parse_output_format(value: &str, source: &str) -> Result<ResponseFormat> {
    match value {
        "json" => Ok(ResponseFormat::Json),
        "markdown" => Ok(ResponseFormat::Markdown),
        _ => anyhow::bail!("{source} must be one of json or markdown"),
    }
}

fn cli_default_key_is_present(path: &Path, key: &str) -> Result<bool> {
    let raw = fs::read_to_string(path)
        .with_context(|| format!("failed to read CLI config {}", path.display()))?;
    let document = toml::from_str::<toml::Value>(&raw)
        .with_context(|| format!("failed to parse CLI config {}", path.display()))?;
    Ok(document
        .get("defaults")
        .and_then(toml::Value::as_table)
        .is_some_and(|defaults| defaults.contains_key(key)))
}

fn load_config_or_default(path: &PathBuf, explicit: bool) -> Result<CliConfig> {
    if path.exists() {
        return Ok(load_cli_config(path)?);
    }
    if explicit {
        anyhow::bail!("config file does not exist: {}", path.display());
    }
    Ok(CliConfig::default())
}

fn read_token_file(path: &std::path::Path) -> Result<String> {
    Ok(std::fs::read_to_string(path)
        .with_context(|| format!("failed to read token file {}", path.display()))?
        .trim()
        .to_string())
}

#[derive(Debug)]
struct IdentityTokenResolution {
    token: Option<String>,
    source_label: String,
    status: &'static str,
    error: Option<String>,
}

fn identity_resolution_disabled(cli: &Cli, config_exists: bool, config: &CliConfig) -> bool {
    cli.no_token
        || (config_exists && config.identity.disabled)
        || env::var("AGENT_ACCESS_NO_TOKEN")
            .map(|value| value.eq_ignore_ascii_case("true"))
            .unwrap_or(false)
}

fn resolve_identity_token_report(
    cli: &Cli,
    config_exists: bool,
    config: &CliConfig,
) -> IdentityTokenResolution {
    if identity_resolution_disabled(cli, config_exists, config) {
        return token_disabled();
    }
    if let Some(token) = &cli.token_value {
        return strict_literal_token("--token-value", token);
    }
    if let Some(file) = &cli.token_file {
        return strict_token_file("--token-file", file);
    }
    if let Some(name) = &cli.token_env {
        return strict_token_env("--token-env", name);
    }
    if let (true, Some(file)) = (config_exists, config.identity.token_file.as_ref()) {
        match optional_config_token_file(file) {
            OptionalTokenFile::Present(token) => {
                return token_present("config identity.token_file", token);
            }
            OptionalTokenFile::Absent => {}
            OptionalTokenFile::Error(error) => {
                return token_error("config identity.token_file", error);
            }
        }
    }
    if let (true, Some(name)) = (config_exists, config.identity.token_env.as_ref())
        && let Some(token) = optional_env_token(name)
    {
        return token_present(format!("config identity.token_env {name}"), token);
    }
    if let Some(token) = optional_env_token("AGENT_ACCESS_TOKEN") {
        return token_present("AGENT_ACCESS_TOKEN", token);
    }
    if let Ok(file) = env::var("AGENT_ACCESS_TOKEN_FILE") {
        return strict_token_file("AGENT_ACCESS_TOKEN_FILE", Path::new(&file));
    }
    if let Ok(name) = env::var("AGENT_ACCESS_TOKEN_ENV")
        && let Some(token) = optional_env_token(&name)
    {
        return token_present(format!("AGENT_ACCESS_TOKEN_ENV {name}"), token);
    }
    token_absent()
}

enum OptionalTokenFile {
    Present(String),
    Absent,
    Error(String),
}

fn optional_config_token_file(path: &str) -> OptionalTokenFile {
    let path = match expand_current_user_home(path, "config identity.token_file") {
        Ok(path) => path,
        Err(error) => return OptionalTokenFile::Error(error.to_string()),
    };
    match fs::read_to_string(&path) {
        Ok(value) => {
            let token = value.trim().to_string();
            if token.is_empty() {
                OptionalTokenFile::Absent
            } else {
                OptionalTokenFile::Present(token)
            }
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => OptionalTokenFile::Absent,
        Err(error) => OptionalTokenFile::Error(format!(
            "failed to read token file {}: {error}",
            path.display()
        )),
    }
}

fn strict_literal_token(label: impl Into<String>, token: &str) -> IdentityTokenResolution {
    let label = label.into();
    if token.trim().is_empty() {
        return token_error(label, "token value must not be empty".to_string());
    }
    token_present(label, token.to_string())
}

fn strict_token_file(label: impl Into<String>, path: &Path) -> IdentityTokenResolution {
    let label = label.into();
    let path = match expand_current_user_home(path, label.as_str()) {
        Ok(path) => path,
        Err(error) => return token_error(label, error.to_string()),
    };
    match fs::read_to_string(&path) {
        Ok(value) => {
            let token = value.trim().to_string();
            if token.is_empty() {
                token_error(label, format!("token file {} is empty", path.display()))
            } else {
                token_present(label, token)
            }
        }
        Err(error) => token_error(
            label,
            format!("failed to read token file {}: {error}", path.display()),
        ),
    }
}

fn strict_token_env(label: impl Into<String>, name: &str) -> IdentityTokenResolution {
    let label = label.into();
    match env::var(name) {
        Ok(token) if token.trim().is_empty() => {
            token_error(label, format!("environment variable {name} is empty"))
        }
        Ok(token) => token_present(label, token),
        Err(_) => token_error(label, format!("environment variable {name} is not set")),
    }
}

fn optional_env_token(name: &str) -> Option<String> {
    env::var(name).ok().filter(|token| !token.trim().is_empty())
}

fn token_present(label: impl Into<String>, token: String) -> IdentityTokenResolution {
    IdentityTokenResolution {
        token: Some(token),
        source_label: label.into(),
        status: "present",
        error: None,
    }
}

fn token_absent() -> IdentityTokenResolution {
    IdentityTokenResolution {
        token: None,
        source_label: "none".to_string(),
        status: "absent",
        error: None,
    }
}

fn token_disabled() -> IdentityTokenResolution {
    IdentityTokenResolution {
        token: None,
        source_label: "disabled".to_string(),
        status: "disabled",
        error: None,
    }
}

fn token_error(label: impl Into<String>, error: String) -> IdentityTokenResolution {
    IdentityTokenResolution {
        token: None,
        source_label: label.into(),
        status: "error",
        error: Some(error),
    }
}

fn read_password_input(
    password_env: &Option<String>,
    password_file: &Option<PathBuf>,
    password_stdin: bool,
) -> Result<String> {
    let sources = usize::from(password_env.is_some())
        + usize::from(password_file.is_some())
        + usize::from(password_stdin);
    if sources > 1 {
        anyhow::bail!(
            "password input requires at most one of --password-env, --password-file, or --password-stdin"
        );
    }
    let password = if let Some(name) = password_env {
        env::var(name).with_context(|| format!("failed to read password from env {name}"))?
    } else if let Some(path) = password_file {
        read_token_file(path)?
    } else if password_stdin {
        let mut value = String::new();
        std::io::stdin()
            .read_to_string(&mut value)
            .context("failed to read password from stdin")?;
        value.trim().to_string()
    } else {
        let first = rpassword::prompt_password("Password: ")
            .context("failed to read password from interactive prompt")?;
        let confirmation = rpassword::prompt_password("Confirm password: ")
            .context("failed to read password confirmation from interactive prompt")?;
        if first != confirmation {
            anyhow::bail!("password confirmation did not match");
        }
        first
    };
    if password.is_empty() {
        anyhow::bail!("password must not be empty");
    }
    Ok(password)
}

fn validate_transport(settings: &ResolvedCliSettings) -> Result<()> {
    let url = Url::parse(&settings.url).context("broker URL must be valid")?;
    if url.scheme() == "http" && !is_loopback_or_localhost(url.host()) && settings.token.is_some() {
        if env::var("AGENT_ACCESS_ENVIRONMENT")
            .map(|value| value == "production")
            .unwrap_or(false)
        {
            anyhow::bail!("insecure broker HTTP override is rejected in production");
        }
        if !settings.allow_insecure_broker_http {
            anyhow::bail!(
                "refusing to send identity material over non-local HTTP broker URL; use --allow-insecure-broker-http for development"
            );
        }
        eprintln!("warning: sending identity material over non-local HTTP broker URL");
    }
    Ok(())
}

fn validate_service_argument(service: &str) -> Result<()> {
    if is_service_name(service) {
        Ok(())
    } else {
        anyhow::bail!("service name is invalid")
    }
}

fn endpoint(base: &str, path: &str) -> Result<String> {
    let base = base.trim_end_matches('/');
    Ok(format!("{base}{path}"))
}

fn exit_config_error(error: ConfigError) -> Result<()> {
    eprintln!("{error}");
    for item in error.errors() {
        eprintln!("- {item}");
    }
    std::process::exit(3);
}

fn default_config_path() -> PathBuf {
    if let Some(path) = env::var_os("AGENT_ACCESS_CONFIG") {
        return PathBuf::from(path);
    }
    if let Some(config_home) = env::var_os("XDG_CONFIG_HOME") {
        return PathBuf::from(config_home).join("agent-access/config.toml");
    }
    if let Some(home) = env::var_os("HOME") {
        return PathBuf::from(home).join(".config/agent-access/config.toml");
    }
    PathBuf::from("agent-access.toml")
}

#[cfg(test)]
mod tests {
    /// The CLI's view of an input schema the broker built.
    fn cli_input_schema(
        schema: agent_access_core::CredentialInputSchema,
    ) -> super::CredentialInputSchema {
        super::CredentialInputSchema {
            profile: schema.profile,
            credential_kind: schema.credential_kind,
            fields: schema.fields,
            input_policy: schema.input_policy,
        }
    }

    #[test]
    fn identity_administration_cli_requires_explicit_versions_and_removes_token_pause() {
        for arguments in [
            vec!["identity-access", "inspect", "alice"],
            vec![
                "identity-access",
                "pause",
                "alice",
                "--expected-version",
                "1",
            ],
            vec![
                "identity-access",
                "resume",
                "alice",
                "--expected-version",
                "2",
            ],
            vec!["identity-bindings", "list", "alice"],
            vec![
                "identity-bindings",
                "create",
                "alice",
                "--namespace",
                "managed_linux",
                "--username",
                "Alice+team@example.test",
            ],
            vec![
                "identity-bindings",
                "create",
                "alice",
                "--namespace",
                "managed_linux",
                "--username",
                "alice",
                "--read-only",
            ],
            vec![
                "identity-bindings",
                "update",
                "alice",
                "binding",
                "--enabled",
                "false",
                "--expected-version",
                "1",
            ],
            vec![
                "identity-bindings",
                "update",
                "alice",
                "binding",
                "--read-only",
                "true",
                "--expected-version",
                "2",
            ],
            vec![
                "identity-bindings",
                "delete",
                "alice",
                "binding",
                "--expected-version",
                "3",
            ],
            vec![
                "identity-token",
                "update",
                "alice",
                "--enabled",
                "true",
                "--read-only",
                "false",
                "--expected-revision",
                "4",
            ],
        ] {
            super::Cli::try_parse_from(
                ["agent-access", "admin", "principals"]
                    .into_iter()
                    .chain(arguments),
            )
            .unwrap();
        }
        for arguments in [
            vec!["identity-token", "pause", "alice"],
            vec!["identity-token", "resume", "alice"],
            vec!["identity-access", "pause", "alice"],
            vec![
                "identity-access",
                "resume",
                "alice",
                "--expected-version",
                "0",
            ],
            vec!["identity-bindings", "delete", "alice", "binding"],
            // The update command replaced enable and disable outright.
            vec![
                "identity-bindings",
                "enable",
                "alice",
                "binding",
                "--expected-version",
                "1",
            ],
            vec![
                "identity-bindings",
                "disable",
                "alice",
                "binding",
                "--expected-version",
                "1",
            ],
            vec![
                "identity-bindings",
                "update",
                "alice",
                "binding",
                "--enabled",
                "true",
                "--expected-version",
                "0",
            ],
            vec![
                "identity-bindings",
                "update",
                "alice",
                "binding",
                "--read-only",
                "true",
            ],
            vec![
                "identity-bindings",
                "update",
                "alice",
                "binding",
                "--read-only",
                "yes",
                "--expected-version",
                "1",
            ],
            vec![
                "identity-bindings",
                "update",
                "alice",
                "binding",
                "--expected-version",
                "1",
            ],
            vec![
                "identity-bindings",
                "create",
                "alice",
                "--namespace",
                "managed_linux",
                "--username",
                "alice",
                "--read-only",
                "true",
            ],
            vec![
                "identity-token",
                "update",
                "alice",
                "--expected-revision",
                "1",
            ],
            vec![
                "identity-token",
                "update",
                "alice",
                "--enabled",
                "false",
                "--expected-revision",
                "0",
            ],
            vec!["identity-token", "update", "alice", "--enabled", "false"],
            vec![
                "identity-token",
                "update",
                "alice",
                "--enabled",
                "false",
                "--expected-version",
                "1",
            ],
        ] {
            assert!(
                super::Cli::try_parse_from(
                    ["agent-access", "admin", "principals"]
                        .into_iter()
                        .chain(arguments.clone())
                )
                .is_err(),
                "accepted {arguments:?}"
            );
        }
    }

    #[test]
    fn identity_path_update_commands_send_only_the_supplied_settings() {
        let parse = |arguments: &[&str]| {
            super::Cli::try_parse_from(
                ["agent-access", "admin", "principals"]
                    .into_iter()
                    .chain(arguments.iter().copied()),
            )
            .unwrap()
        };
        let principals = |cli: super::Cli| match cli.command {
            super::Command::Admin {
                command: super::AdminCommand::Principals { command },
            } => command,
            other => panic!("unexpected command {other:?}"),
        };
        for (arguments, expected) in [
            (
                &["--enabled", "false"][..],
                serde_json::json!({"enabled": false, "expectedVersion": 3}),
            ),
            (
                &["--read-only", "true"][..],
                serde_json::json!({"readOnly": true, "expectedVersion": 3}),
            ),
            (
                &["--enabled", "true", "--read-only", "false"][..],
                serde_json::json!({"enabled": true, "readOnly": false, "expectedVersion": 3}),
            ),
        ] {
            let mut command = vec!["identity-bindings", "update", "alice", "binding"];
            command.extend_from_slice(arguments);
            command.extend_from_slice(&["--expected-version", "3"]);
            let super::AdminPrincipalsCommand::IdentityBindings {
                command:
                    super::AdminIdentityBindingsCommand::Update {
                        settings,
                        expected_version,
                        ..
                    },
            } = principals(parse(&command))
            else {
                panic!("not a binding update: {command:?}");
            };
            assert_eq!(settings.body("expectedVersion", expected_version), expected);

            let mut command = vec!["identity-token", "update", "alice"];
            command.extend_from_slice(arguments);
            command.extend_from_slice(&["--expected-revision", "3"]);
            let super::AdminPrincipalsCommand::IdentityToken {
                command:
                    super::AdminIdentityTokenCommand::Update {
                        settings,
                        expected_revision,
                        ..
                    },
            } = principals(parse(&command))
            else {
                panic!("not a token update: {command:?}");
            };
            let mut expected = expected.clone();
            let fence = expected
                .as_object_mut()
                .unwrap()
                .remove("expectedVersion")
                .unwrap();
            expected["expectedRevision"] = fence;
            assert_eq!(
                settings.body("expectedRevision", expected_revision),
                expected
            );
        }
    }

    use super::*;

    #[test]
    fn cloudbees_ci_log_rejects_removed_offsets_and_invalid_limits() {
        for extra in [
            ["--offset", "0"],
            ["--mode", "progressive"],
            ["--max-bytes", "1023"],
            ["--max-bytes", "65537"],
            ["--max-matches", "0"],
            ["--max-matches", "101"],
        ] {
            let args = [
                "agent-access",
                "cloudbees-ci",
                "build",
                "log",
                "team-ci",
                "payments/build-api",
                "42",
            ]
            .into_iter()
            .chain(extra);
            assert!(Cli::try_parse_from(args).is_err(), "accepted {extra:?}");
        }
    }

    #[test]
    fn cloudbees_ci_job_listing_is_json_only_and_requires_a_controller() {
        for args in [
            vec!["agent-access", "cloudbees-ci", "job", "list"],
            vec![
                "agent-access",
                "cloudbees-ci",
                "job",
                "list",
                "team-ci",
                "--output-format",
                "markdown",
            ],
            vec![
                "agent-access",
                "cloudbees-ci",
                "job",
                "list",
                "--job-url",
                "https://ci.example.com/job/x/",
            ],
        ] {
            assert!(Cli::try_parse_from(args).is_err());
        }
    }

    #[test]
    fn cloudbees_ci_typed_commands_lower_to_canonical_actions() {
        let cases = [
            (
                vec![
                    "job",
                    "list",
                    "team-ci",
                    "--folder",
                    "payments",
                    "--max-results",
                    "3",
                    "--page-token",
                    "opaque",
                ],
                "job.list",
                serde_json::json!({"controller":"team-ci","folder":"payments","maxResults":3,"pageToken":"opaque"}),
            ),
            (
                vec!["job", "view", "team-ci", "payments/build-api"],
                "job.view",
                serde_json::json!({"controller":"team-ci","job":"payments/build-api"}),
            ),
            (
                vec![
                    "build",
                    "list",
                    "team-ci",
                    "payments/build-api",
                    "--max-results",
                    "10",
                ],
                "build.list",
                serde_json::json!({"controller":"team-ci","job":"payments/build-api","maxResults":10}),
            ),
            (
                vec!["build", "view", "team-ci", "payments/build-api", "42"],
                "build.view",
                serde_json::json!({"controller":"team-ci","job":"payments/build-api","buildNumber":42}),
            ),
            (
                vec![
                    "build",
                    "log",
                    "team-ci",
                    "payments/build-api",
                    "42",
                    "--mode",
                    "head",
                    "--cursor",
                    "signed-cursor",
                    "--max-bytes",
                    "8192",
                ],
                "build.log.read",
                serde_json::json!({"controller":"team-ci","job":"payments/build-api","buildNumber":42,"mode":"head","cursor":"signed-cursor","maxBytes":8192}),
            ),
            (
                vec!["build", "log", "team-ci", "payments/build-api", "42"],
                "build.log.read",
                serde_json::json!({"controller":"team-ci","job":"payments/build-api","buildNumber":42}),
            ),
            (
                vec![
                    "build",
                    "log",
                    "team-ci",
                    "payments/build-api",
                    "42",
                    "--mode",
                    "search",
                    "--query",
                    "ERROR",
                    "--max-matches",
                    "3",
                ],
                "build.log.read",
                serde_json::json!({"controller":"team-ci","job":"payments/build-api","buildNumber":42,"mode":"search","query":"ERROR","maxMatches":3}),
            ),
            (
                vec!["build", "tests", "team-ci", "payments/build-api", "42"],
                "build.tests.view",
                serde_json::json!({"controller":"team-ci","job":"payments/build-api","buildNumber":42}),
            ),
            (
                vec!["build", "trigger", "team-ci", "payments/build-api"],
                "build.trigger",
                serde_json::json!({"controller":"team-ci","job":"payments/build-api"}),
            ),
            (
                vec![
                    "build",
                    "artifact",
                    "list",
                    "team-ci",
                    "payments/build-api",
                    "42",
                ],
                "build.artifact.list",
                serde_json::json!({"controller":"team-ci","job":"payments/build-api","buildNumber":42}),
            ),
            (
                vec![
                    "queue",
                    "view",
                    "team-ci",
                    "payments/build-api",
                    "--queue-id",
                    "51",
                ],
                "queue.view",
                serde_json::json!({"controller":"team-ci","job":"payments/build-api","queueId":51}),
            ),
        ];
        for (path, expected_action, expected_inputs) in cases {
            let args = std::iter::once("agent-access")
                .chain(std::iter::once("cloudbees-ci"))
                .chain(path.iter().copied());
            let cli = Cli::try_parse_from(args).expect("typed CloudBees CI command should parse");
            let Command::CloudbeesCi { command } = cli.command else {
                panic!("CloudBees CI command expected");
            };
            let CloudbeesCiInvocation::Json {
                action,
                inputs,
                format,
            } = cloudbees_ci_invocation(&command)
            else {
                panic!("JSON CloudBees CI action expected");
            };
            assert_eq!(action, expected_action);
            assert_eq!(inputs, expected_inputs);
            assert_eq!(format, None);
        }

        let cli = Cli::try_parse_from([
            "agent-access",
            "cloudbees-ci",
            "build",
            "artifact",
            "download",
            "team-ci",
            "payments/build-api",
            "42",
            "--artifact-path",
            "reports/tests.xml",
            "--output",
            "-",
        ])
        .expect("CloudBees CI artifact download should parse");
        let Command::CloudbeesCi { command } = cli.command else {
            panic!("CloudBees CI command expected");
        };
        let CloudbeesCiInvocation::Download { action, inputs } = cloudbees_ci_invocation(&command)
        else {
            panic!("raw CloudBees CI download expected");
        };
        assert_eq!(action, "build.artifact.download");
        assert_eq!(
            inputs,
            serde_json::json!({"controller":"team-ci","job":"payments/build-api","buildNumber":42,"artifactPath":"reports/tests.xml"})
        );
        assert_eq!(cli.output.as_deref(), Some(Path::new("-")));

        for invalid in [
            vec![
                "build",
                "trigger",
                "team-ci",
                "payments/build-api",
                "--parameters",
                "{}",
            ],
            vec![
                "build",
                "log",
                "team-ci",
                "payments/build-api",
                "42",
                "--follow",
            ],
            vec![
                "build",
                "artifact",
                "download",
                "team-ci",
                "payments/build-api",
                "42",
                "--artifact-path",
                "reports/tests.xml",
            ],
            // The former positional artifact path is not accepted.
            vec![
                "build",
                "artifact",
                "download",
                "team-ci",
                "payments/build-api",
                "42",
                "reports/tests.xml",
                "--output",
                "-",
            ],
        ] {
            let args = std::iter::once("agent-access")
                .chain(std::iter::once("cloudbees-ci"))
                .chain(invalid.iter().copied());
            assert!(
                Cli::try_parse_from(args)
                    .map(|cli| validate_output_command(&cli).is_err())
                    .unwrap_or(true)
            );
        }
    }

    #[test]
    fn cloudbees_ci_url_and_build_selector_map_to_canonical_locator_inputs() {
        use clap::CommandFactory;
        const JOB_URL: &str = "https://ci.example.com/team-ci/job/payments/job/build-api/";
        const BUILD_URL: &str = "https://ci.example.com/team-ci/job/payments/job/build-api/42/";
        let lower = |args: &[&str]| {
            let cli = Cli::try_parse_from(
                ["agent-access", "cloudbees-ci"]
                    .into_iter()
                    .chain(args.iter().copied()),
            )
            .unwrap_or_else(|error| panic!("{args:?}: {error}"));
            let Command::CloudbeesCi { command } = cli.command else {
                panic!("CloudBees CI command expected");
            };
            match cloudbees_ci_invocation(&command) {
                CloudbeesCiInvocation::Json { action, inputs, .. }
                | CloudbeesCiInvocation::Download { action, inputs } => (action, inputs),
            }
        };
        for (args, action, inputs) in [
            (
                vec!["job", "view", "--job-url", JOB_URL],
                "job.view",
                serde_json::json!({"url": JOB_URL}),
            ),
            (
                vec!["build", "list", "--job-url", JOB_URL, "--max-results", "5"],
                "build.list",
                serde_json::json!({"url": JOB_URL, "maxResults": 5}),
            ),
            (
                vec!["build", "trigger", "--job-url", JOB_URL],
                "build.trigger",
                serde_json::json!({"url": JOB_URL}),
            ),
            (
                vec!["queue", "view", "--job-url", JOB_URL, "--queue-id", "51"],
                "queue.view",
                serde_json::json!({"url": JOB_URL, "queueId": 51}),
            ),
            (
                vec!["build", "view", "--job-url", BUILD_URL],
                "build.view",
                serde_json::json!({"url": BUILD_URL}),
            ),
            (
                vec![
                    "build",
                    "log",
                    "--job-url",
                    JOB_URL,
                    "--build-selector",
                    "lastFailedBuild",
                    "--mode",
                    "search",
                    "--query",
                    "ERROR",
                ],
                "build.log.read",
                serde_json::json!({"url": JOB_URL, "buildSelector": "lastFailedBuild", "mode": "search", "query": "ERROR"}),
            ),
            (
                vec![
                    "build",
                    "view",
                    "team-ci",
                    "payments/build-api",
                    "--build-selector",
                    "lastSuccessfulBuild",
                ],
                "build.view",
                serde_json::json!({"controller": "team-ci", "job": "payments/build-api", "buildSelector": "lastSuccessfulBuild"}),
            ),
            (
                vec![
                    "build",
                    "pipeline",
                    "node",
                    "--job-url",
                    BUILD_URL,
                    "--node-id",
                    "7",
                ],
                "build.pipeline.node.view",
                serde_json::json!({"url": BUILD_URL, "nodeId": "7"}),
            ),
            (
                vec![
                    "build",
                    "artifact",
                    "download",
                    "--job-url",
                    BUILD_URL,
                    "--artifact-path",
                    "reports/results.zip",
                    "--output",
                    "-",
                ],
                "build.artifact.download",
                serde_json::json!({"url": BUILD_URL, "artifactPath": "reports/results.zip"}),
            ),
        ] {
            assert_eq!(lower(&args), (action, inputs), "{args:?}");
        }
        for invalid in [
            // A job URL replaces both CONTROLLER and JOB; extra positionals are rejected.
            vec!["job", "view", "team-ci", "--job-url", JOB_URL],
            vec!["build", "view", "--job-url", JOB_URL, "42"],
            vec!["build", "view", "team-ci", "payments/build-api"],
            vec!["build", "view", "team-ci"],
            vec![
                "build",
                "view",
                "team-ci",
                "payments/build-api",
                "42",
                "--build-selector",
                "lastBuild",
            ],
            vec![
                "build",
                "view",
                "team-ci",
                "payments/build-api",
                "--build-selector",
                "last-failed-build",
            ],
            vec![
                "build",
                "list",
                "team-ci",
                "payments/build-api",
                "--build-selector",
                "lastBuild",
            ],
            vec!["queue", "view", "team-ci", "payments/build-api", "51"],
        ] {
            assert!(
                Cli::try_parse_from(
                    ["agent-access", "cloudbees-ci"]
                        .into_iter()
                        .chain(invalid.iter().copied())
                )
                .is_err(),
                "accepted {invalid:?}"
            );
        }
        // The global --url still selects the broker beside a job URL.
        let cli = Cli::try_parse_from([
            "agent-access",
            "--url",
            "https://broker.example.test",
            "cloudbees-ci",
            "job",
            "view",
            "--job-url",
            JOB_URL,
        ])
        .unwrap();
        assert_eq!(cli.url.as_deref(), Some("https://broker.example.test"));
        let Command::CloudbeesCi { command } = cli.command else {
            panic!("CloudBees CI command expected");
        };
        let CloudbeesCiInvocation::Json { inputs, .. } = cloudbees_ci_invocation(&command) else {
            panic!("JSON CloudBees CI action expected");
        };
        assert_eq!(inputs, serde_json::json!({"url": JOB_URL}));
        let mut command = Cli::command();
        for path in [
            &["job", "view"][..],
            &["build", "view"],
            &["build", "log"],
            &["build", "pipeline", "node"],
            &["build", "artifact", "download"],
            &["queue", "view"],
        ] {
            let mut current = command
                .find_subcommand_mut("cloudbees-ci")
                .expect("cloudbees-ci command");
            for name in path {
                current = current.find_subcommand_mut(name).expect("subcommand");
            }
            for argument in current.get_arguments() {
                assert!(
                    argument.get_help().is_some(),
                    "{path:?} {} has no help",
                    argument.get_id()
                );
            }
        }
    }

    #[test]
    fn cloudbees_ci_additional_reads_and_downloads_lower_to_catalog_actions() {
        let base = serde_json::json!({"controller":"team-ci","job":"folder/job","buildNumber":42});
        let node = serde_json::json!({"controller":"team-ci","job":"folder/job","buildNumber":42,"nodeId":"7"});
        let cases = [
            (
                vec!["build", "pipeline", "view", "team-ci", "folder/job", "42"],
                "build.pipeline.view",
                base.clone(),
                false,
            ),
            (
                vec![
                    "build",
                    "pipeline",
                    "node",
                    "team-ci",
                    "folder/job",
                    "42",
                    "--node-id",
                    "7",
                ],
                "build.pipeline.node.view",
                node.clone(),
                false,
            ),
            (
                vec![
                    "build",
                    "pipeline",
                    "log",
                    "team-ci",
                    "folder/job",
                    "42",
                    "--node-id",
                    "7",
                ],
                "build.pipeline.node.log.read",
                node,
                false,
            ),
            (
                vec!["build", "pending-inputs", "team-ci", "folder/job", "42"],
                "build.pending-inputs.list",
                base.clone(),
                false,
            ),
            (
                vec![
                    "build",
                    "tests-details",
                    "team-ci",
                    "folder/job",
                    "42",
                    "--max-results",
                    "10",
                ],
                "build.tests.details",
                serde_json::json!({"controller":"team-ci","job":"folder/job","buildNumber":42,"maxResults":10}),
                false,
            ),
            (
                vec![
                    "build",
                    "log-download",
                    "team-ci",
                    "folder/job",
                    "42",
                    "--output",
                    "-",
                ],
                "build.log.download",
                base.clone(),
                true,
            ),
            (
                vec![
                    "build",
                    "tests-download",
                    "team-ci",
                    "folder/job",
                    "42",
                    "--output",
                    "-",
                ],
                "build.tests.download",
                base,
                true,
            ),
        ];
        for (args, expected_action, expected_inputs, download) in cases {
            let cli = Cli::try_parse_from(["agent-access", "cloudbees-ci"].into_iter().chain(args))
                .unwrap();
            let Command::CloudbeesCi { command } = cli.command else {
                panic!("expected CloudBees command")
            };
            match cloudbees_ci_invocation(&command) {
                CloudbeesCiInvocation::Json {
                    action,
                    inputs,
                    format,
                } => {
                    assert!(!download);
                    assert_eq!(action, expected_action);
                    assert_eq!(inputs, expected_inputs);
                    assert_eq!(format, None);
                }
                CloudbeesCiInvocation::Download { action, inputs } => {
                    assert!(download);
                    assert_eq!(action, expected_action);
                    assert_eq!(inputs, expected_inputs);
                    assert_eq!(cli.output.as_deref(), Some(Path::new("-")));
                }
            }
        }
        for command in ["log-download", "tests-download"] {
            assert!(
                Cli::try_parse_from([
                    "agent-access",
                    "cloudbees-ci",
                    "build",
                    command,
                    "team-ci",
                    "folder/job",
                    "42"
                ])
                .map(|cli| validate_output_command(&cli).is_err())
                .unwrap_or(true)
            );
        }
    }

    fn discovery_projection(prefix: Option<&str>, verbose: bool) -> DiscoveryListArgs {
        DiscoveryListArgs {
            prefix: prefix.map(ToString::to_string),
            verbose,
        }
    }

    fn discovery_services_fixture() -> serde_json::Value {
        serde_json::json!([
            {
                "service": "zeta",
                "availability": {"state":"available","requirements":[],"message":"Locally available"},
                "displayName": "Zeta gateway",
                "surface": "gateway",
                "gatewayKind": "git_http",
                "scopeTypes": ["repository"],
                "actions": [{
                    "action": "repo.fetch",
                    "readOnly": true,
                    "description": "Fetch repository",
                    "requiredScopeTypes": ["repository"],
                    "credentialModes": ["service"],
                    "inputSchema": {"type": "object"},
                    "futureField": {"preserved": true}
                }]
            },
            {
                "service": "gitlab",
                "availability": {"state":"available","requirements":[],"message":"Locally available"},
                "displayName": "GitLab REST",
                "surface": "invoke",
                "scopeTypes": ["repository"],
                "actions": [
                    {
                        "action": "project.view",
                        "readOnly": true,
                        "description": "View project",
                        "requiredScopeTypes": ["repository"],
                        "credentialModes": ["per_user", "service"],
                        "inputSchema": {"type": "object"}
                    },
                    {
                        "action": "merge_request.draft_note.publish",
                        "readOnly": false,
                        "description": "Publish draft note",
                        "requiredScopeTypes": ["repository"],
                        "credentialModes": ["service", "per_user"],
                        "upstreamResourceOwnership": "acting_user",
                        "inputSchema": {"type": "object", "required": ["project"]}
                    },
                    {
                        "action": "merge_request.approve",
                        "readOnly": false,
                        "description": "Approve merge request",
                        "requiredScopeTypes": ["repository"],
                        "credentialModes": ["service"],
                        "inputSchema": {"type": "object"}
                    }
                ]
            }
        ])
    }

    #[test]
    fn discovery_service_projections_preserve_labels_and_canonical_surface() {
        let compact = project_service_list(
            discovery_services_fixture(),
            &discovery_projection(None, false),
        )
        .unwrap();
        assert_eq!(compact["services"][0]["surface"], "invoke");
        assert_eq!(compact["services"][0]["displayName"], "GitLab REST");
        assert_eq!(
            compact["services"][0]["actions"],
            serde_json::json!([
                "merge_request.approve",
                "merge_request.draft_note.publish",
                "project.view"
            ])
        );
        assert!(compact["services"][0].get("actionCount").is_none());
        let verbose = project_service_list(
            discovery_services_fixture(),
            &discovery_projection(None, true),
        )
        .unwrap();
        assert_eq!(verbose[1]["actions"][0]["futureField"]["preserved"], true);
        let empty = project_service_list(
            discovery_services_fixture(),
            &discovery_projection(Some("G"), false),
        )
        .unwrap();
        assert_eq!(empty, serde_json::json!({"services":[]}));
    }

    #[test]
    fn discovery_removed_flags_are_rejected_and_resource_query_parses() {
        for args in [
            vec!["services", "list", "--names-only"],
            vec!["resources", "list", "--service", "fake"],
            vec!["actions", "list", "--service", "fake", "--names-only"],
        ] {
            assert!(Cli::try_parse_from(std::iter::once("agent-access").chain(args)).is_err());
        }
        assert!(
            Cli::try_parse_from([
                "agent-access",
                "resource-access",
                "describe",
                "--service",
                "gitlab",
                "--limit",
                "3",
                "--cursor",
                "opaque"
            ])
            .is_ok()
        );
        assert!(
            Cli::try_parse_from([
                "agent-access",
                "actions",
                "list",
                "--service",
                "gitlab",
                "--resource",
                "team/repo"
            ])
            .is_ok()
        );
    }

    #[test]
    fn broker_status_command_parses_as_a_typed_get() {
        let cli = Cli::try_parse_from(["agent-access", "broker", "status"]).unwrap();
        assert!(matches!(
            cli.command,
            Command::Broker {
                command: BrokerCommand::Status
            }
        ));
    }

    #[test]
    fn git_credential_request_accepts_unknown_fields_and_eof() {
        let request = read_git_credential_request(
            b"protocol=https\nhost=git.example.test\nfuture-field=future-value\n".as_slice(),
        )
        .unwrap();

        assert_eq!(
            request,
            GitCredentialRequest {
                protocol: Some("https".to_string()),
                host: Some("git.example.test".to_string()),
            }
        );
    }

    #[test]
    fn git_credential_request_stops_at_blank_line() {
        let request = read_git_credential_request(
            b"protocol=https\nhost=git.example.test\n\nprotocol=http\nhost=other.test\n".as_slice(),
        )
        .unwrap();

        assert_eq!(request.protocol.as_deref(), Some("https"));
        assert_eq!(request.host.as_deref(), Some("git.example.test"));
    }

    #[test]
    fn git_credential_request_rejects_non_record_lines() {
        assert!(
            read_git_credential_request(
                b"protocol=https\nhost=git.example.test\nnot-a-record\n".as_slice()
            )
            .is_err()
        );
    }

    #[test]
    fn git_credential_store_and_erase_consumption_stops_at_blank_line() {
        let bytes = b"protocol=https\npassword=secret\n\nleft-unconsumed";
        let mut input = std::io::Cursor::new(bytes.as_slice());
        consume_git_credential_request(&mut input).unwrap();

        let mut remaining = String::new();
        input.read_to_string(&mut remaining).unwrap();
        assert_eq!(remaining, "left-unconsumed");
    }

    #[test]
    fn maps_exit_codes_from_contract() {
        assert_eq!(cli_exit_code_for_http_status(200), 0);
        assert_eq!(cli_exit_code_for_http_status(403), 2);
        assert_eq!(cli_exit_code_for_http_status(409), 2);
        assert_eq!(cli_exit_code_for_http_status(400), 3);
        assert_eq!(cli_exit_code_for_http_status(424), 4);
        assert_eq!(cli_exit_code_for_http_status(503), 5);
        assert_eq!(cli_exit_code_for_http_status(401), 6);
        assert_eq!(cli_exit_code_for_http_status(429), 7);
    }

    #[test]
    fn rate_limits_print_the_broker_message_as_one_stderr_line() {
        let broker = serde_json::json!({
            "agentRequestId": "agent-1",
            "brokerRequestId": "broker-1",
            "decision": "error",
            "service": "jira",
            "action": "issue.view",
            "resourceScopes": {},
            "reasonCode": "rate_limited",
            "reason": "Rate limit reached for service \"jira\": 20 requests per 1m. Retry after 12s (at 2026-09-25T14:03:12Z). The request was not executed.",
            "result": {
                "limitScope": "principal",
                "service": "jira",
                "limit": 20,
                "windowSeconds": 60,
                "retryAfterSeconds": 12,
                "retryAt": "2026-09-25T14:03:12Z",
                "executionState": "not_dispatched",
                "retrySafe": true
            },
            "error": {"message": "Rate limit reached for service \"jira\": 20 requests per 1m. Retry after 12s (at 2026-09-25T14:03:12Z). The request was not executed."}
        });
        assert_eq!(
            rate_limit_notice(429, &broker).as_deref(),
            Some(
                "rate limited: Rate limit reached for service \"jira\": 20 requests per 1m. Retry after 12s (at 2026-09-25T14:03:12Z). The request was not executed."
            )
        );
        let upstream = serde_json::json!({
            "agentRequestId": "agent-2",
            "brokerRequestId": "broker-2",
            "decision": "error",
            "reasonCode": "upstream_rate_limited",
            "reason": "jira is rate limiting requests.\nRetry later.",
            "result": {"limitScope": "upstream", "service": "jira"},
            "error": {"message": "jira is rate limiting requests.\n\u{1b}[2J Retry later."}
        });
        assert_eq!(
            rate_limit_notice(429, &upstream).as_deref(),
            Some("rate limited: jira is rate limiting requests. [2J Retry later.")
        );
        // Bidi overrides and isolates, zero-width characters, the BOM, and
        // other Unicode format characters are stripped, not rendered.
        let spoofed = serde_json::json!({
            "reasonCode": "upstream_rate_limited",
            "error": {"message": "\u{202e}jira\u{202c} is rate\u{200b} limiting \u{2066}requests\u{2069}.\u{feff} \u{200d}\u{200e}\u{200f}\u{202a}\u{202b}\u{202d}\u{2067}\u{2068}\u{2060}\u{00ad}\u{061c}\u{e0041}Retry later."}
        });
        assert_eq!(
            rate_limit_notice(429, &spoofed).as_deref(),
            Some("rate limited: jira is rate limiting requests. Retry later.")
        );
        assert!(is_unicode_format_character('\u{202e}'));
        assert!(!is_unicode_format_character('a'));
        assert!(!is_unicode_format_character('\u{00e9}'));
        let without_error_body = serde_json::json!({
            "reasonCode": "upstream_rate_limited",
            "reason": "gitlab is rate limiting requests. Retry later."
        });
        assert_eq!(
            rate_limit_notice(429, &without_error_body).as_deref(),
            Some("rate limited: gitlab is rate limiting requests. Retry later.")
        );
        assert_eq!(
            rate_limit_notice(429, &serde_json::json!({"reasonCode": "rate_limited"})).as_deref(),
            Some("rate limited: rate_limited")
        );
        let concurrency = serde_json::json!({
            "reasonCode": "concurrency_limited",
            "error": {"message": "concurrency limit exceeded (4)"}
        });
        assert_eq!(rate_limit_notice(429, &concurrency), None);
        assert_eq!(rate_limit_notice(200, &broker), None);
        assert_eq!(
            rate_limit_notice(
                403,
                &serde_json::json!({"reasonCode": "service_action_denied"})
            ),
            None
        );
    }

    #[test]
    fn endpoint_joins_without_double_slash() {
        assert_eq!(
            endpoint("http://127.0.0.1:8787/", "/v1/me").unwrap(),
            "http://127.0.0.1:8787/v1/me"
        );
    }

    #[test]
    fn jira_rich_content_write_commands_parse_normalized_flags() {
        let commands = [
            vec![
                "agent-access",
                "jira",
                "issue",
                "create",
                "--project",
                "SBC",
                "--issue-type-id",
                "10001",
                "--summary",
                "Created",
                "--content",
                "# Description",
                "--content-format",
                "markdown",
            ],
            vec![
                "agent-access",
                "jira",
                "issue",
                "child",
                "create",
                "--project",
                "SBC",
                "--issue-type-id",
                "10002",
                "--summary",
                "Child",
                "--parent",
                "SBC-1",
                "--content-file",
                "description.txt",
                "--content-format",
                "plain_text",
            ],
            vec![
                "agent-access",
                "jira",
                "issue",
                "update",
                "SBC-1",
                "--content",
                r#"{"type":"doc","version":1,"content":[]}"#,
                "--content-format",
                "adf",
            ],
            vec![
                "agent-access",
                "jira",
                "issue",
                "comment",
                "add",
                "--issue",
                "SBC-1",
                "--content",
                "Added",
                "--content-format",
                "plain_text",
            ],
            vec![
                "agent-access",
                "jira",
                "issue",
                "comment",
                "reply",
                "10",
                "--issue",
                "SBC-1",
                "--content-file",
                "reply.md",
                "--content-format",
                "markdown",
            ],
            vec![
                "agent-access",
                "jira",
                "issue",
                "comment",
                "update",
                "11",
                "--issue",
                "SBC-1",
                "--content",
                "Updated",
                "--content-format",
                "plain_text",
            ],
        ];

        for command in commands {
            Cli::try_parse_from(command).expect("normalized Jira content command should parse");
        }

        let create_without_content = Cli::try_parse_from([
            "agent-access",
            "jira",
            "issue",
            "create",
            "--project",
            "SBC",
            "--issue-type-id",
            "10001",
            "--summary",
            "No description",
        ]);
        assert!(create_without_content.is_ok());

        let summary_only_update = Cli::try_parse_from([
            "agent-access",
            "jira",
            "issue",
            "update",
            "SBC-1",
            "--summary",
            "Renamed",
        ]);
        assert!(summary_only_update.is_ok());
    }

    #[test]
    fn jira_rich_content_flags_reject_incomplete_invalid_and_legacy_inputs() {
        let missing_format = Cli::try_parse_from([
            "agent-access",
            "jira",
            "issue",
            "comment",
            "add",
            "--issue",
            "SBC-1",
            "--content",
            "Comment",
        ])
        .unwrap_err();
        assert_eq!(
            missing_format.kind(),
            clap::error::ErrorKind::MissingRequiredArgument
        );

        let missing_source = Cli::try_parse_from([
            "agent-access",
            "jira",
            "issue",
            "comment",
            "add",
            "--issue",
            "SBC-1",
            "--content-format",
            "markdown",
        ])
        .unwrap_err();
        assert_eq!(
            missing_source.kind(),
            clap::error::ErrorKind::MissingRequiredArgument
        );

        let conflicting_sources = Cli::try_parse_from([
            "agent-access",
            "jira",
            "issue",
            "comment",
            "add",
            "--issue",
            "SBC-1",
            "--content",
            "Comment",
            "--content-file",
            "comment.md",
            "--content-format",
            "markdown",
        ])
        .unwrap_err();
        assert_eq!(
            conflicting_sources.kind(),
            clap::error::ErrorKind::ArgumentConflict
        );

        let unsupported_format = Cli::try_parse_from([
            "agent-access",
            "jira",
            "issue",
            "comment",
            "add",
            "--issue",
            "SBC-1",
            "--content",
            "Comment",
            "--content-format",
            "storage",
        ])
        .unwrap_err();
        assert_eq!(
            unsupported_format.kind(),
            clap::error::ErrorKind::InvalidValue
        );

        let legacy = Cli::try_parse_from([
            "agent-access",
            "jira",
            "issue",
            "comment",
            "add",
            "--issue",
            "SBC-1",
            "--body-file",
            "comment.json",
        ])
        .unwrap_err();
        assert_eq!(legacy.kind(), clap::error::ErrorKind::UnknownArgument);

        let legacy_description = Cli::try_parse_from([
            "agent-access",
            "jira",
            "issue",
            "create",
            "--project",
            "SBC",
            "--issue-type-id",
            "10001",
            "--summary",
            "Legacy",
            "--description-adf-file",
            "description.json",
        ])
        .unwrap_err();
        assert_eq!(
            legacy_description.kind(),
            clap::error::ErrorKind::UnknownArgument
        );
    }

    #[test]
    fn jira_content_lowering_emits_only_canonical_fields() {
        let mut markdown = serde_json::Map::new();
        assert!(
            insert_jira_content_inputs(
                &mut markdown,
                Some("# Update\n\nDone."),
                None,
                Some(JiraContentFormatArg::Markdown),
                true,
                "test command",
            )
            .unwrap()
        );
        assert_eq!(
            serde_json::Value::Object(markdown.clone()),
            serde_json::json!({
                "content": "# Update\n\nDone.",
                "contentFormat": "markdown"
            })
        );
        assert!(!markdown.contains_key("body"));
        assert!(!markdown.contains_key("bodyFormat"));
        assert!(!markdown.contains_key("description"));

        let adf = r#"{"type":"doc","version":1,"content":[]}"#;
        let mut native = serde_json::Map::new();
        insert_jira_content_inputs(
            &mut native,
            Some(adf),
            None,
            Some(JiraContentFormatArg::Adf),
            true,
            "test command",
        )
        .unwrap();
        assert_eq!(native["content"]["type"], "doc");
        assert_eq!(native["contentFormat"], "adf");

        let mut omitted = serde_json::Map::new();
        assert!(
            !insert_jira_content_inputs(&mut omitted, None, None, None, false, "test command",)
                .unwrap()
        );
        assert!(omitted.is_empty());
    }

    #[test]
    fn jira_content_file_lowering_parses_native_json_and_preserves_utf8_text() {
        let adf_path =
            std::env::temp_dir().join(format!("agent-access-cli-content-{}.json", Uuid::new_v4()));
        fs::write(&adf_path, br#"{"type":"doc","version":1,"content":[]}"#).unwrap();
        let (adf, format) = resolve_content_input(
            None,
            Some(&adf_path),
            Some(JiraContentFormatArg::Adf),
            true,
            "test command",
        )
        .unwrap()
        .unwrap();
        assert_eq!(adf["type"], "doc");
        assert_eq!(format, JiraContentFormatArg::Adf);
        fs::remove_file(adf_path).unwrap();

        let markdown_path =
            std::env::temp_dir().join(format!("agent-access-cli-content-{}.md", Uuid::new_v4()));
        fs::write(&markdown_path, "Unicode: café\n").unwrap();
        let (markdown, format) = resolve_content_input(
            None,
            Some(&markdown_path),
            Some(JiraContentFormatArg::Markdown),
            true,
            "test command",
        )
        .unwrap()
        .unwrap();
        assert_eq!(markdown, "Unicode: café\n");
        assert_eq!(format, JiraContentFormatArg::Markdown);
        fs::remove_file(markdown_path).unwrap();
    }

    #[test]
    fn jira_normalized_content_file_reader_enforces_the_cli_safety_limit() {
        let normal_path = std::env::temp_dir().join(format!(
            "agent-access-cli-bounded-content-{}.txt",
            Uuid::new_v4()
        ));
        fs::write(&normal_path, b"bounded content").unwrap();
        assert_eq!(
            read_normalized_content_file(&normal_path).unwrap(),
            b"bounded content"
        );
        fs::remove_file(normal_path).unwrap();

        let oversized_path = std::env::temp_dir().join(format!(
            "agent-access-cli-oversized-content-{}.txt",
            Uuid::new_v4()
        ));
        let oversized = fs::File::create(&oversized_path).unwrap();
        oversized
            .set_len(NORMALIZED_CONTENT_FILE_MAX_BYTES + 1)
            .unwrap();
        drop(oversized);
        let error = read_normalized_content_file(&oversized_path).unwrap_err();
        let message = format!("{error:#}");
        assert!(message.contains("exceeds the CLI safety limit"));
        assert!(message.contains(&NORMALIZED_CONTENT_FILE_MAX_BYTES.to_string()));
        assert!(message.contains("provider and server limits may be lower"));
        fs::remove_file(oversized_path).unwrap();

        let error =
            read_normalized_content_to_limit(std::io::repeat(0), "pseudo-stream", 8).unwrap_err();
        assert!(format!("{error:#}").contains("pseudo-stream"));
        assert_eq!(
            read_normalized_content_to_limit(std::io::Cursor::new([0_u8; 8]), "exact", 8)
                .unwrap()
                .len(),
            8
        );
    }

    fn response_test_settings(
        read_content_format: ReadContentFormat,
        output_format: ResponseFormat,
    ) -> ResolvedCliSettings {
        ResolvedCliSettings {
            url: "http://127.0.0.1:8787".to_string(),
            request_timeout_ms: 30_000,
            tls: CliTlsConfig::default(),
            token: None,
            token_from_literal_arg: false,
            identity_header: "X-Agent-Access-Identity-Token".to_string(),
            identity_scheme: "raw".to_string(),
            allow_insecure_broker_http: false,
            read_content_format,
            output_format,
        }
    }

    #[test]
    fn identity_transport_accepts_only_exact_local_http_hosts() {
        let mut settings = response_test_settings(ReadContentFormat::Native, ResponseFormat::Json);
        settings.token = Some("transport-test-token".to_string());
        for host in ["localhost", "127.0.0.1", "[::1]"] {
            settings.url = format!("http://{host}:8787");
            validate_transport(&settings).unwrap();
        }
        for host in [
            "127.0.0.2",
            "[::ffff:127.0.0.1]",
            "[::2]",
            "[2001:db8::1]",
            "localhost.example",
            "broker.example",
        ] {
            settings.url = format!("http://{host}:8787");
            assert!(validate_transport(&settings).is_err(), "{}", settings.url);
        }
        settings.url = "https://[2001:db8::1]:8787".to_string();
        validate_transport(&settings).unwrap();
    }

    #[test]
    fn read_file_output_renders_markdown_and_preserves_destination_on_errors() {
        let directory = tempfile::tempdir().unwrap();
        let destination = directory.path().join("issue.md");
        let settings = response_test_settings(ReadContentFormat::Native, ResponseFormat::Markdown);
        let ctx = CliContext {
            settings: &settings,
            output: Some(&destination),
        };
        let envelope = serde_json::json!({"decision":"allow","brokerRequestId":"request-1","result":{"format":"markdown","value":"# Issue\n\nDetails\n"}});
        let receipt = write_local_response(
            &ctx,
            200,
            &envelope,
            ResponseFormat::Markdown,
            output::ResponseOutput::prepare(Some(&destination), &["/result/secret".into()])
                .unwrap(),
        )
        .unwrap()
        .unwrap();
        assert_eq!(
            fs::read_to_string(&destination).unwrap(),
            "# Issue\n\nDetails\n"
        );
        assert_eq!(receipt["output"]["contentType"], "text/markdown");
        assert_eq!(receipt["output"]["sensitive"], true);
        assert_eq!(receipt["brokerRequestId"], "request-1");
        assert!(receipt.get("result").is_none());
        let denied = serde_json::json!({"decision":"deny","reasonCode":"action_denied"});
        assert!(
            write_local_response(&ctx, 403, &denied, ResponseFormat::Markdown, None)
                .unwrap()
                .is_none()
        );
        let malformed =
            serde_json::json!({"decision":"allow","result":{"format":"markdown","value":42}});
        assert!(
            write_local_response(&ctx, 200, &malformed, ResponseFormat::Markdown, None).is_err()
        );
        assert_eq!(
            fs::read_to_string(&destination).unwrap(),
            "# Issue\n\nDetails\n"
        );
    }

    #[test]
    fn send_file_destinations_cannot_overwrite_payload_with_metadata() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("response.json");
        let output = SendOutput::File { path: path.clone() };
        let metadata = SendMetadataOutput::File {
            path: directory.path().join(".").join("response.json"),
        };
        assert!(validate_send_destinations(Some(&output), Some(&metadata)).is_err());
        assert!(
            validate_send_destinations(Some(&output), Some(&SendMetadataOutput::Stderr)).is_ok()
        );
        assert!(
            validate_send_destinations(Some(&SendOutput::File { path: "-".into() }), None).is_err()
        );
        assert!(
            validate_send_destinations(Some(&SendOutput::File { path: "./-".into() }), None)
                .is_ok()
        );
    }

    fn response_test_action(
        read_content_formats: &[&str],
        response_formats: &[&str],
    ) -> ApiActionSpec {
        ApiActionSpec {
            scoped_mcp_name: Some("issue.view".to_owned()),
            documentation: None,
            companion_read_actions: Vec::new(),
            listing_of: None,
            read_only: true,
            action: "issue.view".to_string(),
            description: "test action".to_string(),
            required_scope_types: Vec::new(),
            credential_modes: Vec::new(),
            upstream_resource_ownership: None,
            lookup_required: false,
            input_schema: serde_json::json!({"type": "object"}),
            sensitive_input_pointers: Vec::new(),
            sensitive_output_pointers: Vec::new(),
            io: ActionIo::Json,
            response_kind: agent_access_core::ResponseKind::ResponseEnvelope,
            exit_policy: ExitPolicy::InvokeDecision,
            read_content_formats: read_content_formats
                .iter()
                .map(|value| (*value).to_string())
                .collect(),
            response_formats: response_formats
                .iter()
                .map(|value| (*value).to_string())
                .collect(),
            rendered_body_owners: Vec::new(),
            optional_rendered_body_owner_prefixes: Vec::new(),
        }
    }

    #[test]
    fn runtime_catalog_version_errors_precede_required_v2_metadata_validation() {
        let mut value =
            serde_json::to_value(agent_access_core::empty_catalog(serde_json::json!({}))).unwrap();
        value["version"] = serde_json::json!("agent-access.catalog.v1");
        value["services"] =
            serde_json::json!([{"service":"jira","actions":[{"action":"issue.view"}]}]);
        assert!(
            parse_runtime_catalog(value.clone())
                .unwrap_err()
                .to_string()
                .contains("version agent-access.catalog.v1 is not supported")
        );
        value["version"] = serde_json::json!(API_CATALOG_VERSION);
        assert_eq!(
            parse_runtime_catalog(value).unwrap_err().to_string(),
            "runtime catalog response is invalid"
        );
        let mut valid = agent_access_core::empty_catalog(serde_json::json!({}));
        valid.services.push(agent_access_core::ApiServiceSpec {
            availability: None,
            service: "jira".into(),
            display_name: "Jira".into(),
            surface: "invoke".into(),
            scoped_mcp_ready: false,
            scope_types: vec![],
            resource_scopes: Default::default(),
            actions: vec![response_test_action(&[], &[])],
        });
        let mut value = serde_json::to_value(valid).unwrap();
        value["services"][0]["actions"][0]["scopedMcpName"] = serde_json::Value::Null;
        assert!(parse_runtime_catalog(value.clone()).is_ok());
        value["services"][0]["actions"][0]
            .as_object_mut()
            .unwrap()
            .remove("scopedMcpName");
        assert_eq!(
            parse_runtime_catalog(value).unwrap_err().to_string(),
            "runtime catalog response is invalid"
        );
    }

    fn cli_help(args: &[&str]) -> String {
        let mut command = vec!["agent-access"];
        command.extend_from_slice(args);
        command.push("--help");
        Cli::try_parse_from(command).unwrap_err().to_string()
    }

    fn confluence_action_for_cli_path(command: &[&str]) -> String {
        assert_eq!(command.first(), Some(&"confluence"));
        let content_kind = command[1];
        let tail = &command[2..];
        let mut action = Vec::new();
        if content_kind == "blog" || !matches!(tail, ["search"] | ["verify"] | ["attachment", _]) {
            action.push(content_kind.to_string());
        }
        for segment in tail {
            match *segment {
                "replies" => action.extend(["reply".to_string(), "list".to_string()]),
                "reply" => action.extend(["reply".to_string(), "add".to_string()]),
                segment => action.push(segment.replace('-', "_")),
            }
        }
        action.join(".")
    }

    /// Presentation capabilities of a backend action, as a broker configured
    /// with every content format enabled advertises them.
    fn response_capabilities(
        service: &str,
        action: &str,
    ) -> agent_access_provider::presentation::ResponseCapabilities {
        static DESCRIPTORS: std::sync::OnceLock<Vec<agent_access_provider::ServiceDescriptor>> =
            std::sync::OnceLock::new();
        let descriptors = DESCRIPTORS.get_or_init(|| {
            agent_access_broker::composition()
                .unwrap()
                .configured_service_descriptors(
                    r#"
[identity]
mode = "anonymous"
authority = "toml"

[policy]
authority = "toml"
default_decision = "deny"

[providers.jira]
tenant_host = "example.atlassian.net"
allowed_upstream_hosts = ["https://example.atlassian.net/rest/api/3/**"]
content.comment_formats = ["adf"]

[providers.confluence]
tenant_host = "example.atlassian.net"
allowed_upstream_hosts = ["https://example.atlassian.net/wiki/**"]
content.page_formats = ["atlas_doc_format", "storage"]

[providers.gitlab]
api_base_url = "https://gitlab.example.com/api/v4"
web_base_url = "https://gitlab.example.com"
allowed_upstream_hosts = ["https://gitlab.example.com/api/v4/**"]

[limits]
upload_spool_dir = "upload-spool"
"#,
                )
                .unwrap()
        });
        let descriptor = descriptors
            .iter()
            .find(|descriptor| descriptor.service == service)
            .expect("backend is configured");
        agent_access_provider::presentation::response_capabilities(
            descriptor
                .action(action)
                .and_then(|action| action.presentation.as_ref()),
        )
    }

    #[test]
    fn jira_read_flags_follow_the_compiled_capability_matrix() {
        let embedded = [
            (&["jira", "issue", "view"][..], "issue.view"),
            (&["jira", "issue", "create"][..], "issue.create"),
            (&["jira", "issue", "update"][..], "issue.update"),
            (&["jira", "issue", "comment", "list"][..], "comment.list"),
            (&["jira", "issue", "comment", "view"][..], "comment.view"),
            (&["jira", "issue", "comment", "add"][..], "comment.add"),
            (&["jira", "issue", "comment", "reply"][..], "comment.reply"),
            (
                &["jira", "issue", "comment", "update"][..],
                "comment.update",
            ),
        ];
        for (command, action) in embedded {
            assert!(response_capabilities("jira", action).supports_read_content());
            assert!(
                cli_help(command).contains("--read-content-format <READ_CONTENT_FORMAT>"),
                "missing embedded-content flag on {command:?}"
            );
        }

        let whole_result = [
            (&["jira", "project", "list"][..], "project.list"),
            (&["jira", "project", "view"][..], "project.view"),
            (&["jira", "issue-type", "list"][..], "issue_type.list"),
            (&["jira", "issue", "view"][..], "issue.view"),
            (&["jira", "issue", "search"][..], "search"),
            (&["jira", "issue", "comment", "list"][..], "comment.list"),
            (&["jira", "issue", "comment", "view"][..], "comment.view"),
            (
                &["jira", "issue", "comment", "property", "list"][..],
                "comment.property.list",
            ),
            (
                &["jira", "issue", "comment", "property", "get"][..],
                "comment.property.get",
            ),
            (
                &["jira", "issue", "attachment", "list"][..],
                "attachment.list",
            ),
            (&["jira", "issue", "verify"][..], "verify"),
        ];
        for (command, action) in whole_result {
            assert!(response_capabilities("jira", action).supports_markdown_response());
            assert!(
                cli_help(command).contains("--output-format <OUTPUT_FORMAT>"),
                "missing whole-result flag on {command:?}"
            );
        }

        for (command, action) in [
            (
                &["jira", "issue", "child", "create"][..],
                "issue.child.create",
            ),
            (
                &["jira", "issue", "comment", "delete"][..],
                "comment.delete",
            ),
            (
                &["jira", "issue", "attachment", "download"][..],
                "attachment.download",
            ),
        ] {
            let capabilities = response_capabilities("jira", action);
            assert!(!capabilities.supports_read_content());
            assert!(!capabilities.supports_markdown_response());
            let help = cli_help(command);
            assert!(!help.contains("--read-content-format"));
            assert!(!help.contains("--output-format"));
        }
    }

    #[test]
    fn jira_read_and_output_flags_parse_closed_values() {
        Cli::try_parse_from([
            "agent-access",
            "jira",
            "issue",
            "view",
            "SBC-1",
            "--read-content-format",
            "text",
            "--output-format",
            "json",
        ])
        .unwrap();
        Cli::try_parse_from([
            "agent-access",
            "invoke",
            "jira.issue.view",
            "--read-content-format",
            "markdown",
            "--output-format",
            "markdown",
        ])
        .unwrap();

        let bad_read = Cli::try_parse_from([
            "agent-access",
            "jira",
            "issue",
            "view",
            "SBC-1",
            "--read-content-format",
            "plain_text",
        ])
        .unwrap_err();
        assert_eq!(bad_read.kind(), clap::error::ErrorKind::InvalidValue);
        let bad_output = Cli::try_parse_from([
            "agent-access",
            "jira",
            "issue",
            "search",
            "--jql",
            "project=SBC",
            "--output-format",
            "text",
        ])
        .unwrap_err();
        assert_eq!(bad_output.kind(), clap::error::ErrorKind::InvalidValue);
    }

    #[test]
    fn jira_legacy_json_switches_are_removed() {
        for command in [
            vec![
                "agent-access",
                "jira",
                "issue",
                "comment",
                "list",
                "--issue",
                "SBC-1",
                "--json",
            ],
            vec![
                "agent-access",
                "jira",
                "issue",
                "comment",
                "property",
                "list",
                "10",
                "--issue",
                "SBC-1",
                "--json",
            ],
            vec![
                "agent-access",
                "jira",
                "issue",
                "attachment",
                "list",
                "SBC-1",
                "--json",
            ],
        ] {
            let error = Cli::try_parse_from(command).unwrap_err();
            assert_eq!(error.kind(), clap::error::ErrorKind::UnknownArgument);
        }
    }

    #[test]
    fn confluence_read_flags_follow_the_compiled_capability_matrix() {
        let embedded = [
            &["confluence", "page", "view"][..],
            &["confluence", "blog", "view"][..],
            &["confluence", "page", "draft", "view"][..],
            &["confluence", "blog", "draft", "view"][..],
            &["confluence", "page", "footer-comment", "list"][..],
            &["confluence", "page", "footer-comment", "view"][..],
            &["confluence", "page", "footer-comment", "add"][..],
            &["confluence", "page", "footer-comment", "update"][..],
            &["confluence", "page", "footer-comment", "replies"][..],
            &["confluence", "page", "footer-comment", "reply"][..],
            &["confluence", "page", "inline-comment", "list"][..],
            &["confluence", "page", "inline-comment", "view"][..],
            &["confluence", "page", "inline-comment", "update"][..],
            &["confluence", "page", "inline-comment", "replies"][..],
            &["confluence", "page", "inline-comment", "reply"][..],
            &["confluence", "blog", "footer-comment", "list"][..],
            &["confluence", "blog", "footer-comment", "view"][..],
            &["confluence", "blog", "footer-comment", "add"][..],
            &["confluence", "blog", "footer-comment", "update"][..],
            &["confluence", "blog", "footer-comment", "replies"][..],
            &["confluence", "blog", "footer-comment", "reply"][..],
            &["confluence", "blog", "inline-comment", "list"][..],
            &["confluence", "blog", "inline-comment", "view"][..],
            &["confluence", "blog", "inline-comment", "update"][..],
            &["confluence", "blog", "inline-comment", "replies"][..],
            &["confluence", "blog", "inline-comment", "reply"][..],
        ];
        for command in embedded {
            let action = confluence_action_for_cli_path(command);
            assert!(response_capabilities("confluence", &action).supports_read_content());
            assert!(
                cli_help(command).contains("--read-content-format <READ_CONTENT_FORMAT>"),
                "missing embedded-content flag on {command:?}"
            );
        }

        let whole_result = [
            &["confluence", "space", "list"][..],
            &["confluence", "page", "view"][..],
            &["confluence", "page", "search"][..],
            &["confluence", "page", "verify"][..],
            &["confluence", "blog", "view"][..],
            &["confluence", "blog", "search"][..],
            &["confluence", "blog", "verify"][..],
            &["confluence", "page", "draft", "view"][..],
            &["confluence", "page", "draft", "verify"][..],
            &["confluence", "blog", "draft", "view"][..],
            &["confluence", "blog", "draft", "verify"][..],
            &["confluence", "page", "attachment", "list"][..],
            &["confluence", "page", "draft", "attachment", "list"][..],
            &["confluence", "blog", "attachment", "list"][..],
            &["confluence", "blog", "draft", "attachment", "list"][..],
            &["confluence", "page", "footer-comment", "list"][..],
            &["confluence", "page", "footer-comment", "view"][..],
            &["confluence", "page", "footer-comment", "replies"][..],
            &["confluence", "page", "inline-comment", "list"][..],
            &["confluence", "page", "inline-comment", "view"][..],
            &["confluence", "page", "inline-comment", "replies"][..],
            &["confluence", "blog", "footer-comment", "list"][..],
            &["confluence", "blog", "footer-comment", "view"][..],
            &["confluence", "blog", "footer-comment", "replies"][..],
            &["confluence", "blog", "inline-comment", "list"][..],
            &["confluence", "blog", "inline-comment", "view"][..],
            &["confluence", "blog", "inline-comment", "replies"][..],
        ];
        for command in whole_result {
            let action = confluence_action_for_cli_path(command);
            assert!(response_capabilities("confluence", &action).supports_markdown_response());
            assert!(
                cli_help(command).contains("--output-format <OUTPUT_FORMAT>"),
                "missing whole-result flag on {command:?}"
            );
        }

        for command in [
            &["confluence", "page", "create"][..],
            &["confluence", "blog", "update"][..],
            &["confluence", "page", "draft", "publish"][..],
            &["confluence", "page", "footer-comment", "delete"][..],
            &["confluence", "blog", "attachment", "download"][..],
        ] {
            let action = confluence_action_for_cli_path(command);
            let capabilities = response_capabilities("confluence", &action);
            assert!(!capabilities.supports_read_content());
            assert!(!capabilities.supports_markdown_response());
            let help = cli_help(command);
            assert!(!help.contains("--read-content-format"));
            assert!(!help.contains("--output-format"));
        }
    }

    #[test]
    fn confluence_read_and_output_flags_parse_closed_values() {
        Cli::try_parse_from([
            "agent-access",
            "confluence",
            "page",
            "view",
            "123",
            "--read-content-format",
            "text",
            "--output-format",
            "json",
        ])
        .unwrap();
        Cli::try_parse_from([
            "agent-access",
            "confluence",
            "blog",
            "search",
            "--cql",
            "type=blogpost",
            "--output-format",
            "markdown",
        ])
        .unwrap();

        let bad_read = Cli::try_parse_from([
            "agent-access",
            "confluence",
            "page",
            "view",
            "123",
            "--read-content-format",
            "plain_text",
        ])
        .unwrap_err();
        assert_eq!(bad_read.kind(), clap::error::ErrorKind::InvalidValue);
        let unsupported = Cli::try_parse_from([
            "agent-access",
            "confluence",
            "page",
            "create",
            "--space",
            "ENG",
            "--title",
            "Title",
            "--content",
            "Body",
            "--content-format",
            "markdown",
            "--output-format",
            "markdown",
        ])
        .unwrap_err();
        assert_eq!(unsupported.kind(), clap::error::ErrorKind::UnknownArgument);
    }

    #[test]
    fn gitlab_read_flags_follow_the_compiled_capability_matrix() {
        let embedded = [
            (&["gitlab", "issue", "view"][..], "issue.view"),
            (&["gitlab", "issue", "search"][..], "issue.search"),
            (&["gitlab", "issue", "create"][..], "issue.create"),
            (&["gitlab", "issue", "update"][..], "issue.update"),
            (&["gitlab", "issue", "comment"][..], "issue.note.add"),
            (
                &["gitlab", "issue", "update-comment"][..],
                "issue.note.update",
            ),
            (&["gitlab", "issue", "list-comments"][..], "issue.note.list"),
            (&["gitlab", "issue", "view-comment"][..], "issue.note.view"),
            (
                &["gitlab", "merge-request", "view"][..],
                "merge_request.view",
            ),
            (
                &["gitlab", "merge-request", "search"][..],
                "merge_request.search",
            ),
            (
                &["gitlab", "merge-request", "create"][..],
                "merge_request.create",
            ),
            (
                &["gitlab", "merge-request", "update"][..],
                "merge_request.update",
            ),
            (
                &["gitlab", "merge-request", "comment"][..],
                "merge_request.note.add",
            ),
            (
                &["gitlab", "merge-request", "update-comment"][..],
                "merge_request.note.update",
            ),
            (
                &["gitlab", "merge-request", "list-comments"][..],
                "merge_request.note.list",
            ),
            (
                &["gitlab", "merge-request", "view-comment"][..],
                "merge_request.note.view",
            ),
            (
                &["gitlab", "merge-request", "discussion"][..],
                "merge_request.discussion.add",
            ),
            (
                &["gitlab", "merge-request", "update-discussion-note"][..],
                "merge_request.discussion.note.update",
            ),
            (
                &["gitlab", "merge-request", "resolve-discussion"][..],
                "merge_request.discussion.resolve",
            ),
            (
                &["gitlab", "merge-request", "reopen-discussion"][..],
                "merge_request.discussion.reopen",
            ),
            (
                &["gitlab", "merge-request", "list-discussions"][..],
                "merge_request.discussion.list",
            ),
            (
                &["gitlab", "merge-request", "view-discussion"][..],
                "merge_request.discussion.view",
            ),
            (
                &["gitlab", "merge-request", "inline-discussion"][..],
                "merge_request.discussion.inline.add",
            ),
            (
                &["gitlab", "merge-request", "reply-discussion"][..],
                "merge_request.discussion.note.add",
            ),
            (
                &["gitlab", "merge-request", "list-draft-notes"][..],
                "merge_request.draft_note.list",
            ),
            (
                &["gitlab", "merge-request", "view-draft-note"][..],
                "merge_request.draft_note.view",
            ),
            (
                &["gitlab", "merge-request", "add-draft-note"][..],
                "merge_request.draft_note.add",
            ),
            (
                &["gitlab", "merge-request", "update-draft-note"][..],
                "merge_request.draft_note.update",
            ),
        ];
        for (command, action) in embedded {
            assert!(response_capabilities("gitlab", action).supports_read_content());
            assert!(
                cli_help(command).contains("--read-content-format <READ_CONTENT_FORMAT>"),
                "missing embedded-content flag on {command:?}"
            );
        }

        let whole_result = [
            (&["gitlab", "project", "view"][..], "project.view"),
            (&["gitlab", "project", "search"][..], "project.search"),
            (&["gitlab", "search", "issues"][..], "search.issues"),
            (
                &["gitlab", "search", "merge-requests"][..],
                "search.merge_requests",
            ),
            (&["gitlab", "search", "code"][..], "search.code"),
            (&["gitlab", "search", "commits"][..], "search.commits"),
            (&["gitlab", "search", "wiki"][..], "search.wiki"),
            (&["gitlab", "search", "comments"][..], "search.comments"),
            (&["gitlab", "issue", "view"][..], "issue.view"),
            (&["gitlab", "issue", "search"][..], "issue.search"),
            (&["gitlab", "issue", "list-comments"][..], "issue.note.list"),
            (&["gitlab", "issue", "view-comment"][..], "issue.note.view"),
            (
                &["gitlab", "merge-request", "view"][..],
                "merge_request.view",
            ),
            (
                &["gitlab", "merge-request", "search"][..],
                "merge_request.search",
            ),
            (
                &["gitlab", "merge-request", "list-comments"][..],
                "merge_request.note.list",
            ),
            (
                &["gitlab", "merge-request", "view-comment"][..],
                "merge_request.note.view",
            ),
            (
                &["gitlab", "merge-request", "list-discussions"][..],
                "merge_request.discussion.list",
            ),
            (
                &["gitlab", "merge-request", "list-reviewers"][..],
                "merge_request.reviewer.list",
            ),
            (
                &["gitlab", "merge-request", "list-commits"][..],
                "merge_request.commit.list",
            ),
            (
                &["gitlab", "merge-request", "list-pipelines"][..],
                "merge_request.pipeline.list",
            ),
            (
                &["gitlab", "merge-request", "list-diffs"][..],
                "merge_request.diff.list",
            ),
            (
                &["gitlab", "merge-request", "list-diff-versions"][..],
                "merge_request.diff_version.list",
            ),
            (
                &["gitlab", "merge-request", "view-diff-version"][..],
                "merge_request.diff_version.view",
            ),
            (
                &["gitlab", "merge-request", "view-discussion"][..],
                "merge_request.discussion.view",
            ),
            (
                &["gitlab", "merge-request", "list-draft-notes"][..],
                "merge_request.draft_note.list",
            ),
            (
                &["gitlab", "merge-request", "view-draft-note"][..],
                "merge_request.draft_note.view",
            ),
            (
                &["gitlab", "merge-request", "view-approval"][..],
                "merge_request.approval.view",
            ),
            (
                &["gitlab", "merge-request", "view-approval-state"][..],
                "merge_request.approval_state.view",
            ),
            (
                &["gitlab", "merge-request", "list-approval-rules"][..],
                "merge_request.approval_rule.list",
            ),
            (
                &["gitlab", "merge-request", "view-approval-rule"][..],
                "merge_request.approval_rule.view",
            ),
            (&["gitlab", "branch", "list"][..], "branch.list"),
            (&["gitlab", "branch", "view"][..], "branch.view"),
            (
                &["gitlab", "protected-branch", "list"][..],
                "protected_branch.list",
            ),
            (
                &["gitlab", "protected-branch", "view"][..],
                "protected_branch.view",
            ),
            (
                &["gitlab", "protected-branch", "verify"][..],
                "protected_branch.verify",
            ),
            (&["gitlab", "file", "view"][..], "file.view"),
            (&["gitlab", "commit", "list"][..], "commit.list"),
            (&["gitlab", "commit", "view"][..], "commit.view"),
            (&["gitlab", "pipeline", "list"][..], "pipeline.list"),
            (&["gitlab", "pipeline", "view"][..], "pipeline.view"),
            (&["gitlab", "job", "list"][..], "job.list"),
            (&["gitlab", "job", "view"][..], "job.view"),
        ];
        for (command, action) in whole_result {
            assert!(response_capabilities("gitlab", action).supports_markdown_response());
            assert!(
                cli_help(command).contains("--output-format <OUTPUT_FORMAT>"),
                "missing whole-result flag on {command:?}"
            );
        }

        for (command, action) in [
            (
                &["gitlab", "issue", "delete-comment"][..],
                "issue.note.delete",
            ),
            (
                &["gitlab", "merge-request", "merge"][..],
                "merge_request.merge",
            ),
            (&["gitlab", "branch", "create"][..], "branch.create"),
            (&["gitlab", "file", "raw"][..], "file.raw.download"),
            (
                &["gitlab", "merge-request", "diff-raw"][..],
                "merge_request.diff.raw.download",
            ),
            (
                &["gitlab", "merge-request", "delete-draft-note"][..],
                "merge_request.draft_note.delete",
            ),
            (
                &["gitlab", "merge-request", "publish-draft-note"][..],
                "merge_request.draft_note.publish",
            ),
            (
                &["gitlab", "merge-request", "publish-all"][..],
                "merge_request.draft_note.publish_all",
            ),
            (
                &["gitlab", "merge-request", "submit-review"][..],
                "merge_request.review.submit",
            ),
            (
                &["gitlab", "merge-request", "approve"][..],
                "merge_request.approve",
            ),
            (
                &["gitlab", "merge-request", "unapprove"][..],
                "merge_request.unapprove",
            ),
            (
                &["gitlab", "merge-request", "apply-suggestion"][..],
                "merge_request.suggestion.apply",
            ),
            (
                &["gitlab", "merge-request", "apply-suggestions"][..],
                "merge_request.suggestion.batch_apply",
            ),
            (&["gitlab", "job", "trace"][..], "job.trace.download"),
        ] {
            let capabilities = response_capabilities("gitlab", action);
            assert!(!capabilities.supports_read_content());
            assert!(!capabilities.supports_markdown_response());
            let help = cli_help(command);
            assert!(!help.contains("--read-content-format"));
            assert!(!help.contains("--output-format"));
        }
    }

    #[test]
    fn gitlab_collection_projection_and_exact_note_commands_are_closed() {
        for args in [
            vec![
                "agent-access",
                "gitlab",
                "issue",
                "list-comments",
                "group/repo",
                "7",
                "--projection",
                "summary",
            ],
            vec![
                "agent-access",
                "gitlab",
                "merge-request",
                "list-comments",
                "group/repo",
                "5",
                "--projection",
                "summary",
            ],
            vec![
                "agent-access",
                "gitlab",
                "merge-request",
                "list-discussions",
                "group/repo",
                "5",
                "--projection",
                "summary",
            ],
            vec![
                "agent-access",
                "gitlab",
                "merge-request",
                "list-draft-notes",
                "group/repo",
                "5",
                "--projection",
                "summary",
            ],
            vec![
                "agent-access",
                "gitlab",
                "issue",
                "view-comment",
                "group/repo",
                "7",
                "701",
            ],
            vec![
                "agent-access",
                "gitlab",
                "merge-request",
                "view-comment",
                "group/repo",
                "5",
                "501",
            ],
        ] {
            Cli::try_parse_from(args).unwrap();
        }
        assert!(
            Cli::try_parse_from([
                "agent-access",
                "gitlab",
                "issue",
                "list-comments",
                "group/repo",
                "7",
                "--projection",
                "Summary",
            ])
            .is_err()
        );
    }

    #[test]
    fn gitlab_read_and_output_flags_parse_closed_values_and_default_to_ambient_resolution() {
        let parsed = Cli::try_parse_from([
            "agent-access",
            "gitlab",
            "issue",
            "view",
            "group/project",
            "7",
        ])
        .unwrap();
        assert!(matches!(
            parsed.command,
            Command::Gitlab {
                command: GitlabCommand::Issue {
                    command: GitlabIssueCommand::View {
                        response: EmbeddedAndWholeOutputArgs {
                            read_content_format: None,
                            output_format: None,
                        },
                        ..
                    }
                }
            }
        ));

        Cli::try_parse_from([
            "agent-access",
            "gitlab",
            "issue",
            "view",
            "group/project",
            "7",
            "--read-content-format",
            "text",
            "--output-format",
            "markdown",
        ])
        .unwrap();

        let bad_read = Cli::try_parse_from([
            "agent-access",
            "gitlab",
            "issue",
            "view",
            "group/project",
            "7",
            "--read-content-format",
            "plain_text",
        ])
        .unwrap_err();
        assert_eq!(bad_read.kind(), clap::error::ErrorKind::InvalidValue);

        let bad_output = Cli::try_parse_from([
            "agent-access",
            "gitlab",
            "pipeline",
            "list",
            "group/project",
            "--output-format",
            "text",
        ])
        .unwrap_err();
        assert_eq!(bad_output.kind(), clap::error::ErrorKind::InvalidValue);

        let unsupported = Cli::try_parse_from([
            "agent-access",
            "gitlab",
            "merge-request",
            "merge",
            "group/project",
            "2",
            "--sha",
            "deadbeef",
            "--output-format",
            "markdown",
        ])
        .unwrap_err();
        assert_eq!(unsupported.kind(), clap::error::ErrorKind::UnknownArgument);
    }

    #[test]
    fn gitlab_merge_request_review_read_commands_parse_closed_typed_shapes() {
        for command in [
            "list-reviewers",
            "list-commits",
            "list-pipelines",
            "list-diffs",
            "list-diff-versions",
            "list-discussions",
        ] {
            Cli::try_parse_from([
                "agent-access",
                "gitlab",
                "merge-request",
                command,
                "group/project",
                "17",
                "--max-results",
                "25",
                "--page-token",
                "next-page",
                "--output-format",
                "markdown",
            ])
            .unwrap_or_else(|error| panic!("{command} should parse: {error}"));
        }

        let diffs = Cli::try_parse_from([
            "agent-access",
            "gitlab",
            "merge-request",
            "list-diffs",
            "group/project",
            "17",
            "--unidiff",
        ])
        .unwrap();
        assert!(matches!(
            diffs.command,
            Command::Gitlab {
                command: GitlabCommand::MergeRequest {
                    command: GitlabMergeRequestCommand::ListDiffs {
                        ref project,
                        iid: 17,
                        unidiff: true,
                        max_results: None,
                        page_token: None,
                        ..
                    }
                }
            } if project == "group/project"
        ));

        let version = Cli::try_parse_from([
            "agent-access",
            "gitlab",
            "merge-request",
            "view-diff-version",
            "group/project",
            "17",
            "9",
            "--unidiff",
            "--output-format",
            "json",
        ])
        .unwrap();
        assert!(matches!(
            version.command,
            Command::Gitlab {
                command: GitlabCommand::MergeRequest {
                    command: GitlabMergeRequestCommand::ViewDiffVersion {
                        ref project,
                        iid: 17,
                        version_id: 9,
                        unidiff: true,
                        ..
                    }
                }
            } if project == "group/project"
        ));

        let discussion = Cli::try_parse_from([
            "agent-access",
            "gitlab",
            "merge-request",
            "view-discussion",
            "group/project",
            "17",
            "discussion-1",
            "--read-content-format",
            "text",
            "--output-format",
            "markdown",
        ])
        .unwrap();
        assert!(matches!(
            discussion.command,
            Command::Gitlab {
                command: GitlabCommand::MergeRequest {
                    command: GitlabMergeRequestCommand::ViewDiscussion {
                        ref project,
                        iid: 17,
                        ref discussion_id,
                        response: EmbeddedAndWholeOutputArgs {
                            read_content_format: Some(ReadContentFormatArg::Text),
                            output_format: Some(OutputFormatArg::Markdown),
                        },
                    }
                }
            } if project == "group/project" && discussion_id == "discussion-1"
        ));

        let raw = Cli::try_parse_from([
            "agent-access",
            "gitlab",
            "merge-request",
            "diff-raw",
            "group/project",
            "17",
            "--output",
            "-",
        ])
        .unwrap();
        assert!(matches!(
            raw.command,
            Command::Gitlab {
                command: GitlabCommand::MergeRequest {
                    command: GitlabMergeRequestCommand::DiffRaw {
                        ref project,
                        iid: 17,
                    }
                }
            } if project == "group/project" && raw.output.as_deref() == Some(Path::new("-"))
        ));

        let unsupported = Cli::try_parse_from([
            "agent-access",
            "gitlab",
            "merge-request",
            "diff-raw",
            "group/project",
            "17",
            "--output",
            "diff.patch",
            "--output-format",
            "json",
        ])
        .unwrap_err();
        assert_eq!(unsupported.kind(), clap::error::ErrorKind::UnknownArgument);
    }

    #[test]
    fn gitlab_merge_request_review_read_inputs_lower_to_canonical_fields() {
        assert_eq!(
            gitlab_merge_request_inputs("group/project", 17),
            serde_json::json!({
                "project": "group/project",
                "iid": 17
            })
        );
        assert_eq!(
            gitlab_merge_request_list_inputs("group/project", 17, Some(25), Some("next-page")),
            serde_json::json!({
                "project": "group/project",
                "iid": 17,
                "maxResults": 25,
                "pageToken": "next-page"
            })
        );
        assert_eq!(
            gitlab_merge_request_list_inputs("group/project", 17, None, None),
            serde_json::json!({
                "project": "group/project",
                "iid": 17
            })
        );
        assert_eq!(
            gitlab_merge_request_diff_list_inputs(
                "group/project",
                17,
                true,
                Some(10),
                Some("diff-page")
            ),
            serde_json::json!({
                "project": "group/project",
                "iid": 17,
                "unidiff": true,
                "maxResults": 10,
                "pageToken": "diff-page"
            })
        );
        assert_eq!(
            gitlab_merge_request_diff_list_inputs("group/project", 17, false, None, None),
            serde_json::json!({
                "project": "group/project",
                "iid": 17
            })
        );
        assert_eq!(
            gitlab_merge_request_diff_version_inputs("group/project", 17, 9, true),
            serde_json::json!({
                "project": "group/project",
                "iid": 17,
                "diffVersionId": 9,
                "unidiff": true
            })
        );
        assert_eq!(
            gitlab_merge_request_discussion_view_inputs("group/project", 17, "discussion-1"),
            serde_json::json!({
                "project": "group/project",
                "iid": 17,
                "discussionId": "discussion-1"
            })
        );
    }

    #[test]
    fn gitlab_m3_review_commands_parse_closed_typed_shapes() {
        for command in [
            vec![
                "agent-access",
                "gitlab",
                "merge-request",
                "view-approval",
                "group/project",
                "17",
                "--output-format",
                "markdown",
            ],
            vec![
                "agent-access",
                "gitlab",
                "merge-request",
                "view-approval-state",
                "group/project",
                "17",
            ],
            vec![
                "agent-access",
                "gitlab",
                "merge-request",
                "list-approval-rules",
                "group/project",
                "17",
                "--max-results",
                "20",
                "--page-token",
                "next",
            ],
            vec![
                "agent-access",
                "gitlab",
                "merge-request",
                "view-approval-rule",
                "group/project",
                "17",
                "9",
            ],
            vec![
                "agent-access",
                "gitlab",
                "merge-request",
                "approve",
                "group/project",
                "17",
                "--head-sha",
                "0123456789012345678901234567890123456789",
            ],
            vec![
                "agent-access",
                "gitlab",
                "merge-request",
                "unapprove",
                "group/project",
                "17",
            ],
            vec![
                "agent-access",
                "gitlab",
                "merge-request",
                "apply-suggestion",
                "group/project",
                "17",
                "discussion-1",
                "123",
                "456",
                "--expected-head-sha",
                "0123456789012345678901234567890123456789",
                "--commit-message",
                "Apply suggestion %{suggestions_count}",
            ],
            vec![
                "agent-access",
                "gitlab",
                "merge-request",
                "apply-suggestions",
                "group/project",
                "17",
                "--suggestions-file",
                "suggestions.json",
                "--expected-head-sha",
                "0123456789012345678901234567890123456789",
                "--commit-message-file",
                "message.txt",
            ],
        ] {
            Cli::try_parse_from(command).expect("M3 GitLab review command should parse");
        }

        let approve = Cli::try_parse_from([
            "agent-access",
            "gitlab",
            "merge-request",
            "approve",
            "group/project",
            "17",
            "--head-sha",
            "0123456789012345678901234567890123456789",
        ])
        .unwrap();
        assert!(matches!(
            approve.command,
            Command::Gitlab {
                command: GitlabCommand::MergeRequest {
                    command: GitlabMergeRequestCommand::Approve { .. }
                }
            }
        ));
    }

    #[test]
    fn gitlab_m3_review_inputs_lower_only_canonical_fields() {
        assert_eq!(
            gitlab_approval_rule_inputs("group/project", 17, 9),
            serde_json::json!({
                "project": "group/project", "iid": 17, "approvalRuleId": 9
            })
        );
        assert_eq!(
            gitlab_approve_inputs(
                "group/project",
                17,
                "0123456789012345678901234567890123456789"
            ),
            serde_json::json!({
                "project": "group/project", "iid": 17,
                "headSha": "0123456789012345678901234567890123456789"
            })
        );

        let commit = GitlabOptionalCommitMessageArgs {
            commit_message: Some("Apply %{suggestions_count}".to_string()),
            commit_message_file: None,
        };
        assert_eq!(
            gitlab_suggestion_apply_inputs(
                "group/project",
                17,
                "0123456789012345678901234567890123456789",
                "discussion-1",
                123,
                456,
                &commit,
            ),
            serde_json::json!({
                "project": "group/project", "iid": 17,
                "expectedHeadSha": "0123456789012345678901234567890123456789",
                "discussionId": "discussion-1", "noteId": 123, "suggestionId": 456,
                "commitMessage": "Apply %{suggestions_count}"
            })
        );

        let suggestions_path = std::env::temp_dir().join(format!(
            "agent-access-gitlab-suggestions-{}.json",
            std::process::id()
        ));
        std::fs::write(
            &suggestions_path,
            br#"[{"discussionId":"discussion-1","noteId":123,"suggestionId":456}]"#,
        )
        .unwrap();
        let batch = gitlab_suggestion_batch_apply_inputs(
            "group/project",
            17,
            "0123456789012345678901234567890123456789",
            &suggestions_path,
            &GitlabOptionalCommitMessageArgs::default(),
        )
        .unwrap();
        std::fs::remove_file(suggestions_path).unwrap();
        assert_eq!(
            batch,
            serde_json::json!({
                "project": "group/project", "iid": 17,
                "expectedHeadSha": "0123456789012345678901234567890123456789",
                "suggestions": [{
                    "discussionId": "discussion-1", "noteId": 123, "suggestionId": 456
                }]
            })
        );
    }

    #[test]
    fn gitlab_m3_review_cli_rejects_legacy_and_contradictory_shapes() {
        for command in [
            vec![
                "agent-access",
                "gitlab",
                "merge-request",
                "approve",
                "group/project",
                "17",
            ],
            vec![
                "agent-access",
                "gitlab",
                "merge-request",
                "approve",
                "group/project",
                "17",
                "--sha",
                "0123456789012345678901234567890123456789",
            ],
            vec![
                "agent-access",
                "gitlab",
                "merge-request",
                "approve",
                "group/project",
                "17",
                "--head-sha",
                "0123456789012345678901234567890123456789",
                "--approval-password",
                "secret",
            ],
            vec![
                "agent-access",
                "gitlab",
                "merge-request",
                "apply-suggestions",
                "group/project",
                "17",
                "--expected-head-sha",
                "0123456789012345678901234567890123456789",
                "--suggestions-json",
                "[]",
            ],
            vec![
                "agent-access",
                "gitlab",
                "merge-request",
                "apply-suggestion",
                "group/project",
                "17",
                "discussion-1",
                "123",
                "456",
                "--expected-head-sha",
                "0123456789012345678901234567890123456789",
                "--commit-message",
                "one",
                "--commit-message-file",
                "message.txt",
            ],
        ] {
            assert!(
                Cli::try_parse_from(command).is_err(),
                "noncanonical M3 GitLab review shape should be rejected"
            );
        }
    }

    fn required_gitlab_body(content: &str) -> GitlabRequiredContentArgs {
        GitlabRequiredContentArgs {
            content: Some(content.to_string()),
            content_file: None,
            content_format: Some(GitlabContentFormatArg::Markdown),
        }
    }

    fn optional_gitlab_body(content: Option<&str>) -> GitlabOptionalContentArgs {
        GitlabOptionalContentArgs {
            content: content.map(ToString::to_string),
            content_file: None,
            content_format: content.map(|_| GitlabContentFormatArg::PlainText),
        }
    }

    fn gitlab_text_position(old_line: Option<u64>, new_line: Option<u64>) -> GitlabPositionArgs {
        GitlabPositionArgs {
            position_type: Some(GitlabPositionTypeArg::Text),
            old_path: Some("src/old.rs".to_string()),
            new_path: Some("src/new.rs".to_string()),
            old_line,
            new_line,
            ..GitlabPositionArgs::default()
        }
    }

    #[test]
    fn gitlab_merge_request_review_mutation_commands_parse_typed_shapes() {
        for command in [
            vec![
                "agent-access",
                "gitlab",
                "merge-request",
                "inline-discussion",
                "group/project",
                "17",
                "--expected-head-sha",
                "0123456789012345678901234567890123456789",
                "--position-type",
                "text",
                "--old-path",
                "src/lib.rs",
                "--new-path",
                "src/lib.rs",
                "--new-line",
                "42",
                "--content",
                "Please simplify this.",
                "--content-format",
                "markdown",
                "--read-content-format",
                "text",
            ],
            vec![
                "agent-access",
                "gitlab",
                "merge-request",
                "reply-discussion",
                "group/project",
                "17",
                "discussion-1",
                "--content",
                "Fixed.",
                "--content-format",
                "plain_text",
            ],
            vec![
                "agent-access",
                "gitlab",
                "merge-request",
                "list-draft-notes",
                "group/project",
                "17",
                "--max-results",
                "20",
                "--page-token",
                "next",
                "--read-content-format",
                "markdown",
                "--output-format",
                "json",
            ],
            vec![
                "agent-access",
                "gitlab",
                "merge-request",
                "view-draft-note",
                "group/project",
                "17",
                "8",
                "--output-format",
                "markdown",
            ],
            vec![
                "agent-access",
                "gitlab",
                "merge-request",
                "add-draft-note",
                "group/project",
                "17",
                "--content",
                "General draft",
                "--content-format",
                "markdown",
            ],
            vec![
                "agent-access",
                "gitlab",
                "merge-request",
                "add-draft-note",
                "group/project",
                "17",
                "--expected-head-sha",
                "0123456789012345678901234567890123456789",
                "--position-file",
                "position.json",
                "--content",
                "Positioned draft",
                "--content-format",
                "markdown",
            ],
            vec![
                "agent-access",
                "gitlab",
                "merge-request",
                "add-draft-note",
                "group/project",
                "17",
                "--in-reply-to-discussion-id",
                "discussion-1",
                "--resolve-discussion",
                "true",
                "--content",
                "Resolved by this change.",
                "--content-format",
                "plain_text",
            ],
            vec![
                "agent-access",
                "gitlab",
                "merge-request",
                "update-draft-note",
                "group/project",
                "17",
                "8",
                "--content",
                "Updated draft",
                "--content-format",
                "markdown",
            ],
            vec![
                "agent-access",
                "gitlab",
                "merge-request",
                "update-draft-note",
                "group/project",
                "17",
                "8",
                "--expected-head-sha",
                "0123456789012345678901234567890123456789",
                "--position-type",
                "file",
                "--old-path",
                "src/lib.rs",
                "--new-path",
                "src/lib.rs",
            ],
            vec![
                "agent-access",
                "gitlab",
                "merge-request",
                "delete-draft-note",
                "group/project",
                "17",
                "8",
            ],
            vec![
                "agent-access",
                "gitlab",
                "merge-request",
                "publish-draft-note",
                "group/project",
                "17",
                "8",
            ],
            vec![
                "agent-access",
                "gitlab",
                "merge-request",
                "publish-all",
                "group/project",
                "17",
                "--content",
                "Review summary",
                "--content-format",
                "markdown",
                "--internal",
                "false",
            ],
            vec![
                "agent-access",
                "gitlab",
                "merge-request",
                "submit-review",
                "group/project",
                "17",
                "--reviewer-state",
                "requested-changes",
            ],
        ] {
            Cli::try_parse_from(command).expect("M2 GitLab review command should parse");
        }

        let submit = Cli::try_parse_from([
            "agent-access",
            "gitlab",
            "merge-request",
            "submit-review",
            "group/project",
            "17",
            "--reviewer-state",
            "reviewed",
        ])
        .unwrap();
        assert!(matches!(
            submit.command,
            Command::Gitlab {
                command: GitlabCommand::MergeRequest {
                    command: GitlabMergeRequestCommand::SubmitReview {
                        reviewer_state: GitlabReviewerStateArg::Reviewed,
                        ..
                    }
                }
            }
        ));
    }

    #[test]
    fn gitlab_position_flags_lower_every_canonical_position_category() {
        for (position, expected) in [
            (
                gitlab_text_position(None, Some(42)),
                serde_json::json!({
                    "positionType": "text", "oldPath": "src/old.rs",
                    "newPath": "src/new.rs", "newLine": 42
                }),
            ),
            (
                gitlab_text_position(Some(41), None),
                serde_json::json!({
                    "positionType": "text", "oldPath": "src/old.rs",
                    "newPath": "src/new.rs", "oldLine": 41
                }),
            ),
            (
                gitlab_text_position(Some(41), Some(42)),
                serde_json::json!({
                    "positionType": "text", "oldPath": "src/old.rs",
                    "newPath": "src/new.rs", "oldLine": 41, "newLine": 42
                }),
            ),
        ] {
            assert_eq!(
                gitlab_position_value(&position, true, "test").unwrap(),
                Some(expected)
            );
        }

        let multiline = GitlabPositionArgs {
            position_type: Some(GitlabPositionTypeArg::Text),
            old_path: Some("src/lib.rs".to_string()),
            new_path: Some("src/lib.rs".to_string()),
            range_start_old_line: Some(39),
            range_start_new_line: Some(40),
            range_end_old_line: Some(43),
            range_end_new_line: Some(44),
            ..GitlabPositionArgs::default()
        };
        assert_eq!(
            gitlab_position_value(&multiline, true, "test").unwrap(),
            Some(serde_json::json!({
                "positionType": "text",
                "oldPath": "src/lib.rs",
                "newPath": "src/lib.rs",
                "lineRange": {
                    "start": {"oldLine": 39, "newLine": 40},
                    "end": {"oldLine": 43, "newLine": 44}
                }
            }))
        );

        let file = GitlabPositionArgs {
            position_type: Some(GitlabPositionTypeArg::File),
            old_path: Some("old.png".to_string()),
            new_path: Some("new.png".to_string()),
            ..GitlabPositionArgs::default()
        };
        assert_eq!(
            gitlab_position_value(&file, true, "test").unwrap(),
            Some(serde_json::json!({
                "positionType": "file", "oldPath": "old.png", "newPath": "new.png"
            }))
        );

        let image = GitlabPositionArgs {
            position_type: Some(GitlabPositionTypeArg::Image),
            old_path: Some("old.png".to_string()),
            new_path: Some("new.png".to_string()),
            position_width: Some(800),
            position_height: Some(600),
            position_x: Some(12),
            position_y: Some(24),
            ..GitlabPositionArgs::default()
        };
        assert_eq!(
            gitlab_position_value(&image, true, "test").unwrap(),
            Some(serde_json::json!({
                "positionType": "image", "oldPath": "old.png", "newPath": "new.png",
                "width": 800, "height": 600, "x": 12, "y": 24
            }))
        );

        let position_path = std::env::temp_dir().join(format!(
            "agent-access-gitlab-position-{}.json",
            Uuid::new_v4()
        ));
        fs::write(
            &position_path,
            r#"{"positionType":"file","oldPath":"src/lib.rs","newPath":"src/lib.rs"}"#,
        )
        .unwrap();
        let from_file = GitlabPositionArgs {
            position_file: Some(position_path.clone()),
            ..GitlabPositionArgs::default()
        };
        assert_eq!(
            gitlab_position_value(&from_file, true, "test").unwrap(),
            Some(serde_json::json!({
                "positionType": "file", "oldPath": "src/lib.rs", "newPath": "src/lib.rs"
            }))
        );
        fs::remove_file(position_path).unwrap();
    }

    #[test]
    fn gitlab_review_mutations_lower_only_canonical_closed_fields() {
        let position = gitlab_text_position(None, Some(42));
        let body = required_gitlab_body("Please simplify this.");
        assert_eq!(
            gitlab_inline_discussion_inputs(
                "group/project",
                17,
                "0123456789012345678901234567890123456789",
                &position,
                &body,
            )
            .unwrap(),
            serde_json::json!({
                "project": "group/project",
                "iid": 17,
                "expectedHeadSha": "0123456789012345678901234567890123456789",
                "position": {
                    "positionType": "text", "oldPath": "src/old.rs",
                    "newPath": "src/new.rs", "newLine": 42
                },
                "content": "Please simplify this.",
                "contentFormat": "markdown"
            })
        );
        assert_eq!(
            gitlab_discussion_reply_inputs("group/project", 17, "discussion-1", &body).unwrap(),
            serde_json::json!({
                "project": "group/project", "iid": 17,
                "discussionId": "discussion-1",
                "content": "Please simplify this.", "contentFormat": "markdown"
            })
        );
        assert_eq!(
            gitlab_draft_note_add_inputs(
                "group/project",
                17,
                None,
                Some("discussion-1"),
                Some(true),
                &GitlabPositionArgs::default(),
                &body,
            )
            .unwrap(),
            serde_json::json!({
                "project": "group/project", "iid": 17,
                "inReplyToDiscussionId": "discussion-1", "resolveDiscussion": true,
                "content": "Please simplify this.", "contentFormat": "markdown"
            })
        );
        assert_eq!(
            gitlab_draft_note_update_inputs(
                "group/project",
                17,
                8,
                None,
                &GitlabPositionArgs::default(),
                &optional_gitlab_body(Some("Updated")),
            )
            .unwrap(),
            serde_json::json!({
                "project": "group/project", "iid": 17, "draftNoteId": 8,
                "content": "Updated", "contentFormat": "plain_text"
            })
        );
        assert_eq!(
            gitlab_draft_note_update_inputs(
                "group/project",
                17,
                8,
                Some("0123456789012345678901234567890123456789"),
                &GitlabPositionArgs {
                    position_type: Some(GitlabPositionTypeArg::File),
                    old_path: Some("src/lib.rs".to_string()),
                    new_path: Some("src/lib.rs".to_string()),
                    ..GitlabPositionArgs::default()
                },
                &GitlabOptionalContentArgs::default(),
            )
            .unwrap(),
            serde_json::json!({
                "project": "group/project", "iid": 17, "draftNoteId": 8,
                "expectedHeadSha": "0123456789012345678901234567890123456789",
                "position": {
                    "positionType": "file", "oldPath": "src/lib.rs", "newPath": "src/lib.rs"
                }
            })
        );
        assert_eq!(
            gitlab_draft_note_object_inputs("group/project", 17, 8),
            serde_json::json!({"project": "group/project", "iid": 17, "draftNoteId": 8})
        );
        assert_eq!(
            gitlab_publish_all_inputs(
                "group/project",
                17,
                Some(GitlabReviewerStateArg::RequestedChanges),
                &optional_gitlab_body(Some("Summary")),
                Some(false),
            )
            .unwrap(),
            serde_json::json!({
                "project": "group/project", "iid": 17,
                "content": "Summary", "contentFormat": "plain_text", "internal": false,
                "reviewerState": "requestedChanges"
            })
        );
    }

    #[test]
    fn gitlab_review_cli_rejects_noncanonical_and_contradictory_shapes() {
        for legacy_command in ["diff-discussion", "bulk-publish", "publish-drafts"] {
            let error =
                Cli::try_parse_from(["agent-access", "gitlab", "merge-request", legacy_command])
                    .unwrap_err();
            assert_eq!(error.kind(), clap::error::ErrorKind::InvalidSubcommand);
        }

        let invalid_state = Cli::try_parse_from([
            "agent-access",
            "gitlab",
            "merge-request",
            "submit-review",
            "group/project",
            "17",
            "--reviewer-state",
            "requestedChanges",
        ])
        .unwrap_err();
        assert_eq!(invalid_state.kind(), clap::error::ErrorKind::InvalidValue);

        for (position_x, position_y) in [("12.5", "24"), ("12", "24.5")] {
            let error = Cli::try_parse_from([
                "agent-access",
                "gitlab",
                "merge-request",
                "inline-discussion",
                "group/project",
                "17",
                "--expected-head-sha",
                "0123456789012345678901234567890123456789",
                "--position-type",
                "image",
                "--old-path",
                "old.png",
                "--new-path",
                "new.png",
                "--position-width",
                "800",
                "--position-height",
                "600",
                "--position-x",
                position_x,
                "--position-y",
                position_y,
                "--content",
                "Body",
                "--content-format",
                "markdown",
            ])
            .unwrap_err();
            assert_eq!(error.kind(), clap::error::ErrorKind::ValueValidation);
        }

        let incomplete_position = Cli::try_parse_from([
            "agent-access",
            "gitlab",
            "merge-request",
            "inline-discussion",
            "group/project",
            "17",
            "--expected-head-sha",
            "0123456789012345678901234567890123456789",
            "--content",
            "Body",
            "--content-format",
            "markdown",
        ])
        .unwrap_err();
        assert_eq!(
            incomplete_position.kind(),
            clap::error::ErrorKind::MissingRequiredArgument
        );

        let conflicting_position_sources = Cli::try_parse_from([
            "agent-access",
            "gitlab",
            "merge-request",
            "inline-discussion",
            "group/project",
            "17",
            "--expected-head-sha",
            "0123456789012345678901234567890123456789",
            "--position-file",
            "position.json",
            "--position-type",
            "file",
            "--old-path",
            "src/lib.rs",
            "--new-path",
            "src/lib.rs",
            "--content",
            "Body",
            "--content-format",
            "markdown",
        ])
        .unwrap_err();
        assert_eq!(
            conflicting_position_sources.kind(),
            clap::error::ErrorKind::ArgumentConflict
        );

        assert!(gitlab_position_value(&gitlab_text_position(None, None), true, "test").is_err());
        let mut contradictory = gitlab_text_position(None, Some(4));
        contradictory.range_start_new_line = Some(3);
        contradictory.range_end_new_line = Some(4);
        assert!(gitlab_position_value(&contradictory, true, "test").is_err());
        assert!(
            gitlab_draft_note_update_inputs(
                "group/project",
                17,
                8,
                None,
                &GitlabPositionArgs::default(),
                &GitlabOptionalContentArgs::default(),
            )
            .is_err()
        );
        assert!(
            gitlab_publish_all_inputs(
                "group/project",
                17,
                None,
                &GitlabOptionalContentArgs::default(),
                Some(true),
            )
            .is_err()
        );
    }

    #[test]
    fn gitlab_review_cli_help_exposes_canonical_position_and_review_flags() {
        let inline = cli_help(&["gitlab", "merge-request", "inline-discussion"]);
        for flag in [
            "--expected-head-sha",
            "--position-file",
            "--position-type",
            "--old-path",
            "--new-path",
            "--old-line",
            "--new-line",
            "--range-start-old-line",
            "--range-end-new-line",
            "--position-width",
            "--content-format",
        ] {
            assert!(inline.contains(flag), "inline help omitted {flag}");
        }
        assert!(inline.contains("--position-x <POSITION_X>"));
        assert!(inline.contains("--position-y <POSITION_Y>"));
        assert!(inline.contains("horizontal image coordinate (non-negative integer)"));
        assert!(inline.contains("vertical image coordinate (non-negative integer)"));
        assert!(!inline.contains("anchor-token"));
        assert!(!inline.contains("base-sha"));
        assert!(!inline.contains("line-code"));

        let submit = cli_help(&["gitlab", "merge-request", "submit-review"]);
        assert!(submit.contains("--reviewer-state <REVIEWER_STATE>"));
        assert!(submit.contains("reviewed"));
        assert!(submit.contains("requested-changes"));
        assert!(submit.contains("--internal <INTERNAL>"));
    }

    #[test]
    fn confluence_legacy_json_switches_are_removed() {
        for command in [
            vec![
                "agent-access",
                "confluence",
                "page",
                "attachment",
                "list",
                "123",
                "--json",
            ],
            vec![
                "agent-access",
                "confluence",
                "blog",
                "attachment",
                "list",
                "456",
                "--json",
            ],
            vec![
                "agent-access",
                "confluence",
                "page",
                "draft",
                "attachment",
                "list",
                "123",
                "--draft-handle",
                "draft-1",
                "--json",
            ],
            vec![
                "agent-access",
                "confluence",
                "blog",
                "draft",
                "attachment",
                "list",
                "456",
                "--draft-handle",
                "draft-2",
                "--json",
            ],
        ] {
            let error = Cli::try_parse_from(command).unwrap_err();
            assert_eq!(error.kind(), clap::error::ErrorKind::UnknownArgument);
        }
    }

    #[test]
    fn response_option_resolution_obeys_precedence_and_capabilities() {
        let settings =
            response_test_settings(ReadContentFormat::Markdown, ResponseFormat::Markdown);
        let ambient_conflict =
            resolve_response_options(&settings, None, None, true, true, "jira.issue.view")
                .unwrap_err();
        assert!(format!("{ambient_conflict:#}").contains("explicitly select --output-format"));

        let explicit_whole = resolve_response_options(
            &settings,
            None,
            Some(OutputFormatArg::Markdown),
            true,
            true,
            "jira.issue.view",
        )
        .unwrap();
        assert_eq!(
            explicit_whole.read_content_format,
            ReadContentFormat::Native
        );
        assert_eq!(explicit_whole.response_format, ResponseFormat::Markdown);

        let explicit = resolve_response_options(
            &settings,
            Some(ReadContentFormatArg::Text),
            Some(OutputFormatArg::Json),
            true,
            true,
            "jira.issue.view",
        )
        .unwrap();
        assert_eq!(explicit.read_content_format, ReadContentFormat::Text);
        assert_eq!(explicit.response_format, ResponseFormat::Json);

        let embedded_only =
            resolve_response_options(&settings, None, None, true, false, "jira.issue.create")
                .unwrap();
        assert_eq!(
            embedded_only.read_content_format,
            ReadContentFormat::Markdown
        );
        assert_eq!(embedded_only.response_format, ResponseFormat::Json);

        let omitted =
            resolve_response_options(&settings, None, None, false, false, "jira.comment.delete")
                .unwrap();
        assert_eq!(omitted, ResponseOptions::default());

        let unsupported = resolve_response_options(
            &settings,
            Some(ReadContentFormatArg::Text),
            Some(OutputFormatArg::Json),
            false,
            false,
            "jira.comment.delete",
        )
        .unwrap_err();
        assert!(format!("{unsupported:#}").contains("does not support --read-content-format"));
    }

    #[test]
    fn mutation_verification_failure_remains_an_error_envelope() {
        let typed = Cli::try_parse_from([
            "agent-access",
            "gitlab",
            "merge-request",
            "inline-discussion",
            "group/project",
            "17",
            "--expected-head-sha",
            "0123456789012345678901234567890123456789",
            "--position-type",
            "text",
            "--old-path",
            "src/lib.rs",
            "--new-path",
            "src/lib.rs",
            "--new-line",
            "42",
            "--content",
            "secret review body",
            "--content-format",
            "markdown",
        ])
        .unwrap();
        assert!(matches!(
            typed.command,
            Command::Gitlab {
                command: GitlabCommand::MergeRequest {
                    command: GitlabMergeRequestCommand::InlineDiscussion { .. }
                }
            }
        ));

        let envelope = serde_json::json!({
            "agentRequestId": "agent-request-1",
            "brokerRequestId": "broker-request-1",
            "decision": "error",
            "service": "gitlab",
            "action": "merge_request.discussion.inline.add",
            "resourceScopes": {"repository": ["group/project"]},
            "reasonCode": "mutation_verification_failed",
            "result": {
                "mutationStatus": "applied_unverified",
                "retrySafe": false,
                "verificationStage": "mutation_readback",
                "safeLocators": {"discussionId": "discussion-1", "noteId": 12}
            },
            "error": {"message": "upstream mutation could not be fully verified"}
        });
        assert_eq!(cli_exit_code_for_http_status(409), 2);
        assert!(response_shape_valid(
            409,
            ResponseShape::Envelope,
            &envelope
        ));
        assert!(is_mutation_verification_failure(&envelope));
        assert_eq!(markdown_result_value(&envelope).unwrap(), None);
        validate_embedded_invoke_result(&envelope, ReadContentFormat::Markdown, &[], &[]).unwrap();
        assert_eq!(
            envelope["result"]["safeLocators"],
            serde_json::json!({"discussionId": "discussion-1", "noteId": 12})
        );
        let rendered = serde_json::to_string_pretty(&envelope).unwrap();
        assert!(rendered.contains("mutation_verification_failed"));
        assert!(rendered.contains("mutation_readback"));
        assert!(rendered.contains("safeLocators"));
        for secret in [
            "secret review body",
            "src/lib.rs",
            "0123456789012345678901234567890123456789",
            "access-token",
        ] {
            assert!(!rendered.contains(secret));
        }
    }

    #[test]
    fn positioned_input_invalid_categories_remain_closed_error_results() {
        for category in ["coordinates_unresolved", "patch_unavailable"] {
            let envelope = serde_json::json!({
                "agentRequestId": "agent-request-2",
                "brokerRequestId": "broker-request-2",
                "decision": "deny",
                "service": "gitlab",
                "action": "merge_request.discussion.inline.add",
                "resourceScopes": {"repository": ["group/project"]},
                "reasonCode": "input_invalid",
                "result": {"inputCategory": category},
                "error": {"message": "position could not be constructed"}
            });
            assert_eq!(cli_exit_code_for_http_status(400), 3);
            assert!(response_shape_valid(
                400,
                ResponseShape::Envelope,
                &envelope
            ));
            assert!(!is_mutation_verification_failure(&envelope));
            assert_eq!(markdown_result_value(&envelope).unwrap(), None);
            validate_embedded_invoke_result(&envelope, ReadContentFormat::Markdown, &[], &[])
                .unwrap();
            assert_eq!(
                envelope["result"],
                serde_json::json!({"inputCategory": category})
            );
            let rendered = serde_json::to_string_pretty(&envelope).unwrap();
            assert!(rendered.contains(category));
            assert!(!rendered.contains("src/lib.rs"));
            assert!(!rendered.contains("secret review body"));
        }
    }

    fn owners(pointers: &[&str]) -> Vec<String> {
        pointers
            .iter()
            .map(|pointer| (*pointer).to_string())
            .collect()
    }

    #[test]
    fn embedded_result_validation_checks_companions_at_declared_owners() {
        let issue = serde_json::json!({
            "decision": "allow",
            "result": {
                "key": "SBC-1",
                "description": {"type": "doc", "version": 1, "content": []},
                "renderedBody": {"format": "markdown", "value": ""}
            }
        });
        validate_embedded_invoke_result(
            &issue,
            ReadContentFormat::Markdown,
            &owners(&["/result"]),
            &[],
        )
        .unwrap();

        let comments = serde_json::json!({
            "decision": "allow",
            "result": {
                "comments": [
                    {"body": {"type": "doc", "version": 1, "content": []},
                     "renderedBody": {"format": "text", "value": "body"}},
                    {"commentId": "11"}
                ]
            }
        });
        let comment_owners = owners(&["/result/comments/*"]);
        validate_embedded_invoke_result(&comments, ReadContentFormat::Text, &comment_owners, &[])
            .unwrap();

        for (result, expected) in [
            (
                serde_json::json!({"comments": [{"renderedBody": {"format": "text"}}]}),
                "missing renderedBody.value",
            ),
            (
                serde_json::json!({"comments": [{"renderedBody": "text"}]}),
                "renderedBody that is not an object",
            ),
            (
                serde_json::json!({"comments": [{"renderedBody": {"format": "markdown", "value": ""}}]}),
                "invalid renderedBody format",
            ),
            (
                serde_json::json!({"comments": ["not an owner"]}),
                "body owner is not an object",
            ),
            (
                serde_json::json!({"comments": {"0": {}}}),
                "body collection is not an array",
            ),
            (serde_json::json!({}), "missing body owner field comments"),
        ] {
            let envelope = serde_json::json!({"decision": "allow", "result": result});
            let error = validate_embedded_invoke_result(
                &envelope,
                ReadContentFormat::Text,
                &comment_owners,
                &[],
            )
            .unwrap_err()
            .to_string();
            assert!(error.contains(expected), "{error} lacks {expected}");
        }
    }

    #[test]
    fn embedded_result_validation_only_skips_declared_optional_missing_fields() {
        let body_owners = owners(&["/result", "/result/commentPage/comments/*"]);
        let optional_prefixes = owners(&["/result/commentPage"]);
        for result in [
            serde_json::json!({"key": "PROJ-1"}),
            serde_json::json!({"commentPage": {"comments": []}}),
            serde_json::json!({"commentPage": {"comments": [
                {"renderedBody": {"format": "text", "value": "reply"}}
            ]}}),
        ] {
            let envelope = serde_json::json!({"decision": "allow", "result": result});
            validate_embedded_invoke_result(
                &envelope,
                ReadContentFormat::Text,
                &body_owners,
                &optional_prefixes,
            )
            .unwrap();
        }

        for (result, expected) in [
            (
                serde_json::json!({"commentPage": null}),
                "body owner parent is not an object",
            ),
            (
                serde_json::json!({"commentPage": {}}),
                "missing body owner field comments",
            ),
            (
                serde_json::json!({"commentPage": {"comments": null}}),
                "body collection is not an array",
            ),
            (
                serde_json::json!({"commentPage": {"comments": [null]}}),
                "body owner is not an object",
            ),
            (
                serde_json::json!({"commentPage": {"comments": [
                    {"renderedBody": {"format": "text"}}
                ]}}),
                "missing renderedBody.value",
            ),
        ] {
            let envelope = serde_json::json!({"decision": "allow", "result": result});
            let error = validate_embedded_invoke_result(
                &envelope,
                ReadContentFormat::Text,
                &body_owners,
                &optional_prefixes,
            )
            .unwrap_err()
            .to_string();
            assert!(error.contains(expected), "{error} lacks {expected}");
        }

        // An optional descendant cannot make its required parent optional.
        let error = validate_embedded_invoke_result(
            &serde_json::json!({"decision": "allow"}),
            ReadContentFormat::Text,
            &body_owners,
            &optional_prefixes,
        )
        .unwrap_err();
        assert!(
            error
                .to_string()
                .contains("missing body owner field result")
        );

        // Match encoded wildcard paths exactly, without treating adjacent fields as optional.
        let nested_owners = owners(&["/result/items/*/optional~1body"]);
        let nested_optional = owners(&["/result/items/*/optional~1body"]);
        let envelope = serde_json::json!({"decision": "allow", "result": {"items": [
            {}, {"optional/body": {"renderedBody": {"format": "text", "value": "body"}}}
        ]}});
        validate_embedded_invoke_result(
            &envelope,
            ReadContentFormat::Text,
            &nested_owners,
            &nested_optional,
        )
        .unwrap();
    }

    #[test]
    fn embedded_result_validation_ignores_renderedbody_keys_inside_native_content() {
        let issue = serde_json::json!({
            "decision": "allow",
            "result": {
                "key": "SBC-1",
                "description": {
                    "type": "doc",
                    "version": 1,
                    "content": [{
                        "type": "extension",
                        "attrs": {
                            "extensionKey": "macro",
                            "parameters": {"renderedBody": "foo"}
                        }
                    }]
                },
                "fields": {"renderedBody": 7},
                "renderedBody": {"format": "markdown", "value": "macro"}
            }
        });
        validate_embedded_invoke_result(
            &issue,
            ReadContentFormat::Markdown,
            &owners(&["/result"]),
            &[],
        )
        .unwrap();
    }

    #[test]
    fn embedded_result_validation_preserves_native_and_error_envelopes() {
        let unnormalized = serde_json::json!({
            "decision": "allow",
            "result": {"renderedBody": "not checked in native mode"}
        });
        validate_embedded_invoke_result(
            &unnormalized,
            ReadContentFormat::Native,
            &owners(&["/result"]),
            &[],
        )
        .unwrap();

        let denied = serde_json::json!({
            "decision": "deny",
            "error": {"reasonCode": "right_missing", "message": "denied"}
        });
        validate_embedded_invoke_result(
            &denied,
            ReadContentFormat::Markdown,
            &owners(&["/result"]),
            &[],
        )
        .unwrap();
    }

    #[test]
    fn generic_invoke_catalog_fetch_gate_has_zero_requests_at_defaults() {
        assert!(!generic_invoke_needs_catalog(
            ReadContentFormat::Native,
            ResponseFormat::Json
        ));
        assert!(generic_invoke_needs_catalog(
            ReadContentFormat::Markdown,
            ResponseFormat::Json
        ));
        assert!(generic_invoke_needs_catalog(
            ReadContentFormat::Native,
            ResponseFormat::Markdown
        ));
    }

    #[test]
    fn generic_invoke_catalog_hidden_actions_drop_ambient_defaults_but_reject_explicit_flags() {
        let settings =
            response_test_settings(ReadContentFormat::Markdown, ResponseFormat::Markdown);
        assert_eq!(
            resolve_generic_response_options_from_action(
                &settings,
                None,
                None,
                None,
                "jira.issue.view",
            )
            .unwrap(),
            ResponseOptions::default()
        );

        let explicit = resolve_generic_response_options_from_action(
            &settings,
            None,
            Some(ReadContentFormatArg::Markdown),
            None,
            "jira.issue.view",
        )
        .unwrap_err();
        assert!(format!("{explicit:#}").contains("does not expose action jira.issue.view"));
    }

    #[test]
    fn generic_invoke_nonadvertising_actions_drop_ambient_defaults_but_reject_explicit_formats() {
        let settings =
            response_test_settings(ReadContentFormat::Markdown, ResponseFormat::Markdown);
        let action = response_test_action(&[], &[]);
        assert_eq!(
            resolve_generic_response_options_from_action(
                &settings,
                Some(&action),
                None,
                None,
                "jira.issue.view",
            )
            .unwrap(),
            ResponseOptions::default()
        );
        assert!(
            resolve_generic_response_options_from_action(
                &settings,
                Some(&action),
                None,
                Some(OutputFormatArg::Markdown),
                "jira.issue.view",
            )
            .unwrap_err()
            .to_string()
            .contains("does not support --output-format")
        );
    }

    #[test]
    fn generic_download_ignores_ambient_formats_and_rejects_explicit_conversion() {
        let settings =
            response_test_settings(ReadContentFormat::Markdown, ResponseFormat::Markdown);
        let mut action = response_test_action(&["markdown"], &["markdown"]);
        action.io = agent_access_provider::raw_download_io();
        assert_eq!(
            resolve_generic_response_options_from_action(
                &settings,
                Some(&action),
                None,
                None,
                "reports.download",
            )
            .unwrap(),
            ResponseOptions::default()
        );
        for (read, output) in [
            (Some(ReadContentFormatArg::Markdown), None),
            (Some(ReadContentFormatArg::Text), None),
            (None, Some(OutputFormatArg::Markdown)),
        ] {
            assert!(
                resolve_generic_response_options_from_action(
                    &settings,
                    Some(&action),
                    read,
                    output,
                    "reports.download",
                )
                .is_err()
            );
        }
    }

    #[tokio::test]
    async fn generic_invoke_default_options_do_not_contact_the_catalog() {
        let mut settings = response_test_settings(ReadContentFormat::Native, ResponseFormat::Json);
        settings.url = "http://127.0.0.1:0".into();
        let ctx = CliContext {
            settings: &settings,
            output: None,
        };
        let plan = resolve_generic_invoke_options(&ctx, "reports", "download", None, None)
            .await
            .unwrap();
        assert!(plan.action_spec.is_none());
        assert_eq!(plan.options, ResponseOptions::default());
    }

    #[test]
    fn config_default_presence_uses_toml_semantics() {
        let section = std::env::temp_dir().join(format!(
            "agent-access-cli-defaults-section-{}.toml",
            Uuid::new_v4()
        ));
        fs::write(
            &section,
            "[defaults]\nread_content_format = \"native\"\noutput_format = \"json\"\n",
        )
        .unwrap();
        assert!(cli_default_key_is_present(&section, "read_content_format").unwrap());
        assert!(cli_default_key_is_present(&section, "output_format").unwrap());
        fs::remove_file(section).unwrap();

        let dotted = std::env::temp_dir().join(format!(
            "agent-access-cli-defaults-dotted-{}.toml",
            Uuid::new_v4()
        ));
        fs::write(&dotted, "defaults.output_format = \"markdown\"\n").unwrap();
        assert!(cli_default_key_is_present(&dotted, "output_format").unwrap());
        assert!(!cli_default_key_is_present(&dotted, "read_content_format").unwrap());
        fs::remove_file(dotted).unwrap();

        let inline = std::env::temp_dir().join(format!(
            "agent-access-cli-defaults-inline-{}.toml",
            Uuid::new_v4()
        ));
        fs::write(
            &inline,
            "defaults = { \"read_content_format\" = \"text\", output_format = \"markdown\" } # comment\n",
        )
        .unwrap();
        assert!(cli_default_key_is_present(&inline, "read_content_format").unwrap());
        assert!(cli_default_key_is_present(&inline, "output_format").unwrap());
        fs::remove_file(inline).unwrap();

        let quoted = std::env::temp_dir().join(format!(
            "agent-access-cli-defaults-quoted-{}.toml",
            Uuid::new_v4()
        ));
        fs::write(
            &quoted,
            "[\"defaults\"]\n\"read_content_format\" = \"markdown\"\n",
        )
        .unwrap();
        assert!(cli_default_key_is_present(&quoted, "read_content_format").unwrap());
        assert!(!cli_default_key_is_present(&quoted, "output_format").unwrap());
        fs::remove_file(quoted).unwrap();

        let invalid = std::env::temp_dir().join(format!(
            "agent-access-cli-defaults-invalid-{}.toml",
            Uuid::new_v4()
        ));
        fs::write(&invalid, "defaults = { output_format = \"markdown\"\n").unwrap();
        assert!(cli_default_key_is_present(&invalid, "output_format").is_err());
        fs::remove_file(invalid).unwrap();

        let invalid_value = std::env::temp_dir().join(format!(
            "agent-access-cli-defaults-invalid-value-{}.toml",
            Uuid::new_v4()
        ));
        fs::write(&invalid_value, "[defaults]\noutput_format = \"yaml\"\n").unwrap();
        assert!(load_config_or_default(&invalid_value, true).is_err());
        fs::remove_file(invalid_value).unwrap();
    }

    #[test]
    fn response_format_defaults_use_env_only_when_config_key_is_absent() {
        static ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
        let _guard = ENV_LOCK.lock().unwrap();
        let read_env = env::var_os("AGENT_ACCESS_READ_CONTENT_FORMAT");
        let output_env = env::var_os("AGENT_ACCESS_OUTPUT_FORMAT");
        let config_path = std::env::temp_dir().join(format!(
            "agent-access-cli-defaults-precedence-{}.toml",
            Uuid::new_v4()
        ));

        // SAFETY: access to these fixed process variables is serialized by
        // ENV_LOCK for this test and their original values are restored below.
        unsafe {
            env::set_var("AGENT_ACCESS_READ_CONTENT_FORMAT", "text");
            env::set_var("AGENT_ACCESS_OUTPUT_FORMAT", "markdown");
        }
        fs::write(&config_path, "[defaults]\noutput_format = \"json\"\n").unwrap();
        assert_eq!(
            resolve_read_content_format_default(&config_path, true, ReadContentFormat::Native,)
                .unwrap(),
            ReadContentFormat::Text
        );
        assert_eq!(
            resolve_output_format_default(&config_path, true, ResponseFormat::Json).unwrap(),
            ResponseFormat::Json
        );

        // Invalid environment defaults fail closed when the config does not
        // define the corresponding key.
        unsafe {
            env::set_var("AGENT_ACCESS_READ_CONTENT_FORMAT", "html");
        }
        assert!(
            resolve_read_content_format_default(&config_path, true, ReadContentFormat::Native,)
                .unwrap_err()
                .to_string()
                .contains("must be one of native, markdown, or text")
        );

        fs::remove_file(config_path).unwrap();
        // SAFETY: restore the exact pre-test process environment.
        unsafe {
            match read_env {
                Some(value) => env::set_var("AGENT_ACCESS_READ_CONTENT_FORMAT", value),
                None => env::remove_var("AGENT_ACCESS_READ_CONTENT_FORMAT"),
            }
            match output_env {
                Some(value) => env::set_var("AGENT_ACCESS_OUTPUT_FORMAT", value),
                None => env::remove_var("AGENT_ACCESS_OUTPUT_FORMAT"),
            }
        }
    }

    #[test]
    fn markdown_output_extracts_only_valid_allow_results() {
        let allowed = serde_json::json!({
            "agentRequestId": "agent-1",
            "brokerRequestId": "broker-1",
            "decision": "allow",
            "result": {"format": "markdown", "value": "# SBC-1\n"}
        });
        assert_eq!(markdown_result_value(&allowed).unwrap(), Some("# SBC-1\n"));

        let conflict = serde_json::json!({
            "agentRequestId": "agent-1",
            "brokerRequestId": "broker-1",
            "decision": "allow",
            "reasonCode": "verification_mismatch",
            "result": {"format": "markdown", "value": "# Verification\n"}
        });
        assert_eq!(
            markdown_result_value(&conflict).unwrap(),
            Some("# Verification\n")
        );

        let denied = serde_json::json!({
            "agentRequestId": "agent-1",
            "brokerRequestId": "broker-1",
            "decision": "deny",
            "error": {"reasonCode": "right_missing", "message": "denied"}
        });
        assert_eq!(markdown_result_value(&denied).unwrap(), None);

        let malformed = serde_json::json!({
            "agentRequestId": "agent-1",
            "brokerRequestId": "broker-1",
            "decision": "allow",
            "result": {"format": "markdown"}
        });
        assert!(markdown_result_value(&malformed).is_err());
    }

    #[test]
    fn send_invoke_accepts_explicit_response_options_without_ambient_injection() {
        let explicit = parse_send_request(serde_json::json!({
            "version": "agent-access.send.v1",
            "kind": "invoke",
            "service": "jira",
            "action": "issue.view",
            "inputs": {"issue": "SBC-1"},
            "readContentFormat": "text",
            "responseFormat": "markdown"
        }))
        .unwrap();
        assert!(matches!(
            explicit,
            SendRequest::Invoke {
                read_content_format: ReadContentFormat::Text,
                response_format: ResponseFormat::Markdown,
                ..
            }
        ));

        let omitted = parse_send_request(serde_json::json!({
            "version": "agent-access.send.v1",
            "kind": "invoke",
            "service": "jira",
            "action": "issue.view",
            "inputs": {"issue": "SBC-1"}
        }))
        .unwrap();
        assert!(matches!(
            omitted,
            SendRequest::Invoke {
                read_content_format: ReadContentFormat::Native,
                response_format: ResponseFormat::Json,
                ..
            }
        ));
    }

    #[test]
    fn gitlab_rich_content_write_commands_parse_normalized_flags() {
        let commands = [
            vec![
                "agent-access",
                "gitlab",
                "issue",
                "create",
                "group/project",
                "--title",
                "Created",
                "--content",
                "# Description",
                "--content-format",
                "markdown",
            ],
            vec![
                "agent-access",
                "gitlab",
                "issue",
                "update",
                "group/project",
                "1",
                "--content-file",
                "description.txt",
                "--content-format",
                "plain_text",
            ],
            vec![
                "agent-access",
                "gitlab",
                "issue",
                "comment",
                "group/project",
                "1",
                "--content",
                "Added",
                "--content-format",
                "plain_text",
            ],
            vec![
                "agent-access",
                "gitlab",
                "issue",
                "update-comment",
                "group/project",
                "1",
                "10",
                "--content-file",
                "note.md",
                "--content-format",
                "markdown",
            ],
            vec![
                "agent-access",
                "gitlab",
                "merge-request",
                "create",
                "group/project",
                "--source-branch",
                "feature",
                "--target-branch",
                "main",
                "--title",
                "Created",
                "--content",
                "Description",
                "--content-format",
                "plain_text",
            ],
            vec![
                "agent-access",
                "gitlab",
                "merge-request",
                "update",
                "group/project",
                "2",
                "--content-file",
                "description.md",
                "--content-format",
                "markdown",
            ],
            vec![
                "agent-access",
                "gitlab",
                "merge-request",
                "comment",
                "group/project",
                "2",
                "--content",
                "Note",
                "--content-format",
                "markdown",
            ],
            vec![
                "agent-access",
                "gitlab",
                "merge-request",
                "update-comment",
                "group/project",
                "2",
                "20",
                "--content-file",
                "note.txt",
                "--content-format",
                "plain_text",
            ],
            vec![
                "agent-access",
                "gitlab",
                "merge-request",
                "discussion",
                "group/project",
                "2",
                "--content",
                "Discussion",
                "--content-format",
                "markdown",
            ],
            vec![
                "agent-access",
                "gitlab",
                "merge-request",
                "update-discussion-note",
                "group/project",
                "2",
                "discussion-1",
                "21",
                "--content-file",
                "discussion.txt",
                "--content-format",
                "plain_text",
            ],
        ];

        for command in commands {
            Cli::try_parse_from(command).expect("normalized GitLab content command should parse");
        }

        for command in [
            vec![
                "agent-access",
                "gitlab",
                "issue",
                "create",
                "group/project",
                "--title",
                "No description",
            ],
            vec![
                "agent-access",
                "gitlab",
                "issue",
                "update",
                "group/project",
                "1",
                "--title",
                "Renamed",
            ],
            vec![
                "agent-access",
                "gitlab",
                "merge-request",
                "create",
                "group/project",
                "--source-branch",
                "feature",
                "--target-branch",
                "main",
                "--title",
                "No description",
            ],
            vec![
                "agent-access",
                "gitlab",
                "merge-request",
                "update",
                "group/project",
                "2",
                "--title",
                "Renamed",
            ],
        ] {
            Cli::try_parse_from(command).expect("GitLab descriptions should remain optional");
        }
    }

    #[test]
    fn gitlab_rich_content_flags_reject_incomplete_invalid_and_legacy_inputs() {
        let missing_format = Cli::try_parse_from([
            "agent-access",
            "gitlab",
            "issue",
            "comment",
            "group/project",
            "1",
            "--content",
            "Note",
        ])
        .unwrap_err();
        assert_eq!(
            missing_format.kind(),
            clap::error::ErrorKind::MissingRequiredArgument
        );

        let missing_source = Cli::try_parse_from([
            "agent-access",
            "gitlab",
            "issue",
            "create",
            "group/project",
            "--title",
            "Created",
            "--content-format",
            "markdown",
        ])
        .unwrap_err();
        assert_eq!(
            missing_source.kind(),
            clap::error::ErrorKind::MissingRequiredArgument
        );

        let conflicting_sources = Cli::try_parse_from([
            "agent-access",
            "gitlab",
            "merge-request",
            "discussion",
            "group/project",
            "2",
            "--content",
            "Discussion",
            "--content-file",
            "discussion.md",
            "--content-format",
            "markdown",
        ])
        .unwrap_err();
        assert_eq!(
            conflicting_sources.kind(),
            clap::error::ErrorKind::ArgumentConflict
        );

        let unsupported_format = Cli::try_parse_from([
            "agent-access",
            "gitlab",
            "issue",
            "comment",
            "group/project",
            "1",
            "--content",
            "Note",
            "--content-format",
            "adf",
        ])
        .unwrap_err();
        assert_eq!(
            unsupported_format.kind(),
            clap::error::ErrorKind::InvalidValue
        );

        for legacy in [
            vec![
                "agent-access",
                "gitlab",
                "issue",
                "create",
                "group/project",
                "--title",
                "Legacy",
                "--description-file",
                "description.md",
            ],
            vec![
                "agent-access",
                "gitlab",
                "merge-request",
                "comment",
                "group/project",
                "2",
                "--body-file",
                "note.md",
            ],
        ] {
            let error = Cli::try_parse_from(legacy).unwrap_err();
            assert_eq!(error.kind(), clap::error::ErrorKind::UnknownArgument);
        }
    }

    #[test]
    fn gitlab_content_lowering_emits_only_canonical_fields() {
        let mut markdown = serde_json::Map::new();
        assert!(
            insert_gitlab_content_inputs(
                &mut markdown,
                Some("# Update\n\nDone."),
                None,
                Some(GitlabContentFormatArg::Markdown),
                true,
                "test command",
            )
            .unwrap()
        );
        assert_eq!(
            serde_json::Value::Object(markdown.clone()),
            serde_json::json!({
                "content": "# Update\n\nDone.",
                "contentFormat": "markdown"
            })
        );
        for legacy in ["body", "bodyFormat", "description", "descriptionFormat"] {
            assert!(!markdown.contains_key(legacy));
        }

        let mut omitted = serde_json::Map::new();
        assert!(
            !insert_gitlab_content_inputs(&mut omitted, None, None, None, false, "test command")
                .unwrap()
        );
        assert!(omitted.is_empty());

        let empty = resolve_content_input(
            Some(""),
            None,
            Some(GitlabContentFormatArg::PlainText),
            false,
            "test command",
        )
        .unwrap()
        .unwrap();
        assert_eq!(empty.0, "");
        assert_eq!(empty.1, GitlabContentFormatArg::PlainText);
    }

    #[test]
    fn gitlab_content_file_help_documents_safety_bound_and_no_stdin() {
        let help = Cli::try_parse_from(["agent-access", "gitlab", "issue", "comment", "--help"])
            .unwrap_err()
            .to_string();
        assert!(help.contains("maximum 512 MiB / 536870912 bytes"));
        assert!(help.contains("provider and server limits may be lower"));
        assert!(help.contains("'-' is a literal path, not stdin"));
        assert!(help.contains("--content-format <CONTENT_FORMAT>"));
        assert!(help.contains("markdown"));
        assert!(help.contains("plain_text"));
    }

    #[test]
    fn gitlab_repository_file_content_file_remains_independent() {
        let command = Cli::try_parse_from([
            "agent-access",
            "gitlab",
            "file",
            "create",
            "group/project",
            "--path",
            "README.md",
            "--branch",
            "main",
            "--content-file",
            "README.md",
            "--message",
            "Create README",
        ])
        .expect("repository file create should retain its content-file input");
        assert!(matches!(
            command.command,
            Command::Gitlab {
                command: GitlabCommand::File {
                    command: GitlabFileCommand::Create { .. }
                }
            }
        ));
    }

    #[test]
    fn token_pause_and_resume_commands_parse_and_build_canonical_paths() {
        let pause = Cli::try_parse_from(["agent-access", "tokens", "pause", "token-1"])
            .expect("self-service pause command should parse");
        assert!(matches!(
            pause.command,
            Command::Tokens {
                command: TokensCommand::Pause { ref token_id }
            } if token_id == "token-1"
        ));
        assert_eq!(
            self_token_action_path("token-1", BrokerTokenAction::Pause),
            "/v1/tokens/token-1/pause"
        );

        let resume = Cli::try_parse_from(["agent-access", "tokens", "resume", "token-2"])
            .expect("self-service resume command should parse");
        assert!(matches!(
            resume.command,
            Command::Tokens {
                command: TokensCommand::Resume { ref token_id }
            } if token_id == "token-2"
        ));
        assert_eq!(
            self_token_action_path("token-2", BrokerTokenAction::Resume),
            "/v1/tokens/token-2/resume"
        );

        let admin_pause =
            Cli::try_parse_from(["agent-access", "admin", "tokens", "pause", "token-3"])
                .expect("admin pause command should parse");
        assert!(matches!(
            admin_pause.command,
            Command::Admin {
                command: AdminCommand::Tokens {
                    command: AdminTokensCommand::Pause { ref token_id }
                }
            } if token_id == "token-3"
        ));
        assert_eq!(
            admin_token_action_path("token-3", BrokerTokenAction::Pause),
            "/v1/admin/tokens/token-3/pause"
        );

        let admin_resume =
            Cli::try_parse_from(["agent-access", "admin", "tokens", "resume", "token-4"])
                .expect("admin resume command should parse");
        assert!(matches!(
            admin_resume.command,
            Command::Admin {
                command: AdminCommand::Tokens {
                    command: AdminTokensCommand::Resume { ref token_id }
                }
            } if token_id == "token-4"
        ));
        assert_eq!(
            admin_token_action_path("token-4", BrokerTokenAction::Resume),
            "/v1/admin/tokens/token-4/resume"
        );
    }

    #[test]
    fn confluence_page_placement_commands_parse_locator_flags() {
        let create = Cli::try_parse_from([
            "agent-access",
            "confluence",
            "page",
            "create",
            "--space",
            "ENG",
            "--title",
            "Runbook",
            "--parent",
            "123",
            "--content-file",
            "body.html",
            "--content-format",
            "storage",
        ])
        .unwrap();
        let Command::Confluence {
            command:
                ConfluenceCommand::Page {
                    command: ConfluencePageCommand::Create { parent, .. },
                },
        } = create.command
        else {
            panic!("expected confluence page create command");
        };
        assert_eq!(parent.as_deref(), Some("123"));

        let draft_create = Cli::try_parse_from([
            "agent-access",
            "confluence",
            "page",
            "draft",
            "create",
            "--space",
            "ENG",
            "--title",
            "Draft",
            "--parent-url",
            "https://example.atlassian.net/wiki/spaces/ENG/pages/123",
            "--content-file",
            "body.html",
            "--content-format",
            "storage",
        ])
        .unwrap();
        let Command::Confluence {
            command:
                ConfluenceCommand::Page {
                    command:
                        ConfluencePageCommand::Draft {
                            command: ConfluencePageDraftCommand::Create { parent_url, .. },
                        },
                },
        } = draft_create.command
        else {
            panic!("expected confluence page draft create command");
        };
        assert_eq!(
            parent_url.as_deref(),
            Some("https://example.atlassian.net/wiki/spaces/ENG/pages/123")
        );

        let page_move = Cli::try_parse_from([
            "agent-access",
            "confluence",
            "page",
            "move",
            "456",
            "--position",
            "before",
            "--target",
            "123",
        ])
        .unwrap();
        let Command::Confluence {
            command:
                ConfluenceCommand::Page {
                    command:
                        ConfluencePageCommand::Move {
                            page_id,
                            position,
                            target,
                            ..
                        },
                },
        } = page_move.command
        else {
            panic!("expected confluence page move command");
        };
        assert_eq!(page_id.as_deref(), Some("456"));
        assert!(matches!(position, ConfluencePageMovePositionArg::Before));
        assert_eq!(target.as_deref(), Some("123"));
    }

    #[test]
    fn confluence_page_create_parent_flags_are_mutually_exclusive() {
        let error = Cli::try_parse_from([
            "agent-access",
            "confluence",
            "page",
            "create",
            "--space",
            "ENG",
            "--title",
            "Runbook",
            "--parent",
            "123",
            "--parent-url",
            "https://example.atlassian.net/wiki/spaces/ENG/pages/123",
            "--content-file",
            "body.html",
            "--content-format",
            "storage",
        ])
        .unwrap_err();
        assert_eq!(error.kind(), clap::error::ErrorKind::ArgumentConflict);
    }

    #[test]
    fn confluence_normalized_content_flags_cover_all_twenty_write_commands() {
        let commands = [
            vec!["page", "create", "--space", "ENG", "--title", "Page"],
            vec!["page", "update", "123", "--base-version", "1"],
            vec![
                "page", "draft", "create", "--space", "ENG", "--title", "Draft",
            ],
            vec!["page", "draft", "stage", "123", "--base-version", "1"],
            vec![
                "page",
                "draft",
                "update",
                "123",
                "--draft-handle",
                "draft-1",
            ],
            vec!["page", "footer-comment", "add", "123"],
            vec![
                "page",
                "footer-comment",
                "update",
                "456",
                "--base-version",
                "1",
            ],
            vec!["page", "footer-comment", "reply", "456"],
            vec![
                "page",
                "inline-comment",
                "update",
                "456",
                "--base-version",
                "1",
            ],
            vec!["page", "inline-comment", "reply", "456"],
            vec!["blog", "create", "--space", "ENG", "--title", "Post"],
            vec!["blog", "update", "123", "--base-version", "1"],
            vec![
                "blog", "draft", "create", "--space", "ENG", "--title", "Draft",
            ],
            vec!["blog", "draft", "stage", "123", "--base-version", "1"],
            vec![
                "blog",
                "draft",
                "update",
                "123",
                "--draft-handle",
                "draft-1",
            ],
            vec!["blog", "footer-comment", "add", "123"],
            vec![
                "blog",
                "footer-comment",
                "update",
                "456",
                "--base-version",
                "1",
            ],
            vec!["blog", "footer-comment", "reply", "456"],
            vec![
                "blog",
                "inline-comment",
                "update",
                "456",
                "--base-version",
                "1",
            ],
            vec!["blog", "inline-comment", "reply", "456"],
        ];

        for command in commands {
            let mut args = vec!["agent-access", "confluence"];
            args.extend(command);
            args.extend(["--content", "# Update", "--content-format", "markdown"]);
            Cli::try_parse_from(args).expect("normalized Confluence write command should parse");
        }
    }

    #[test]
    fn confluence_content_flags_are_typed_exclusive_and_remove_legacy_writes() {
        Cli::try_parse_from([
            "agent-access",
            "confluence",
            "page",
            "create",
            "--space",
            "ENG",
            "--title",
            "Native",
            "--content",
            r#"{"type":"doc","version":1,"content":[]}"#,
            "--content-format",
            "atlas_doc_format",
        ])
        .expect("current page writes support native ADF");

        let unsupported_adf = Cli::try_parse_from([
            "agent-access",
            "confluence",
            "blog",
            "create",
            "--space",
            "ENG",
            "--title",
            "Post",
            "--content",
            "{}",
            "--content-format",
            "atlas_doc_format",
        ])
        .unwrap_err();
        assert_eq!(unsupported_adf.kind(), clap::error::ErrorKind::InvalidValue);

        let conflicting_sources = Cli::try_parse_from([
            "agent-access",
            "confluence",
            "page",
            "footer-comment",
            "add",
            "123",
            "--content",
            "Comment",
            "--content-file",
            "comment.md",
            "--content-format",
            "markdown",
        ])
        .unwrap_err();
        assert_eq!(
            conflicting_sources.kind(),
            clap::error::ErrorKind::ArgumentConflict
        );

        let missing_source = Cli::try_parse_from([
            "agent-access",
            "confluence",
            "page",
            "footer-comment",
            "add",
            "123",
            "--content-format",
            "markdown",
        ])
        .unwrap_err();
        assert_eq!(
            missing_source.kind(),
            clap::error::ErrorKind::MissingRequiredArgument
        );

        let legacy = Cli::try_parse_from([
            "agent-access",
            "confluence",
            "page",
            "create",
            "--space",
            "ENG",
            "--title",
            "Legacy",
            "--body-file",
            "body.html",
            "--body-format",
            "storage",
        ])
        .unwrap_err();
        assert_eq!(legacy.kind(), clap::error::ErrorKind::UnknownArgument);

        let read_selector = Cli::try_parse_from([
            "agent-access",
            "confluence",
            "page",
            "draft",
            "view",
            "123",
            "--draft-handle",
            "draft-1",
            "--body-format",
            "storage",
        ]);
        assert!(
            read_selector.is_ok(),
            "read-side body format must remain supported"
        );
    }

    #[test]
    fn confluence_content_lowering_is_canonical_and_parses_only_native_adf_as_json() {
        let mut markdown = serde_json::Map::new();
        insert_confluence_content_inputs(
            &mut markdown,
            Some("# Update\n\nDone."),
            None,
            ConfluenceContentFormatArg::Markdown,
            "test command",
        )
        .unwrap();
        assert_eq!(
            serde_json::Value::Object(markdown.clone()),
            serde_json::json!({
                "content": "# Update\n\nDone.",
                "contentFormat": "markdown"
            })
        );
        assert!(!markdown.contains_key("body"));
        assert!(!markdown.contains_key("bodyFormat"));

        let mut native = serde_json::Map::new();
        insert_confluence_content_inputs(
            &mut native,
            Some(r#"{"type":"doc","version":1,"content":[]}"#),
            None,
            ConfluencePageContentFormatArg::AtlasDocFormat,
            "test command",
        )
        .unwrap();
        assert_eq!(native["content"]["type"], "doc");
        assert_eq!(native["contentFormat"], "atlas_doc_format");

        let adf_path = std::env::temp_dir().join(format!(
            "agent-access-cli-confluence-content-{}.json",
            Uuid::new_v4()
        ));
        fs::write(&adf_path, br#"{"type":"doc","version":1,"content":[]}"#).unwrap();
        let file_native = resolve_content_input(
            None,
            Some(&adf_path),
            Some(ConfluencePageContentFormatArg::AtlasDocFormat),
            true,
            "test command",
        )
        .unwrap()
        .unwrap();
        assert_eq!(file_native.0["type"], "doc");
        fs::remove_file(adf_path).unwrap();

        let malformed = resolve_content_input(
            Some("not JSON"),
            None,
            Some(ConfluencePageContentFormatArg::AtlasDocFormat),
            true,
            "test command",
        )
        .unwrap_err();
        assert!(format!("{malformed:#}").contains("valid atlas_doc_format JSON"));

        let storage = resolve_content_input(
            Some("<p>literal</p>"),
            None,
            Some(ConfluencePageContentFormatArg::Storage),
            true,
            "test command",
        )
        .unwrap()
        .unwrap();
        assert_eq!(storage.0, "<p>literal</p>");
    }

    #[test]
    fn confluence_content_help_uses_normalized_write_vocabulary() {
        let help = Cli::try_parse_from(["agent-access", "confluence", "page", "create", "--help"])
            .unwrap_err()
            .to_string();
        assert!(help.contains("--content <CONTENT>"));
        assert!(help.contains("--content-file <CONTENT_FILE>"));
        assert!(help.contains("--content-format <CONTENT_FORMAT>"));
        assert!(help.contains("atlas_doc_format"));
        assert!(!help.contains("--body-file"));
    }

    #[test]
    fn confluence_parent_and_move_locators_lower_to_canonical_inputs() {
        let mut create_inputs = serde_json::Map::new();
        confluence_optional_parent_locator_inputs(
            &mut create_inputs,
            Some("123"),
            None,
            "confluence page create",
        );
        assert_eq!(create_inputs["parentPageId"], "123");

        let mut move_inputs = confluence_page_argument_locator_inputs(
            None,
            Some("https://example.atlassian.net/wiki/spaces/ENG/pages/456"),
            "confluence page move",
        );
        move_inputs.insert("position".to_string(), serde_json::json!("after"));
        confluence_move_target_locator_inputs(
            &mut move_inputs,
            None,
            Some("https://example.atlassian.net/wiki/spaces/ENG/pages/123"),
            "confluence page move",
        );
        assert_eq!(
            serde_json::Value::Object(move_inputs),
            serde_json::json!({
                "url": "https://example.atlassian.net/wiki/spaces/ENG/pages/456",
                "position": "after",
                "targetUrl": "https://example.atlassian.net/wiki/spaces/ENG/pages/123"
            })
        );
    }

    #[test]
    fn send_route_resolution_encodes_path_and_declared_query_values() {
        let service_route = agent_access_broker::composition()
            .unwrap()
            .http_route_specs()
            .into_iter()
            .find(|route| route.method == "GET" && route.route == "/v1/services/{service}")
            .unwrap();
        let service_path = resolve_route_path(
            &service_route,
            BTreeMap::from([("service".to_string(), "jira/cloud project #1".to_string())]),
            BTreeMap::new(),
        )
        .unwrap();
        assert_eq!(service_path, "/v1/services/jira%2Fcloud%20project%20%231");

        let grants_route = agent_access_broker::composition()
            .unwrap()
            .http_route_specs()
            .into_iter()
            .find(|route| route.method == "GET" && route.route == "/v1/admin/policy/grants")
            .unwrap();
        let grants_path = resolve_route_path(
            &grants_route,
            BTreeMap::new(),
            BTreeMap::from([
                ("service".to_string(), serde_json::json!("jira")),
                ("status".to_string(), serde_json::json!("active")),
                (
                    "subject".to_string(),
                    serde_json::json!(["user:alice", "group:agents"]),
                ),
            ]),
        )
        .unwrap();
        assert_eq!(
            grants_path,
            "/v1/admin/policy/grants?service=jira&status=active&subject=user%3Aalice&subject=group%3Aagents"
        );
    }

    #[test]
    fn send_route_resolution_rejects_unknown_params_and_structured_query_objects() {
        let route = agent_access_broker::composition()
            .unwrap()
            .http_route_specs()
            .into_iter()
            .find(|route| route.method == "GET" && route.route == "/v1/admin/policy/grants")
            .unwrap();

        let unknown = resolve_route_path(
            &route,
            BTreeMap::new(),
            BTreeMap::from([("unexpected".to_string(), serde_json::json!("value"))]),
        )
        .unwrap_err();
        assert!(format!("{unknown:#}").contains("has no query parameter unexpected"));

        let object_value = resolve_route_path(
            &route,
            BTreeMap::new(),
            BTreeMap::from([("service".to_string(), serde_json::json!({"name": "jira"}))]),
        )
        .unwrap_err();
        assert!(format!("{object_value:#}").contains("must be a scalar or array of scalars"));
    }

    #[test]
    fn send_envelope_shape_validation_runs_before_catalog_dependent_checks() {
        let missing_kind = serde_json::json!({
            "version": "agent-access.send.v1",
            "service": "fake",
            "action": "echo"
        });
        let missing_kind_error = validate_send_envelope_shape(&missing_kind).unwrap_err();
        assert!(format!("{missing_kind_error:#}").contains("missing field `kind`"));

        let body_null = serde_json::json!({
            "version": "agent-access.send.v1",
            "kind": "http",
            "method": "POST",
            "route": "/v1/credentials",
            "body": null
        });
        let body_null_error = validate_send_envelope_shape(&body_null).unwrap_err();
        assert!(format!("{body_null_error:#}").contains("body cannot be null"));
    }

    #[test]
    fn send_secret_sources_patch_local_values_and_argv_rejects_inline_secrets() {
        let temp_secret =
            std::env::temp_dir().join(format!("agent-access-send-secret-{}.txt", Uuid::new_v4()));
        fs::write(&temp_secret, "secret-token").unwrap();
        let mut request = serde_json::json!({
            "version": "agent-access.send.v1",
            "kind": "http",
            "method": "PUT",
            "route": "/v1/credentials/connections/{connection}",
            "pathParams": {
                "connection": "jira"
            },
            "body": {
                "profile": "atlassian-api-token"
            },
            "secretSources": [
                {
                    "pointer": "/body/secret/apiToken",
                    "source": {
                        "type": "file",
                        "path": temp_secret
                    }
                }
            ]
        });

        apply_secret_sources(
            &mut request,
            JsonInputSourceKind::File,
            &["/body/secret".to_string()],
        )
        .unwrap();
        assert_eq!(request["body"]["secret"]["apiToken"], "secret-token");
        fs::remove_file(temp_secret).unwrap();

        let inline = serde_json::json!({
            "version": "agent-access.send.v1",
            "kind": "http",
            "method": "PUT",
            "route": "/v1/credentials/connections/{connection}",
            "body": {
                "secret": {
                    "apiToken": "inline"
                }
            }
        });
        let error =
            reject_inline_sensitive_values(&inline, &["/body/secret".to_string()]).unwrap_err();
        assert!(format!("{error:#}").contains("use secretSources"));

        let non_secret_parent = serde_json::json!({"body": {"secretless": "ok"}});
        reject_inline_sensitive_values(&non_secret_parent, &["/body/secret".to_string()]).unwrap();
    }

    #[test]
    fn send_secret_sources_reject_undeclared_sensitive_pointers() {
        let mut request = serde_json::json!({
            "version": "agent-access.send.v1",
            "kind": "http",
            "method": "PUT",
            "route": "/v1/credentials/connections/{connection}",
            "secretSources": [
                {
                    "pointer": "/body/notSecret/apiToken",
                    "source": {
                        "type": "env",
                        "name": "AGENT_ACCESS_TEST_SECRET"
                    }
                }
            ]
        });

        let error = apply_secret_sources(
            &mut request,
            JsonInputSourceKind::File,
            &["/body/secret".to_string()],
        )
        .unwrap_err();
        assert!(format!("{error:#}").contains("not declared sensitive"));
        assert!(sensitive_pointer_allowed(
            "/body/secret/apiToken",
            &["/body/secret".to_string()]
        ));
        assert!(!sensitive_pointer_allowed(
            "/body/secretless",
            &["/body/secret".to_string()]
        ));
    }

    #[test]
    fn send_invoke_sensitive_pointers_reject_inline_and_patch_secret_sources() {
        let temp_secret = std::env::temp_dir().join(format!(
            "agent-access-send-invoke-secret-{}.txt",
            Uuid::new_v4()
        ));
        fs::write(&temp_secret, "api-key").unwrap();
        let catalog = ApiCatalog {
            version: API_CATALOG_VERSION.to_string(),
            identity: serde_json::json!({}),
            execution_context: None,
            resource_types: Vec::new(),
            services: vec![agent_access_core::ApiServiceSpec {
                availability: None,
                service: "api".to_string(),
                display_name: "API".to_string(),
                surface: "invoke".to_string(),
                scoped_mcp_ready: true,
                scope_types: vec!["endpoint".to_string()],
                resource_scopes: BTreeMap::new(),
                actions: vec![ApiActionSpec {
                    scoped_mcp_name: Some("call".to_owned()),
                    documentation: None,
                    companion_read_actions: Vec::new(),
                    listing_of: None,
                    read_only: true,
                    action: "call".to_string(),
                    description: "Call".to_string(),
                    required_scope_types: vec!["endpoint".to_string()],
                    credential_modes: vec!["service".to_string()],
                    upstream_resource_ownership: None,
                    lookup_required: false,
                    input_schema: serde_json::json!({ "type": "object" }),
                    sensitive_input_pointers: vec!["/inputs/headers/X-Api-Key".to_string()],
                    sensitive_output_pointers: Vec::new(),
                    io: ActionIo::Json,
                    response_kind: agent_access_core::ResponseKind::ResponseEnvelope,
                    exit_policy: ExitPolicy::InvokeDecision,
                    read_content_formats: Vec::new(),
                    response_formats: Vec::new(),
                    rendered_body_owners: Vec::new(),
                    optional_rendered_body_owner_prefixes: Vec::new(),
                }],
            }],
            routes: Vec::new(),
            send: agent_access_core::SendCatalogSpec {
                version: SEND_SCHEMA_VERSION.to_string(),
                catalog_required: true,
            },
        };
        let inline = serde_json::json!({
            "version": "agent-access.send.v1",
            "kind": "invoke",
            "service": "api",
            "action": "call",
            "inputs": {
                "headers": {
                    "x-api-key": "inline"
                }
            }
        });
        let pointers = send_sensitive_pointers(&catalog, &inline).unwrap();
        assert!(sensitive_pointer_allowed(
            "/inputs/headers/x-api-key",
            &pointers
        ));
        let error = reject_inline_sensitive_values(&inline, &pointers).unwrap_err();
        assert!(format!("{error:#}").contains("use secretSources"));

        let mut sourced = serde_json::json!({
            "version": "agent-access.send.v1",
            "kind": "invoke",
            "service": "api",
            "action": "call",
            "inputs": {
                "headers": {}
            },
            "secretSources": [
                {
                    "pointer": "/inputs/headers/x-api-key",
                    "source": {
                        "type": "file",
                        "path": temp_secret
                    }
                }
            ]
        });
        apply_secret_sources(&mut sourced, JsonInputSourceKind::File, &pointers).unwrap();
        assert_eq!(sourced["inputs"]["headers"]["x-api-key"], "api-key");
        fs::remove_file(temp_secret).unwrap();
    }

    #[test]
    fn gitlab_project_upload_requires_one_locator_and_one_file() {
        for locator in [
            vec!["team/repo"],
            vec!["--project-url", "https://gitlab.example.com/team/repo"],
        ] {
            let mut args = vec!["agent-access", "gitlab", "project", "upload"];
            args.extend(locator);
            args.extend(["--file", "session.html", "--content-type", "text/html"]);
            let cli = Cli::try_parse_from(args).unwrap();
            assert!(matches!(cli.command, Command::Gitlab {
                command: GitlabCommand::Project {
                    command: GitlabProjectCommand::Upload { ref file, ref content_type, .. }
                }
            } if file == &PathBuf::from("session.html") && content_type.as_deref() == Some("text/html")));
        }
        for trailing in [
            vec!["--file", "session.html"],
            vec!["team/repo"],
            vec![
                "team/repo",
                "--project-url",
                "https://gitlab.example.com/team/repo",
                "--file",
                "session.html",
            ],
            vec!["team/repo", "--file", "first.html", "--file", "second.html"],
        ] {
            let mut args = vec!["agent-access", "gitlab", "project", "upload"];
            args.extend(trailing);
            assert!(Cli::try_parse_from(args).is_err());
        }
    }

    #[test]
    fn gitlab_send_upload_rejects_multiple_files() {
        let plan = agent_access_provider::attachment_upload_plan(&["project", "url"], Some(1));
        let files = ["first.html", "second.html"].map(|path| SendFileDescriptor {
            role: "attachment".to_string(),
            path: PathBuf::from(path),
            filename: None,
            content_type: Some("text/html".to_string()),
        });
        assert!(validate_upload_files(&plan, &files[..1], "gitlab", "project.upload").is_ok());
        assert!(validate_upload_files(&plan, &files, "gitlab", "project.upload").is_err());
    }

    #[test]
    fn send_upload_metadata_uses_catalog_pointer_and_fields() {
        let plan = MultipartUploadSpec::new(
            "asset".to_string(),
            "/payload/uploads".to_string(),
            "asset".to_string(),
        )
        .with_file_count(1, Some(3))
        .with_locator_inputs(vec!["pageId".to_string()])
        .with_metadata_fields(vec!["field".to_string(), "filename".to_string()])
        .allowing_caller_content_type();
        let entry = upload_metadata_entry(
            &plan,
            UploadFileMetadata {
                field: "asset0",
                filename: "diagram.png",
                content_type: "image/png",
                size: 12,
                sha256: "abc123",
            },
            "confluence.attachment.add",
        )
        .unwrap();
        assert_eq!(
            entry,
            serde_json::json!({
                "field": "asset0",
                "filename": "diagram.png"
            })
        );
        let mut inputs = serde_json::json!({
            "payload": {
                "pageId": "123"
            }
        });
        set_upload_metadata(&mut inputs, &plan, vec![entry]).unwrap();
        assert_eq!(inputs["payload"]["uploads"][0]["field"], "asset0");
        assert!(inputs["payload"]["uploads"][0].get("contentType").is_none());

        let mut unsupported = plan;
        unsupported.metadata_fields = vec!["unknown".to_string()];
        let error = upload_metadata_entry(
            &unsupported,
            UploadFileMetadata {
                field: "asset0",
                filename: "diagram.png",
                content_type: "image/png",
                size: 12,
                sha256: "abc123",
            },
            "confluence.attachment.add",
        )
        .unwrap_err();
        assert!(format!("{error:#}").contains("unsupported metadata field unknown"));
    }

    #[test]
    fn upload_source_requires_a_regular_file() {
        let directory = tempfile::tempdir().unwrap();
        let error = upload_file_metadata(directory.path()).unwrap_err();
        assert!(error.to_string().contains("must be a regular file"));

        let path = directory.path().join("attachment.txt");
        fs::write(&path, b"attachment").unwrap();
        assert_eq!(upload_file_metadata(&path).unwrap().len(), 10);
    }

    #[cfg(unix)]
    #[test]
    fn upload_source_rejects_fifo_without_opening_and_accepts_regular_symlink() {
        use std::os::unix::ffi::OsStrExt;

        let directory = tempfile::tempdir().unwrap();
        let fifo = directory.path().join("attachment.fifo");
        let fifo_name = std::ffi::CString::new(fifo.as_os_str().as_bytes()).unwrap();
        // No writer is connected: opening this FIFO for reading would block.
        assert_eq!(unsafe { libc::mkfifo(fifo_name.as_ptr(), 0o600) }, 0);
        let error = upload_file_metadata(&fifo).unwrap_err();
        assert!(error.to_string().contains("must be a regular file"));

        let path = directory.path().join("attachment.txt");
        fs::write(&path, b"attachment").unwrap();
        let symlink = directory.path().join("attachment-link.txt");
        std::os::unix::fs::symlink(&path, &symlink).unwrap();
        assert_eq!(upload_file_metadata(&symlink).unwrap().len(), 10);
    }

    #[test]
    fn send_upload_validation_uses_catalog_plan_constraints() {
        let plan = MultipartUploadSpec::new(
            "asset".to_string(),
            "/uploads".to_string(),
            "asset".to_string(),
        )
        .with_file_count(1, Some(2))
        .with_metadata_fields(vec!["field".to_string()]);
        let file = SendFileDescriptor {
            role: "asset".to_string(),
            path: PathBuf::from("a.txt"),
            filename: None,
            content_type: None,
        };
        validate_upload_files(&plan, std::slice::from_ref(&file), "files", "asset.add").unwrap();

        let min_error = validate_upload_files(&plan, &[], "files", "asset.add").unwrap_err();
        assert!(format!("{min_error:#}").contains("requires at least 1 file"));

        let max_error = validate_upload_files(
            &plan,
            &[file.clone(), file.clone(), file.clone()],
            "files",
            "asset.add",
        )
        .unwrap_err();
        assert!(format!("{max_error:#}").contains("accepts at most 2"));

        let mut wrong_role = file.clone();
        wrong_role.role = "thumbnail".to_string();
        let role_error =
            validate_upload_files(&plan, &[wrong_role], "files", "asset.add").unwrap_err();
        assert!(format!("{role_error:#}").contains("not valid"));

        let mut content_type = file;
        content_type.content_type = Some("text/plain".to_string());
        let content_type_error =
            validate_upload_files(&plan, &[content_type], "files", "asset.add").unwrap_err();
        assert!(format!("{content_type_error:#}").contains("contentType is not valid"));
    }

    #[test]
    fn send_rejects_literal_token_for_management_routes() {
        let settings = ResolvedCliSettings {
            url: "http://127.0.0.1:8787".to_string(),
            request_timeout_ms: 30_000,
            tls: CliTlsConfig::default(),
            token: Some("literal".to_string()),
            token_from_literal_arg: true,
            identity_header: "Authorization".to_string(),
            identity_scheme: "Bearer".to_string(),
            allow_insecure_broker_http: false,
            read_content_format: ReadContentFormat::Native,
            output_format: ResponseFormat::Json,
        };
        let ctx = CliContext {
            settings: &settings,
            output: None,
        };
        let mut catalog = agent_access_core::empty_catalog(serde_json::json!({}));
        catalog.routes = agent_access_broker::composition()
            .unwrap()
            .http_route_specs();
        let request = serde_json::json!({
            "version": "agent-access.send.v1",
            "kind": "http",
            "method": "GET",
            "route": "/v1/admin/policy/grants"
        });

        let error = reject_literal_identity_token_for_send_management(&ctx, &catalog, &request)
            .unwrap_err();
        assert!(format!("{error:#}").contains("management routes do not accept --token-value"));

        let request = serde_json::json!({
            "version": "agent-access.send.v1",
            "kind": "http",
            "method": "GET",
            "route": "/v1/services/{service}"
        });
        reject_literal_identity_token_for_send_management(&ctx, &catalog, &request).unwrap();
    }

    #[tokio::test]
    async fn send_http_rejects_raw_json_routes_before_dispatch() {
        let server = wiremock::MockServer::start().await;
        let mut settings = response_test_settings(ReadContentFormat::Native, ResponseFormat::Json);
        settings.url = server.uri();
        let ctx = CliContext {
            settings: &settings,
            output: None,
        };
        let mut upload = agent_access_broker::composition()
            .unwrap()
            .http_route_specs()
            .into_iter()
            .find(|route| route.operation == "admin.imports.document.upload")
            .unwrap();
        let mut catalog = agent_access_core::empty_catalog(serde_json::json!({}));
        for dedicated_upload in [true, false] {
            if !dedicated_upload {
                upload.route = "/v1/synthetic/{service}/source".into();
                upload.operation = "synthetic.source.upload".into();
            }
            catalog.routes = vec![upload.clone()];
            for body in [
                Some(
                    serde_json::from_str(r#"{"swagger":"2.0","duplicate":1,"duplicate":2}"#)
                        .unwrap(),
                ),
                None,
            ] {
                let error = run_send_http(
                    &ctx,
                    &catalog,
                    "PUT",
                    &upload.route,
                    BTreeMap::from([("service".into(), "example".into())]),
                    BTreeMap::from([
                        ("expectedVersion".into(), serde_json::json!(2)),
                        ("expectedCatalogRevision".into(), serde_json::json!(7)),
                    ]),
                    body,
                )
                .await
                .unwrap_err();
                assert_eq!(error.downcast_ref::<DeferredCliError>().unwrap().code, 3);
                assert!(error.to_string().contains("unsupported by kind=http"));
                if dedicated_upload {
                    assert!(
                        error
                            .to_string()
                            .contains("agent-access admin imports upload-document")
                    );
                }
            }
        }
        assert!(server.received_requests().await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn send_http_rejects_raw_json_before_reading_secret_sources() {
        use wiremock::{
            Mock, MockServer, ResponseTemplate,
            matchers::{method, path},
        };
        let server = MockServer::start().await;
        let mut settings = response_test_settings(ReadContentFormat::Native, ResponseFormat::Json);
        settings.url = server.uri();
        let ctx = CliContext {
            settings: &settings,
            output: None,
        };
        let mut catalog = agent_access_core::empty_catalog(serde_json::json!({}));
        catalog.routes = agent_access_broker::composition()
            .unwrap()
            .http_route_specs();
        Mock::given(method("GET"))
            .and(path("/v1/spec/catalog"))
            .respond_with(ResponseTemplate::new(200).set_body_json(&catalog))
            .expect(1)
            .mount(&server)
            .await;
        let dir = tempfile::tempdir().unwrap();
        let request_file = dir.path().join("request.json");
        fs::write(
            &request_file,
            serde_json::to_vec(&serde_json::json!({
                "version": SEND_SCHEMA_VERSION,
                "kind": "http",
                "method": "PUT",
                "route": "/v1/admin/imports/{service}/document",
                "pathParams": {"service": "example"},
                "query": {"expectedVersion": 2, "expectedCatalogRevision": 7},
                "secretSources": [{
                    "pointer": "/body",
                    "source": {"type": "file", "path": dir.path().join("absent.json")}
                }]
            }))
            .unwrap(),
        )
        .unwrap();
        let error = run_send_command(&ctx, &None, &Some(request_file), false)
            .await
            .unwrap_err();
        assert_eq!(error.downcast_ref::<DeferredCliError>().unwrap().code, 3);
        assert!(
            error
                .to_string()
                .contains("agent-access admin imports upload-document")
        );
        let requests = server.received_requests().await.unwrap();
        assert_eq!(requests.len(), 1);
        assert_eq!(requests[0].method, "GET");
        server.verify().await;
    }

    #[test]
    fn send_http_response_shape_follows_route_catalog() {
        let routes = agent_access_broker::composition()
            .unwrap()
            .http_route_specs();
        let management = routes
            .iter()
            .find(|route| route.method == "GET" && route.route == "/v1/admin/policy/grants")
            .unwrap();
        assert_eq!(
            response_shape_for_route(management),
            ResponseShape::ManagementObject
        );
        let discovery = routes
            .iter()
            .find(|route| route.method == "GET" && route.route == "/v1/services")
            .unwrap();
        assert_eq!(response_shape_for_route(discovery), ResponseShape::Json);
        let broker_status = routes
            .iter()
            .find(|route| route.method == "GET" && route.route == "/v1/broker/status")
            .unwrap();
        assert_eq!(response_shape_for_route(broker_status), ResponseShape::Json);
    }

    #[test]
    fn token_issue_restriction_flags_parse_as_typed_values() {
        let cli = Cli::try_parse_from([
            "agent-access",
            "tokens",
            "issue",
            "--name",
            "restricted",
            "--execution-context",
            "internal",
            "--service",
            "gitlab",
            "--action",
            "gitlab=repo.fetch",
            "--resource-id",
            "gitlab=payments",
            "--resource-group-id",
            "gitlab=engineering",
        ])
        .unwrap();
        let Command::Tokens {
            command:
                TokensCommand::Issue {
                    resource_ids,
                    resource_group_ids,
                    ..
                },
        } = cli.command
        else {
            panic!("token issue expected")
        };
        assert_eq!(
            resource_ids,
            [TokenResourceReference {
                service: "gitlab".into(),
                id: "payments".into()
            }]
        );
        assert_eq!(resource_group_ids[0].id, "engineering");
        for invalid in [
            "missing-separator",
            "Bad.Service=page.view",
            "gitlab=Bad Action",
        ] {
            assert!(parse_token_action_restriction(invalid).is_err());
        }
        assert!(parse_token_resource_reference("gitlab=").is_err());
        assert!(parse_token_resource_reference("payments").is_err());
        for flag in ["--scope", "--repository", "--namespace"] {
            assert!(
                Cli::try_parse_from([
                    "agent-access",
                    "tokens",
                    "issue",
                    "--name",
                    "old",
                    "--execution-context",
                    "internal",
                    flag,
                    "gitlab.repository=old"
                ])
                .is_err()
            );
        }
    }

    #[test]
    fn self_token_issue_requires_an_execution_context() {
        assert!(
            Cli::try_parse_from([
                "agent-access",
                "tokens",
                "issue",
                "--name",
                "missing-context",
            ])
            .is_err()
        );
    }

    #[test]
    fn token_issue_commands_reject_removed_device_name_flag() {
        assert!(
            Cli::try_parse_from([
                "agent-access",
                "tokens",
                "issue",
                "--name",
                "legacy",
                "--execution-context",
                "internal",
                "--device-name",
                "workstation",
            ])
            .is_err()
        );
        assert!(
            Cli::try_parse_from([
                "agent-access",
                "admin",
                "tokens",
                "issue",
                "alice",
                "--name",
                "legacy",
                "--execution-context",
                "internal",
                "--device-name",
                "workstation",
            ])
            .is_err()
        );
    }

    #[test]
    fn token_resource_restrictions_preserve_follow_grants_and_empty_selection() {
        let services = vec!["gitlab".to_string()];
        let actions = vec![parse_token_action_restriction("gitlab=repo.fetch").unwrap()];
        let selection = |ids: &[TokenResourceReference],
                         groups: &[TokenResourceReference],
                         restricted: &[String]| {
            token_service_restrictions(TokenServiceRestrictionsInput {
                services: &services,
                actions: &actions,
                resource_ids: ids,
                resource_group_ids: groups,
                restricted_services: restricted,
                service_restrictions_file: &None,
            })
            .unwrap()
            .unwrap()
        };
        assert!(
            selection(&[], &[], &[])["gitlab"]
                .get("resources")
                .is_none()
        );
        assert_eq!(
            selection(&[], &[], &services)["gitlab"]["resources"],
            serde_json::json!({"resourceIds":[],"resourceGroupIds":[]})
        );
        let ids = [parse_token_resource_reference("gitlab=payments").unwrap()];
        let groups = [parse_token_resource_reference("gitlab=engineering").unwrap()];
        assert_eq!(
            selection(&ids, &groups, &[])["gitlab"]["resources"],
            serde_json::json!({"resourceIds":["payments"],"resourceGroupIds":["engineering"]})
        );
    }

    #[test]
    fn token_restriction_file_preserves_empty_and_rejects_legacy_scope_fields() {
        let path = std::env::temp_dir().join(format!(
            "agent-access-resource-selection-{}.json",
            Uuid::new_v4()
        ));
        let parse = || {
            token_service_restrictions(TokenServiceRestrictionsInput {
                services: &["jira".into()],
                actions: &[],
                resource_ids: &[],
                resource_group_ids: &[],
                restricted_services: &[],
                service_restrictions_file: &Some(path.clone()),
            })
        };
        fs::write(&path, r#"{"jira":{"actions":["issue.view"],"resources":{"resourceIds":[],"resourceGroupIds":[]}}}"#).unwrap();
        let valid = parse();
        fs::write(
            &path,
            r#"{"jira":{"actions":["issue.view"],"resourceScopes":{"project":["ENG"]}}}"#,
        )
        .unwrap();
        let legacy = parse();
        fs::remove_file(path).unwrap();
        assert_eq!(
            valid.unwrap().unwrap()["jira"]["resources"],
            serde_json::json!({"resourceIds":[],"resourceGroupIds":[]})
        );
        assert!(legacy.is_err());
    }

    #[test]
    fn token_issue_restrictions_reject_duplicates_and_unlisted_services() {
        let services = vec!["jira".to_string()];
        let actions = vec![parse_token_action_restriction("jira=issue.view").unwrap()];
        let refs = vec![parse_token_resource_reference("jira=eng").unwrap(); 2];
        assert!(
            token_service_restrictions(TokenServiceRestrictionsInput {
                services: &services,
                actions: &actions,
                resource_ids: &refs,
                resource_group_ids: &[],
                restricted_services: &[],
                service_restrictions_file: &None,
            })
            .is_err()
        );
        let refs = vec![parse_token_resource_reference("gitlab=eng").unwrap()];
        assert!(
            token_service_restrictions(TokenServiceRestrictionsInput {
                services: &services,
                actions: &actions,
                resource_ids: &refs,
                resource_group_ids: &[],
                restricted_services: &[],
                service_restrictions_file: &None,
            })
            .is_err()
        );
        assert!(
            token_service_restrictions(TokenServiceRestrictionsInput {
                services: &services,
                actions: &[],
                resource_ids: &[],
                resource_group_ids: &[],
                restricted_services: &services,
                service_restrictions_file: &None,
            })
            .is_err()
        );
        assert!(
            token_service_restrictions(TokenServiceRestrictionsInput {
                services: &["jira".into(), "jira".into()],
                actions: &[],
                resource_ids: &[],
                resource_group_ids: &[],
                restricted_services: &[],
                service_restrictions_file: &None,
            })
            .is_err()
        );
    }

    #[test]
    fn admin_agent_token_issue_nests_service_restrictions_in_scopes() {
        let actions = [parse_token_action_restriction("jira=issue.view").unwrap()];
        let refs = [parse_token_resource_reference("jira=eng").unwrap()];
        let body = admin_token_issue_body(AdminTokenIssueCliInput {
            name: "administered",
            token_class: "agent_invoke",
            ttl: &None,
            expires_at: &None,
            never: false,
            services: &["jira".into()],
            actions: &actions,
            resource_ids: &refs,
            resource_group_ids: &[],
            restricted_services: &[],
            service_restrictions_file: &None,
            execution_contexts: &["internal".into()],
        })
        .unwrap();
        assert_eq!(
            body["scopes"]["serviceRestrictions"]["jira"]["resources"]["resourceIds"],
            serde_json::json!(["eng"])
        );
        assert!(
            admin_token_issue_body(AdminTokenIssueCliInput {
                name: "management",
                token_class: "user_manage",
                ttl: &None,
                expires_at: &None,
                never: false,
                services: &[],
                actions: &actions,
                resource_ids: &[],
                resource_group_ids: &[],
                restricted_services: &[],
                service_restrictions_file: &None,
                execution_contexts: &[],
            })
            .is_err()
        );
    }

    #[test]
    fn grant_reference_selections_keep_explicit_empty_and_reject_old_policy_shapes() {
        assert_eq!(policy_resources_value(&[], &[], &None, &None, false), None);
        assert_eq!(
            policy_resources_value(&[], &[], &Some("{}".into()), &None, false),
            Some(serde_json::json!({"resourceIds":[],"resourceGroupIds":[]}))
        );
        assert_eq!(
            policy_resources_value(&["repo".into()], &["team".into()], &None, &None, false),
            Some(serde_json::json!({"resourceIds":["repo"],"resourceGroupIds":["team"]}))
        );
        assert!(
            serde_json::from_value::<ResourceSelection>(
                serde_json::json!({"repository":["engineering/payments"]})
            )
            .is_err()
        );
        for flag in [
            "--scope",
            "--resource-scopes-json",
            "--resource-scopes-file",
        ] {
            assert!(
                Cli::try_parse_from([
                    "agent-access",
                    "admin",
                    "policy",
                    "grants",
                    "update",
                    "grant",
                    "--expected-version",
                    "1",
                    flag,
                    "old"
                ])
                .is_err()
            );
        }
    }

    #[test]
    fn policy_grant_create_body_emits_subjects_array() {
        let grant_id = Some("grant-1".to_string());
        let subjects = vec!["group:agents".to_string(), "user:admin".to_string()];
        let actions = vec!["echo".to_string()];
        let execution_contexts = vec!["external".to_string(), "internal".to_string()];
        let scopes = vec!["TEST".to_string()];
        let none_string = None;
        let none_path = None;
        let body = policy_grant_create_body(PolicyGrantCreateCliInput {
            grant_id: &grant_id,
            subjects: &subjects,
            service: "fake",
            actions: &actions,
            execution_contexts: &execution_contexts,
            resource_ids: &scopes,
            resource_group_ids: &[],
            resources_json: &none_string,
            resources_file: &none_path,
            credential_mode: "service",
            priority: Some(10),
            status: &Some("disabled".to_string()),
            description: &Some("Test access".to_string()),
        });

        assert_eq!(body["grantId"], "grant-1");
        assert_eq!(
            body["subjects"],
            serde_json::json!(["group:agents", "user:admin"])
        );
        assert!(body.get("subject").is_none());
        assert_eq!(
            body["executionContexts"],
            serde_json::json!(["external", "internal"])
        );
        assert_eq!(
            body["resources"]["resourceIds"],
            serde_json::json!(["TEST"])
        );

        let single_subject = vec!["group:agents".to_string()];
        let body = policy_grant_create_body(PolicyGrantCreateCliInput {
            grant_id: &None,
            subjects: &single_subject,
            service: "fake",
            actions: &actions,
            execution_contexts: &execution_contexts,
            resource_ids: &scopes,
            resource_group_ids: &[],
            resources_json: &none_string,
            resources_file: &none_path,
            credential_mode: "service",
            priority: None,
            status: &none_string,
            description: &none_string,
        });
        assert_eq!(body["subjects"], serde_json::json!(["group:agents"]));
        assert!(body.get("subject").is_none());
    }

    #[test]
    fn policy_grant_execution_context_flags_are_repeatable_and_required_for_create() {
        let create = Cli::try_parse_from([
            "agent-access",
            "admin",
            "policy",
            "grants",
            "create",
            "--subject",
            "group:agents",
            "--service",
            "fake",
            "--action",
            "echo",
            "--execution-context",
            "external",
            "--execution-context",
            "internal",
            "--credential-mode",
            "service",
        ])
        .unwrap();
        let Command::Admin {
            command:
                AdminCommand::Policy {
                    command:
                        AdminPolicyCommand::Grants {
                            command:
                                AdminPolicyGrantsCommand::Create {
                                    execution_contexts, ..
                                },
                        },
                },
        } = create.command
        else {
            panic!("expected admin policy grant create command");
        };
        assert_eq!(execution_contexts, ["external", "internal"]);

        let missing = Cli::try_parse_from([
            "agent-access",
            "admin",
            "policy",
            "grants",
            "create",
            "--subject",
            "group:agents",
            "--service",
            "fake",
            "--action",
            "echo",
            "--credential-mode",
            "service",
        ]);
        assert!(missing.is_err());

        let update = Cli::try_parse_from([
            "agent-access",
            "admin",
            "policy",
            "grants",
            "update",
            "grant-1",
            "--expected-version",
            "2",
            "--execution-context",
            "workstation",
            "--execution-context",
            "internal",
        ])
        .unwrap();
        let Command::Admin {
            command:
                AdminCommand::Policy {
                    command:
                        AdminPolicyCommand::Grants {
                            command:
                                AdminPolicyGrantsCommand::Update {
                                    execution_contexts, ..
                                },
                        },
                },
        } = update.command
        else {
            panic!("expected admin policy grant update command");
        };
        assert_eq!(execution_contexts, ["workstation", "internal"]);

        let validate = Cli::try_parse_from([
            "agent-access",
            "admin",
            "policy",
            "grants",
            "validate",
            "--execution-context",
            "external",
            "--execution-context",
            "internal",
        ])
        .unwrap();
        let Command::Admin {
            command:
                AdminCommand::Policy {
                    command:
                        AdminPolicyCommand::Grants {
                            command:
                                AdminPolicyGrantsCommand::Validate {
                                    execution_contexts, ..
                                },
                        },
                },
        } = validate.command
        else {
            panic!("expected admin policy grant validate command");
        };
        assert_eq!(execution_contexts, ["external", "internal"]);
    }

    #[test]
    fn policy_grant_patch_body_replaces_subjects_and_omits_when_absent() {
        let subjects = vec!["group:agents".to_string(), "user:admin".to_string()];
        let empty_subjects = Vec::new();
        let empty_actions = Vec::new();
        let execution_contexts = vec!["external".to_string(), "internal".to_string()];
        let empty_execution_contexts = Vec::new();
        let empty_scopes = Vec::new();
        let none_string = None;
        let none_path = None;
        let body = policy_grant_patch_body(PolicyGrantPatchCliInput {
            expected_version: 4,
            subjects: &subjects,
            service: &None,
            actions: &empty_actions,
            execution_contexts: &execution_contexts,
            resource_ids: &empty_scopes,
            resource_group_ids: &[],
            resources_json: &none_string,
            resources_file: &none_path,
            credential_mode: &None,
            priority: None,
            clear_priority: false,
            status: &None,
            description: &None,
            clear_description: false,
        });

        assert_eq!(body["expectedVersion"], 4);
        assert_eq!(
            body["subjects"],
            serde_json::json!(["group:agents", "user:admin"])
        );
        assert!(body.get("subject").is_none());
        assert_eq!(
            body["executionContexts"],
            serde_json::json!(["external", "internal"])
        );

        let body = policy_grant_patch_body(PolicyGrantPatchCliInput {
            expected_version: 5,
            subjects: &empty_subjects,
            service: &None,
            actions: &empty_actions,
            execution_contexts: &empty_execution_contexts,
            resource_ids: &empty_scopes,
            resource_group_ids: &[],
            resources_json: &none_string,
            resources_file: &none_path,
            credential_mode: &None,
            priority: None,
            clear_priority: false,
            status: &None,
            description: &Some("Updated".to_string()),
            clear_description: false,
        });

        assert_eq!(body["expectedVersion"], 5);
        assert_eq!(body["description"], "Updated");
        assert!(body.get("subjects").is_none());
        assert!(body.get("subject").is_none());
        assert!(body.get("executionContexts").is_none());
    }

    #[test]
    fn policy_grant_validate_body_uses_subjects_for_create_and_patch() {
        let single_subject = vec!["group:agents".to_string()];
        let patch_subjects = vec!["user:admin".to_string(), "group:agents".to_string()];
        let actions = vec!["echo".to_string()];
        let empty_actions = Vec::new();
        let execution_contexts = vec!["external".to_string()];
        let patch_execution_contexts = vec!["internal".to_string(), "workstation".to_string()];
        let scopes = vec!["TEST".to_string()];
        let empty_scopes = Vec::new();
        let none_string = None;
        let none_path = None;
        let service = Some("fake".to_string());
        let credential_mode = Some("service".to_string());

        let body = policy_grant_validate_body(PolicyGrantValidateCliInput {
            grant_id: &None,
            expected_version: None,
            subjects: &single_subject,
            service: &service,
            actions: &actions,
            execution_contexts: &execution_contexts,
            resource_ids: &scopes,
            resource_group_ids: &[],
            resources_json: &none_string,
            resources_file: &none_path,
            credential_mode: &credential_mode,
            priority: None,
            clear_priority: false,
            status: &None,
            description: &None,
            clear_description: false,
        });

        assert_eq!(body["subjects"], serde_json::json!(["group:agents"]));
        assert!(body.get("subject").is_none());
        assert_eq!(body["executionContexts"], serde_json::json!(["external"]));
        assert_eq!(
            body["resources"]["resourceIds"],
            serde_json::json!(["TEST"])
        );

        let grant_id = Some("grant-1".to_string());
        let body = policy_grant_validate_body(PolicyGrantValidateCliInput {
            grant_id: &grant_id,
            expected_version: Some(3),
            subjects: &patch_subjects,
            service: &None,
            actions: &empty_actions,
            execution_contexts: &patch_execution_contexts,
            resource_ids: &empty_scopes,
            resource_group_ids: &[],
            resources_json: &none_string,
            resources_file: &none_path,
            credential_mode: &None,
            priority: None,
            clear_priority: false,
            status: &None,
            description: &None,
            clear_description: false,
        });

        assert_eq!(body["grantId"], "grant-1");
        assert_eq!(body["expectedVersion"], 3);
        assert_eq!(
            body["subjects"],
            serde_json::json!(["user:admin", "group:agents"])
        );
        assert!(body.get("subject").is_none());
        assert_eq!(
            body["executionContexts"],
            serde_json::json!(["internal", "workstation"])
        );

        let empty_execution_contexts = Vec::new();
        let body = policy_grant_validate_body(PolicyGrantValidateCliInput {
            grant_id: &grant_id,
            expected_version: Some(3),
            subjects: &[],
            service: &None,
            actions: &[],
            execution_contexts: &empty_execution_contexts,
            resource_ids: &[],
            resource_group_ids: &[],
            resources_json: &none_string,
            resources_file: &none_path,
            credential_mode: &None,
            priority: None,
            clear_priority: false,
            status: &None,
            description: &Some("unchanged contexts".to_string()),
            clear_description: false,
        });
        assert!(body.get("executionContexts").is_none());
    }

    #[test]
    fn admin_policy_grants_list_path_filters_exact_subject() {
        assert_eq!(
            admin_policy_grants_list_path(&Some("group:agents".to_string()), &None, &None, &None,),
            "/v1/admin/policy/grants?subject=group%3Aagents"
        );
        assert_eq!(
            admin_policy_grants_list_path(
                &Some("user:admin@example.com".to_string()),
                &Some("fake".to_string()),
                &Some("active".to_string()),
                &Some("external".to_string()),
            ),
            "/v1/admin/policy/grants?subject=user%3Aadmin%40example.com&service=fake&status=active&executionContext=external"
        );

        let parsed = Cli::try_parse_from([
            "agent-access",
            "admin",
            "policy",
            "grants",
            "list",
            "--execution-context",
            "workstation",
        ])
        .unwrap();
        let Command::Admin {
            command:
                AdminCommand::Policy {
                    command:
                        AdminPolicyCommand::Grants {
                            command:
                                AdminPolicyGrantsCommand::List {
                                    execution_context, ..
                                },
                        },
                },
        } = parsed.command
        else {
            panic!("expected admin policy grants list command");
        };
        assert_eq!(execution_context.as_deref(), Some("workstation"));
    }

    #[test]
    fn policy_manager_commands_require_principal_and_build_encoded_paths() {
        let principal = Cli::try_parse_from([
            "agent-access",
            "admin",
            "policy",
            "managers",
            "grant",
            "--service",
            "jira/cloud",
            "--principal",
            "alice@example.com",
        ])
        .unwrap();
        let Command::Admin {
            command:
                AdminCommand::Policy {
                    command:
                        AdminPolicyCommand::Managers {
                            command: AdminPolicyManagersCommand::Grant { service, principal },
                        },
                },
        } = principal.command
        else {
            panic!("expected admin policy managers grant command");
        };
        assert_eq!(
            admin_policy_manager_assignment_path(&service, &principal),
            "/v1/admin/policy/services/jira%2Fcloud/managers/alice@example.com"
        );

        let missing = Cli::try_parse_from([
            "agent-access",
            "admin",
            "policy",
            "managers",
            "revoke",
            "--service",
            "jira",
        ]);
        assert!(missing.is_err());

        let conflicting = Cli::try_parse_from([
            "agent-access",
            "admin",
            "policy",
            "managers",
            "grant",
            "--service",
            "jira",
            "--principal",
            "alice",
            "--group",
            "jira-admins",
        ]);
        assert!(conflicting.is_err());
    }

    #[test]
    fn policy_manager_list_path_uses_exact_service_filter() {
        assert_eq!(
            admin_policy_managers_list_path(&None),
            "/v1/admin/policy/service-managers"
        );
        assert_eq!(
            admin_policy_managers_list_path(&Some("jira/cloud".to_string())),
            "/v1/admin/policy/service-managers?service=jira%2Fcloud"
        );
    }

    #[test]
    fn policy_grant_subject_commands_emit_existing_route_bodies() {
        let add = policy_grant_subject_mutation_body("group:agents", 7, None);
        assert_eq!(
            add,
            serde_json::json!({
                "subject": "group:agents",
                "expectedVersion": 7
            })
        );

        let remove =
            policy_grant_subject_mutation_body("user:alice@example.com", 8, Some("disable_grant"));
        assert_eq!(
            remove,
            serde_json::json!({
                "subject": "user:alice@example.com",
                "expectedVersion": 8,
                "lastSubjectBehavior": "disable_grant"
            })
        );

        let parsed = Cli::try_parse_from([
            "agent-access",
            "admin",
            "policy",
            "grants",
            "subjects",
            "remove",
            "grant-1",
            "--subject",
            "group:agents",
            "--expected-version",
            "4",
            "--last-subject-behavior",
            "disable_grant",
        ])
        .unwrap();
        let Command::Admin {
            command:
                AdminCommand::Policy {
                    command:
                        AdminPolicyCommand::Grants {
                            command:
                                AdminPolicyGrantsCommand::Subjects {
                                    command:
                                        AdminPolicyGrantSubjectsCommand::Remove {
                                            last_subject_behavior,
                                            ..
                                        },
                                },
                        },
                },
        } = parsed.command
        else {
            panic!("expected admin policy grant subject remove command");
        };
        assert_eq!(last_subject_behavior, "disable_grant");
    }

    #[test]
    fn credential_put_body_collects_fields_from_schema_sources() {
        let schema = cli_input_schema(
            agent_access_core::credential_input_schema(
                "jira",
                "Jira",
                "atlassian-api-token",
                "basic_api_token",
            )
            .unwrap(),
        );
        let token_path =
            std::env::temp_dir().join(format!("agent-access-cli-token-{}.txt", Uuid::new_v4()));
        fs::write(&token_path, b"secret-token\n").unwrap();
        let username = Some("alice@example.com".to_string());
        let none_string = None;
        let fields = Vec::new();
        let field_files = vec![NamedPath {
            name: "token".to_string(),
            path: token_path.clone(),
        }];
        let field_stdin = None;

        let body = credential_put_body(CredentialPutInput {
            schema: &schema,
            username: &username,
            username_env: &none_string,
            username_file: &None,
            field: &fields,
            field_env: &fields,
            field_file: &field_files,
            field_stdin: &field_stdin,
            display_name: &Some("Alice Jira".to_string()),
            expires_at: &none_string,
        })
        .unwrap();

        assert_eq!(body["profile"], "atlassian-api-token");
        assert_eq!(body["secret"]["username"], "alice@example.com");
        assert_eq!(body["secret"]["token"], "secret-token");
        assert_eq!(body["metadata"]["displayName"], "Alice Jira");
        fs::remove_file(token_path).unwrap();
    }

    #[test]
    fn credential_put_body_collects_token_from_field_env() {
        let schema = cli_input_schema(
            agent_access_core::credential_input_schema(
                "jira",
                "Jira",
                "atlassian-api-token",
                "basic_api_token",
            )
            .unwrap(),
        );
        let env_name = format!("AGENT_ACCESS_TEST_TOKEN_{}", Uuid::new_v4().simple());
        // SAFETY: the variable name is UUID-derived and scoped to this test.
        unsafe {
            env::set_var(&env_name, "secret-token");
        }
        let username = Some("alice@example.com".to_string());
        let none_string = None;
        let fields = Vec::new();
        let field_env = vec![NamedValue {
            name: "token".to_string(),
            value: env_name.clone(),
        }];
        let empty_paths = Vec::new();
        let field_stdin = None;

        let body = credential_put_body(CredentialPutInput {
            schema: &schema,
            username: &username,
            username_env: &none_string,
            username_file: &None,
            field: &fields,
            field_env: &field_env,
            field_file: &empty_paths,
            field_stdin: &field_stdin,
            display_name: &none_string,
            expires_at: &none_string,
        })
        .unwrap();

        assert_eq!(body["secret"]["token"], "secret-token");
        // SAFETY: this removes only the UUID-derived variable set above.
        unsafe {
            env::remove_var(env_name);
        }
    }

    #[test]
    fn credential_put_body_plans_token_from_field_stdin() {
        let schema = cli_input_schema(
            agent_access_core::credential_input_schema(
                "jira",
                "Jira",
                "atlassian-api-token",
                "basic_api_token",
            )
            .unwrap(),
        );
        let username = Some("alice@example.com".to_string());
        let empty_values = Vec::new();
        let empty_paths = Vec::new();
        let none_string = None;
        let field_stdin = Some("token".to_string());

        let plans = credential_field_source_plans(&CredentialPutInput {
            schema: &schema,
            username: &username,
            username_env: &none_string,
            username_file: &None,
            field: &empty_values,
            field_env: &empty_values,
            field_file: &empty_paths,
            field_stdin: &field_stdin,
            display_name: &none_string,
            expires_at: &none_string,
        })
        .unwrap();

        assert_eq!(plans.len(), 2);
        assert_eq!(plans["token"].input, CredentialFieldInput::Stdin);
    }

    #[test]
    fn credential_put_body_rejects_secret_literal_fields() {
        let schema = cli_input_schema(
            agent_access_core::credential_input_schema(
                "jira",
                "Jira",
                "atlassian-api-token",
                "basic_api_token",
            )
            .unwrap(),
        );
        let username = None;
        let fields = vec![NamedValue {
            name: "token".to_string(),
            value: "secret-token".to_string(),
        }];
        let empty_values = Vec::new();
        let empty_paths = Vec::new();
        let none_string = None;
        let field_stdin = None;

        let error = credential_put_body(CredentialPutInput {
            schema: &schema,
            username: &username,
            username_env: &none_string,
            username_file: &None,
            field: &fields,
            field_env: &empty_values,
            field_file: &empty_paths,
            field_stdin: &field_stdin,
            display_name: &none_string,
            expires_at: &none_string,
        })
        .unwrap_err();

        assert!(format!("{error:#}").contains("secret"));
        assert!(format!("{error:#}").contains("--field-env token=ENV_VAR"));
    }

    #[test]
    fn credential_put_body_rejects_duplicate_sources_before_reading_values() {
        let schema = cli_input_schema(
            agent_access_core::credential_input_schema(
                "jira",
                "Jira",
                "atlassian-api-token",
                "basic_api_token",
            )
            .unwrap(),
        );
        let username = Some("alice@example.com".to_string());
        let field_env = vec![NamedValue {
            name: "token".to_string(),
            value: "AGENT_ACCESS_TEST_MISSING_TOKEN_ENV".to_string(),
        }];
        let field_file = vec![NamedPath {
            name: "token".to_string(),
            path: PathBuf::from("/tmp/agent-access-test-token"),
        }];
        let empty_values = Vec::new();
        let none_string = None;
        let field_stdin = None;

        let error = credential_field_source_plans(&CredentialPutInput {
            schema: &schema,
            username: &username,
            username_env: &none_string,
            username_file: &None,
            field: &empty_values,
            field_env: &field_env,
            field_file: &field_file,
            field_stdin: &field_stdin,
            display_name: &none_string,
            expires_at: &none_string,
        })
        .unwrap_err();

        assert!(format!("{error:#}").contains("provided more than once"));
    }

    #[test]
    fn credential_put_body_allows_identical_duplicate_source_plans() {
        let schema = cli_input_schema(
            agent_access_core::credential_input_schema(
                "jira",
                "Jira",
                "atlassian-api-token",
                "basic_api_token",
            )
            .unwrap(),
        );
        let username = Some("alice@example.com".to_string());
        let duplicate = vec![
            NamedValue {
                name: "token".to_string(),
                value: "AGENT_ACCESS_TEST_DUPLICATE_TOKEN_ENV".to_string(),
            },
            NamedValue {
                name: "token".to_string(),
                value: "AGENT_ACCESS_TEST_DUPLICATE_TOKEN_ENV".to_string(),
            },
        ];
        let empty_values = Vec::new();
        let empty_paths = Vec::new();
        let none_string = None;
        let field_stdin = None;
        let plans = credential_field_source_plans(&CredentialPutInput {
            schema: &schema,
            username: &username,
            username_env: &none_string,
            username_file: &None,
            field: &empty_values,
            field_env: &duplicate,
            field_file: &empty_paths,
            field_stdin: &field_stdin,
            display_name: &none_string,
            expires_at: &none_string,
        })
        .unwrap();

        assert_eq!(plans.len(), 2);
        assert_eq!(
            plans["token"].input,
            CredentialFieldInput::Env("AGENT_ACCESS_TEST_DUPLICATE_TOKEN_ENV".to_string())
        );
    }

    #[test]
    fn credential_put_body_rejects_unsupported_schema_input_methods_before_stdin() {
        let schema = cli_input_schema(
            agent_access_core::credential_input_schema(
                "jira",
                "Jira",
                "atlassian-api-token",
                "basic_api_token",
            )
            .unwrap(),
        );
        let empty_values = Vec::new();
        let field_files = vec![NamedPath {
            name: "token".to_string(),
            path: PathBuf::from("/tmp/agent-access-test-token"),
        }];
        let none_string = None;
        let field_stdin = Some("username".to_string());

        let error = credential_put_body(CredentialPutInput {
            schema: &schema,
            username: &none_string,
            username_env: &none_string,
            username_file: &None,
            field: &empty_values,
            field_env: &empty_values,
            field_file: &field_files,
            field_stdin: &field_stdin,
            display_name: &none_string,
            expires_at: &none_string,
        })
        .unwrap_err();

        assert!(format!("{error:#}").contains("does not support stdin"));
    }

    #[test]
    fn parses_named_credential_fields_and_schema_profile_query() {
        assert_eq!(
            parse_named_value("field.name=value=with=equals").unwrap(),
            NamedValue {
                name: "field.name".to_string(),
                value: "value=with=equals".to_string()
            }
        );
        assert_eq!(
            parse_named_value("apiKey=value").unwrap(),
            NamedValue {
                name: "apiKey".to_string(),
                value: "value".to_string()
            }
        );
        assert!(parse_named_value("Bad=value").is_err());
        assert_eq!(
            credential_input_schema_path(
                "/v1/credentials/connections/jira",
                &Some("jira cloud/profile".to_string())
            ),
            "/v1/credentials/connections/jira/input-schema?profile=jira+cloud%2Fprofile"
        );
    }

    #[test]
    fn omitted_input_methods_default_to_non_stdin_non_prompt_sources() {
        let non_secret = CredentialInputField {
            name: "apiKey".to_string(),
            required: true,
            secret: false,
            prompt: "API key".to_string(),
            description: None,
            input_methods: None,
        };
        let secret = CredentialInputField {
            name: "token".to_string(),
            required: true,
            secret: true,
            prompt: "Token".to_string(),
            description: None,
            input_methods: None,
        };

        assert!(credential_field_allows_source(
            &non_secret,
            CredentialFieldSource::Literal
        ));
        assert!(credential_field_allows_source(
            &secret,
            CredentialFieldSource::Env
        ));
        assert!(credential_field_allows_source(
            &secret,
            CredentialFieldSource::File
        ));
        assert!(!credential_field_allows_source(
            &secret,
            CredentialFieldSource::Literal
        ));
        assert!(!credential_field_allows_source(
            &secret,
            CredentialFieldSource::Stdin
        ));
        assert!(!credential_field_allows_source(
            &secret,
            CredentialFieldSource::Prompt
        ));
    }

    #[test]
    fn explicit_attachment_content_type_requires_one_file() {
        assert!(
            validate_attachment_content_type_override(
                "test attach",
                &[PathBuf::from("a.txt"), PathBuf::from("b.png")],
                Some("text/plain")
            )
            .is_err()
        );
        assert!(
            validate_attachment_content_type_override(
                "test attach",
                &[PathBuf::from("a.txt")],
                Some("text/plain")
            )
            .is_ok()
        );
        assert!(
            validate_attachment_content_type_override(
                "test attach",
                &[PathBuf::from("a.txt"), PathBuf::from("b.png")],
                None
            )
            .is_ok()
        );
    }

    #[test]
    fn validates_expected_broker_response_shapes() {
        let envelope = serde_json::json!({
            "agentRequestId": "agent",
            "brokerRequestId": "broker",
            "decision": "allow"
        });
        assert!(response_shape_valid(
            200,
            ResponseShape::Envelope,
            &envelope
        ));
        assert!(response_shape_valid(
            403,
            ResponseShape::Array,
            &serde_json::json!({
                "agentRequestId": "agent",
                "brokerRequestId": "broker",
                "decision": "deny"
            })
        ));
        assert!(response_shape_valid(
            200,
            ResponseShape::Array,
            &serde_json::json!([])
        ));
        assert!(!response_shape_valid(
            200,
            ResponseShape::Envelope,
            &serde_json::json!({"status": "ok"})
        ));
        assert!(!response_shape_valid(
            200,
            ResponseShape::Array,
            &serde_json::json!({"service": "fake"})
        ));
        assert!(response_shape_valid(
            403,
            ResponseShape::Object,
            &serde_json::json!({
                "requestId": "request",
                "brokerRequestId": "broker",
                "decision": "deny"
            })
        ));
    }

    #[test]
    fn parses_download_metadata_header_and_rejects_malformed_values() {
        let metadata = serde_json::json!({
            "agentRequestId": "agent",
            "brokerRequestId": "broker",
            "decision": "allow"
        });
        let encoded = BASE64.encode(serde_json::to_vec(&metadata).unwrap());
        assert_eq!(
            parse_download_metadata_header(Some(&encoded)).unwrap(),
            metadata
        );
        assert_eq!(
            parse_download_metadata_header(None).unwrap_err(),
            "download metadata is missing"
        );
        assert!(
            parse_download_metadata_header(Some("not-base64"))
                .unwrap_err()
                .starts_with("download metadata is invalid")
        );
        let invalid_json = BASE64.encode(b"not-json");
        assert!(
            parse_download_metadata_header(Some(&invalid_json))
                .unwrap_err()
                .starts_with("download metadata is not JSON")
        );
        assert_eq!(
            parse_download_metadata_header(Some(&"A".repeat(16_385))).unwrap_err(),
            "download metadata exceeds the header limit"
        );
    }

    fn download_test_metadata(mutation: bool) -> serde_json::Value {
        let mut value = serde_json::json!({
            "agentRequestId":"agent", "brokerRequestId":"broker", "decision":"allow",
            "result": {"size":3, "sha256":format!("{:x}", Sha256::digest(b"abc")),
                "contentType":"application/octet-stream", "upstreamCommand":{"warnings":["bounded warning"]}}
        });
        if mutation {
            value["result"]["mutationStatus"] = serde_json::json!("applied_unverified");
            value["result"]["retrySafe"] = serde_json::json!(false);
            value["result"]["safeLocators"] = serde_json::json!({"secret":"private-locator"});
        }
        value
    }

    async fn download_test_response(
        metadata: &serde_json::Value,
        wire_body: &str,
    ) -> reqwest::Response {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let header = BASE64.encode(serde_json::to_vec(metadata).unwrap());
        let wire_body = wire_body.to_owned();
        let server = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut request = [0; 8192];
            let mut received = 0;
            while !request[..received]
                .windows(4)
                .any(|bytes| bytes == b"\r\n\r\n")
            {
                assert!(
                    received < request.len(),
                    "HTTP request headers exceed fixture limit"
                );
                let count = stream.read(&mut request[received..]).unwrap();
                assert_ne!(count, 0, "HTTP request ended before the header terminator");
                received += count;
            }
            write!(stream, "HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\n{RESULT_METADATA_HEADER}: {header}\r\nTransfer-Encoding: chunked\r\n\r\n{wire_body}").unwrap();
        });
        let response = reqwest::Client::new()
            .get(format!("http://{address}/download"))
            .send()
            .await
            .unwrap();
        server.join().unwrap();
        response
    }

    #[tokio::test]
    async fn download_failures_keep_explicit_mutation_outcomes_without_payload_or_sensitive_locators()
     {
        for body in [
            "3\r\nabc\r\nZ\r\n",
            "2\r\nab\r\n0\r\n\r\n",
            "3\r\nxyz\r\n0\r\n\r\n",
        ] {
            let dir = tempfile::tempdir().unwrap();
            let path = dir.path().join("download");
            fs::write(&path, b"original").unwrap();
            let metadata = download_test_metadata(true);
            let response = download_test_response(&metadata, body).await;
            let error = download_response_value(
                response,
                &path,
                DownloadOutput::prepare(&path, None).unwrap(),
                &[
                    "/result/upstreamCommand".into(),
                    "/result/safeLocators/secret".into(),
                ],
                RESULT_METADATA_HEADER,
            )
            .await
            .unwrap_err();
            assert!(matches!(error, DownloadResponseError::Remote(_)));
            let error = error.into_error();
            let failure = error.downcast_ref::<output::LocalOutputFailure>().unwrap();
            assert_eq!(failure.exit_code, 5);
            assert_eq!(failure.details["operationStatus"], "applied_unverified");
            assert_eq!(failure.details["retrySafe"], false);
            assert_eq!(failure.details["output"]["destinationReplaced"], false);
            assert!(!failure.to_string().contains("private-locator"));
            assert!(!failure.to_string().contains("bounded warning"));
            assert_eq!(fs::read(&path).unwrap(), b"original");
            assert_eq!(fs::read_dir(dir.path()).unwrap().count(), 1);
        }
    }

    #[tokio::test]
    async fn verified_download_reports_commit_failure_as_local_with_known_read_success() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("download");
        let reserved = DownloadOutput::prepare(&path, None).unwrap();
        // Force replacement to fail after reservation and completed verification.
        fs::create_dir(&path).unwrap();
        let response =
            download_test_response(&download_test_metadata(false), "3\r\nabc\r\n0\r\n\r\n").await;
        let error = download_response_value(response, &path, reserved, &[], RESULT_METADATA_HEADER)
            .await
            .unwrap_err();
        assert!(matches!(error, DownloadResponseError::Local(_)));
        let error = error.into_error();
        let failure = error.downcast_ref::<output::LocalOutputFailure>().unwrap();
        assert_eq!(failure.exit_code, 1);
        assert_eq!(failure.details["operationStatus"], "succeeded");
        assert_eq!(failure.details["output"]["destinationReplaced"], false);
        assert!(path.is_dir());
        assert_eq!(fs::read_dir(dir.path()).unwrap().count(), 1);
    }

    #[tokio::test]
    async fn shared_download_receipt_retains_bounded_metadata_and_sensitivity_after_verification() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("download");
        let metadata = download_test_metadata(true);
        let response = download_test_response(&metadata, "3\r\nabc\r\n0\r\n\r\n").await;
        let (_, receipt) = download_response_value(
            response,
            &path,
            DownloadOutput::prepare(&path, None).unwrap(),
            &["/result/upstreamCommand".into()],
            RESULT_METADATA_HEADER,
        )
        .await
        .unwrap();
        assert_eq!(receipt["operationStatus"], "applied_unverified");
        assert_eq!(
            receipt["result"]["upstreamCommand"]["warnings"][0],
            "bounded warning"
        );
        assert_eq!(receipt["output"]["size"], 3);
        assert_eq!(receipt["output"]["sensitive"], true);
        assert_eq!(receipt["output"]["sha256"], metadata["result"]["sha256"]);
        assert_eq!(receipt["output"]["contentType"], "application/octet-stream");
        assert_eq!(fs::read(&path).unwrap(), b"abc");
    }

    #[test]
    fn early_download_failures_do_not_invent_read_completion_or_accept_invalid_receipts() {
        let metadata = download_test_metadata(false);
        for status in [None, Some("unrecognized"), Some("applied_unverified")] {
            let mut metadata = metadata.clone();
            if let Some(status) = status {
                metadata["result"]["mutationStatus"] = serde_json::json!(status);
            }
            // No valid explicit receipt: missing retrySafe must not become evidence.
            let error = DownloadResponseError::Local(anyhow::anyhow!("disk full"))
                .with_outcome(&metadata, Path::new("download"), &[], false)
                .into_error();
            assert!(!error.is::<output::LocalOutputFailure>());
        }
        let error = DownloadResponseError::Local(anyhow::anyhow!("disk full"))
            .with_outcome(
                &download_test_metadata(true),
                Path::new("download"),
                &[],
                false,
            )
            .into_error();
        let failure = error.downcast_ref::<output::LocalOutputFailure>().unwrap();
        assert_eq!(failure.exit_code, 1);
        assert_eq!(failure.details["operationStatus"], "applied_unverified");
    }

    #[test]
    fn download_metadata_accepts_unknown_size_and_rejects_invalid_size() {
        let absent = serde_json::json!({"result":{}});
        let null = serde_json::json!({"result":{"size":null}});
        assert_eq!(download_expectations(&absent).unwrap().size, None);
        assert_eq!(download_expectations(&null).unwrap().size, None);
        assert_eq!(next_download_size(0, 3, None).unwrap(), 3);
        verify_download_summary(
            &DownloadWriteSummary {
                size: 3,
                sha256: "0".repeat(64),
            },
            &download_expectations(&null).unwrap(),
        )
        .unwrap();
        let invalid = serde_json::json!({"result":{"size":"three"}});
        assert!(download_expectations(&invalid).is_err());
    }

    #[tokio::test]
    async fn failed_download_stream_preserves_existing_output_file() {
        let output =
            std::env::temp_dir().join(format!("agent-access-cli-download-{}.txt", Uuid::new_v4()));
        fs::write(&output, b"original").unwrap();
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let metadata = serde_json::json!({
            "agentRequestId": "agent",
            "brokerRequestId": "broker",
            "decision": "allow",
            "result": {
                "size": 7
            }
        });
        let encoded_metadata = BASE64.encode(serde_json::to_vec(&metadata).unwrap());
        let server = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut request = [0_u8; 1024];
            let _ = stream.read(&mut request);
            write!(
                stream,
                "HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\n{RESULT_METADATA_HEADER}: {encoded_metadata}\r\nTransfer-Encoding: chunked\r\n\r\n7\r\npartial\r\nZ\r\n"
            )
            .unwrap();
        });

        let response = reqwest::Client::new()
            .get(format!("http://{address}/download"))
            .send()
            .await
            .unwrap();
        let error = download_response_value(
            response,
            &output,
            DownloadOutput::prepare(&output, None).unwrap(),
            &[],
            RESULT_METADATA_HEADER,
        )
        .await
        .unwrap_err();

        assert!(
            format!("{error:#}").contains("failed to read broker download bytes")
                || format!("{error:#}").contains("error decoding response body")
        );
        assert!(matches!(error, DownloadResponseError::Remote(_)));
        assert!(!error.into_error().is::<output::LocalOutputFailure>());
        assert_eq!(fs::read(&output).unwrap(), b"original");
        server.join().unwrap();
        fs::remove_file(&output).unwrap();
    }

    #[tokio::test]
    async fn oversized_download_metadata_preserves_existing_output_file() {
        let output =
            std::env::temp_dir().join(format!("agent-access-cli-oversize-{}.txt", Uuid::new_v4()));
        fs::write(&output, b"original").unwrap();
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let metadata = serde_json::json!({
            "agentRequestId": "agent",
            "brokerRequestId": "broker",
            "decision": "allow",
            "result": {
                "size": 3
            }
        });
        let encoded_metadata = BASE64.encode(serde_json::to_vec(&metadata).unwrap());
        let server = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut request = [0_u8; 1024];
            let _ = stream.read(&mut request);
            write!(
                stream,
                "HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\n{RESULT_METADATA_HEADER}: {encoded_metadata}\r\nContent-Length: 7\r\n\r\npartial"
            )
            .unwrap();
        });

        let response = reqwest::Client::new()
            .get(format!("http://{address}/download"))
            .send()
            .await
            .unwrap();
        let error = download_response_value(
            response,
            &output,
            DownloadOutput::prepare(&output, None).unwrap(),
            &[],
            RESULT_METADATA_HEADER,
        )
        .await
        .unwrap_err();

        assert!(format!("{error:#}").contains("download size mismatch"));
        assert!(matches!(error, DownloadResponseError::Remote(_)));
        assert!(!error.into_error().is::<output::LocalOutputFailure>());
        assert_eq!(fs::read(&output).unwrap(), b"original");
        server.join().unwrap();
        fs::remove_file(&output).unwrap();
    }

    #[test]
    fn gitlab_webhook_commands_parse_closed_typed_shapes() {
        for args in [
            vec!["agent-access", "gitlab", "webhook", "list", "group/project"],
            vec![
                "agent-access",
                "gitlab",
                "webhook",
                "view",
                "group/project",
                "42",
            ],
            vec![
                "agent-access",
                "gitlab",
                "webhook",
                "create",
                "group/project",
                "--destination-url",
                "https://hooks.example.test/events",
                "--event",
                "push",
                "--event",
                "merge_requests",
                "--branch-filter-strategy",
                "all_branches",
                "--secret-token-env",
                "HOOK_TOKEN",
                "--signing-token-file",
                "/run/secrets/signing-token",
            ],
            vec![
                "agent-access",
                "gitlab",
                "webhook",
                "update",
                "group/project",
                "42",
                "--clear-events",
                "--clear-description",
                "--clear-custom-webhook-template",
                "--clear-token",
                "--confirm-destination-reset",
            ],
            vec![
                "agent-access",
                "gitlab",
                "webhook",
                "delete",
                "group/project",
                "42",
            ],
            vec![
                "agent-access",
                "gitlab",
                "webhook",
                "test",
                "group/project",
                "42",
                "--event",
                "merge_requests",
            ],
            vec![
                "agent-access",
                "gitlab",
                "webhook",
                "event",
                "list",
                "group/project",
                "42",
                "--status",
                "server_failure",
                "--max-results",
                "20",
                "--page-token",
                "next",
            ],
            vec![
                "agent-access",
                "gitlab",
                "webhook",
                "event",
                "resend",
                "group/project",
                "42",
                "9001",
            ],
            vec![
                "agent-access",
                "gitlab",
                "webhook",
                "custom-header",
                "set",
                "group/project",
                "42",
                "Authorization",
                "--value-stdin",
            ],
            vec![
                "agent-access",
                "gitlab",
                "webhook",
                "custom-header",
                "delete",
                "group/project",
                "42",
                "Authorization",
            ],
        ] {
            Cli::try_parse_from(args.clone())
                .unwrap_or_else(|error| panic!("{args:?} should parse: {error}"));
        }

        for bad_event in ["unknown", "tag-push", "merge-requests"] {
            assert!(
                Cli::try_parse_from([
                    "agent-access",
                    "gitlab",
                    "webhook",
                    "create",
                    "group/project",
                    "--destination-url",
                    "https://hooks.example.test/events",
                    "--event",
                    bad_event,
                ])
                .is_err()
            );
        }
        assert!(
            Cli::try_parse_from([
                "agent-access",
                "gitlab",
                "webhook",
                "test",
                "group/project",
                "42",
                "--event",
                "deployments",
            ])
            .is_err()
        );

        let dormant = Cli::try_parse_from([
            "agent-access",
            "gitlab",
            "webhook",
            "create",
            "group/project",
            "--destination-url",
            "https://hooks.example.test/events",
        ])
        .unwrap();
        assert!(matches!(
            dormant.command,
            Command::Gitlab {
                command: GitlabCommand::Webhook {
                    command: GitlabWebhookCommand::Create { ref events, .. }
                }
            } if events.is_empty()
        ));

        let replacement = Cli::try_parse_from([
            "agent-access",
            "gitlab",
            "webhook",
            "update",
            "group/project",
            "42",
            "--event",
            "push",
            "--event",
            "notes",
        ])
        .unwrap();
        assert!(matches!(
            replacement.command,
            Command::Gitlab {
                command: GitlabCommand::Webhook {
                    command: GitlabWebhookCommand::Update {
                        ref events,
                        clear_events: false,
                        ..
                    }
                }
            } if events == &[GitlabWebhookEventArg::Push, GitlabWebhookEventArg::Notes]
        ));
        assert!(
            Cli::try_parse_from([
                "agent-access",
                "gitlab",
                "webhook",
                "update",
                "group/project",
                "42",
                "--event",
                "push",
                "--clear-events",
            ])
            .is_err()
        );
        for command in ["list", "view"] {
            let mut args = vec![
                "agent-access",
                "gitlab",
                "webhook",
                command,
                "group/project",
            ];
            if command == "view" {
                args.push("42");
            }
            args.extend(["--output-format", "markdown"]);
            assert!(Cli::try_parse_from(args).is_err());
        }
        for invalid_status in ["2000", "99", "600", "failure"] {
            assert!(
                Cli::try_parse_from([
                    "agent-access",
                    "gitlab",
                    "webhook",
                    "event",
                    "list",
                    "group/project",
                    "42",
                    "--status",
                    invalid_status,
                ])
                .is_err()
            );
        }
        assert!(
            Cli::try_parse_from([
                "agent-access",
                "gitlab",
                "webhook",
                "event",
                "list",
                "group/project",
                "42",
                "--max-results",
                "21",
            ])
            .is_err()
        );
    }

    #[test]
    fn gitlab_webhook_cli_exposes_only_non_literal_secret_sources() {
        for literal_flag in ["--token", "--signing-token"] {
            assert!(
                Cli::try_parse_from([
                    "agent-access",
                    "gitlab",
                    "webhook",
                    "create",
                    "group/project",
                    "--destination-url",
                    "https://hooks.example.test/events",
                    literal_flag,
                    "must-not-parse",
                ])
                .is_err()
            );
        }
        assert!(
            Cli::try_parse_from([
                "agent-access",
                "gitlab",
                "webhook",
                "custom-header",
                "set",
                "group/project",
                "42",
                "Authorization",
                "--value",
                "must-not-parse",
            ])
            .is_err()
        );
        assert!(
            Cli::try_parse_from([
                "agent-access",
                "gitlab",
                "webhook",
                "custom-header",
                "set",
                "group/project",
                "42",
                "Authorization",
            ])
            .is_err()
        );
        assert!(
            Cli::try_parse_from([
                "agent-access",
                "gitlab",
                "webhook",
                "update",
                "group/project",
                "42",
                "--secret-token-env",
                "HOOK_TOKEN",
                "--clear-token",
            ])
            .is_err()
        );
    }

    #[test]
    fn gitlab_webhook_secret_file_preserves_exact_utf8() {
        let path = std::env::temp_dir().join(format!(
            "agent-access-cli-webhook-secret-{}.txt",
            Uuid::new_v4()
        ));
        fs::write(&path, "  café\n").unwrap();
        let value = read_webhook_secret_source("test secret", None, Some(&path), false)
            .unwrap()
            .unwrap();
        assert_eq!(value, "  café\n");
        fs::remove_file(path).unwrap();

        assert!(ensure_single_webhook_secret_stdin(true, true).is_err());

        let mut identifiers_only = serde_json::Map::new();
        identifiers_only.insert("project".to_string(), serde_json::json!("group/project"));
        identifiers_only.insert("webhookId".to_string(), serde_json::json!(42));
        assert!(ensure_webhook_update_has_changes(&identifiers_only).is_err());
        identifiers_only.insert(
            "confirmDestinationReset".to_string(),
            serde_json::json!(true),
        );
        assert!(ensure_webhook_update_has_changes(&identifiers_only).is_err());
        identifiers_only.insert("events".to_string(), serde_json::json!([]));
        ensure_webhook_update_has_changes(&identifiers_only).unwrap();
    }
}

#[cfg(test)]
mod gmail_cli_tests {
    use super::*;
    #[test]
    fn gmail_typed_commands_map_to_canonical_actions() {
        for (args, action, inputs) in [
            (vec!["account"], "account.view", serde_json::json!({})),
            (vec!["labels"], "label.list", serde_json::json!({})),
            (
                vec![
                    "message",
                    "search",
                    "--query",
                    "in:trash",
                    "--include-spam-trash",
                    "--max-results",
                    "5",
                    "--page-token",
                    "next",
                ],
                "message.search",
                serde_json::json!({"query":"in:trash","includeSpamTrash":true,"maxResults":5,"pageToken":"next"}),
            ),
            (
                vec!["message", "view", "abc"],
                "message.view",
                serde_json::json!({"id":"abc"}),
            ),
            (
                vec!["thread", "view", "abc"],
                "thread.view",
                serde_json::json!({"id":"abc"}),
            ),
            (
                vec!["message", "archive", "abc"],
                "message.archive",
                serde_json::json!({"id":"abc"}),
            ),
            (
                vec!["thread", "archive", "abc"],
                "thread.archive",
                serde_json::json!({"id":"abc"}),
            ),
            (
                vec!["message", "trash", "abc"],
                "message.trash",
                serde_json::json!({"id":"abc"}),
            ),
            (
                vec!["thread", "trash", "abc"],
                "thread.trash",
                serde_json::json!({"id":"abc"}),
            ),
            (
                vec!["message", "restore", "abc"],
                "message.restore",
                serde_json::json!({"id":"abc"}),
            ),
            (
                vec!["thread", "restore", "abc"],
                "thread.restore",
                serde_json::json!({"id":"abc"}),
            ),
        ] {
            let cli =
                Cli::try_parse_from(["agent-access", "gmail"].into_iter().chain(args)).unwrap();
            let Command::Gmail { command } = cli.command else {
                panic!("wrong command")
            };
            let (actual, value) = gmail_invocation(&command);
            assert_eq!(actual, format!("gmail.{action}"));
            assert_eq!(value, inputs);
        }
        for verb in ["send", "delete"] {
            assert!(
                Cli::try_parse_from(["agent-access", "gmail", "message", verb, "abc"]).is_err()
            );
        }
    }
}
