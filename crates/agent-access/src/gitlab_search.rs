use super::{CliContext, WholeOutputArgs, run_typed_invoke_value};
use anyhow::Result;
use clap::{Args, Subcommand, ValueEnum};
use serde_json::{Value, json};

#[derive(Debug, Args)]
pub(super) struct ProjectSearchArgs {
    /// Match project names, paths, or descriptions; omit to browse.
    #[arg(long)]
    search: Option<String>,
    /// Include ancestor namespaces in matching (Broker default: true).
    #[arg(long, action = clap::ArgAction::Set)]
    include_namespaces: Option<bool>,
    /// Select archived or active projects; omit to include either state.
    #[arg(long, action = clap::ArgAction::Set)]
    archived: Option<bool>,
    #[command(flatten)]
    page: SearchPageArgs,
    #[command(flatten)]
    response: WholeOutputArgs,
}

impl ProjectSearchArgs {
    fn inputs(&self) -> Value {
        let mut inputs = json!({});
        if let Some(search) = &self.search {
            inputs["search"] = json!(search);
        }
        if let Some(include_namespaces) = self.include_namespaces {
            inputs["includeNamespaces"] = json!(include_namespaces);
        }
        if let Some(archived) = self.archived {
            inputs["archived"] = json!(archived);
        }
        self.page.apply(&mut inputs);
        inputs
    }
}

#[derive(Debug, Subcommand)]
pub(super) enum SearchCommand {
    /// Search issue text across authorized repositories or an explicitly selected project.
    Issues(ContentSearchArgs),
    /// Search merge-request text across authorized repositories or an explicitly selected project.
    MergeRequests(ContentSearchArgs),
    /// Search filenames and code content with the selected native engine.
    Code {
        #[command(flatten)]
        search: ContentSearchArgs,
        /// Use a regular expression (requires the Zoekt engine).
        #[arg(long)]
        regex: bool,
    },
    /// Search commit messages with the selected native engine.
    Commits(ContentSearchArgs),
    /// Search project wiki content with the selected native engine.
    Wiki(ContentSearchArgs),
    /// Search supported repository comments with the selected native engine.
    Comments(ContentSearchArgs),
}

#[derive(Debug, Args)]
pub(super) struct ContentSearchArgs {
    /// Native search expression; syntax and coverage depend on the engine.
    #[arg(long)]
    search: String,
    /// Canonical project path; required when the engine lacks instance search.
    #[arg(long)]
    project: Option<String>,
    /// Configured search engine; omit to use the Broker's default.
    #[arg(long, value_enum)]
    engine: Option<SearchEngine>,
    #[command(flatten)]
    page: SearchPageArgs,
    #[command(flatten)]
    response: WholeOutputArgs,
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum SearchEngine {
    Basic,
    Advanced,
    Zoekt,
}

impl SearchEngine {
    fn as_str(self) -> &'static str {
        match self {
            Self::Basic => "basic",
            Self::Advanced => "advanced",
            Self::Zoekt => "zoekt",
        }
    }
}

#[derive(Debug, Args)]
struct SearchPageArgs {
    /// Maximum items to return, within the Broker's configured cap.
    #[arg(long, value_parser = clap::value_parser!(u32).range(1..=100))]
    max_results: Option<u32>,
    /// Resume with the unchanged query, filters, engine, and page size.
    #[arg(long)]
    page_token: Option<String>,
}

impl SearchPageArgs {
    fn apply(&self, inputs: &mut Value) {
        if let Some(max_results) = self.max_results {
            inputs["maxResults"] = json!(max_results);
        }
        if let Some(page_token) = &self.page_token {
            inputs["pageToken"] = json!(page_token);
        }
    }
}

impl SearchCommand {
    fn invocation(&self) -> (&'static str, Value, &WholeOutputArgs) {
        let (action, args, regex) = match self {
            Self::Issues(args) => ("gitlab.search.issues", args, false),
            Self::MergeRequests(args) => ("gitlab.search.merge_requests", args, false),
            Self::Code { search, regex } => ("gitlab.search.code", search, *regex),
            Self::Commits(args) => ("gitlab.search.commits", args, false),
            Self::Wiki(args) => ("gitlab.search.wiki", args, false),
            Self::Comments(args) => ("gitlab.search.comments", args, false),
        };
        let mut inputs = json!({"search": args.search});
        if let Some(project) = &args.project {
            inputs["project"] = json!(project);
        }
        if let Some(engine) = args.engine {
            inputs["engine"] = json!(engine.as_str());
        }
        if regex {
            inputs["regex"] = json!(true);
        }
        args.page.apply(&mut inputs);
        (action, inputs, &args.response)
    }
}

pub(super) async fn run_project(ctx: &CliContext<'_>, args: &ProjectSearchArgs) -> Result<()> {
    run_typed_invoke_value(
        ctx,
        "gitlab.project.search",
        args.inputs(),
        None,
        args.response.output_format,
    )
    .await
}

pub(super) async fn run_content(ctx: &CliContext<'_>, command: &SearchCommand) -> Result<()> {
    let (action, inputs, response) = command.invocation();
    run_typed_invoke_value(ctx, action, inputs, None, response.output_format).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Cli, Command, GitlabCommand, GitlabProjectCommand, OutputFormatArg};
    use clap::Parser;

    fn parse_content(args: &[&str]) -> SearchCommand {
        let cli = Cli::try_parse_from(args).unwrap();
        let Command::Gitlab {
            command: GitlabCommand::Search { command },
        } = cli.command
        else {
            panic!("expected native search command");
        };
        command
    }

    fn parse_project(args: &[&str]) -> ProjectSearchArgs {
        let cli = Cli::try_parse_from(args).unwrap();
        let Command::Gitlab {
            command:
                GitlabCommand::Project {
                    command: GitlabProjectCommand::Search(args),
                },
        } = cli.command
        else {
            panic!("expected project search command");
        };
        args
    }

    #[test]
    fn discovery_preserves_browse_and_explicit_boolean_filters() {
        let browse = parse_project(&["agent-access", "gitlab", "project", "search"]);
        assert_eq!(browse.inputs(), json!({}));
        let args = parse_project(&[
            "agent-access",
            "gitlab",
            "project",
            "search",
            "--search",
            "dispatch",
            "--include-namespaces",
            "false",
            "--archived",
            "false",
            "--max-results",
            "20",
            "--page-token",
            "opaque",
            "--output-format",
            "markdown",
        ]);
        assert_eq!(
            args.inputs(),
            json!({
                "search": "dispatch", "includeNamespaces": false, "archived": false,
                "maxResults": 20, "pageToken": "opaque",
            })
        );
        assert_eq!(args.response.output_format, Some(OutputFormatArg::Markdown));
        let args = parse_project(&[
            "agent-access",
            "gitlab",
            "project",
            "search",
            "--include-namespaces",
            "true",
            "--archived",
            "true",
        ]);
        assert_eq!(
            args.inputs(),
            json!({"includeNamespaces": true, "archived": true})
        );
    }

    #[test]
    fn content_categories_map_to_distinct_canonical_actions() {
        for (command, action) in [
            ("issues", "gitlab.search.issues"),
            ("merge-requests", "gitlab.search.merge_requests"),
            ("code", "gitlab.search.code"),
            ("commits", "gitlab.search.commits"),
            ("wiki", "gitlab.search.wiki"),
            ("comments", "gitlab.search.comments"),
        ] {
            let command = parse_content(&[
                "agent-access",
                "gitlab",
                "search",
                command,
                "--search",
                "credential rotation",
                "--project",
                "engineering/dispatch",
                "--engine",
                "advanced",
                "--max-results",
                "20",
                "--page-token",
                "opaque",
                "--output-format",
                "json",
                "--output",
                "results.json",
            ]);
            let (actual, inputs, response) = command.invocation();
            assert_eq!(actual, action);
            assert_eq!(
                inputs,
                json!({
                    "search": "credential rotation", "project": "engineering/dispatch",
                    "engine": "advanced", "maxResults": 20, "pageToken": "opaque",
                })
            );
            assert_eq!(response.output_format, Some(OutputFormatArg::Json));
        }
    }

    #[test]
    fn default_content_inputs_do_not_override_broker_capabilities() {
        let command = parse_content(&[
            "agent-access",
            "gitlab",
            "search",
            "code",
            "--search",
            "verify_token",
        ]);
        assert_eq!(command.invocation().1, json!({"search": "verify_token"}));
        let command = parse_content(&[
            "agent-access",
            "gitlab",
            "search",
            "code",
            "--search",
            "verify_.*",
            "--engine",
            "zoekt",
            "--regex",
        ]);
        assert_eq!(
            command.invocation().1,
            json!({
                "search": "verify_.*", "engine": "zoekt", "regex": true,
            })
        );
    }

    #[test]
    fn search_rejects_noncanonical_flags_and_invalid_cli_values() {
        for args in [
            vec!["issue", "search", "--search", "text"],
            vec!["merge-request", "search", "--search", "text"],
            vec!["search", "issues"],
            vec!["search", "issues", "--search", "text", "--regex"],
            vec![
                "search",
                "issues",
                "--search",
                "text",
                "--engine",
                "automatic",
            ],
            vec!["search", "issues", "--search", "text", "--max-results", "0"],
            vec![
                "search",
                "issues",
                "--search",
                "text",
                "--max-results",
                "101",
            ],
            vec!["search", "issues", "--search", "text", "--scope", "blobs"],
            vec![
                "search",
                "issues",
                "--search",
                "text",
                "--read-content-format",
                "markdown",
            ],
            vec!["project", "search", "--archived"],
            vec!["project", "search", "--include-namespaces", "yes"],
        ] {
            let command = [vec!["agent-access", "gitlab"], args].concat();
            assert!(
                Cli::try_parse_from(&command).is_err(),
                "accepted {command:?}"
            );
        }
    }
}
