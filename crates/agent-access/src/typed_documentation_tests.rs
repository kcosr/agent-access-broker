//! Published typed-command recipes follow the CLI's actual command tree.
use crate::Cli;
use agent_access_provider::{BackendConfig, ServiceDescriptor};
use clap::CommandFactory;
use std::collections::BTreeSet;

fn descriptors() -> Vec<(&'static str, ServiceDescriptor)> {
    // Enable optional action families. This is one complete descriptor per
    // provider, not a separately maintained list of action IDs or CLI paths.
    let jira: agent_access_jira::JiraProviderConfig = toml::from_str(
        r#"tenant_host = "example.atlassian.net"
allowed_upstream_hosts = ["https://example.atlassian.net/**"]
[content]
comment_formats = ["adf"]
"#,
    )
    .unwrap();
    let confluence: agent_access_confluence::ConfluenceProviderConfig = toml::from_str(
        r#"tenant_host = "example.atlassian.net"
allowed_upstream_hosts = ["https://example.atlassian.net/**"]
[content]
page_formats = ["storage", "atlas_doc_format"]
blog_formats = ["storage"]
comment_formats = ["storage"]
"#,
    )
    .unwrap();
    let gitlab: agent_access_gitlab::GitlabProviderConfig = toml::from_str(
        r#"api_base_url = "https://gitlab.example.com/api/v4"
web_base_url = "https://gitlab.example.com"
allowed_upstream_hosts = ["https://gitlab.example.com/**"]
[provisioning]
enabled = true
"#,
    )
    .unwrap();
    let cloudbees: agent_access_cloudbees_ci::CloudbeesCiProviderConfig = toml::from_str(
        r#"allowed_upstream_hosts = ["https://ci.example.com/**"]
[controllers.team]
base_url = "https://ci.example.com/"
"#,
    )
    .unwrap();
    vec![
        ("jira", jira.descriptor()),
        ("confluence", confluence.descriptor()),
        ("gitlab", gitlab.descriptor()),
        ("cloudbees-ci", cloudbees.descriptor()),
        ("gmail", agent_access_gmail::descriptor()),
        ("teams", agent_access_teams::descriptor()),
        (
            "oauth-stub",
            agent_access_fake::OAuthStubProviderConfig {
                base_url: "http://127.0.0.1:8099".into(),
            }
            .descriptor(),
        ),
    ]
}

#[test]
fn published_typed_commands_match_clap_paths_and_usage() {
    let mut cli = Cli::command();
    cli.build();
    let mut actions = BTreeSet::new();
    let mut command_paths = BTreeSet::new();
    for (group, descriptor) in descriptors() {
        for action in descriptor.actions {
            let identity = format!("{}.{}", descriptor.service, action.action);
            assert!(
                actions.insert(identity.clone()),
                "duplicate action {identity}"
            );
            let documentation = action.documentation.expect("action documentation");
            let mapping = documentation["typedCommand"]
                .as_str()
                .unwrap_or_else(|| panic!("{identity}: missing typedCommand"));
            let (usage, help) = mapping
                .strip_prefix("Typed CLI wrapper: ")
                .and_then(|mapping| mapping.split_once("; run "))
                .unwrap_or_else(|| panic!("{identity}: missing usage or help command: {mapping}"));
            let help_path = help
                .strip_suffix(" --help for flags and input alternatives.")
                .unwrap_or_else(|| panic!("{identity}: missing --help command: {mapping}"));
            let path: Vec<_> = help_path.split_whitespace().collect();
            assert_eq!(path.first().copied(), Some(cli.get_name()), "{identity}");
            assert_eq!(path.get(1).copied(), Some(group), "{identity}");
            assert!(
                command_paths.insert(help_path.to_owned()),
                "{identity}: duplicate wrapper {help_path}"
            );
            let mut command = &mut cli;
            for component in &path[1..] {
                command = command.find_subcommand_mut(component).unwrap_or_else(|| {
                    panic!("{identity}: unknown subcommand {component} in {help_path}")
                });
                assert_eq!(
                    command.get_name(),
                    *component,
                    "{identity}: use the canonical command name"
                );
            }
            assert!(
                command.get_subcommands().next().is_none(),
                "{identity}: {help_path} names a command group"
            );
            let rendered = command.render_usage().to_string();
            assert_eq!(
                rendered.strip_prefix("Usage: "),
                Some(usage),
                "{identity}: published usage differs from {help_path} --help"
            );
        }
    }
    assert_eq!(
        actions.len(),
        230,
        "cover every native and OAuth fixture action"
    );
}
