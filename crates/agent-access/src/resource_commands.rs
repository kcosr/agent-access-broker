use super::*;
use agent_access_provider::ResourceType;

fn parse_resource_type(value: &str) -> Result<ResourceType, String> {
    ResourceType::new(value)
}

const RESOURCE_TYPE_HELP: &str = "Registered resource type ID; list the broker's types, labels, and selector forms with `agent-access admin policy resources types`";

#[derive(Debug, Subcommand)]
pub(crate) enum ResourcesCommand {
    List,
    /// List the resource types this broker registers, with their selector forms.
    Types,
    Get {
        id: String,
    },
    UsedBy {
        id: String,
    },
    /// Explicitly reveal one private resource attribute (admin only).
    Reveal {
        id: String,
        attribute: String,
    },
    Create {
        #[arg(long)]
        id: Option<String>,
        #[arg(long, value_parser = parse_resource_type, help = RESOURCE_TYPE_HELP)]
        resource_type: ResourceType,
        #[arg(long, value_parser = ["exact", "namespace", "all"])]
        selector_kind: String,
        #[arg(long)]
        selector_value: Option<String>,
        #[arg(long)]
        display_name: Option<String>,
        /// JSON object of private string attributes; values remain redacted in the response.
        #[arg(long)]
        attributes_file: Option<PathBuf>,
        #[arg(long = "execution-context", required = true)]
        execution_contexts: Vec<String>,
        #[arg(long, action = clap::ArgAction::Set)]
        enabled: Option<bool>,
    },
    Update {
        id: String,
        #[arg(long, value_parser = parse_expected_version)]
        expected_version: i64,
        #[arg(long, value_parser = parse_resource_type, help = RESOURCE_TYPE_HELP)]
        resource_type: Option<ResourceType>,
        #[arg(long, value_parser = ["exact", "namespace", "all"])]
        selector_kind: Option<String>,
        #[arg(long, requires = "selector_kind")]
        selector_value: Option<String>,
        #[arg(long, conflicts_with = "clear_display_name")]
        display_name: Option<String>,
        #[arg(long)]
        clear_display_name: bool,
        /// Replace supplied private attributes; omission preserves stored values.
        #[arg(long)]
        attributes_file: Option<PathBuf>,
        #[arg(long = "execution-context")]
        execution_contexts: Vec<String>,
        #[arg(long, action = clap::ArgAction::Set)]
        enabled: Option<bool>,
    },
    Delete {
        id: String,
        #[arg(long, value_parser = parse_expected_version)]
        expected_version: i64,
    },
}

#[derive(Debug, Subcommand)]
pub(crate) enum ResourceGroupsCommand {
    List,
    Get {
        id: String,
    },
    UsedBy {
        id: String,
    },
    Create {
        #[arg(long)]
        id: Option<String>,
        #[arg(long)]
        name: String,
        #[arg(long = "included-resource-id")]
        included_resource_ids: Vec<String>,
        #[arg(
            long = "excluded-resource-id",
            help = "Exclude this selector in every context; remains effective when the resource is disabled"
        )]
        excluded_resource_ids: Vec<String>,
    },
    Update {
        id: String,
        #[arg(long, value_parser = parse_expected_version)]
        expected_version: i64,
        #[arg(long)]
        name: Option<String>,
        #[arg(long = "included-resource-id", conflicts_with = "clear_included")]
        included_resource_ids: Vec<String>,
        #[arg(long = "excluded-resource-id", conflicts_with = "clear_excluded")]
        excluded_resource_ids: Vec<String>,
        #[arg(long)]
        clear_included: bool,
        #[arg(long)]
        clear_excluded: bool,
    },
    Delete {
        id: String,
        #[arg(long, value_parser = parse_expected_version)]
        expected_version: i64,
    },
}

fn selector_value(kind: &str, value: &Option<String>) -> Result<serde_json::Value> {
    match (kind, value) {
        ("all", None) => Ok(serde_json::json!({"kind":"all"})),
        ("exact" | "namespace", Some(value)) if !value.is_empty() => {
            Ok(serde_json::json!({"kind":kind,"value":value}))
        }
        _ => anyhow::bail!(
            "exact and namespace selectors require --selector-value; all does not accept it"
        ),
    }
}

fn record_path(collection: &str, id: &str) -> String {
    format!("/v1/admin/policy/{collection}/{}", encoded_path_segment(id))
}

fn read_attributes_file(path: &Path) -> Result<serde_json::Value> {
    use std::io::Read;
    if !std::fs::metadata(path)
        .context("cannot inspect resource attributes file")?
        .is_file()
    {
        anyhow::bail!("resource attributes file must be a regular file");
    }
    let file = std::fs::File::open(path).context("cannot open resource attributes file")?;
    if !file.metadata()?.is_file() {
        anyhow::bail!("resource attributes file must be a regular file");
    }
    let mut bytes = Vec::new();
    file.take(64 * 1024 + 1)
        .read_to_end(&mut bytes)
        .context("cannot read resource attributes file")?;
    if bytes.len() > 64 * 1024 {
        anyhow::bail!("resource attributes file exceeds 64 KiB");
    }
    // Never include parser diagnostics: malformed input can contain a secret.
    let attributes: serde_json::Value = serde_json::from_slice(&bytes).map_err(|_| {
        anyhow::anyhow!("resource attributes file must contain a JSON object of strings")
    })?;
    if !attributes
        .as_object()
        .is_some_and(|object| object.values().all(serde_json::Value::is_string))
    {
        anyhow::bail!("resource attributes file must contain a JSON object of strings");
    }
    Ok(attributes)
}

pub(crate) async fn run_resources(ctx: &CliContext<'_>, command: &ResourcesCommand) -> Result<()> {
    let collection = "/v1/admin/policy/resources";
    match command {
        ResourcesCommand::List => run_broker_get(ctx, collection, ResponseShape::Object).await,
        ResourcesCommand::Types => {
            run_broker_get(ctx, "/v1/resource-types", ResponseShape::Object).await
        }
        ResourcesCommand::Get { id } => {
            run_broker_get(ctx, &record_path("resources", id), ResponseShape::Object).await
        }
        ResourcesCommand::Reveal { id, attribute } => {
            run_broker_json_method(
                ctx,
                reqwest::Method::POST,
                &format!(
                    "{}/attributes/{}/reveal",
                    record_path("resources", id),
                    encoded_path_segment(attribute)
                ),
                None,
            )
            .await
        }
        ResourcesCommand::UsedBy { id } => {
            run_broker_get(
                ctx,
                &format!("{}/used-by", record_path("resources", id)),
                ResponseShape::Object,
            )
            .await
        }
        ResourcesCommand::Delete {
            id,
            expected_version,
        } => {
            run_broker_json_method(
                ctx,
                reqwest::Method::DELETE,
                &format!(
                    "{}?expectedVersion={expected_version}",
                    record_path("resources", id)
                ),
                None,
            )
            .await
        }
        ResourcesCommand::Create {
            id,
            resource_type,
            selector_kind,
            selector_value: value,
            display_name,
            attributes_file,
            execution_contexts,
            enabled,
        } => {
            let mut body = serde_json::json!({"resourceType":resource_type,"selector":selector_value(selector_kind, value)?,"allowedExecutionContexts":execution_contexts});
            if let Some(id) = id {
                body["id"] = serde_json::json!(id);
            }
            if let Some(name) = display_name {
                body["displayName"] = serde_json::json!(name);
            }
            if let Some(path) = attributes_file {
                body["attributes"] = read_attributes_file(path)?;
            }
            if let Some(enabled) = enabled {
                body["enabled"] = serde_json::json!(enabled);
            }
            run_broker_json_method(ctx, reqwest::Method::POST, collection, Some(body)).await
        }
        ResourcesCommand::Update {
            id,
            expected_version,
            resource_type,
            selector_kind,
            selector_value: value,
            display_name,
            clear_display_name,
            attributes_file,
            execution_contexts,
            enabled,
        } => {
            let mut body = serde_json::json!({"expectedVersion":expected_version});
            if let Some(path) = attributes_file {
                body["attributes"] = read_attributes_file(path)?;
            }
            if let Some(kind) = resource_type {
                body["resourceType"] = serde_json::json!(kind);
            }
            if let Some(kind) = selector_kind {
                body["selector"] = selector_value(kind, value)?;
            }
            if *clear_display_name {
                body["displayName"] = serde_json::Value::Null;
            } else if let Some(name) = display_name {
                body["displayName"] = serde_json::json!(name);
            }
            if !execution_contexts.is_empty() {
                body["allowedExecutionContexts"] = serde_json::json!(execution_contexts);
            }
            if let Some(enabled) = enabled {
                body["enabled"] = serde_json::json!(enabled);
            }
            if body.as_object().expect("object").len() == 1 {
                anyhow::bail!("resource update requires at least one changed field");
            }
            run_broker_json_method(
                ctx,
                reqwest::Method::PATCH,
                &record_path("resources", id),
                Some(body),
            )
            .await
        }
    }
}

pub(crate) async fn run_resource_groups(
    ctx: &CliContext<'_>,
    command: &ResourceGroupsCommand,
) -> Result<()> {
    let collection = "/v1/admin/policy/resource-groups";
    match command {
        ResourceGroupsCommand::List => run_broker_get(ctx, collection, ResponseShape::Object).await,
        ResourceGroupsCommand::Get { id } => {
            run_broker_get(
                ctx,
                &record_path("resource-groups", id),
                ResponseShape::Object,
            )
            .await
        }
        ResourceGroupsCommand::UsedBy { id } => {
            run_broker_get(
                ctx,
                &format!("{}/used-by", record_path("resource-groups", id)),
                ResponseShape::Object,
            )
            .await
        }
        ResourceGroupsCommand::Delete {
            id,
            expected_version,
        } => {
            run_broker_json_method(
                ctx,
                reqwest::Method::DELETE,
                &format!(
                    "{}?expectedVersion={expected_version}",
                    record_path("resource-groups", id)
                ),
                None,
            )
            .await
        }
        ResourceGroupsCommand::Create {
            id,
            name,
            included_resource_ids,
            excluded_resource_ids,
        } => {
            let mut body = serde_json::json!({"name":name,"includedResourceIds":included_resource_ids,"excludedResourceIds":excluded_resource_ids});
            if let Some(id) = id {
                body["id"] = serde_json::json!(id);
            }
            run_broker_json_method(ctx, reqwest::Method::POST, collection, Some(body)).await
        }
        ResourceGroupsCommand::Update {
            id,
            expected_version,
            name,
            included_resource_ids,
            excluded_resource_ids,
            clear_included,
            clear_excluded,
        } => {
            let mut body = serde_json::json!({"expectedVersion":expected_version});
            if let Some(name) = name {
                body["name"] = serde_json::json!(name);
            }
            if *clear_included || !included_resource_ids.is_empty() {
                body["includedResourceIds"] = serde_json::json!(included_resource_ids);
            }
            if *clear_excluded || !excluded_resource_ids.is_empty() {
                body["excludedResourceIds"] = serde_json::json!(excluded_resource_ids);
            }
            if body.as_object().expect("object").len() == 1 {
                anyhow::bail!("resource-group update requires at least one changed field");
            }
            run_broker_json_method(
                ctx,
                reqwest::Method::PATCH,
                &record_path("resource-groups", id),
                Some(body),
            )
            .await
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn selectors_do_not_accept_ambiguous_coverage() {
        assert!(selector_value("all", &Some("engineering".into())).is_err());
        assert!(selector_value("exact", &None).is_err());
        assert!(selector_value("namespace", &Some(String::new())).is_err());
        assert_eq!(
            selector_value("all", &None).unwrap(),
            serde_json::json!({"kind":"all"})
        );
        assert_eq!(
            selector_value("namespace", &Some("engineering/platform".into())).unwrap(),
            serde_json::json!({"kind":"namespace","value":"engineering/platform"})
        );
    }

    #[test]
    fn resource_group_update_requires_explicit_clear_for_empty_membership() {
        let cli = Cli::try_parse_from([
            "agent-access",
            "admin",
            "policy",
            "resource-groups",
            "update",
            "engineering",
            "--expected-version",
            "3",
            "--clear-included",
        ])
        .unwrap();
        let Command::Admin {
            command:
                AdminCommand::Policy {
                    command:
                        AdminPolicyCommand::ResourceGroups {
                            command:
                                ResourceGroupsCommand::Update {
                                    clear_included,
                                    included_resource_ids,
                                    ..
                                },
                        },
                },
        } = cli.command
        else {
            panic!("group update expected")
        };
        assert!(clear_included);
        assert!(included_resource_ids.is_empty());
        assert!(
            Cli::try_parse_from([
                "agent-access",
                "admin",
                "policy",
                "resource-groups",
                "update",
                "engineering",
                "--expected-version",
                "3",
                "--clear-excluded",
                "--excluded-resource-id",
                "private"
            ])
            .is_err()
        );
    }

    #[test]
    fn resources_do_not_require_a_duplicate_display_name_or_generated_id() {
        let cli = Cli::try_parse_from([
            "agent-access",
            "admin",
            "policy",
            "resources",
            "create",
            "--resource-type",
            "git_repository",
            "--selector-kind",
            "exact",
            "--selector-value",
            "engineering/payments",
            "--execution-context",
            "internal",
        ])
        .unwrap();
        let Command::Admin {
            command:
                AdminCommand::Policy {
                    command:
                        AdminPolicyCommand::Resources {
                            command:
                                ResourcesCommand::Create {
                                    id, display_name, ..
                                },
                        },
                },
        } = cli.command
        else {
            panic!("resource create expected")
        };
        assert!(id.is_none());
        assert!(display_name.is_none());
    }

    #[test]
    fn cloudbees_ci_job_resources_accept_namespace_selectors() {
        let cli = Cli::try_parse_from([
            "agent-access",
            "admin",
            "policy",
            "resources",
            "create",
            "--resource-type",
            "cloudbees_ci_job",
            "--selector-kind",
            "namespace",
            "--selector-value",
            "team-ci/payments",
            "--execution-context",
            "internal",
        ])
        .unwrap();
        let Command::Admin {
            command:
                AdminCommand::Policy {
                    command:
                        AdminPolicyCommand::Resources {
                            command:
                                ResourcesCommand::Create {
                                    resource_type,
                                    selector_kind,
                                    selector_value,
                                    ..
                                },
                        },
                },
        } = cli.command
        else {
            panic!("CloudBees CI resource create expected")
        };
        assert_eq!(
            resource_type,
            ResourceType::new("cloudbees_ci_job").unwrap()
        );
        assert_eq!(selector_kind, "namespace");
        assert_eq!(selector_value.as_deref(), Some("team-ci/payments"));
    }

    #[test]
    fn oauth_collection_resources_parse_for_create_and_update() {
        for operation in ["create", "update"] {
            for kind in ["exact", "all"] {
                let mut args = vec!["agent-access", "admin", "policy", "resources", operation];
                if operation == "update" {
                    args.extend(["collection-alpha", "--expected-version", "1"]);
                }
                args.extend([
                    "--resource-type",
                    "oauth_collection",
                    "--selector-kind",
                    kind,
                    "--execution-context",
                    "internal",
                ]);
                if kind == "exact" {
                    args.extend(["--selector-value", "alpha"]);
                }
                let cli = Cli::try_parse_from(args).unwrap();
                let Command::Admin {
                    command:
                        AdminCommand::Policy {
                            command: AdminPolicyCommand::Resources { command },
                        },
                } = cli.command
                else {
                    panic!("resource command expected")
                };
                let resource_type = match command {
                    ResourcesCommand::Create { resource_type, .. } => resource_type,
                    ResourcesCommand::Update { resource_type, .. } => resource_type.unwrap(),
                    _ => panic!("resource mutation expected"),
                };
                assert_eq!(
                    resource_type,
                    ResourceType::new("oauth_collection").unwrap()
                );
                assert_eq!(
                    serde_json::to_value(resource_type).unwrap(),
                    "oauth_collection"
                );
            }
        }
        assert!(parse_resource_type("OAuth-Collections").is_err());
    }

    #[test]
    fn resource_type_help_points_to_broker_type_listing() {
        for operation in ["create", "update"] {
            let help = Cli::try_parse_from([
                "agent-access",
                "admin",
                "policy",
                "resources",
                operation,
                "--help",
            ])
            .unwrap_err();
            assert_eq!(help.kind(), clap::error::ErrorKind::DisplayHelp);
            assert!(
                help.to_string()
                    .contains("agent-access admin policy resources types"),
                "{help}"
            );
        }
        assert!(
            Cli::try_parse_from(["agent-access", "admin", "policy", "resources", "types"]).is_ok()
        );
    }
}
