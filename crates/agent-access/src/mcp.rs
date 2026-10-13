//! Local MCP adapter. The SDK owns the wire protocol; the broker owns authorization.

mod discovery;
pub(crate) mod tools;
mod transport;

use std::path::PathBuf;

use agent_access_core::mcp::McpView;
use anyhow::{Context, Result};
use rmcp::{
    ErrorData, RoleServer, ServerHandler, ServiceExt,
    model::{
        CacheScope, CallToolRequestParams, CallToolResponse, CallToolResult, ContentBlock,
        Implementation, ListToolsResult, PaginatedRequestParams, ServerCapabilities, ServerConfig,
        Tool,
    },
    service::{QuitReason, RequestContext},
};
use serde_json::Value;
use sha2::{Digest, Sha256};

const PAGE_SIZE: usize = 100;
const CONFIG_ERROR: &str = "Cannot resolve broker configuration or identity. Check agent-access config syntax, broker URL/TLS settings, and token sources. Use HTTPS when sending identity tokens to a non-local broker.";
const TRANSPORT_ERROR: &str = "Broker transport was rejected. Use a valid HTTPS broker URL and TLS configuration. Non-local HTTP with an identity token requires --allow-insecure-broker-http for development and is never allowed when AGENT_ACCESS_ENVIRONMENT=production.";

struct BrokerMcp {
    cli: crate::Cli,
    config: PathBuf,
    view: McpView,
}

impl BrokerMcp {
    fn settings(&self) -> Result<crate::ResolvedCliSettings> {
        // Resolve for every request: token files and config may rotate while the
        // client keeps this subprocess alive. Never cache an identity or grants.
        let settings = crate::resolve_cli_settings(&self.cli, &self.config)
            .map_err(|_| anyhow::anyhow!(CONFIG_ERROR))?;
        validate_broker_transport(&settings)?;
        Ok(settings)
    }
}

pub(crate) fn parse_service(value: &str) -> Result<String, String> {
    if agent_access_provider::is_service_name(value) {
        Ok(value.to_owned())
    } else {
        Err("service must be one canonical service ID".into())
    }
}

fn validate_broker_transport(settings: &crate::ResolvedCliSettings) -> Result<()> {
    // Keep the CLI's transport policy, but expose a fixed actionable diagnostic:
    // neither an invalid URL nor any error chain may leak credential material.
    crate::validate_transport(settings).map_err(|_| anyhow::anyhow!(TRANSPORT_ERROR))
}

impl ServerHandler for BrokerMcp {
    fn get_info(&self) -> ServerConfig {
        ServerConfig::new(ServerCapabilities::builder().enable_tools().build())
            .with_server_info(Implementation::new(
                self.view.service().unwrap_or("agent-access").to_owned(),
                env!("CARGO_PKG_VERSION"),
            ))
            .with_instructions(format!(
                "{} Tools include five discovery helpers and currently available provider actions. The broker checks \
                 resource permissions on every call. File paths refer to the machine running this \
                 local agent-access process. Refresh tools/list to discover changed permissions. \
                 Cancellation does not guarantee that an upstream mutation was rolled back.",
                match self.view.service() {
                    Some(service) => format!("This connection exposes only service {service}. Provider tools retain their original names. Discovery helpers use canonical action IDs, which may differ from tool names."),
                    None => "This connection exposes the caller's aggregate broker tools.".into(),
                }
            ))
    }

    async fn list_tools(
        &self,
        request: Option<PaginatedRequestParams>,
        context: RequestContext<RoleServer>,
    ) -> Result<ListToolsResult, ErrorData> {
        let settings = self
            .settings()
            .map_err(|error| ErrorData::internal_error(error.to_string(), None))?;
        let tools = tokio::select! {
            biased;
            _ = context.ct.cancelled() => return Err(ErrorData::internal_error("Request cancelled", None)),
            result = tools::list_tools(&settings, &self.view) => result
                .map_err(|error| ErrorData::internal_error(error.to_string(), None))?,
        };
        paginate(
            tools.tools,
            &tools.binding,
            request.and_then(|params| params.cursor).as_deref(),
        )
    }

    async fn call_tool(
        &self,
        request: CallToolRequestParams,
        context: RequestContext<RoleServer>,
    ) -> Result<CallToolResponse, ErrorData> {
        let settings = match self.settings() {
            Ok(settings) => settings,
            Err(error) => return Ok(tool_error(error.to_string()).into()),
        };
        let result = tokio::select! {
            biased;
            _ = context.ct.cancelled() => tool_error(
                "Request cancelled. An upstream mutation may already have completed; inspect its state before retrying."
            ),
            result = tools::call_tool(&settings, &self.view, &request.name, request.arguments.unwrap_or_default()) => {
                match result {
                    Ok(result) => result,
                    Err(error) if error.is::<tools::UnknownToolError>() => {
                        return Err(ErrorData::invalid_params(error.to_string(), None));
                    }
                    Err(error) if error.is::<crate::output::LocalOutputFailure>() => {
                        let failure = error.downcast_ref::<crate::output::LocalOutputFailure>().expect("matched local output failure");
                        serde_json::from_value(tools::envelope_result(200, failure.details.clone(), true)
                            .expect("local failure is serializable"))
                            .expect("local failure is a tool result")
                    }
                    Err(error) => tool_error(error.to_string()),
                }
            }
        };
        Ok(result.into())
    }
}

fn tool_error(message: impl Into<String>) -> CallToolResult {
    CallToolResult::error(vec![ContentBlock::text(message)])
}

fn paginate(
    mut tools: Vec<Tool>,
    binding: &Value,
    cursor: Option<&str>,
) -> Result<ListToolsResult, ErrorData> {
    tools.sort_by(|left, right| left.name.cmp(&right.name));
    let serialized = serde_json::to_vec(&(binding, &tools))
        .map_err(|_| ErrorData::internal_error("Cannot serialize broker catalog", None))?;
    let fingerprint = format!("{:x}", Sha256::digest(serialized));
    let offset = match cursor {
        None => 0,
        Some(cursor) => {
            let invalid = || {
                ErrorData::invalid_params(
                    "Invalid or stale catalog cursor; restart tools/list without a cursor",
                    None,
                )
            };
            let (expected, offset) = cursor.split_once(':').ok_or_else(invalid)?;
            let offset: usize = offset.parse().map_err(|_| invalid())?;
            if expected != fingerprint
                || offset == 0
                || offset >= tools.len()
                || !offset.is_multiple_of(PAGE_SIZE)
            {
                return Err(invalid());
            }
            offset
        }
    };
    let end = offset.saturating_add(PAGE_SIZE).min(tools.len());
    let next_cursor = (end < tools.len()).then(|| format!("{fingerprint}:{end}"));
    let mut result =
        ListToolsResult::with_all_items(tools.into_iter().skip(offset).take(PAGE_SIZE).collect())
            .with_ttl_ms(0)
            .with_cache_scope(CacheScope::Private);
    result.next_cursor = next_cursor;
    Ok(result)
}

pub async fn serve(cli: crate::Cli, config: PathBuf, view: McpView) -> Result<()> {
    let server = BrokerMcp { cli, config, view };
    server.settings()?;
    // No CLI rendering or stdout logging is allowed here: stdout is exclusively
    // newline-delimited MCP JSON-RPC, including during authentication failures.
    let (input, oversized) = transport::BoundedStdioRead::new(tokio::io::stdin());
    let service = server
        .serve((input, tokio::io::stdout()))
        .await
        // SDK initialization errors may contain a client's raw message. Do not
        // echo arbitrary request bodies to stderr (they can contain secrets).
        .map_err(|_| anyhow::anyhow!("MCP stdio initialization failed"))?;
    if let QuitReason::JoinError(error) =
        service.waiting().await.context("MCP stdio task failed")?
    {
        return Err(error).context("MCP stdio service failed");
    }
    if oversized.load(std::sync::atomic::Ordering::Relaxed) {
        anyhow::bail!("MCP input frame exceeds 16 MiB; use requestFile for large action inputs");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;
    use serde_json::json;

    fn catalog(count: usize) -> Vec<Tool> {
        (0..count)
            .map(|index| {
                Tool::new(
                    format!("tool_{index:04}"),
                    "test",
                    json!({"type":"object"}).as_object().unwrap().clone(),
                )
            })
            .collect()
    }

    #[test]
    fn pagination_is_complete_stable_and_identity_private() {
        let mut tools = catalog(201);
        tools.reverse();
        let first = paginate(
            tools,
            &json!({"view":"Aggregate","identity":"alice","context":"internal"}),
            None,
        )
        .unwrap();
        assert_eq!(first.tools.len(), 100);
        assert_eq!(first.tools[0].name, "tool_0000");
        assert_eq!(first.ttl_ms, Some(0));
        assert_eq!(first.cache_scope, Some(CacheScope::Private));
        let second = paginate(
            catalog(201),
            &json!({"view":"Aggregate","identity":"alice","context":"internal"}),
            first.next_cursor.as_deref(),
        )
        .unwrap();
        assert_eq!(second.tools[0].name, "tool_0100");
        let third = paginate(
            catalog(201),
            &json!({"view":"Aggregate","identity":"alice","context":"internal"}),
            second.next_cursor.as_deref(),
        )
        .unwrap();
        assert_eq!(third.tools.len(), 1);
        assert_eq!(third.tools[0].name, "tool_0200");
        assert!(third.next_cursor.is_none());
    }

    #[test]
    fn stale_and_invalid_cursors_fail_instead_of_skipping_changed_tools() {
        let first = paginate(catalog(101), &json!({}), None).unwrap();
        assert!(paginate(catalog(102), &json!({}), first.next_cursor.as_deref()).is_err());
        let mut changed = catalog(101);
        changed[0].description = Some("updated schema description".into());
        assert!(paginate(changed, &json!({}), first.next_cursor.as_deref()).is_err());
        for cursor in ["", "100", "x:100", "x:0", "x:99999999999999999999999999999"] {
            assert!(paginate(catalog(101), &json!({}), Some(cursor)).is_err());
        }
        assert!(
            paginate(Vec::new(), &json!({}), None)
                .unwrap()
                .tools
                .is_empty()
        );
    }

    #[test]
    fn one_canonical_service_is_optional_and_immutable_in_cli_syntax() {
        for service in ["fake", "jira-team", "team_2"] {
            let cli =
                crate::Cli::try_parse_from(["agent-access", "mcp", "serve", "--service", service])
                    .unwrap();
            assert!(
                matches!(cli.command, crate::Command::Mcp { command: crate::McpCommand::Serve { service: Some(selected) } } if selected == service)
            );
        }
        for service in [
            "",
            "*",
            "fake,jira",
            "Fake",
            "fake/other",
            "fake%2Fother",
            "service.with.dots",
            &"a".repeat(64),
        ] {
            assert!(
                crate::Cli::try_parse_from(["agent-access", "mcp", "serve", "--service", service])
                    .is_err()
            );
        }
        assert!(
            crate::Cli::try_parse_from([
                "agent-access",
                "mcp",
                "serve",
                "--service",
                "fake",
                "--service",
                "jira"
            ])
            .is_err()
        );
        let cli = crate::Cli::try_parse_from(["agent-access", "mcp", "serve"]).unwrap();
        assert!(matches!(
            cli.command,
            crate::Command::Mcp {
                command: crate::McpCommand::Serve { service: None }
            }
        ));
    }

    #[test]
    fn pagination_binds_view_identity_context_and_complete_dispatch_metadata() {
        let binding = json!({"view":McpView::Service("one".into()),"identity":{"principal":"alice"},"executionContext":"internal"});
        let first = paginate(catalog(101), &binding, None).unwrap();
        for (field, replacement) in [
            ("view", json!(McpView::Aggregate)),
            ("view", json!(McpView::Service("two".into()))),
            ("identity", json!({"principal":"bob"})),
            ("executionContext", json!("external")),
        ] {
            let mut changed = binding.clone();
            changed[field] = replacement;
            assert!(paginate(catalog(101), &changed, first.next_cursor.as_deref()).is_err());
        }
        let mut changed = serde_json::to_value(catalog(101)).unwrap();
        changed[0]["_meta"] = json!({"agent-access/service":"one","agent-access/action":"changed"});
        assert!(
            paginate(
                serde_json::from_value(changed).unwrap(),
                &binding,
                first.next_cursor.as_deref()
            )
            .is_err()
        );
        assert!(paginate(catalog(101), &binding, first.next_cursor.as_deref()).is_ok());
    }

    #[test]
    fn invalid_configuration_does_not_echo_secret_source_text() {
        let file = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(file.path(), "private-secret-marker = [ invalid TOML").unwrap();
        let cli = crate::Cli::try_parse_from([
            "agent-access",
            "--config",
            file.path().to_str().unwrap(),
            "mcp",
            "serve",
        ])
        .unwrap();
        let server = BrokerMcp {
            cli,
            config: file.path().to_path_buf(),
            view: McpView::Aggregate,
        };
        let error = server.settings().unwrap_err();
        assert_eq!(format!("{error:#}"), CONFIG_ERROR);
    }

    #[test]
    fn rejected_transport_explains_https_and_development_override_without_secrets() {
        let settings = crate::ResolvedCliSettings {
            url: "http://broker.example.test".into(),
            tls: Default::default(),
            token: Some("private-token-marker".into()),
            token_from_literal_arg: false,
            identity_header: "X-Agent-Access-Identity-Token".into(),
            identity_scheme: "raw".into(),
            allow_insecure_broker_http: false,
            read_content_format: Default::default(),
            output_format: Default::default(),
        };
        // Rejected regardless of the ambient production setting; no process
        // environment mutation is needed to exercise the transport policy.
        let error = validate_broker_transport(&settings).unwrap_err();
        let message = format!("{error:#}");
        assert_eq!(message, TRANSPORT_ERROR);
        assert!(message.contains("HTTPS"));
        assert!(message.contains("--allow-insecure-broker-http"));
        assert!(message.contains("AGENT_ACCESS_ENVIRONMENT=production"));
        assert!(!message.contains("private-token-marker"));
        assert!(!message.contains("broker.example.test"));
    }
}
