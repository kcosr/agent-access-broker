//! Fixed discovery helpers. These describe broker capabilities; they do not execute actions.
use agent_access_core::mcp::McpView;
use anyhow::{Context, Result};
use rmcp::model::CallToolResult;
use serde_json::{Map, Value};

pub(super) async fn call(
    settings: &crate::ResolvedCliSettings,
    view: &McpView,
    name: &str,
    arguments: Map<String, Value>,
) -> Result<CallToolResult> {
    agent_access_core::mcp::validate_helper_arguments_for_view(
        name,
        &arguments,
        agent_access_core::mcp::ProjectionMode::Stdio,
        view,
    )?;
    let text = |key: &str| arguments.get(key).and_then(Value::as_str);
    let output = text("outputPath").map(std::path::Path::new);
    if let Some(path) = output {
        super::tools::require_absolute(path)?;
    }
    let result = match name {
        "services_list" => crate::discovery::services_list(settings, text("prefix"), false).await,
        "resource_access_describe" => {
            crate::discovery::resource_access_describe(
                settings,
                text("service").unwrap(),
                text("action"),
                text("resourceType"),
                text("prefix"),
                arguments
                    .get("limit")
                    .and_then(Value::as_u64)
                    .map(|value| value as u32),
                text("cursor"),
            )
            .await
        }
        "actions_list" => {
            crate::discovery::actions_list(
                settings,
                text("service").unwrap(),
                text("resource"),
                text("resourceType"),
                text("prefix"),
                false,
            )
            .await
        }
        "actions_describe" => {
            crate::discovery::action_describe(
                settings,
                view,
                text("service").unwrap(),
                text("action").unwrap(),
            )
            .await
        }
        "services_describe" => {
            crate::discovery::service_describe(settings, text("service").unwrap()).await
        }
        _ => unreachable!("known discovery helper"),
    };
    let (status, mut value, is_error) = match result {
        Ok(value) => (200, value, false),
        Err(error) => match error.downcast_ref::<crate::discovery::BrokerFailure>() {
            Some(failure) => (failure.status, failure.body.clone(), true),
            None => return Err(error),
        },
    };
    if !is_error
        && name == "services_list"
        && let Some(selected) = view.service()
    {
        value
            .get_mut("services")
            .and_then(Value::as_array_mut)
            .context("invalid broker service list")?
            .retain(|service| service["service"] == selected);
    }
    if !is_error && let Some(output) = output {
        value = super::tools::save_json_response(output, &value)?;
    }
    Ok(serde_json::from_value(super::tools::envelope_result(
        status, value, is_error,
    )?)?)
}
