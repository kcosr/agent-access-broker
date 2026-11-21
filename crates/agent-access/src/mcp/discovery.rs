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
        && name == "services_describe"
        && let Some(selected) = view.service()
    {
        validate_scoped_service_detail(&value, selected)?;
    }
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
    if name == "resource_access_describe"
        && !is_error
        && !resource_access_result_fits(
            &value,
            agent_access_core::RESOURCE_ACCESS_MAX_RESPONSE_BYTES,
        )
    {
        return Ok(serde_json::from_value(super::tools::envelope_result(
            422,
            serde_json::json!({
                "decision": "error", "reasonCode": "resource_access_too_complex", "result": null,
                "error": { "message": "Resource access response exceeds the result size limit." }
            }),
            true,
        )?)?);
    }
    Ok(serde_json::from_value(super::tools::envelope_result(
        status, value, is_error,
    )?)?)
}

/// Count both the structured value and its escaped JSON text before allocating
/// the duplicated MCP result. A compact JSON stream contains no literal controls.
fn resource_access_result_fits(value: &Value, maximum: usize) -> bool {
    struct SizeCounter {
        bytes: usize,
        maximum: usize,
    }
    impl std::io::Write for SizeCounter {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            let extra = bytes
                .iter()
                .filter(|byte| matches!(**byte, b'"' | b'\\'))
                .count();
            self.bytes = bytes
                .len()
                .checked_mul(2)
                .and_then(|amount| amount.checked_add(extra))
                .and_then(|amount| self.bytes.checked_add(amount))
                .filter(|size| *size <= self.maximum)
                .ok_or_else(|| std::io::Error::other("resource access result exceeds limit"))?;
            Ok(bytes.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    let shell = serde_json::json!({"content":[{"type":"text","text":""}],"structuredContent":null,"isError":false});
    let base = serde_json::to_vec(&shell).expect("fixed MCP shell").len() - 4;
    if base > maximum {
        return false;
    }
    serde_json::to_writer(
        SizeCounter {
            bytes: base,
            maximum,
        },
        value,
    )
    .is_ok()
}

fn validate_scoped_service_detail(value: &Value, selected: &str) -> Result<()> {
    let parsed = agent_access_core::mcp::parse_discovery_service(value.clone())?;
    let service = parsed.capabilities;
    // The host omits limits for anonymous discovery. Scoped views require an
    // authenticated caller, just as their catalog-based admission does.
    let authenticated = value.get("limits").is_some_and(Value::is_object);
    let mut actions = std::collections::BTreeSet::new();
    if service.service != selected
        || service.surface != "invoke"
        || !authenticated
        || value["scopedMcpReady"] != true
        || (service.actions.is_empty()
            && matches!(
                value["availability"]["state"].as_str(),
                Some("available" | "partial")
            ))
        || service
            .actions
            .iter()
            .any(|action| !actions.insert(&action.action))
    {
        anyhow::bail!("service view is unavailable");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resource_access_wrapper_preflight_counts_escaped_and_unicode_text_exactly() {
        for value in [
            serde_json::json!({"url": "https://example.test/quote\"/backslash\\/é/\n"}),
            serde_json::json!([null, true, 12, {}]),
        ] {
            let result = super::super::tools::envelope_result(200, value.clone(), false).unwrap();
            let bytes = serde_json::to_vec(&result).unwrap().len();
            assert!(resource_access_result_fits(&value, bytes));
            assert!(resource_access_result_fits(&value, bytes + 1));
            assert!(!resource_access_result_fits(&value, bytes - 1));
        }
    }

    #[test]
    fn resource_access_wrapper_preflight_bounds_large_nested_results() {
        let value = serde_json::json!({"access": [ {"coverage": "x".repeat(1024 * 1024)} ]});
        assert!(!resource_access_result_fits(&value, 1024));
    }
}
