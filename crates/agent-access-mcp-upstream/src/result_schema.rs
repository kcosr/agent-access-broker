//! The result schemas of every imported MCP action: the `upstreamMcp`
//! wrapper `normalize_result` builds and the write receipt fields
//! `McpProvider::invoke` adds. The tool's content blocks and structured
//! result stay open leaves whatever output schema the tool declared, so a
//! refresh or acceptance never invalidates a client's cached validator.
use agent_access_provider::ActionResultSchemas;
use serde_json::{Value, json};

fn upstream_mcp(description: &str) -> Value {
    json!({
        "type": "object",
        "description": description,
        "properties": {
            "content": {"type": "array", "items": {"type": "object"}, "description": "The tool's content blocks."},
            "isError": {"type": "boolean"},
            "structuredContent": {"description": "The tool's structured result, as returned, when it gave one."}
        },
        "required": ["content", "isError"]
    })
}

pub(crate) fn result_schemas() -> ActionResultSchemas {
    ActionResultSchemas::new(json!({
        "type": "object",
        "properties": {
            "upstreamMcp": upstream_mcp("The upstream tool's result."),
            "mutationStatus": {"const": "applied_unverified", "description": "Present for writes: the tool ran, but its effect is unverified."},
            "retrySafe": {"const": false, "description": "Present for writes."}
        },
        "required": ["upstreamMcp"]
    }))
    .with_error(json!({
        "type": "object",
        "properties": {
            "upstreamMcp": upstream_mcp("The result of a tool that reported an error."),
            "toolDispatched": {"type": "boolean", "description": "Present for writes: whether the tool call was sent."}
        }
    }))
}
