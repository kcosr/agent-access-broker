//! The result schemas of command import actions. A JSON action's result is
//! the command's `result` as `upstreamCommand` (see [`crate::response`]);
//! a download's is its bounded metadata object there, with the size and
//! hash the adapter computes and the file name and media type at the root
//! (see [`crate::download`]). The command's own data stays an open leaf
//! whatever output schema its manifest declares, so a refresh or acceptance
//! never invalidates a client's cached validator. A write's receipt fields
//! are optional, since the reviewed classification may change.
use agent_access_provider::ActionResultSchemas;
use serde_json::json;

pub(crate) fn result_schemas(download: bool) -> ActionResultSchemas {
    let mut success = json!({
        "type": "object",
        "properties": {
            "upstreamCommand": {"description": "The command's result."},
            "mutationStatus": {"const": "applied_unverified", "description": "Present for writes: the command reported success, but its effect is unverified."},
            "retrySafe": {"const": false, "description": "Present for writes."},
            "safeLocators": {
                "type": "object",
                "additionalProperties": {"type": ["string", "integer"]},
                "description": "Present for writes whose command named what changed."
            }
        },
        "required": ["upstreamCommand"]
    });
    if download {
        let properties = &mut success["properties"];
        properties["upstreamCommand"] =
            json!({"type": "object", "description": "The command's download metadata."});
        properties["filename"] = json!({"type": "string"});
        properties["contentType"] = json!({"type": "string"});
        properties["size"] =
            json!({"type": "integer", "description": "Decoded file size in bytes."});
        properties["sha256"] =
            json!({"type": "string", "description": "Hex SHA-256 of the decoded file."});
        success["required"] = json!([
            "upstreamCommand",
            "filename",
            "contentType",
            "size",
            "sha256"
        ]);
    }
    ActionResultSchemas::new(success).with_error(json!({
        "type": "object",
        "properties": {
            "operationDispatched": {"type": "boolean", "description": "Present beside a write's receipt: whether the command process started."}
        }
    }))
}
