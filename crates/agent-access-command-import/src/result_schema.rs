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

/// Asserts that `outcome`, of a JSON action or a `download`, conforms
/// strictly to the result schemas the hook states, both as the command
/// provider returns it and as core delivers a failed write, with the
/// `operationDispatched` fact beside the receipt.
#[cfg(test)]
pub(crate) fn assert_conforms(
    download: bool,
    outcome: &Result<agent_access_provider::ProviderResult, agent_access_provider::ProviderError>,
) {
    use agent_access_provider::test_support::assert_result_conforms;
    let action = agent_access_provider::ActionDescriptor::new(
        "item.update",
        "Command action",
        json!({"type": "object"}),
    )
    .result_schemas(result_schemas(download));
    assert_result_conforms(&action, outcome);
    if let Err(error) = outcome
        && let Some(result) = error
            .result
            .as_deref()
            .and_then(serde_json::Value::as_object)
            .filter(|result| result.contains_key("mutationStatus"))
    {
        let mut result = result.clone();
        result.insert("operationDispatched".into(), json!(true));
        let delivered = agent_access_provider::ProviderError::error(
            agent_access_provider::ReasonCode::OperationFailed,
            "delivered",
        )
        .with_result(serde_json::Value::Object(result));
        assert_result_conforms(&action, &Err(delivered));
    }
}
