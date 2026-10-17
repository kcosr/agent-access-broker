//! Operator-owned receiver contracts. Source schemas stay unchanged in storage.
use agent_access_provider::{ActionDescriptor, SecretInputDescriptor};
use serde_json::Value;

pub const IMPORT_MAX_SECRET_INPUT_BYTES: usize = 65_536;
pub const RECEIVER_OUTPUT_NOTICE: &str = "Accepts secret references in the designated fields. Every call returns a completion receipt only; upstream response content is hidden. Use a separately authorized read action to inspect stored metadata.";

/// Compile the SDK contract without modifying the accepted upstream definition.
pub fn receiver_descriptor(
    action: &super::ImportedActionDefinition,
    inputs: &[SecretInputDescriptor],
) -> Result<ActionDescriptor, String> {
    validate_receiver_storage(inputs)?;
    let mut descriptor = ActionDescriptor::new(
        &action.action,
        &action.description,
        action.input_schema.clone(),
    );
    for input in inputs {
        descriptor = descriptor.secret_input(input.clone());
    }
    descriptor
        .validate_secret_contract()
        .map_err(|error| error.to_string())?;
    Ok(descriptor)
}

/// Structural validation independent of a retained adapter or source schema.
pub fn validate_receiver_storage(inputs: &[SecretInputDescriptor]) -> Result<(), String> {
    if inputs
        .windows(2)
        .any(|pair| pair[0].pointer() >= pair[1].pointer())
    {
        return Err("secret input settings must be unique and sorted by pointer".into());
    }
    if inputs.len() > 16
        || serde_json::to_vec(inputs)
            .map_err(|_| "invalid secret input settings")?
            .len()
            > IMPORT_MAX_SECRET_INPUT_BYTES
    {
        return Err("secret input settings exceed limits".into());
    }
    // A synthetic fixed-property schema lets the SDK enforce pointer grammar,
    // depth, uniqueness and overlap even if a retained source is unsupported.
    let mut schema = serde_json::json!({"type":"object","properties":{}});
    for input in inputs {
        let pointer = input.pointer();
        if pointer.len() > 1024 || !pointer.starts_with("/inputs/") {
            return Err("invalid secret input pointer".into());
        }
        let parts = pointer[8..].split('/').collect::<Vec<_>>();
        if parts.len() > 16 {
            return Err("invalid secret input pointer".into());
        }
        let mut node = &mut schema;
        for (index, part) in parts.iter().enumerate() {
            let property = part.replace("~1", "/").replace("~0", "~");
            let properties = node
                .get_mut("properties")
                .and_then(Value::as_object_mut)
                .ok_or("overlapping secret input pointers")?;
            node = properties.entry(property).or_insert_with(|| {
                if index + 1 == parts.len() {
                    serde_json::json!({"type":"string"})
                } else {
                    serde_json::json!({"type":"object","properties":{}})
                }
            });
        }
    }
    let mut action = ActionDescriptor::new("receiver", "Receiver", schema);
    for input in inputs {
        action = action.secret_input(input.clone());
    }
    action
        .validate_secret_contract()
        .map_err(|error| error.to_string())
}

/// Fixed string paths eligible under the SDK's schema profile, bounded by source limits.
pub fn receiver_candidates(action: &super::ImportedActionDefinition) -> Vec<String> {
    fn visit(schema: &Value, pointer: String, paths: &mut Vec<String>) {
        if pointer.len() > 1024 || pointer.matches('/').count() > 17 {
            return;
        }
        if schema.get("type").and_then(Value::as_str) == Some("string") {
            if schema.get("x-mcp-header").is_none() {
                paths.push(pointer);
            }
            return;
        }
        if let Some(properties) = schema.get("properties").and_then(Value::as_object) {
            for (name, child) in properties {
                visit(
                    child,
                    format!("{pointer}/{}", name.replace('~', "~0").replace('/', "~1")),
                    paths,
                );
            }
        }
    }
    let mut paths = Vec::new();
    visit(&action.input_schema, "/inputs".into(), &mut paths);
    // One schema copy, with at most one active candidate contract. Previously
    // marked writeOnly annotations do not affect another field's eligibility.
    let mut descriptor = ActionDescriptor::new(
        &action.action,
        &action.description,
        action.input_schema.clone(),
    );
    let mut candidates = Vec::new();
    for pointer in paths {
        descriptor.secret_inputs.clear();
        descriptor = descriptor.secret_input(SecretInputDescriptor::new(&pointer));
        if descriptor.validate_secret_contract().is_ok() {
            candidates.push(pointer);
        }
    }
    candidates.sort();
    candidates
}

/// MCP permits only SDK-validated payload properties, never mirrored headers.
pub fn validate_mcp_receivers(
    action: &super::ImportedActionDefinition,
    inputs: &[SecretInputDescriptor],
) -> Result<(), String> {
    receiver_descriptor(action, inputs)?;
    for input in inputs {
        // The SDK already proved the pointer grammar and fixed traversal.
        let mut node = &action.input_schema;
        for part in input.pointer()[8..].split('/') {
            let property = part.replace("~1", "/").replace("~0", "~");
            node = node
                .get("properties")
                .and_then(|properties| properties.get(&property))
                .ok_or("invalid secret receiver property")?;
        }
        if node.get("x-mcp-header").is_some() {
            return Err("secret receiver properties cannot mirror protocol headers".into());
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    fn action(schema: Value) -> super::super::ImportedActionDefinition {
        super::super::ImportedActionDefinition {
            action: "receive".into(),
            source: serde_json::json!({"toolName":"receive"}),
            label: None,
            description: "Receive a value".into(),
            input_schema: schema,
            output_schema: None,
            annotations: serde_json::json!({}),
            read_only: false,
        }
    }
    #[test]
    fn receiver_candidates_use_sdk_fixed_string_contract_and_exclude_headers() {
        let source = action(serde_json::json!({"type":"object","properties":{
            "plain":{"type":"string","minLength":3},
            "credentials":{"type":"object","properties":{"a/b~c":{"type":"string"}}},
            "region":{"type":"string","x-mcp-header":"Region"},
            "union":{"oneOf":[{"type":"string"},{"type":"null"}]},
            "array":{"type":"array","items":{"type":"string"}},
            "dynamic":{"type":"object","additionalProperties":{"type":"string"}},
            "ref":{"$ref":"#/$defs/token"}
        },"$defs":{"token":{"type":"string"}}}));
        assert_eq!(
            receiver_candidates(&source),
            ["/inputs/credentials/a~1b~0c", "/inputs/plain"]
        );
        let input = SecretInputDescriptor::new("/inputs/plain");
        let descriptor = receiver_descriptor(&source, &[input]).unwrap();
        assert_eq!(
            descriptor.input_schema["properties"]["plain"]["writeOnly"],
            true
        );
        assert!(
            source.input_schema["properties"]["plain"]
                .get("writeOnly")
                .is_none()
        );
        assert!(
            validate_mcp_receivers(&source, &[SecretInputDescriptor::new("/inputs/region")])
                .is_err()
        );
        let union = descriptor.reference_input_schema().unwrap();
        assert_eq!(union["properties"]["plain"]["oneOf"][0]["minLength"], 3);
    }
    #[test]
    fn receiver_storage_rejects_invalid_overlap_duplicates_and_unsorted_paths() {
        for pointers in [
            vec!["/inputs/x", "/inputs/x"],
            vec!["/inputs/x", "/inputs/x/y"],
            vec!["/inputs/z", "/inputs/a"],
            vec!["/inputs/"],
            vec!["/inputs/x~2"],
            vec!["/inputs/*"],
            vec!["/other/x"],
        ] {
            assert!(
                validate_receiver_storage(
                    &pointers
                        .iter()
                        .map(|p| SecretInputDescriptor::new(*p))
                        .collect::<Vec<_>>()
                )
                .is_err(),
                "{pointers:?}"
            );
        }
        assert!(
            validate_receiver_storage(&[SecretInputDescriptor::new("/inputs/credentials/token")])
                .is_ok()
        );
    }
}
