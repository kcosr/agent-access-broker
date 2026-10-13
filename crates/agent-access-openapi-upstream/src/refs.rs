//! References stay inside typed component locations of the fetched JSON document.
use agent_access_core::imports::{BoundedImportSchema, IMPORT_MAX_SCHEMA_DEPTH};
use serde_json::{Value, json};
use std::collections::BTreeSet;

pub(crate) fn object<'a>(
    document: &'a Value,
    value: &'a Value,
    category: &str,
) -> Result<&'a Value, String> {
    let mut current = value;
    let mut seen = BTreeSet::new();
    for _ in 0..32 {
        let fields = current
            .as_object()
            .ok_or("referenced OpenAPI value must be an object")?;
        let Some(reference) = fields.get("$ref") else {
            return Ok(current);
        };
        if fields
            .keys()
            .any(|key| !matches!(key.as_str(), "$ref" | "description" | "summary"))
        {
            return Err(
                "structural references support only summary and description siblings".into(),
            );
        }
        let pointer = local_pointer(reference.as_str().ok_or("invalid reference")?)?;
        if !pointer.starts_with(&format!("/components/{category}/"))
            || !seen.insert(pointer.clone())
        {
            return Err(
                "reference is cyclic or does not target its typed local component collection"
                    .into(),
            );
        }
        current = document
            .pointer(&pointer)
            .ok_or("local component reference is missing")?;
    }
    Err("local reference chain exceeds its limit".into())
}
fn local_pointer(reference: &str) -> Result<String, String> {
    let fragment = reference
        .strip_prefix('#')
        .ok_or("external references are unsupported")?;
    let pointer = percent_encoding::percent_decode_str(fragment)
        .decode_utf8()
        .map_err(|_| "invalid reference encoding")?;
    if !pointer.starts_with('/') {
        return Err("only local JSON Pointer references are supported".into());
    }
    Ok(pointer.into_owned())
}
fn fragment(pointer: &str) -> String {
    let mut result = String::from("#");
    for byte in pointer.bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'/' | b'~' | b'-' | b'.' | b'_' | b'$') {
            result.push(char::from(byte));
        } else {
            use std::fmt::Write;
            write!(&mut result, "%{byte:02X}").expect("String write");
        }
    }
    result
}
fn rewrite(schema: &mut Value, needed: &mut BTreeSet<String>, depth: usize) -> Result<(), String> {
    if depth > IMPORT_MAX_SCHEMA_DEPTH {
        return Err("schema depth exceeds limit".into());
    }
    if schema.is_boolean() {
        return Ok(());
    }
    let fields = schema
        .as_object_mut()
        .ok_or("schema must be an object or boolean")?;
    if let Some(reference) = fields.get_mut("$ref") {
        let pointer = local_pointer(reference.as_str().ok_or("invalid schema reference")?)?;
        let rest = pointer
            .strip_prefix("/components/schemas/")
            .ok_or("schema references must target local components.schemas")?;
        let name = rest.split('/').next().ok_or("missing schema component")?;
        if name.is_empty() {
            return Err("missing schema component".into());
        }
        needed.insert(name.to_owned());
        *reference = Value::String(fragment(&format!("/$defs/{rest}")));
    }
    if fields.get("$schema").and_then(Value::as_str)
        == Some("https://spec.openapis.org/oas/3.1/dialect/base")
    {
        fields.insert(
            "$schema".into(),
            json!("https://json-schema.org/draft/2020-12/schema"),
        );
    }
    for (key, value) in fields {
        match key.as_str() {
            "properties" | "patternProperties" | "$defs" | "definitions" | "dependentSchemas" => {
                for child in value
                    .as_object_mut()
                    .ok_or("schema map must be an object")?
                    .values_mut()
                {
                    rewrite(child, needed, depth + 1)?;
                }
            }
            "allOf" | "anyOf" | "oneOf" | "prefixItems" => {
                for child in value
                    .as_array_mut()
                    .ok_or("schema alternatives must be an array")?
                {
                    rewrite(child, needed, depth + 1)?;
                }
            }
            "additionalProperties"
            | "unevaluatedProperties"
            | "propertyNames"
            | "contains"
            | "items"
            | "unevaluatedItems"
            | "not"
            | "if"
            | "then"
            | "else"
            | "contentSchema" => rewrite(value, needed, depth + 1)?,
            _ => {}
        }
    }
    Ok(())
}

pub(crate) fn schema(document: &Value, mut root: Value) -> Result<Value, String> {
    let mut needed = BTreeSet::new();
    rewrite(&mut root, &mut needed, 0)?;
    let mut complete = BTreeSet::new();
    let mut definitions = serde_json::Map::new();
    while let Some(name) = needed.pop_first() {
        if !complete.insert(name.clone()) {
            continue;
        }
        if complete.len() > 256 {
            return Err("too many referenced schema components".into());
        }
        let mut value = document
            .pointer(&format!("/components/schemas/{name}"))
            .ok_or("local schema component is missing")?
            .clone();
        rewrite(&mut value, &mut needed, 0)?;
        // Decode JSON Pointer escaping for the actual map key.
        definitions.insert(name.replace("~1", "/").replace("~0", "~"), value);
    }
    if !definitions.is_empty() {
        root.as_object_mut()
            .ok_or("root schema must be object")?
            .insert("$defs".into(), Value::Object(definitions));
    }
    BoundedImportSchema::compile(&root)?;
    Ok(root)
}
