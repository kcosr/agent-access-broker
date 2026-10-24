//! References stay inside typed component locations of the fetched JSON document.
use crate::model::Dialect;
use agent_access_core::imports::{BoundedImportSchema, IMPORT_MAX_SCHEMA_DEPTH};
use serde_json::{Value, json};
use std::collections::BTreeSet;

pub(crate) fn object<'a>(
    document: &'a Value,
    value: &'a Value,
    category: &str,
) -> Result<&'a Value, String> {
    object_for(document, value, category, Dialect::OpenApi31)
}
pub(crate) fn object_for<'a>(
    document: &'a Value,
    value: &'a Value,
    category: &str,
    dialect: Dialect,
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
        if fields.keys().any(|key| {
            !matches!(key.as_str(), "$ref" | "description" | "summary")
                && !(dialect == Dialect::Swagger2
                    && (key == "title" || key.starts_with("x-") && key != "x-nullable"))
        }) {
            return Err(
                "structural references support only summary and description siblings".into(),
            );
        }
        let pointer = local_pointer(reference.as_str().ok_or("invalid reference")?)?;
        if !pointer.starts_with(&prefix(category, dialect)) || !seen.insert(pointer.clone()) {
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
pub(crate) fn local_pointer(reference: &str) -> Result<String, String> {
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
fn rewrite(
    schema: &mut Value,
    needed: &mut BTreeSet<String>,
    depth: usize,
    dialect: Dialect,
    request: bool,
    boolean_allowed: bool,
) -> Result<(), String> {
    if depth > IMPORT_MAX_SCHEMA_DEPTH {
        return Err("schema depth exceeds limit".into());
    }
    if schema.is_boolean() {
        if dialect == Dialect::Swagger2 && !boolean_allowed {
            return Err(
                "Swagger schemas must be objects; only additionalProperties admits boolean flags"
                    .into(),
            );
        }
        return Ok(());
    }
    if dialect == Dialect::Swagger2 {
        normalize_swagger(schema, request)?;
    }
    let fields = schema
        .as_object_mut()
        .ok_or("schema must be an object or boolean")?;
    if let Some(reference) = fields.get_mut("$ref") {
        let pointer = local_pointer(reference.as_str().ok_or("invalid schema reference")?)?;
        let rest = pointer
            .strip_prefix(&prefix("schemas", dialect))
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
                    rewrite(child, needed, depth + 1, dialect, request, false)?;
                }
            }
            "allOf" | "anyOf" | "oneOf" | "prefixItems" => {
                for child in value
                    .as_array_mut()
                    .ok_or("schema alternatives must be an array")?
                {
                    rewrite(child, needed, depth + 1, dialect, request, false)?;
                }
            }
            "additionalProperties" => rewrite(value, needed, depth + 1, dialect, request, true)?,
            "unevaluatedProperties"
            | "propertyNames"
            | "contains"
            | "items"
            | "unevaluatedItems"
            | "not"
            | "if"
            | "then"
            | "else"
            | "contentSchema" => rewrite(value, needed, depth + 1, dialect, request, false)?,
            _ => {}
        }
    }
    Ok(())
}

pub(crate) fn schema_for(
    document: &Value,
    mut root: Value,
    dialect: Dialect,
    request: bool,
) -> Result<Value, String> {
    let mut needed = BTreeSet::new();
    rewrite(&mut root, &mut needed, 0, dialect, request, false)?;
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
            .pointer(&format!("{}{name}", prefix("schemas", dialect)))
            .ok_or("local schema component is missing")?
            .clone();
        let mut local_needed = BTreeSet::new();
        rewrite(&mut value, &mut local_needed, 0, dialect, request, false)?;
        needed.extend(local_needed.iter().cloned());
        // Decode JSON Pointer escaping for the actual map key.
        definitions.insert(name.replace("~1", "/").replace("~0", "~"), value);
    }
    if !definitions.is_empty() {
        root.as_object_mut()
            .ok_or("root schema must be object")?
            .insert("$defs".into(), Value::Object(definitions));
    }
    if dialect == Dialect::Swagger2 {
        reject_swagger_cycles(&root)?;
    }
    BoundedImportSchema::compile(&root)?;
    Ok(root)
}

fn prefix(category: &str, dialect: Dialect) -> String {
    match dialect {
        Dialect::OpenApi31 => format!("/components/{category}/"),
        Dialect::Swagger2 => format!(
            "/{}/",
            if category == "schemas" {
                "definitions"
            } else {
                category
            }
        ),
    }
}
// References to sibling schema locations in one definition are not cycles.
// Key this graph by exact schema pointers, rather than component names.
fn reject_swagger_cycles(root: &Value) -> Result<(), String> {
    let mut pending = schema_references(root)?;
    let mut dependencies = std::collections::BTreeMap::new();
    while let Some(pointer) = pending.pop_first() {
        if dependencies.contains_key(&pointer) {
            continue;
        }
        let target = root
            .pointer(&pointer)
            .ok_or("local Swagger schema reference is missing")?;
        let children = schema_references(target)?;
        pending.extend(children.iter().cloned());
        dependencies.insert(pointer, children);
    }
    let mut complete = std::collections::BTreeMap::new();
    for pointer in dependencies.keys() {
        check_cycle(
            pointer,
            &dependencies,
            &mut BTreeSet::new(),
            &mut complete,
            0,
        )?;
    }
    Ok(())
}
fn schema_references(schema: &Value) -> Result<BTreeSet<String>, String> {
    let mut pending = vec![(schema, 0)];
    let mut references = BTreeSet::new();
    while let Some((schema, depth)) = pending.pop() {
        if depth > IMPORT_MAX_SCHEMA_DEPTH {
            return Err("schema depth exceeds limit".into());
        }
        let Some(fields) = schema.as_object() else {
            continue;
        };
        if let Some(reference) = fields.get("$ref") {
            references.insert(local_pointer(
                reference
                    .as_str()
                    .ok_or("invalid Swagger schema reference")?,
            )?);
        }
        for (key, value) in fields {
            match key.as_str() {
                "properties" | "$defs" => pending.extend(
                    value
                        .as_object()
                        .ok_or("schema map must be an object")?
                        .values()
                        .map(|v| (v, depth + 1)),
                ),
                "allOf" => pending.extend(
                    value
                        .as_array()
                        .ok_or("schema alternatives must be an array")?
                        .iter()
                        .map(|v| (v, depth + 1)),
                ),
                "items" | "additionalProperties" => pending.push((value, depth + 1)),
                _ => {}
            }
        }
    }
    Ok(references)
}
fn check_cycle(
    name: &str,
    dependencies: &std::collections::BTreeMap<String, BTreeSet<String>>,
    visiting: &mut BTreeSet<String>,
    heights: &mut std::collections::BTreeMap<String, usize>,
    depth: usize,
) -> Result<usize, String> {
    if let Some(height) = heights.get(name) {
        if depth + height > 32 {
            return Err("Swagger schema reference chain exceeds its limit".into());
        }
        return Ok(*height);
    }
    if depth > 32 || !visiting.insert(name.into()) {
        return Err("Swagger schema reference is cyclic or exceeds its chain limit".into());
    }
    let mut height = 0;
    if let Some(children) = dependencies.get(name) {
        for child in children {
            height =
                height.max(1 + check_cycle(child, dependencies, visiting, heights, depth + 1)?);
        }
    }
    visiting.remove(name);
    heights.insert(name.into(), height);
    Ok(height)
}
fn normalize_swagger(schema: &mut Value, request: bool) -> Result<(), String> {
    let fields = schema
        .as_object_mut()
        .ok_or("Swagger schemas must be objects")?;
    if fields.contains_key("$ref") {
        if fields.keys().any(|key| {
            !matches!(key.as_str(), "$ref" | "description" | "title" | "summary")
                && !(key.starts_with("x-") && key != "x-nullable")
        }) {
            return Err("Swagger schema references do not support semantic siblings".into());
        }
        fields.retain(|key, _| key == "$ref");
        return Ok(());
    }
    for (key, value) in fields.iter() {
        if key == "x-nullable"
            || !(matches!(
                key.as_str(),
                "type"
                    | "properties"
                    | "required"
                    | "items"
                    | "additionalProperties"
                    | "enum"
                    | "minimum"
                    | "maximum"
                    | "exclusiveMinimum"
                    | "exclusiveMaximum"
                    | "multipleOf"
                    | "minLength"
                    | "maxLength"
                    | "pattern"
                    | "minItems"
                    | "maxItems"
                    | "uniqueItems"
                    | "minProperties"
                    | "maxProperties"
                    | "allOf"
                    | "description"
                    | "title"
                    | "example"
                    | "default"
                    | "format"
                    | "readOnly"
                    | "externalDocs"
            ) || key.starts_with("x-"))
        {
            return Err("unsupported Swagger schema keyword".into());
        }
        if key == "type"
            && !matches!(
                value.as_str(),
                Some("string" | "integer" | "number" | "boolean" | "object" | "array")
            )
        {
            return Err("unsupported Swagger schema type".into());
        }
        if key == "readOnly" && (value.as_bool().is_none() || request && value == &json!(true)) {
            return Err("readOnly request schemas are unsupported".into());
        }
    }
    for (inclusive, exclusive) in [
        ("minimum", "exclusiveMinimum"),
        ("maximum", "exclusiveMaximum"),
    ] {
        if fields.get(inclusive).is_some_and(|v| !v.is_number()) {
            return Err("Swagger numeric bound must be a number".into());
        }
        if let Some(value) = fields.remove(exclusive) {
            let exclusive_value = value
                .as_bool()
                .ok_or("Swagger exclusive bounds must be boolean")?;
            if exclusive_value {
                let bound = fields
                    .remove(inclusive)
                    .ok_or("exclusive Swagger bound requires its numeric bound")?;
                fields.insert(exclusive.into(), bound);
            }
        }
    }
    Ok(())
}
