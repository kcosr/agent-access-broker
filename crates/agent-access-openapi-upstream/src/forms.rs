//! Scalar form admission is shared by source compilation and offline plan loading.
use crate::{config::bounded, model::FormField, refs};
use serde_json::{Value, json};
use std::collections::BTreeSet;

fn resolve<'a>(root: &'a Value, value: &'a Value) -> Result<&'a Value, String> {
    let mut value = value;
    let mut seen = BTreeSet::new();
    for _ in 0..32 {
        let map = value.as_object().ok_or("form schemas must be objects")?;
        let Some(reference) = map.get("$ref") else {
            return Ok(value);
        };
        if map.keys().any(|key| {
            !matches!(
                key.as_str(),
                "$ref"
                    | "description"
                    | "title"
                    | "summary"
                    | "default"
                    | "examples"
                    | "example"
                    | "$defs"
            )
        }) {
            return Err("form references cannot have semantic siblings".into());
        }
        let pointer = refs::local_pointer(reference.as_str().ok_or("invalid form reference")?)?;
        if !seen.insert(pointer.clone()) {
            return Err("cyclic form reference".into());
        }
        value = root
            .pointer(&pointer)
            .ok_or("form schema reference is missing")?;
    }
    Err("form reference chain exceeds its limit".into())
}
fn required(
    schema: &Value,
    properties: &serde_json::Map<String, Value>,
) -> Result<BTreeSet<String>, String> {
    let mut names = BTreeSet::new();
    if let Some(values) = schema.get("required") {
        let values = values.as_array().ok_or("required must be an array")?;
        if values.len() > 128 {
            return Err("form required list exceeds its limit".into());
        }
        for value in values {
            let name = value.as_str().ok_or("required entries must be strings")?;
            if !properties.contains_key(name) || !names.insert(name.to_owned()) {
                return Err("required entries must be unique declared fields".into());
            }
        }
    }
    Ok(names)
}
pub(crate) fn fields(input: &Value) -> Result<Vec<FormField>, String> {
    let root_properties = input
        .get("properties")
        .and_then(Value::as_object)
        .ok_or("input properties must be an object")?;
    required(input, root_properties)?;
    if input.get("additionalProperties") != Some(&json!(false)) {
        return Err("form operation inputs must be closed".into());
    }
    let body = resolve(
        input,
        root_properties
            .get("body")
            .ok_or("form body schema is missing")?,
    )?;
    if body.get("type").and_then(Value::as_str) != Some("object")
        || body.get("additionalProperties") != Some(&json!(false))
    {
        return Err("form body must be a closed object".into());
    }
    if body.as_object().expect("resolved").keys().any(|key| {
        !matches!(
            key.as_str(),
            "type"
                | "properties"
                | "required"
                | "additionalProperties"
                | "minProperties"
                | "maxProperties"
                | "description"
                | "title"
                | "default"
                | "examples"
                | "example"
                | "$defs"
                | "$schema"
        )
    }) {
        return Err("unsupported form object schema keyword".into());
    }
    let properties = body
        .get("properties")
        .and_then(Value::as_object)
        .filter(|m| !m.is_empty() && m.len() <= 128)
        .ok_or("forms require between one and 128 fields")?;
    let required = required(body, properties)?;
    properties
        .iter()
        .map(|(name, value)| {
            if !bounded(name, 256) {
                return Err("invalid form field name".into());
            }
            let value = resolve(input, value)?;
            if value.as_object().expect("resolved").keys().any(|key| {
                !matches!(
                    key.as_str(),
                    "type"
                        | "enum"
                        | "const"
                        | "minimum"
                        | "maximum"
                        | "exclusiveMinimum"
                        | "exclusiveMaximum"
                        | "multipleOf"
                        | "minLength"
                        | "maxLength"
                        | "pattern"
                        | "format"
                        | "description"
                        | "title"
                        | "default"
                        | "examples"
                        | "example"
                        | "readOnly"
                        | "writeOnly"
                        | "deprecated"
                        | "$defs"
                        | "$schema"
                ) && !key.starts_with("x-")
            }) {
                return Err("unsupported scalar form schema keyword".into());
            }
            let kind = value
                .get("type")
                .and_then(Value::as_str)
                .filter(|kind| matches!(*kind, "string" | "integer" | "number" | "boolean"))
                .ok_or("form fields must declare one ordinary scalar type")?;
            Ok(FormField {
                name: name.clone(),
                value_type: kind.into(),
                required: required.contains(name),
            })
        })
        .collect()
}
pub(crate) fn encoding(encoding: Option<&Value>, fields: &[FormField]) -> Result<(), String> {
    let Some(encoding) = encoding else {
        return Ok(());
    };
    for (name, entry) in encoding
        .as_object()
        .ok_or("form encoding must be an object")?
    {
        if !fields.iter().any(|field| &field.name == name) {
            return Err("encoding must reference a declared form field".into());
        }
        for (key, value) in entry
            .as_object()
            .ok_or("field encoding must be an object")?
        {
            if !match key.as_str() {
                "style" => value.as_str() == Some("form"),
                "explode" => value.as_bool() == Some(true),
                "allowReserved" => value.as_bool() == Some(false),
                "headers" => value.as_object().is_some_and(|m| m.is_empty()),
                _ => false,
            } {
                return Err("unsupported scalar form encoding".into());
            }
        }
    }
    Ok(())
}
