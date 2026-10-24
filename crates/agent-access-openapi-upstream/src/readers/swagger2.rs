//! Swagger 2.0 source semantics, normalized into the shared HTTP compiler.
use crate::{
    config::{Settings, bounded},
    model::*,
    refs,
};
use agent_access_core::imports::ImportedServiceDefinition;
use serde_json::{Map, Value, json};
use std::collections::BTreeMap;
use url::{Position, Url};

pub(crate) fn security_schemes(document: &Value) -> Vec<Security> {
    document
        .get("securityDefinitions")
        .and_then(Value::as_object)
        .into_iter()
        .flatten()
        .filter_map(|(name, value)| {
            if !bounded(name, 256) {
                return None;
            }
            let security = match (
                value.get("type").and_then(Value::as_str),
                value.get("in").and_then(Value::as_str),
            ) {
                (Some("basic"), _) => Security {
                    scheme: name.clone(),
                    kind: "basic".into(),
                    header: None,
                },
                (Some("apiKey"), Some("header")) => Security {
                    scheme: name.clone(),
                    kind: "raw_header".into(),
                    header: Some(value.get("name")?.as_str()?.into()),
                },
                _ => return None,
            };
            security.delivery().ok()?;
            Some(security)
        })
        .collect()
}
pub(crate) fn operation(
    document: &Value,
    item: &Value,
    value: &Value,
    definition: &ImportedServiceDefinition,
) -> Result<Operation, String> {
    value.as_object().ok_or("operation must be an object")?;
    if item.get("$ref").is_some() {
        return Err("Swagger path-item references are unsupported".into());
    }
    let settings = Settings::parse(definition)?;
    let mut parameters = Vec::new();
    let mut json_body = None;
    let mut properties = Map::new();
    let mut required = Vec::new();
    for parameter in super::parameters(document, item, value, Dialect::Swagger2)? {
        let location = parameter["in"].as_str().expect("validated location");
        let name = parameter["name"].as_str().expect("validated name");
        let is_required = parameter
            .get("required")
            .map(|v| v.as_bool().ok_or("required must be boolean"))
            .transpose()?
            .unwrap_or(false);
        if location == "body" {
            if json_body.is_some() {
                return Err("only one Swagger body parameter is supported".into());
            }
            let schema = parameter
                .get("schema")
                .filter(|v| v.is_object())
                .ok_or("Swagger body requires a schema object")?
                .clone();
            json_body = Some((schema, is_required));
            continue;
        }
        if !matches!(location, "path" | "query" | "header" | "formData") {
            return Err("unsupported Swagger parameter location".into());
        }
        if parameter
            .get("allowEmptyValue")
            .is_some_and(|v| v != &json!(false))
        {
            return Err("allowEmptyValue is unsupported".into());
        }
        let schema = parameter_schema(&parameter)?;
        if location == "formData" {
            if parameter.get("collectionFormat").is_some()
                || !matches!(
                    schema.get("type").and_then(Value::as_str),
                    Some("string" | "number" | "integer" | "boolean")
                )
            {
                return Err("Swagger forms require ordinary scalar fields".into());
            }
            properties.insert(name.into(), schema);
            if is_required {
                required.push(json!(name));
            }
        } else {
            let array = schema.get("type").and_then(Value::as_str) == Some("array");
            let collection = parameter
                .get("collectionFormat")
                .map(|v| v.as_str().ok_or("collectionFormat must be a string"))
                .transpose()?;
            if collection.is_some() && !array {
                return Err("collectionFormat requires a query array".into());
            }
            let explode = if array && location == "query" {
                match collection.unwrap_or("csv") {
                    "csv" => false,
                    "multi" => true,
                    _ => return Err("unsupported Swagger query collection format".into()),
                }
            } else {
                location == "query"
            };
            let mut normalized = json!({"name":name,"in":location,"required":is_required,"schema":schema,"explode":explode});
            if let Some(allow) = parameter.get("allowEmptyValue") {
                normalized["allowEmptyValue"] = allow.clone();
            }
            parameters.push(normalized);
        }
    }
    let body = if let Some((schema, required)) = json_body {
        if !properties.is_empty() {
            return Err("Swagger body and formData parameters cannot be combined".into());
        }
        require_media(document, value, "consumes", "application/json")?;
        Body::Json { schema, required }
    } else if !properties.is_empty() {
        require_media(
            document,
            value,
            "consumes",
            "application/x-www-form-urlencoded",
        )?;
        Body::FormUrlEncoded {
            required: !required.is_empty(),
            schema: json!({"type":"object","properties":properties,"required":required,"additionalProperties":false}),
            encoding: None,
        }
    } else {
        Body::None
    };
    let mut responses = BTreeMap::new();
    for (status, response) in value
        .get("responses")
        .and_then(Value::as_object)
        .ok_or("responses must be an object")?
    {
        if status.starts_with("x-") {
            continue;
        }
        if status != "default"
            && !(status.len() == 3
                && status.bytes().all(|b| b.is_ascii_digit())
                && crate::compile::valid_status(status))
        {
            return Err("Swagger requires a three-digit response status or default".into());
        }
        let response = refs::object_for(document, response, "responses", Dialect::Swagger2)?;
        let spec = if let Some(schema) = response.get("schema") {
            if !schema.is_object() {
                return Err("Swagger response schema must be an object".into());
            }
            let media = media(document, value, "produces")?;
            let selected = media
                .iter()
                .find(|s| s.as_str() == Some("application/json"))
                .or_else(|| {
                    media.iter().find(|v| {
                        v.as_str()
                            .is_some_and(super::openapi31::json_response_media)
                    })
                })
                .and_then(Value::as_str)
                .ok_or("Swagger response schema requires supported JSON produces")?;
            Response {
                content_type: Some(selected.into()),
                schema: Some(schema.clone()),
            }
        } else {
            Response {
                content_type: None,
                schema: None,
            }
        };
        responses.insert(status.clone(), spec);
    }
    Ok(Operation {
        destinations: Some(destinations(document, value, &settings.document)?),
        security_schemes: security_schemes(document),
        security_requirements: value
            .get("security")
            .or_else(|| document.get("security"))
            .cloned()
            .unwrap_or(Value::Null),
        parameters,
        body,
        responses,
    })
}
fn parameter_schema(parameter: &Value) -> Result<Value, String> {
    let mut schema = Map::new();
    for (key, value) in parameter.as_object().ok_or("parameter must be an object")? {
        if matches!(
            key.as_str(),
            "name" | "in" | "required" | "collectionFormat" | "allowEmptyValue"
        ) {
            continue;
        }
        if matches!(
            key.as_str(),
            "type"
                | "format"
                | "description"
                | "items"
                | "default"
                | "enum"
                | "maximum"
                | "minimum"
                | "exclusiveMaximum"
                | "exclusiveMinimum"
                | "maxLength"
                | "minLength"
                | "pattern"
                | "maxItems"
                | "minItems"
                | "uniqueItems"
                | "multipleOf"
        ) || key.starts_with("x-")
        {
            schema.insert(key.clone(), value.clone());
        } else {
            return Err("unsupported Swagger non-body parameter field".into());
        }
    }
    Ok(Value::Object(schema))
}
fn media<'a>(
    document: &'a Value,
    operation: &'a Value,
    key: &str,
) -> Result<&'a Vec<Value>, String> {
    let values = operation
        .get(key)
        .or_else(|| document.get(key))
        .and_then(Value::as_array)
        .ok_or("Swagger media declaration must be an array")?;
    if values.iter().any(|v| !v.is_string()) {
        return Err("Swagger media entries must be strings".into());
    }
    Ok(values)
}
fn require_media(
    document: &Value,
    operation: &Value,
    key: &str,
    expected: &str,
) -> Result<(), String> {
    if !media(document, operation, key)?
        .iter()
        .any(|v| v.as_str() == Some(expected))
    {
        return Err("Swagger request body has no supported media type".into());
    }
    Ok(())
}
fn destinations(document: &Value, operation: &Value, definition: &Url) -> Result<Vec<Url>, String> {
    let host = match document.get("host") {
        None => &definition[Position::BeforeHost..Position::AfterPort],
        Some(v) => v
            .as_str()
            .filter(|s| bounded(s, 512))
            .ok_or("invalid Swagger host")?,
    };
    if host.contains(['/', '\\', '@', '?', '#', '%']) || host.chars().any(char::is_whitespace) {
        return Err("Swagger host must contain only a host and optional port".into());
    }
    let base = match document.get("basePath") {
        None => "/",
        Some(v) => v.as_str().ok_or("Swagger basePath must be a string")?,
    };
    if !bounded(base, 2048)
        || !base.starts_with('/')
        || base.starts_with("//")
        || base.contains(['\\', '?', '#', '%', '{', '}'])
        || base.split('/').any(|v| matches!(v, "." | ".."))
    {
        return Err("invalid Swagger basePath".into());
    }
    let fallback = vec![json!(definition.scheme())];
    let schemes = operation
        .get("schemes")
        .or_else(|| document.get("schemes"))
        .map(|v| v.as_array().ok_or("Swagger schemes must be an array"))
        .transpose()?
        .unwrap_or(&fallback);
    let mut candidates = Vec::new();
    for scheme in schemes {
        let scheme = scheme
            .as_str()
            .filter(|s| matches!(*s, "http" | "https"))
            .ok_or("unsupported Swagger scheme")?;
        candidates.push(crate::config::endpoint(&format!(
            "{scheme}://{host}{base}"
        ))?);
    }
    Ok(candidates)
}
