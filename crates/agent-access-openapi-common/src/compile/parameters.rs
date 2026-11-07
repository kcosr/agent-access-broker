use crate::{GatewayParameterV1, bounded, schema, source::Dialect};
use serde_json::{Map, Value, json};
use std::collections::{BTreeMap, BTreeSet};

#[derive(Default)]
pub(super) struct SwaggerBody {
    pub body: Option<(Value, bool)>,
    pub form: Vec<Value>,
}

pub(super) fn parameters(
    dialect: Dialect,
    document: &Value,
    item: &Value,
    operation: &Value,
) -> Result<(Vec<GatewayParameterV1>, SwaggerBody), String> {
    let mut effective = BTreeMap::new();
    for level in [item, operation] {
        let Some(values) = level.get("parameters") else {
            continue;
        };
        let values = values
            .as_array()
            .filter(|v| v.len() <= 64)
            .ok_or("parameters must be a bounded array")?;
        let mut seen = BTreeSet::new();
        for value in values {
            let value = dialect.object(document, value, "parameters")?;
            let name = value
                .get("name")
                .and_then(Value::as_str)
                .filter(|v| bounded(v, 256))
                .ok_or("parameter name is invalid")?;
            let location = value
                .get("in")
                .and_then(Value::as_str)
                .ok_or("parameter location is missing")?;
            let key = (
                location.to_owned(),
                if location == "header" {
                    name.to_ascii_lowercase()
                } else {
                    name.to_owned()
                },
            );
            if !seen.insert(key.clone()) {
                return Err("duplicate parameter in one definition level".into());
            }
            effective.insert(key, value);
        }
    }
    if effective.len() > 64 {
        return Err("gateway operation has too many parameters".into());
    }
    let mut parameters = Vec::new();
    let mut body = SwaggerBody::default();
    for ((location, _), value) in effective {
        let name = value["name"].as_str().expect("validated name");
        let required = boolean(value, "required", false)?;
        if dialect == Dialect::Swagger2 {
            if location == "body" {
                if body.body.is_some() {
                    return Err("only one Swagger body parameter is supported".into());
                }
                let schema = value
                    .get("schema")
                    .ok_or("Swagger body requires a schema")?;
                dialect.documentation_schema(document, schema)?;
                body.body = Some((schema.clone(), required));
                continue;
            }
            if location == "formData" {
                if value.get("type").and_then(Value::as_str) == Some("file") {
                    return Err("multipart/file form bodies are unsupported".into());
                }
                // Field-level form semantics are documentation; only the raw body's media/presence are enforced.
                if value.get("type").and_then(Value::as_str).is_none() {
                    return Err("Swagger form field requires a declared type".into());
                }
                body.form.push(value.clone());
                continue;
            }
        }
        if !matches!(location.as_str(), "path" | "query" | "header") {
            return Err("unsupported gateway parameter location".into());
        }
        if boolean(value, "allowReserved", false)? || boolean(value, "allowEmptyValue", false)? {
            return Err(
                "allowReserved and allowEmptyValue parameter overrides are unsupported".into(),
            );
        }
        let (schema, style, explode) = match dialect {
            Dialect::OpenApi31 => {
                let fields = value.as_object().expect("validated parameter");
                if fields.keys().any(|key| {
                    !matches!(
                        key.as_str(),
                        "name"
                            | "in"
                            | "description"
                            | "required"
                            | "deprecated"
                            | "allowEmptyValue"
                            | "style"
                            | "explode"
                            | "allowReserved"
                            | "schema"
                            | "example"
                            | "examples"
                    ) && !key.starts_with("x-")
                }) {
                    return Err("unsupported OpenAPI parameter field".into());
                }
                let raw = value
                    .get("schema")
                    .ok_or("gateway parameter requires a schema")?;
                let schema = primitive_schema(dialect, document, raw)?;
                let style = value
                    .get("style")
                    .map(|v| v.as_str().ok_or("parameter style must be a string"))
                    .transpose()?
                    .unwrap_or(if location == "query" {
                        "form"
                    } else {
                        "simple"
                    })
                    .to_owned();
                let explode = boolean(value, "explode", location == "query")?;
                (schema, style, explode)
            }
            Dialect::Swagger2 => {
                let schema = swagger_schema(value, false)?;
                let array = schema["type"] == "array";
                let collection = value
                    .get("collectionFormat")
                    .map(|v| v.as_str().ok_or("collectionFormat must be a string"))
                    .transpose()?;
                if collection.is_some() && !array {
                    return Err("collectionFormat requires a query array".into());
                }
                let explode = if array {
                    if location != "query" {
                        return Err("only query parameters support arrays".into());
                    }
                    match collection.unwrap_or("csv") {
                        "csv" => false,
                        "multi" => true,
                        _ => return Err("unsupported Swagger array collectionFormat".into()),
                    }
                } else {
                    location == "query"
                };
                (
                    schema,
                    if location == "query" {
                        "form"
                    } else {
                        "simple"
                    }
                    .to_owned(),
                    explode,
                )
            }
        };
        schema::validate_schema(&schema, location == "query")?;
        parameters.push(GatewayParameterV1 {
            name: name.into(),
            location,
            required,
            style,
            explode,
            schema,
        });
    }
    Ok((parameters, body))
}

pub(super) fn primitive_schema(
    dialect: Dialect,
    document: &Value,
    raw: &Value,
) -> Result<Value, String> {
    let mut schema = dialect.object(document, raw, "schemas")?.clone();
    if schema.get("type").and_then(Value::as_str) == Some("array") {
        let items = schema
            .get("items")
            .ok_or("query array requires primitive items")?;
        let items = dialect.object(document, items, "schemas")?.clone();
        schema["items"] = items;
    }
    Ok(schema)
}

pub(super) fn boolean(value: &Value, key: &str, default: bool) -> Result<bool, String> {
    value
        .get(key)
        .map(|v| {
            v.as_bool()
                .ok_or_else(|| "parameter/body flag must be boolean".to_owned())
        })
        .transpose()
        .map(|v| v.unwrap_or(default))
}

pub(super) fn swagger_schema(value: &Value, header: bool) -> Result<Value, String> {
    let mut fields = Map::new();
    for (key, value) in value
        .as_object()
        .ok_or("Swagger parameter must be an object")?
    {
        if matches!(
            key.as_str(),
            "name" | "in" | "required" | "collectionFormat" | "allowEmptyValue"
        ) && !header
            || key.starts_with("x-")
        {
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
        ) {
            fields.insert(key.clone(), value.clone());
        } else {
            return Err("unsupported Swagger parameter/header field".into());
        }
    }
    if let Some(items) = fields.get_mut("items") {
        *items = swagger_schema(items, true)?;
    }
    for (inclusive, exclusive) in [
        ("minimum", "exclusiveMinimum"),
        ("maximum", "exclusiveMaximum"),
    ] {
        if let Some(value) = fields.remove(exclusive) {
            if value == json!(true) {
                let bound = fields
                    .remove(inclusive)
                    .ok_or("exclusive Swagger bound requires its numeric bound")?;
                fields.insert(exclusive.into(), bound);
            } else if value != json!(false) {
                return Err("Swagger exclusive bounds must be boolean".into());
            }
        }
    }
    Ok(Value::Object(fields))
}
