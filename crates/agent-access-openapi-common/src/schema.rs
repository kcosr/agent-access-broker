//! Finite parameter validation; request and response body schemas never enter this validator.
use regex::RegexBuilder;
use serde_json::{Value, json};
use std::cmp::Ordering;

pub(crate) const MAX_VALUE_BYTES: usize = 4096;

fn regex(pattern: &str) -> Result<regex::Regex, String> {
    if pattern.len() > 512 {
        return Err("gateway parameter pattern exceeds its limit".into());
    }
    RegexBuilder::new(pattern)
        .size_limit(64 * 1024)
        .dfa_size_limit(64 * 1024)
        .build()
        .map_err(|_| "gateway parameter pattern is unsupported".into())
}

/// Returns the same strict schema after checking all keywords; nothing semantic is discarded.
pub(crate) fn validate_schema(schema: &Value, array_allowed: bool) -> Result<(), String> {
    let fields = schema
        .as_object()
        .ok_or("gateway parameter schema must be an object")?;
    if serde_json::to_vec(schema)
        .map_err(|_| "invalid parameter schema")?
        .len()
        > 8192
    {
        return Err("gateway parameter schema exceeds its byte limit".into());
    }
    let kind = fields
        .get("type")
        .and_then(Value::as_str)
        .ok_or("parameter schema needs a primitive type")?;
    if kind == "array" {
        if !array_allowed {
            return Err("only query parameters support arrays".into());
        }
        if fields.keys().any(|key| {
            !matches!(
                key.as_str(),
                "type"
                    | "items"
                    | "minItems"
                    | "maxItems"
                    | "uniqueItems"
                    | "description"
                    | "title"
                    | "default"
                    | "examples"
            )
        }) {
            return Err("unsupported gateway array schema keyword".into());
        }
        validate_schema(
            fields
                .get("items")
                .ok_or("query arrays require primitive items")?,
            false,
        )?;
        for key in ["minItems", "maxItems"] {
            if fields
                .get(key)
                .is_some_and(|v| v.as_u64().is_none_or(|n| n > 256))
            {
                return Err("gateway array bounds must be integers at most 256".into());
            }
        }
        if fields.get("uniqueItems").is_some_and(|v| !v.is_boolean()) {
            return Err("uniqueItems must be boolean".into());
        }
        if fields.get("minItems").and_then(Value::as_u64).unwrap_or(0)
            > fields
                .get("maxItems")
                .and_then(Value::as_u64)
                .unwrap_or(256)
        {
            return Err("gateway array bounds conflict".into());
        }
        return Ok(());
    }
    if !matches!(kind, "string" | "integer" | "number" | "boolean") {
        return Err("gateway parameters require non-null primitive types".into());
    }
    for (key, value) in fields {
        match key.as_str() {
            "type" | "description" | "title" | "default" | "examples" => {}
            "enum" => {
                let values = value
                    .as_array()
                    .filter(|v| !v.is_empty() && v.len() <= 64)
                    .ok_or("parameter enum must be bounded and nonempty")?;
                if values.iter().any(|v| !type_matches(v, kind)) {
                    return Err("parameter enum does not match its type".into());
                }
            }
            "minLength" | "maxLength" if kind == "string" => {
                if value.as_u64().is_none_or(|n| n > MAX_VALUE_BYTES as u64) {
                    return Err("parameter string bounds exceed their limit".into());
                }
            }
            "pattern" if kind == "string" => {
                regex(value.as_str().ok_or("parameter pattern must be a string")?)?;
            }
            "minimum" | "maximum" | "exclusiveMinimum" | "exclusiveMaximum"
                if matches!(kind, "integer" | "number") =>
            {
                if value.as_f64().is_none_or(|n| !n.is_finite())
                    || kind == "integer" && integer(value).is_none()
                {
                    return Err("parameter numeric bounds must be finite numbers".into());
                }
            }
            "multipleOf" if matches!(kind, "integer" | "number") => {
                if value.as_f64().is_none_or(|n| !n.is_finite() || n <= 0.0)
                    || kind == "integer" && integer(value).is_none()
                {
                    return Err("parameter multipleOf must be a positive finite number".into());
                }
            }
            "format" => {
                if !matches!(
                    (kind, value.as_str()),
                    ("integer", Some("int32" | "int64")) | ("number", Some("float" | "double"))
                ) {
                    return Err("unsupported gateway parameter format".into());
                }
            }
            _ => return Err("unsupported gateway parameter schema keyword".into()),
        }
    }
    if fields.get("minLength").and_then(Value::as_u64).unwrap_or(0)
        > fields
            .get("maxLength")
            .and_then(Value::as_u64)
            .unwrap_or(MAX_VALUE_BYTES as u64)
    {
        return Err("parameter string bounds conflict".into());
    }
    if let (Some(min), Some(max)) = (fields.get("minimum"), fields.get("maximum"))
        && numeric_order(min, max) == Some(Ordering::Greater)
    {
        return Err("parameter numeric bounds conflict".into());
    }
    Ok(())
}

fn type_matches(value: &Value, kind: &str) -> bool {
    match kind {
        "string" => value.is_string(),
        "boolean" => value.is_boolean(),
        "number" => value.is_number(),
        "integer" => value.as_i64().is_some() || value.as_u64().is_some(),
        _ => false,
    }
}

fn integer(value: &Value) -> Option<i128> {
    value
        .as_i64()
        .map(i128::from)
        .or_else(|| value.as_u64().map(i128::from))
}

fn numeric_order(left: &Value, right: &Value) -> Option<Ordering> {
    match (integer(left), integer(right)) {
        (Some(left), Some(right)) => Some(left.cmp(&right)),
        _ => left.as_f64()?.partial_cmp(&right.as_f64()?),
    }
}

pub(crate) fn scalar(raw: &str, schema: &Value) -> Result<Value, String> {
    if raw.len() > MAX_VALUE_BYTES || raw.chars().any(char::is_control) {
        return Err("gateway parameter exceeds its value profile".into());
    }
    let kind = schema["type"].as_str().ok_or("invalid parameter schema")?;
    let value = match kind {
        "string" => json!(raw),
        "boolean" => match raw {
            "true" => json!(true),
            "false" => json!(false),
            _ => return Err("gateway boolean parameter is invalid".into()),
        },
        "integer" => {
            if raw.is_empty() || raw.starts_with('+') || raw.trim() != raw {
                return Err("gateway integer parameter is invalid".into());
            }
            if let Ok(value) = raw.parse::<i64>() {
                json!(value)
            } else if let Ok(value) = raw.parse::<u64>() {
                json!(value)
            } else {
                return Err("gateway integer parameter is invalid".into());
            }
        }
        "number" => {
            let value: Value =
                serde_json::from_str(raw).map_err(|_| "gateway numeric parameter is invalid")?;
            if !value.is_number() || raw.trim() != raw {
                return Err("gateway numeric parameter is invalid".into());
            }
            value
        }
        _ => return Err("gateway parameter schema is invalid".into()),
    };
    if let Some(values) = schema.get("enum").and_then(Value::as_array)
        && !values.contains(&value)
    {
        return Err("gateway parameter is outside its declared enum".into());
    }
    if kind == "string" {
        let length = raw.chars().count() as u64;
        if schema
            .get("minLength")
            .and_then(Value::as_u64)
            .is_some_and(|n| length < n)
            || schema
                .get("maxLength")
                .and_then(Value::as_u64)
                .is_some_and(|n| length > n)
        {
            return Err("gateway parameter violates its string bound".into());
        }
        if let Some(pattern) = schema.get("pattern").and_then(Value::as_str)
            && !regex(pattern)?.is_match(raw)
        {
            return Err("gateway parameter does not match its declared pattern".into());
        }
    }
    if kind == "integer" {
        let number = integer(&value).ok_or("invalid integer parameter")?;
        if schema
            .get("minimum")
            .and_then(integer)
            .is_some_and(|v| number < v)
            || schema
                .get("maximum")
                .and_then(integer)
                .is_some_and(|v| number > v)
            || schema
                .get("exclusiveMinimum")
                .and_then(integer)
                .is_some_and(|v| number <= v)
            || schema
                .get("exclusiveMaximum")
                .and_then(integer)
                .is_some_and(|v| number >= v)
            || schema
                .get("multipleOf")
                .and_then(integer)
                .is_some_and(|v| number % v != 0)
            || schema.get("format").and_then(Value::as_str) == Some("int32")
                && i32::try_from(number).is_err()
            || schema.get("format").and_then(Value::as_str) == Some("int64")
                && i64::try_from(number).is_err()
        {
            return Err("gateway parameter violates its integer bound".into());
        }
    }
    if kind == "number" {
        let number = value.as_f64().ok_or("invalid numeric parameter")?;
        if !number.is_finite()
            || schema
                .get("minimum")
                .is_some_and(|bound| numeric_order(&value, bound).is_none_or(|order| order.is_lt()))
            || schema
                .get("maximum")
                .is_some_and(|bound| numeric_order(&value, bound).is_none_or(|order| order.is_gt()))
            || schema.get("exclusiveMinimum").is_some_and(|bound| {
                numeric_order(&value, bound).is_none_or(|order| !order.is_gt())
            })
            || schema.get("exclusiveMaximum").is_some_and(|bound| {
                numeric_order(&value, bound).is_none_or(|order| !order.is_lt())
            })
        {
            return Err("gateway parameter violates its numeric bound".into());
        }
        if let Some(divisor) = schema.get("multipleOf") {
            let violates = match (integer(&value), integer(divisor)) {
                (Some(value), Some(divisor)) => divisor <= 0 || value % divisor != 0,
                _ => {
                    let ratio = number / divisor.as_f64().ok_or("invalid numeric divisor")?;
                    !ratio.is_finite()
                        || (ratio - ratio.round()).abs() > f64::EPSILON * ratio.abs().max(1.0) * 4.0
                }
            };
            if violates {
                return Err("gateway parameter violates its multipleOf bound".into());
            }
        }
        if schema.get("format").and_then(Value::as_str) == Some("float")
            && !(number as f32).is_finite()
        {
            return Err("gateway parameter violates its numeric format".into());
        }
    }
    Ok(value)
}

pub(crate) fn array(values: &[String], schema: &Value) -> Result<(), String> {
    if values.len() > 256
        || schema
            .get("minItems")
            .and_then(Value::as_u64)
            .is_some_and(|n| (values.len() as u64) < n)
        || schema
            .get("maxItems")
            .and_then(Value::as_u64)
            .is_some_and(|n| values.len() as u64 > n)
    {
        return Err("gateway query array violates its item bound".into());
    }
    let mut validated = Vec::new();
    for value in values {
        let value = scalar(value, &schema["items"])?;
        if schema.get("uniqueItems") == Some(&json!(true)) && validated.contains(&value) {
            return Err("gateway query array contains repeated values".into());
        }
        validated.push(value);
    }
    Ok(())
}
