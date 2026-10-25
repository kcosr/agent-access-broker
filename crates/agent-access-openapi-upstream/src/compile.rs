//! Common bounded compiler for both document readers.
use crate::config::bounded;
use crate::{config::Settings, model::*, refs};
use agent_access_core::imports::*;
use serde_json::{Map, Value, json};
use std::collections::{BTreeMap, BTreeSet};
pub(crate) fn operation(
    document: &Value,
    dialect: Dialect,
    definition: &ImportedServiceDefinition,
    operation: &Operation,
    path: &str,
    method: &str,
) -> Result<(Value, Plan), String> {
    let settings = Settings::parse(definition)?;
    validate_path(path)?;
    if method == "trace" {
        return Err("TRACE operations are unsupported".into());
    }
    let endpoint = crate::config::endpoint(&definition.endpoint)?;
    if operation.destinations.as_ref().is_some_and(|destinations| {
        !destinations.iter().any(|candidate| {
            candidate.as_str().trim_end_matches('/') == endpoint.as_str().trim_end_matches('/')
        })
    }) {
        return Err(
            "operation destinations do not include the independently approved API base URL".into(),
        );
    }
    let scheme = settings
        .scheme
        .ok_or("select an execution security scheme, save the draft, and refresh discovery")?;
    let security = operation
        .security_schemes
        .iter()
        .find(|candidate| candidate.scheme == scheme)
        .cloned()
        .ok_or("selected security scheme is missing or unsupported")?;
    let delivery = security.delivery()?;
    if definition
        .execution_bindings
        .iter()
        .any(|binding| binding.delivery != delivery)
    {
        return Err(
            "selected security scheme does not match the configured credential delivery".into(),
        );
    }
    let requirements = operation
        .security_requirements
        .as_array()
        .ok_or("operation has no supported authenticated security requirement")?;
    if !requirements.iter().any(|requirement| {
        requirement.as_object().is_some_and(|map| {
            map.len() == 1
                && map
                    .get(&scheme)
                    .and_then(Value::as_array)
                    .is_some_and(Vec::is_empty)
        })
    }) {
        return Err("operation security requires unsupported or combined credentials; a single selected Basic/bearer/header-key alternative is required".into());
    }
    if operation.parameters.len() > 128 {
        return Err("operation exceeds 128 parameters".into());
    }
    let mut groups: BTreeMap<&str, Map<String, Value>> = BTreeMap::new();
    let mut required: BTreeMap<&str, Vec<Value>> = BTreeMap::new();
    let mut parameters = Vec::new();
    let mut path_parameters = BTreeSet::new();
    for value in &operation.parameters {
        let location = value["in"].as_str().expect("validated");
        let group = match location {
            "path" => "path",
            "query" => "query",
            "header" => "headers",
            _ => return Err("only path, query and header parameters are supported".into()),
        };
        let name = value["name"].as_str().expect("validated");
        if value.get("content").is_some()
            || value
                .get("allowReserved")
                .is_some_and(|v| v != &json!(false))
            || value
                .get("allowEmptyValue")
                .is_some_and(|v| v != &json!(false))
        {
            return Err(
                "content parameters, allowReserved and allowEmptyValue are unsupported".into(),
            );
        }
        let style = value
            .get("style")
            .and_then(Value::as_str)
            .unwrap_or(if location == "query" {
                "form"
            } else {
                "simple"
            });
        let explode = value
            .get("explode")
            .map(|v| v.as_bool().ok_or("explode must be boolean"))
            .transpose()?
            .unwrap_or(style == "form");
        if style
            != if location == "query" {
                "form"
            } else {
                "simple"
            }
        {
            return Err("unsupported parameter serialization style".into());
        }
        let is_required = value
            .get("required")
            .map(|v| v.as_bool().ok_or("required must be boolean"))
            .transpose()?
            .unwrap_or(false);
        if location == "path" {
            if !is_required {
                return Err("path parameters must be required".into());
            }
            path_parameters.insert(name.to_owned());
        }
        if location == "header" {
            crate::config::parameter_header(name)?;
            if security
                .header
                .as_ref()
                .is_some_and(|header| header.eq_ignore_ascii_case(name))
            {
                return Err("parameter collides with the execution credential header".into());
            }
        }
        let schema = value.get("schema").ok_or("parameter schema is required")?;
        let resolved = refs::object_for(document, schema, "schemas", dialect)?;
        let kind = resolved
            .get("type")
            .and_then(Value::as_str)
            .ok_or("parameter must declare a primitive type")?;
        let value_type = if kind == "array" && location == "query" {
            let item = refs::object_for(
                document,
                resolved.get("items").ok_or("query array needs items")?,
                "schemas",
                dialect,
            )?;
            if !primitive(item.get("type").and_then(Value::as_str)) {
                return Err("query arrays require primitive items".into());
            }
            item["type"].as_str().expect("primitive")
        } else if !primitive(Some(kind)) {
            return Err(
                "only primitive parameters and primitive query arrays are supported".into(),
            );
        } else {
            kind
        };
        groups
            .entry(group)
            .or_default()
            .insert(name.into(), schema.clone());
        if is_required {
            required.entry(group).or_default().push(json!(name));
        }
        parameters.push(Parameter {
            name: name.into(),
            location: location.into(),
            style: style.into(),
            explode,
            required: is_required,
            value_type: value_type.into(),
            array: kind == "array",
        });
    }
    if path_parameters != validate_path(path)? {
        return Err(
            "path template variables and required path parameters must match exactly".into(),
        );
    }
    let mut properties = Map::new();
    let mut root_required = Vec::new();
    for (group, props) in groups {
        let required = required.remove(group).unwrap_or_default();
        if !required.is_empty() {
            root_required.push(json!(group));
        }
        properties.insert(group.into(),json!({"type":"object","properties":props,"required":required,"additionalProperties":false}));
    }
    let request_body = !matches!(operation.body, Body::None);
    if request_body && matches!(method, "get" | "head" | "options") {
        return Err("request bodies on GET, HEAD or OPTIONS are unsupported".into());
    }
    match &operation.body {
        Body::None => {}
        Body::Json { schema, required }
        | Body::FormUrlEncoded {
            schema, required, ..
        } => {
            properties.insert("body".into(), schema.clone());
            if *required {
                root_required.push(json!("body"));
            }
        }
    }
    let input = refs::schema_for(
        document,
        json!({"type":"object","properties":properties,"required":root_required,"additionalProperties":false}),
        dialect,
        true,
    )?;
    let form_body = if let Body::FormUrlEncoded { encoding, .. } = &operation.body {
        let fields = crate::forms::fields(&input)?;
        crate::forms::encoding(encoding.as_ref(), &fields)?;
        Some(FormBody { fields })
    } else {
        None
    };
    let mut responses = BTreeMap::new();
    for (status, response) in &operation.responses {
        if !valid_status(status) {
            return Err("invalid response status selector".into());
        }
        responses.insert(
            status.clone(),
            Response {
                content_type: response.content_type.clone(),
                schema: response
                    .schema
                    .as_ref()
                    .map(|schema| {
                        refs::schema_for(document, json!({"allOf":[schema]}), dialect, false)
                    })
                    .transpose()?,
            },
        );
    }
    if responses.len() > 64 {
        return Err("operation exceeds 64 responses".into());
    }
    if !responses
        .keys()
        .any(|status| status.starts_with('2') || status == "default")
    {
        return Err("operation has no declared successful response".into());
    }
    let plan = Plan {
        method: method.to_ascii_uppercase(),
        path: path.into(),
        security,
        parameters,
        request_body,
        form_body,
        responses,
    };
    if serde_json::to_vec(&plan)
        .map_err(|_| "invalid operation plan")?
        .len()
        + serde_json::to_vec(&input)
            .map_err(|_| "invalid schema")?
            .len()
        > IMPORT_MAX_TOOL_BYTES / 2
    {
        return Err("operation contract exceeds import size budget".into());
    }
    Ok((input, plan))
}
fn primitive(kind: Option<&str>) -> bool {
    matches!(kind, Some("string" | "integer" | "number" | "boolean"))
}
pub(crate) fn valid_status(status: &str) -> bool {
    status == "default"
        || matches!(status, "1XX" | "2XX" | "3XX" | "4XX" | "5XX")
        || status
            .parse::<u16>()
            .is_ok_and(|n| (100..=599).contains(&n) && status.len() == 3)
}
pub(crate) fn validate_path(path: &str) -> Result<BTreeSet<String>, String> {
    if !bounded(path, 2048)
        || !path.starts_with('/')
        || path.starts_with("//")
        || path.contains(['\\', '?', '#', '%'])
    {
        return Err("operation path is unsupported".into());
    }
    let mut names = BTreeSet::new();
    for segment in path.split('/') {
        if matches!(segment, "." | "..") {
            return Err("dot segments are forbidden".into());
        }
        if segment.contains(['{', '}']) {
            let name = segment
                .strip_prefix('{')
                .and_then(|v| v.strip_suffix('}'))
                .filter(|v| bounded(v, 256) && !v.contains(['{', '}']))
                .ok_or("path variables must occupy an entire segment")?;
            names.insert(name.to_owned());
        }
    }
    Ok(names)
}
