//! OpenAPI 3.1 source semantics; execution contracts are compiled elsewhere.
use crate::{
    config::{Settings, bounded},
    model::*,
    refs,
};
use agent_access_core::imports::ImportedServiceDefinition;
use serde_json::{Value, json};
use std::collections::BTreeMap;
use url::Url;

pub(crate) fn operation(
    document: &Value,
    item: &Value,
    value: &Value,
    definition: &ImportedServiceDefinition,
) -> Result<Operation, String> {
    value.as_object().ok_or("operation must be an object")?;
    if value
        .get("callbacks")
        .is_some_and(|v| v.as_object().is_none_or(|m| !m.is_empty()))
    {
        return Err("callback operations are unsupported".into());
    }
    let settings = Settings::parse(definition)?;
    let body = match value.get("requestBody") {
        None => Body::None,
        Some(body) => {
            let body = refs::object(document, body, "requestBodies")?;
            let content = body
                .get("content")
                .and_then(Value::as_object)
                .ok_or("request body content must be an object")?;
            let required = body
                .get("required")
                .and_then(Value::as_bool)
                .unwrap_or(false);
            if let Some(media) = content.get("application/json") {
                Body::Json {
                    schema: media.get("schema").cloned().unwrap_or(json!(true)),
                    required,
                }
            } else if let Some(media) = content.get("application/x-www-form-urlencoded") {
                let required = body
                    .get("required")
                    .map(|v| v.as_bool().ok_or("requestBody required must be boolean"))
                    .transpose()?
                    .unwrap_or(false);
                Body::FormUrlEncoded {
                    schema: media
                        .get("schema")
                        .cloned()
                        .ok_or("form body schema is required")?,
                    required,
                    encoding: media.get("encoding").cloned(),
                }
            } else {
                return Err("request body must support application/json or application/x-www-form-urlencoded".into());
            }
        }
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
        let response = refs::object(document, response, "responses")?;
        let spec = match response.get("content") {
            Some(content) => {
                let content = content
                    .as_object()
                    .ok_or("response content must be an object")?;
                if content.is_empty() {
                    Response {
                        content_type: None,
                        schema: None,
                    }
                } else {
                    let (media, value) = content
                        .get_key_value("application/json")
                        .or_else(|| content.iter().find(|(key, _)| json_response_media(key)))
                        .ok_or("response must support JSON or explicitly have no content")?;
                    Response {
                        content_type: Some(media.clone()),
                        schema: Some(value.get("schema").cloned().unwrap_or(json!(true))),
                    }
                }
            }
            None => Response {
                content_type: None,
                schema: None,
            },
        };
        responses.insert(status.clone(), spec);
    }
    Ok(Operation {
        destinations: destinations(
            document,
            item,
            value,
            &settings.document,
            &definition.endpoint,
        )?,
        security_schemes: security_schemes(document),
        security_requirements: value
            .get("security")
            .or_else(|| document.get("security"))
            .cloned()
            .unwrap_or(Value::Null),
        parameters: super::parameters(document, item, value, Dialect::OpenApi31)?,
        body,
        responses,
    })
}
pub(crate) fn json_response_media(media: &str) -> bool {
    media == "application/json"
        || (media.starts_with("application/")
            && media.ends_with("+json")
            && bounded(media, 128)
            && !media.contains([';', ' ', '\t']))
}
pub(crate) fn security_schemes(document: &Value) -> Vec<Security> {
    document
        .pointer("/components/securitySchemes")
        .and_then(Value::as_object)
        .into_iter()
        .flatten()
        .filter_map(|(name, value)| {
            if !bounded(name, 256) {
                return None;
            }
            let value = refs::object(document, value, "securitySchemes").ok()?;
            let scheme = match (
                value.get("type").and_then(Value::as_str),
                value.get("scheme").and_then(Value::as_str),
                value.get("in").and_then(Value::as_str),
            ) {
                (Some("http"), Some(scheme), _) if scheme.eq_ignore_ascii_case("bearer") => {
                    Security {
                        scheme: name.into(),
                        kind: "bearer".into(),
                        header: None,
                    }
                }
                (Some("http"), Some(scheme), _) if scheme.eq_ignore_ascii_case("basic") => {
                    Security {
                        scheme: name.into(),
                        kind: "basic".into(),
                        header: None,
                    }
                }
                (Some("apiKey"), _, Some("header")) => Security {
                    scheme: name.into(),
                    kind: "raw_header".into(),
                    header: Some(value.get("name")?.as_str()?.into()),
                },
                _ => return None,
            };
            scheme.delivery().ok()?;
            Some(scheme)
        })
        .collect()
}
fn destinations(
    document: &Value,
    item: &Value,
    operation: &Value,
    definition_url: &Url,
    endpoint: &str,
) -> Result<Option<Vec<Url>>, String> {
    let Some(servers) = operation
        .get("servers")
        .or_else(|| item.get("servers"))
        .or_else(|| document.get("servers"))
    else {
        return Ok(None);
    };
    let servers = servers.as_array().ok_or("servers must be an array")?;
    if servers.is_empty() {
        return Err(
            "empty server overrides are unsupported; configure an explicit matching server".into(),
        );
    }
    let endpoint = crate::config::endpoint(endpoint)?;
    let mut candidates = Vec::new();
    for server in servers {
        let Some(raw) = server.get("url").and_then(Value::as_str) else {
            continue;
        };
        let mut raw = raw.to_owned();
        if let Some(variables) = server.get("variables").and_then(Value::as_object) {
            for (name, value) in variables {
                let Some(default) = value.get("default").and_then(Value::as_str) else {
                    return Err("server variable needs a fixed default".into());
                };
                if !bounded(default, 256)
                    || default.contains(['{', '}'])
                    || value.get("enum").is_some_and(|values| {
                        values
                            .as_array()
                            .is_none_or(|values| !values.contains(&json!(default)))
                    })
                {
                    return Err("server variable default is invalid".into());
                }
                raw = raw.replace(&format!("{{{name}}}"), default);
            }
        }
        if raw.contains(['{', '}']) {
            continue;
        }
        if let Ok(url) = definition_url.join(&raw)
            && url.query().is_none()
            && url.fragment().is_none()
            && url.username().is_empty()
            && url.password().is_none()
        {
            let approved =
                url.as_str().trim_end_matches('/') == endpoint.as_str().trim_end_matches('/');
            candidates.push(url);
            if approved {
                break;
            }
        }
    }
    Ok(Some(candidates))
}
