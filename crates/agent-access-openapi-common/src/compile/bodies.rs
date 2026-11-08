use super::parameters::{SwaggerBody, boolean, primitive_schema, swagger_schema};
use crate::{
    GatewayRequestBodyV1, GatewayResponseHeaderV1, GatewayResponseV1, profile, schema,
    source::Dialect, validate_declared_header,
};
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};

pub(super) fn request(
    dialect: Dialect,
    document: &Value,
    operation: &Value,
    swagger: SwaggerBody,
) -> Result<Option<GatewayRequestBodyV1>, String> {
    match dialect {
        Dialect::OpenApi31 => {
            let Some(body) = operation.get("requestBody") else {
                return Ok(None);
            };
            let body = dialect.object(document, body, "requestBodies")?;
            let content = body
                .get("content")
                .and_then(Value::as_object)
                .filter(|v| !v.is_empty() && v.len() <= 8)
                .ok_or("request body content must be a bounded nonempty object")?;
            let mut media_types = Vec::new();
            for (media, definition) in content {
                if !profile::supported_media(media) {
                    return Err("gateway request body supports raw JSON, URL-encoded form and octet-stream only".into());
                }
                definition
                    .as_object()
                    .ok_or("request media definition must be an object")?;
                if definition
                    .get("encoding")
                    .is_some_and(|v| v.as_object().is_none_or(|m| !m.is_empty()))
                {
                    return Err("request media encoding overrides are unsupported".into());
                }
                if let Some(schema) = definition.get("schema") {
                    dialect.documentation_schema(document, schema)?;
                }
                media_types.push(media.clone());
            }
            Ok(Some(GatewayRequestBodyV1 {
                required: boolean(body, "required", false)?,
                media_types,
            }))
        }
        Dialect::Swagger2 => {
            if swagger.body.is_none() && swagger.form.is_empty() {
                return Ok(None);
            }
            if swagger.body.is_some() && !swagger.form.is_empty() {
                return Err("Swagger body and form parameters cannot be combined".into());
            }
            let media_types = media(document, operation, "consumes", true)?;
            if media_types.iter().any(|v| !profile::supported_media(v)) {
                return Err("gateway request body supports raw JSON, URL-encoded form and octet-stream only".into());
            }
            if !swagger.form.is_empty()
                && media_types
                    .iter()
                    .any(|v| v != "application/x-www-form-urlencoded")
            {
                return Err("Swagger form parameters require URL-encoded body media only".into());
            }
            let required = swagger.body.is_some_and(|(_, required)| required)
                || swagger
                    .form
                    .iter()
                    .any(|v| v.get("required") == Some(&Value::Bool(true)));
            Ok(Some(GatewayRequestBodyV1 {
                required,
                media_types,
            }))
        }
    }
}

pub(super) fn responses(
    dialect: Dialect,
    document: &Value,
    operation: &Value,
) -> Result<BTreeMap<String, GatewayResponseV1>, String> {
    let responses = operation
        .get("responses")
        .and_then(Value::as_object)
        .filter(|v| !v.is_empty() && v.len() <= 128)
        .ok_or("responses must be a bounded nonempty object")?;
    let mut result = BTreeMap::new();
    for (status, response) in responses {
        if status.starts_with("x-") {
            continue;
        }
        if !profile::valid_status(status, dialect == Dialect::OpenApi31) {
            return Err("unsupported gateway response status selector".into());
        }
        let response = dialect.object(document, response, "responses")?;
        let mut headers = Vec::new();
        let mut names = BTreeSet::new();
        if let Some(values) = response.get("headers") {
            let values = values
                .as_object()
                .filter(|v| v.len() <= 64)
                .ok_or("response headers must be a bounded object")?;
            for (name, header) in values {
                validate_declared_header(name)?;
                if !names.insert(name.to_ascii_lowercase()) {
                    return Err("case-insensitive duplicate response header declaration".into());
                }
                let schema = match dialect {
                    Dialect::OpenApi31 => {
                        let header = dialect.object(document, header, "headers")?;
                        if header
                            .get("style")
                            .is_some_and(|v| v.as_str() != Some("simple"))
                            || boolean(header, "explode", false)?
                            || boolean(header, "required", false)?
                        {
                            return Err(
                                "response headers support optional simple scalar values only"
                                    .into(),
                            );
                        }
                        if header
                            .as_object()
                            .expect("validated header")
                            .keys()
                            .any(|key| {
                                !matches!(
                                    key.as_str(),
                                    "description"
                                        | "required"
                                        | "deprecated"
                                        | "style"
                                        | "explode"
                                        | "schema"
                                        | "example"
                                        | "examples"
                                ) && !key.starts_with("x-")
                            })
                        {
                            return Err("unsupported response header field".into());
                        }
                        primitive_schema(
                            dialect,
                            document,
                            header
                                .get("schema")
                                .ok_or("response header requires a scalar schema")?,
                        )?
                    }
                    Dialect::Swagger2 => swagger_schema(header, true)?,
                };
                schema::validate_schema(&schema, false)?;
                headers.push(GatewayResponseHeaderV1 {
                    name: name.clone(),
                    schema,
                });
            }
        }
        let content_types = match dialect {
            Dialect::OpenApi31 => {
                let mut media = Vec::new();
                if let Some(content) = response.get("content") {
                    for (name, definition) in content
                        .as_object()
                        .filter(|v| v.len() <= 32)
                        .ok_or("response content must be a bounded object")?
                    {
                        if !profile::media_token(name) {
                            return Err(
                                "response media types must be concrete bounded names".into()
                            );
                        }
                        definition
                            .as_object()
                            .ok_or("response media definition must be an object")?;
                        if let Some(schema) = definition.get("schema") {
                            dialect.documentation_schema(document, schema)?;
                        }
                        media.push(name.clone());
                    }
                }
                media
            }
            Dialect::Swagger2 => {
                if let Some(schema) = response.get("schema") {
                    dialect.documentation_schema(document, schema)?;
                }
                media(document, operation, "produces", false)?
            }
        };
        result.insert(
            status.clone(),
            GatewayResponseV1 {
                headers,
                content_types,
            },
        );
    }
    Ok(result)
}

fn media(
    document: &Value,
    operation: &Value,
    key: &str,
    required: bool,
) -> Result<Vec<String>, String> {
    let Some(value) = operation.get(key).or_else(|| document.get(key)) else {
        return if required {
            Err("Swagger body requires an explicit media declaration".into())
        } else {
            Ok(Vec::new())
        };
    };
    let values = value
        .as_array()
        .filter(|v| !v.is_empty() && v.len() <= 32)
        .ok_or("Swagger media declaration must be a bounded nonempty array")?;
    let mut result = Vec::new();
    for value in values {
        let value = value
            .as_str()
            .filter(|v| profile::media_token(v))
            .ok_or("Swagger media entry must be a concrete bounded name")?;
        if result.iter().any(|v| v == value) {
            return Err("duplicate Swagger media declaration".into());
        }
        result.push(value.to_owned());
    }
    Ok(result)
}
