use crate::{
    GATEWAY_COMMON_REQUEST_HEADERS, GatewayAuthenticationSelection, GatewaySecurityV1, bounded,
    source::Dialect, validate_declared_header,
};
use serde_json::Value;
use std::collections::BTreeMap;

pub(super) fn schemes(dialect: Dialect, document: &Value) -> Vec<GatewaySecurityV1> {
    let values = match dialect {
        Dialect::OpenApi31 => document.pointer("/components/securitySchemes"),
        Dialect::Swagger2 => document.get("securityDefinitions"),
    };
    values
        .and_then(Value::as_object)
        .into_iter()
        .flatten()
        .filter_map(|(name, value)| scheme(dialect, document, name, value).ok())
        .collect()
}

/// Source-declared credential carriers remain reserved even when an anonymous alternative is selected.
pub(super) fn reject_credential_parameters(
    dialect: Dialect,
    document: &Value,
    parameters: &[crate::GatewayParameterV1],
    responses: &BTreeMap<String, crate::GatewayResponseV1>,
) -> Result<(), String> {
    let collection = match dialect {
        Dialect::OpenApi31 => document.pointer("/components/securitySchemes"),
        Dialect::Swagger2 => document.get("securityDefinitions"),
    };
    for (_, scheme) in collection.and_then(Value::as_object).into_iter().flatten() {
        let scheme = match dialect {
            Dialect::OpenApi31 => match dialect.object(document, scheme, "securitySchemes") {
                Ok(scheme) => scheme,
                Err(_) => continue,
            },
            Dialect::Swagger2 => scheme,
        };
        if scheme.get("type").and_then(Value::as_str) != Some("apiKey") {
            continue;
        }
        let (Some(location), Some(name)) = (
            scheme.get("in").and_then(Value::as_str),
            scheme.get("name").and_then(Value::as_str),
        ) else {
            continue;
        };
        let conflict = parameters.iter().any(|parameter| {
            parameter.location == location
                && if location == "header" {
                    parameter.name.eq_ignore_ascii_case(name)
                } else {
                    parameter.name == name
                }
        });
        if conflict
            || location == "header"
                && responses.values().any(|response| {
                    response
                        .headers
                        .iter()
                        .any(|header| header.name.eq_ignore_ascii_case(name))
                })
        {
            return Err("declared gateway parameter or response header conflicts with a source credential carrier".into());
        }
    }
    Ok(())
}

fn scheme(
    dialect: Dialect,
    document: &Value,
    name: &str,
    value: &Value,
) -> Result<GatewaySecurityV1, String> {
    if !bounded(name, 256) {
        return Err("security scheme name is invalid".into());
    }
    let value = match dialect {
        Dialect::OpenApi31 => dialect.object(document, value, "securitySchemes")?,
        Dialect::Swagger2 => value,
    };
    let (kind, header) = match (
        dialect,
        value.get("type").and_then(Value::as_str),
        value.get("scheme").and_then(Value::as_str),
        value.get("in").and_then(Value::as_str),
    ) {
        (Dialect::Swagger2, Some("basic"), _, _) => ("basic", None),
        (Dialect::OpenApi31, Some("http"), Some(scheme), _)
            if scheme.eq_ignore_ascii_case("basic") =>
        {
            ("basic", None)
        }
        (Dialect::OpenApi31, Some("http"), Some(scheme), _)
            if scheme.eq_ignore_ascii_case("bearer") =>
        {
            ("bearer", None)
        }
        (_, Some("apiKey"), _, Some("header")) => {
            let header = value
                .get("name")
                .and_then(Value::as_str)
                .ok_or("header API key requires a header name")?;
            validate_declared_header(header)?;
            if GATEWAY_COMMON_REQUEST_HEADERS.contains(&header.to_ascii_lowercase().as_str()) {
                return Err("credential header conflicts with a common protocol header".into());
            }
            ("raw_header", Some(header.to_owned()))
        }
        _ => {
            return Err(
                "gateway supports static Basic, Bearer and header API-key schemes only".into(),
            );
        }
    };
    Ok(GatewaySecurityV1 {
        kind: kind.into(),
        scheme: Some(name.into()),
        header,
    })
}

pub(super) fn select(
    dialect: Dialect,
    document: &Value,
    operation: &Value,
    selection: &GatewayAuthenticationSelection,
) -> Result<GatewaySecurityV1, String> {
    let requirements = operation
        .get("security")
        .or_else(|| document.get("security"));
    let requirements = match requirements {
        None => None,
        Some(value) => Some(
            value
                .as_array()
                .filter(|v| v.len() <= 64)
                .ok_or("security must be a bounded array of alternatives")?,
        ),
    };
    if let Some(requirements) = requirements {
        for alternative in requirements {
            let alternative = alternative
                .as_object()
                .filter(|v| v.len() <= 16)
                .ok_or("security alternative must be a bounded object")?;
            for (name, scopes) in alternative {
                if !bounded(name, 256)
                    || scopes.as_array().is_none_or(|v| {
                        v.len() > 64
                            || v.iter()
                                .any(|v| v.as_str().is_none_or(|v| !bounded(v, 256)))
                    })
                {
                    return Err("security alternative has invalid names or scopes".into());
                }
            }
        }
    }
    match selection {
        GatewayAuthenticationSelection::Anonymous => {
            if requirements.is_none_or(|v| {
                v.is_empty()
                    || v.iter()
                        .any(|v| v.as_object().is_some_and(|m| m.is_empty()))
            }) {
                Ok(GatewaySecurityV1 {
                    kind: "anonymous".into(),
                    scheme: None,
                    header: None,
                })
            } else {
                Err("operation security does not allow anonymous upstream access".into())
            }
        }
        GatewayAuthenticationSelection::Static { scheme: None } => Err(
            "select a supported static security scheme before accepting gateway operations".into(),
        ),
        GatewayAuthenticationSelection::Static { scheme: Some(name) } => {
            if !requirements.is_some_and(|v| {
                v.iter().any(|alternative| {
                    alternative.as_object().is_some_and(|m| {
                        m.len() == 1
                            && m.get(name)
                                .and_then(Value::as_array)
                                .is_some_and(Vec::is_empty)
                    })
                })
            }) {
                return Err(
                    "selected static scheme is not a supported single-scheme operation alternative"
                        .into(),
                );
            }
            schemes(dialect, document)
                .into_iter()
                .find(|v| v.scheme.as_ref() == Some(name))
                .ok_or_else(|| "selected operation security scheme is unsupported".into())
        }
    }
}
