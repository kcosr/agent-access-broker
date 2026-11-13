//! Explicit upstream authentication, independent of document-fetch credentials.
use crate::{
    config::{Settings, bounded},
    model::{Dialect, Operation, Security},
    refs,
};
use serde_json::Value;

pub(crate) fn select(operation: &Operation, settings: &Settings) -> Result<Security, String> {
    // Absence permits anonymous access. A present null (or another malformed
    // value) does not: the readers retain the difference before normalization.
    let requirements = operation
        .security_requirements
        .as_ref()
        .map(|value| {
            value
                .as_array()
                .filter(|v| v.len() <= 64)
                .ok_or("security must be a bounded array of alternatives")
        })
        .transpose()?;
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
    if settings.anonymous {
        if requirements.is_none_or(|v| {
            v.is_empty()
                || v.iter()
                    .any(|v| v.as_object().is_some_and(|v| v.is_empty()))
        }) {
            return Ok(Security::Anonymous {});
        }
        return Err("operation security does not allow anonymous upstream access".into());
    }
    let scheme = settings
        .scheme
        .as_ref()
        .ok_or("select an execution security scheme, save the draft, and refresh discovery")?;
    let security = operation
        .security_schemes
        .iter()
        .find(|candidate| candidate.scheme() == Some(scheme.as_str()))
        .ok_or("selected security scheme is missing or unsupported")?;
    if !requirements.is_some_and(|v| {
        v.iter().any(|requirement| {
            requirement.as_object().is_some_and(|map| {
                map.len() == 1
                    && map
                        .get(scheme)
                        .and_then(Value::as_array)
                        .is_some_and(Vec::is_empty)
            })
        })
    }) {
        return Err("operation security requires unsupported or combined credentials; a single selected Basic/bearer/header-key alternative is required".into());
    }
    Ok(security.clone())
}

/// An anonymous action cannot accept a declared API key as an ordinary input.
pub(crate) fn reject_credential_parameters(
    document: &Value,
    dialect: Dialect,
    parameters: &[Value],
) -> Result<(), String> {
    let schemes = match dialect {
        Dialect::OpenApi31 => document.pointer("/components/securitySchemes"),
        Dialect::Swagger2 => document.get("securityDefinitions"),
    };
    for (_, scheme) in schemes.and_then(Value::as_object).into_iter().flatten() {
        let scheme = match dialect {
            Dialect::OpenApi31 => match refs::object(document, scheme, "securitySchemes") {
                Ok(value) => value,
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
        if parameters.iter().any(|parameter| {
            parameter["in"].as_str() == Some(location)
                && parameter["name"].as_str().is_some_and(|input| {
                    if location == "header" {
                        input.eq_ignore_ascii_case(name)
                    } else {
                        input == name
                    }
                })
        }) {
            return Err(
                "anonymous operation parameter conflicts with a source credential carrier".into(),
            );
        }
    }
    Ok(())
}
