use crate::{
    config::bounded,
    document::{Plan, valid_status, validate_path},
};
use agent_access_core::imports::*;
use agent_access_provider::*;
use futures_util::StreamExt;
use http::{HeaderMap, HeaderName, HeaderValue};
use reqwest::{Method, Response};
use serde_json::{Value, json};
use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;
use url::Url;

pub(crate) const MAX_DOCUMENT_BYTES: usize = 4 * 1024 * 1024;
const MAX_REQUEST_BYTES: usize = 1024 * 1024;
pub(crate) struct CompiledAction {
    pub definition: ImportedActionDefinition,
    pub plan: Plan,
    input: BoundedImportSchema,
    pub responses: BTreeMap<String, Option<BoundedImportSchema>>,
}
impl CompiledAction {
    pub fn new(definition: &ImportedActionDefinition) -> Result<Self, String> {
        if serde_json::to_vec(definition)
            .map_err(|_| "invalid action")?
            .len()
            > IMPORT_MAX_TOOL_BYTES
        {
            return Err("action exceeds import size limit".into());
        }
        let annotations = definition
            .annotations
            .as_object()
            .filter(|map| map.len() == 1)
            .ok_or("OpenAPI action annotations must contain only the execution plan")?;
        let plan: Plan = serde_json::from_value(
            annotations
                .get("openapi")
                .ok_or("OpenAPI execution plan is missing")?
                .clone(),
        )
        .map_err(|_| "OpenAPI execution plan is invalid")?;
        if !matches!(
            plan.method.as_str(),
            "GET" | "POST" | "PUT" | "PATCH" | "DELETE" | "HEAD" | "OPTIONS"
        ) {
            return Err("unsupported HTTP method".into());
        }
        let path_variables = validate_path(&plan.path)?;
        if !bounded(&plan.security.scheme, 256) {
            return Err("invalid execution security scheme".into());
        }
        plan.security.delivery()?;
        let source = definition
            .source
            .as_object()
            .ok_or("operation source must be an object")?;
        if !(source.len() == 1
            && source
                .get("operationId")
                .and_then(Value::as_str)
                .is_some_and(|s| bounded(s, 256)))
            && !(source.len() == 2
                && source.get("method") == Some(&json!(plan.method))
                && source.get("path") == Some(&json!(plan.path)))
        {
            return Err("operation source does not identify the accepted operation".into());
        }
        if definition.input_schema.get("type").and_then(Value::as_str) != Some("object")
            || plan.parameters.len() > 128
        {
            return Err("operation inputs must be a bounded object".into());
        }
        let mut names = BTreeSet::new();
        let mut paths = BTreeSet::new();
        for parameter in &plan.parameters {
            if !bounded(&parameter.name, 256)
                || !matches!(
                    parameter.value_type.as_str(),
                    "string" | "boolean" | "number" | "integer"
                )
            {
                return Err("invalid parameter contract".into());
            }
            let group = match parameter.location.as_str() {
                "path" => {
                    if !parameter.required {
                        return Err("path variables must be required".into());
                    }
                    paths.insert(parameter.name.clone());
                    "path"
                }
                "query" => "query",
                "header" => {
                    crate::config::parameter_header(&parameter.name)?;
                    if plan
                        .security
                        .header
                        .as_ref()
                        .is_some_and(|header| header.eq_ignore_ascii_case(&parameter.name))
                    {
                        return Err("parameter collides with credential header".into());
                    }
                    "headers"
                }
                _ => return Err("invalid parameter location".into()),
            };
            if parameter.style != if group == "query" { "form" } else { "simple" }
                || (parameter.array && group != "query")
            {
                return Err("unsupported serialization contract".into());
            }
            let name = if group == "headers" {
                parameter.name.to_ascii_lowercase()
            } else {
                parameter.name.clone()
            };
            if !names.insert((group, name))
                || definition
                    .input_schema
                    .get("properties")
                    .and_then(|v| v.get(group))
                    .and_then(|v| v.get("properties"))
                    .and_then(|v| v.get(&parameter.name))
                    .is_none()
            {
                return Err("parameter contract does not match input schema".into());
            }
        }
        if paths != path_variables {
            return Err("path variable contract mismatch".into());
        }
        if plan.request_body
            != definition
                .input_schema
                .get("properties")
                .is_some_and(|v| v.get("body").is_some())
        {
            return Err("request body contract mismatch".into());
        }
        if plan.responses.is_empty() || plan.responses.len() > 64 {
            return Err("response contract exceeds supported bounds".into());
        }
        let mut responses = BTreeMap::new();
        for (status, response) in &plan.responses {
            if !valid_status(status) {
                return Err("invalid response status".into());
            }
            let compiled = match (&response.content_type, &response.schema) {
                (None, None) => None,
                (Some(media), Some(schema))
                    if media == "application/json"
                        || (media.starts_with("application/")
                            && media.ends_with("+json")
                            && bounded(media, 128)) =>
                {
                    Some(BoundedImportSchema::compile(schema)?)
                }
                _ => return Err("unsupported response media contract".into()),
            };
            responses.insert(status.clone(), compiled);
        }
        Ok(Self {
            definition: definition.clone(),
            plan,
            input: BoundedImportSchema::compile(&definition.input_schema)?,
            responses,
        })
    }
    pub fn request(&self, base: &Url, inputs: &Value) -> Result<(Url, HeaderMap), ProviderError> {
        if !self.input.is_valid(inputs)
            || serde_json::to_vec(inputs).map_err(|_| input_error())?.len() > MAX_REQUEST_BYTES
        {
            return Err(input_error());
        }
        let mut path = self.plan.path.clone();
        let mut query = Vec::new();
        let mut headers = HeaderMap::new();
        for parameter in &self.plan.parameters {
            let group = if parameter.location == "header" {
                "headers"
            } else {
                &parameter.location
            };
            let Some(value) = inputs.get(group).and_then(|v| v.get(&parameter.name)) else {
                if parameter.required {
                    return Err(input_error());
                } else {
                    continue;
                }
            };
            if parameter.array {
                let values = value.as_array().ok_or_else(input_error)?;
                if values.len() > 256 {
                    return Err(input_error());
                }
                let values = values
                    .iter()
                    .map(|value| scalar(value, &parameter.value_type).map(|s| encode(&s)))
                    .collect::<Result<Vec<_>, _>>()?;
                if parameter.explode {
                    for value in values {
                        query.push(format!("{}={value}", encode(&parameter.name)));
                    }
                } else {
                    query.push(format!("{}={}", encode(&parameter.name), values.join(",")));
                }
                continue;
            }
            let text = scalar(value, &parameter.value_type)?;
            match parameter.location.as_str() {
                "path" => {
                    if text.is_empty()
                        || text.contains(['/', '\\', '%'])
                        || matches!(text.as_str(), "." | "..")
                    {
                        return Err(input_error());
                    }
                    path = path.replace(&format!("{{{}}}", parameter.name), &encode(&text));
                }
                "query" => query.push(format!("{}={}", encode(&parameter.name), encode(&text))),
                "header" => {
                    if !text.bytes().all(|byte| (0x20..=0x7e).contains(&byte)) {
                        return Err(input_error());
                    }
                    let mut value = HeaderValue::from_str(&text).map_err(|_| input_error())?;
                    value.set_sensitive(true);
                    headers.insert(
                        HeaderName::from_bytes(parameter.name.as_bytes())
                            .map_err(|_| input_error())?,
                        value,
                    );
                }
                _ => return Err(input_error()),
            }
        }
        let raw = format!(
            "{}{}{}",
            base.as_str().trim_end_matches('/'),
            path,
            if query.is_empty() {
                String::new()
            } else {
                format!("?{}", query.join("&"))
            }
        );
        if raw.len() > 8192 {
            return Err(input_error());
        }
        let url = Url::parse(&raw).map_err(|_| input_error())?;
        let prefix = format!("{}/", base.path().trim_end_matches('/'));
        if url.origin() != base.origin() || !url.path().starts_with(&prefix) {
            return Err(input_error());
        }
        Ok((url, headers))
    }
}
fn scalar(value: &Value, kind: &str) -> Result<String, ProviderError> {
    let text = match (kind, value) {
        ("string", Value::String(value)) => value.clone(),
        ("boolean", Value::Bool(value)) => value.to_string(),
        ("number", Value::Number(value)) => value.to_string(),
        ("integer", Value::Number(value)) => {
            if let Some(value) = value.as_i64() {
                value.to_string()
            } else if let Some(value) = value.as_u64() {
                value.to_string()
            } else {
                let value = value
                    .as_f64()
                    .filter(|n| n.fract() == 0.0 && n.abs() <= 9_007_199_254_740_991.0)
                    .ok_or_else(input_error)?;
                format!("{value:.0}")
            }
        }
        _ => return Err(input_error()),
    };
    if text.len() > 4096 || text.chars().any(char::is_control) {
        return Err(input_error());
    }
    Ok(text)
}
fn encode(text: &str) -> String {
    let mut encoded = String::new();
    for byte in text.bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~') {
            encoded.push(char::from(byte));
        } else {
            use std::fmt::Write;
            write!(&mut encoded, "%{byte:02X}").expect("String write");
        }
    }
    encoded
}
pub(crate) fn client(
    endpoint: &Url,
    allowed: &[String],
    host: &BuildContext<'_>,
) -> Result<Arc<UpstreamClient>, ProviderBuildError> {
    Ok(Arc::new(UpstreamClient::build(
        UpstreamClientSpec {
            label: "imports.openapi_http",
            provider: "openapi_http",
            base: endpoint,
            egress: EgressDeclaration::Ordinary(None),
            allowed_upstream_hosts: allowed,
            profile: ClientProfile::SingleAttempt,
            status_reasons: &[],
        },
        host.clients(),
    )?))
}
pub(crate) fn auth(
    delivery: &ImportedCredentialDelivery,
    credential: &ExecutionCredential,
) -> Result<HeaderMap, ProviderError> {
    delivery.validate().map_err(|_| credential_error())?;
    if let ImportedCredentialDelivery::RawHeader { name } = delivery {
        crate::config::parameter_header(name).map_err(|_| credential_error())?;
    }
    let token = match credential.view() {
        CredentialView::Bearer { token }
            if !token.is_empty()
                && token.len() <= 32768
                && token.bytes().all(|b| (0x21..=0x7e).contains(&b)) =>
        {
            token
        }
        CredentialView::Bearer { .. } | CredentialView::Basic { .. } => {
            return Err(credential_error());
        }
    };
    let (name, text) = match delivery {
        ImportedCredentialDelivery::Bearer => (
            HeaderName::from_static("authorization"),
            format!("Bearer {token}"),
        ),
        ImportedCredentialDelivery::RawHeader { name } => (
            HeaderName::from_bytes(name.as_bytes()).map_err(|_| credential_error())?,
            token.to_owned(),
        ),
    };
    let mut value = HeaderValue::from_str(&text).map_err(|_| credential_error())?;
    value.set_sensitive(true);
    Ok(HeaderMap::from_iter([(name, value)]))
}
pub(crate) async fn read_body(response: Response, limit: usize) -> Result<Vec<u8>, ProviderError> {
    if response.content_length().is_some_and(|n| n > limit as u64) {
        return Err(protocol_error());
    }
    let mut bytes = Vec::new();
    let mut stream = response.bytes_stream();
    while let Some(chunk) = stream.next().await {
        let chunk = chunk.map_err(|_| {
            ProviderError::error(
                ReasonCode::UpstreamConnectionFailed,
                "upstream HTTP body did not complete",
            )
        })?;
        if bytes.len().saturating_add(chunk.len()) > limit {
            return Err(protocol_error());
        }
        bytes.extend_from_slice(&chunk);
    }
    Ok(bytes)
}
pub(crate) fn input_error() -> ProviderError {
    ProviderError::deny(
        ReasonCode::InputInvalid,
        "inputs do not match the accepted OpenAPI operation",
    )
}
pub(crate) fn credential_error() -> ProviderError {
    ProviderError::deny(
        ReasonCode::CredentialInvalid,
        "OpenAPI operation requires its selected static token credential",
    )
}
pub(crate) fn protocol_error() -> ProviderError {
    ProviderError::error(
        ReasonCode::UpstreamProtocolFailed,
        "upstream HTTP response does not match the accepted OpenAPI contract",
    )
}
pub(crate) fn method(plan: &Plan) -> Method {
    Method::from_bytes(plan.method.as_bytes()).expect("validated method")
}
