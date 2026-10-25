use crate::{
    config::bounded,
    document::{Plan, valid_status, validate_path},
};
use agent_access_core::imports::*;
use agent_access_provider::*;
use http::{HeaderMap, HeaderName, HeaderValue};
use reqwest::{Method, Response};
use serde_json::{Value, json};
use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;
use url::Url;

const MAX_REQUEST_BYTES: usize = 1024 * 1024;
pub(crate) struct CompiledAction {
    pub definition: ImportedActionDefinition,
    pub plan: Plan,
    input: BoundedImportSchema,
    body: BodyPlan,
    pub responses: BTreeMap<String, Option<BoundedImportSchema>>,
}
pub(crate) struct PreparedRequest {
    pub url: Url,
    pub headers: HeaderMap,
    pub body: Option<(&'static str, Vec<u8>)>,
}
enum BodyPlan {
    None,
    Json,
    FormUrlEncoded(Vec<crate::model::FormField>),
}
impl CompiledAction {
    pub fn new(definition: &ImportedActionDefinition) -> Result<Self, String> {
        if definition.download {
            return Err("OpenAPI imports do not support download actions".into());
        }
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
        if plan.security.kind == "basic"
            && annotations["openapi"]["security"].get("header").is_some()
        {
            return Err("Basic security must not declare a header field".into());
        }
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
        if plan.request_body && matches!(plan.method.as_str(), "GET" | "HEAD" | "OPTIONS") {
            return Err("request bodies on GET, HEAD or OPTIONS are unsupported".into());
        }
        let body = match (&plan.form_body, plan.request_body) {
            (None, false) => BodyPlan::None,
            (None, true) => BodyPlan::Json,
            (Some(_), false) => return Err("formBody requires requestBody".into()),
            (Some(form), true) => {
                let fields = crate::forms::fields(&definition.input_schema)?;
                if form.fields != fields {
                    return Err("form descriptors do not match the closed body schema".into());
                }
                BodyPlan::FormUrlEncoded(fields)
            }
        };
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
                    if crate::readers::openapi31::json_response_media(media) =>
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
            body,
        })
    }
    pub fn request(&self, base: &Url, inputs: &Value) -> Result<PreparedRequest, ProviderError> {
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
                    .map(|value| parameter_scalar(value, &parameter.value_type).map(|s| encode(&s)))
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
            let text = parameter_scalar(value, &parameter.value_type)?;
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
        let body = match (inputs.get("body"), &self.body) {
            (None, _) => None,
            (Some(value), BodyPlan::Json) => Some((
                "application/json",
                serde_json::to_vec(value).map_err(|_| input_error())?,
            )),
            (Some(value), BodyPlan::FormUrlEncoded(fields)) => {
                let mut encoded = String::new();
                for field in fields {
                    let Some(value) = value.get(&field.name) else {
                        continue;
                    };
                    let text = scalar(value, &field.value_type)?;
                    // Append the standard UTF-8 form encoder's fragments directly.
                    // Never allocate an expanded pair larger than the body budget.
                    let separator = usize::from(!encoded.is_empty());
                    for fragment in std::iter::repeat_n("&", separator)
                        .chain(url::form_urlencoded::byte_serialize(field.name.as_bytes()))
                        .chain(std::iter::once("="))
                        .chain(url::form_urlencoded::byte_serialize(text.as_bytes()))
                    {
                        if encoded.len() + fragment.len() > MAX_REQUEST_BYTES {
                            return Err(input_error());
                        }
                        encoded.push_str(fragment);
                    }
                }
                Some(("application/x-www-form-urlencoded", encoded.into_bytes()))
            }
            (Some(_), BodyPlan::None) => return Err(input_error()),
        };
        Ok(PreparedRequest { url, headers, body })
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
    Ok(text)
}
fn parameter_scalar(value: &Value, kind: &str) -> Result<String, ProviderError> {
    let text = scalar(value, kind)?;
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
        UpstreamClientSpec::new(
            "imports.openapi_http",
            "openapi_http",
            endpoint,
            EgressDeclaration::Ordinary(None),
            allowed,
            ClientProfile::SingleAttempt,
        ),
        host.clients(),
    )?))
}
/// The selected static credential in its delivery, checked and presented by the
/// SDK.
pub(crate) fn auth(
    delivery: &ImportedCredentialDelivery,
    credential: &ExecutionCredential,
) -> Result<UpstreamAuthorization, ProviderError> {
    delivery.validate().map_err(|_| credential_error())?;
    let placement = match delivery {
        ImportedCredentialDelivery::Bearer => CredentialPlacement::bearer(),
        ImportedCredentialDelivery::Basic => CredentialPlacement::basic(),
        ImportedCredentialDelivery::RawHeader { name } => {
            crate::config::parameter_header(name).map_err(|_| credential_error())?;
            CredentialPlacement::header(
                HeaderName::from_bytes(name.as_bytes()).map_err(|_| credential_error())?,
            )
        }
        // Stdin delivery belongs to command imports, never to HTTP.
        ImportedCredentialDelivery::Stdin => return Err(credential_error()),
    };
    credential
        .authorization_as(&placement)
        .map_err(|_| credential_error())
}
pub(crate) async fn read_body(response: Response, limit: usize) -> Result<Vec<u8>, ProviderError> {
    read_bounded_body(response, limit as u64, None)
        .await
        .map_err(|error| match error {
            BodyReadError::TooLarge => protocol_error(),
            _ => ProviderError::error(
                ReasonCode::UpstreamConnectionFailed,
                "upstream HTTP body did not complete",
            ),
        })
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
