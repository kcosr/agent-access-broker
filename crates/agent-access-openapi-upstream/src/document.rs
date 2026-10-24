use crate::{
    config::{Settings, bounded},
    refs,
};
use agent_access_core::imports::*;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value, json};
use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;
use url::Url;

const METHODS: [&str; 8] = [
    "get", "put", "post", "delete", "patch", "head", "options", "trace",
];
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct Security {
    pub scheme: String,
    pub kind: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub header: Option<String>,
}
impl Security {
    pub fn delivery(&self) -> Result<ImportedCredentialDelivery, String> {
        match (self.kind.as_str(), self.header.as_ref()) {
            ("bearer", None) => Ok(ImportedCredentialDelivery::Bearer),
            ("raw_header", Some(name)) => {
                let delivery = ImportedCredentialDelivery::RawHeader { name: name.clone() };
                crate::config::parameter_header(name)?;
                Ok(delivery)
            }
            _ => Err("unsupported OpenAPI security mapping".into()),
        }
    }
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct Parameter {
    pub name: String,
    pub location: String,
    pub style: String,
    pub explode: bool,
    pub required: bool,
    pub value_type: String,
    pub array: bool,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct Response {
    pub content_type: Option<String>,
    pub schema: Option<Value>,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct Plan {
    pub method: String,
    pub path: String,
    pub security: Security,
    pub parameters: Vec<Parameter>,
    pub request_body: bool,
    pub responses: BTreeMap<String, Response>,
}

pub(crate) struct Document {
    pub value: Arc<Value>,
    pub operations: Vec<(String, String)>,
    pub metadata: Value,
    pub version: String,
    counts: BTreeMap<String, usize>,
}
impl Document {
    pub fn new(value: Value, definition: &ImportedServiceDefinition) -> Result<Self, String> {
        let version = value
            .get("openapi")
            .and_then(Value::as_str)
            .ok_or("OpenAPI version is missing")?
            .to_owned();
        if !version.strip_prefix("3.1.").is_some_and(|patch| {
            !patch.is_empty() && patch.len() <= 4 && patch.bytes().all(|byte| byte.is_ascii_digit())
        }) {
            return Err("only OpenAPI 3.1.x JSON documents are supported".into());
        }
        if value.get("jsonSchemaDialect").is_some_and(|dialect| {
            !matches!(
                dialect.as_str(),
                Some(
                    "https://spec.openapis.org/oas/3.1/dialect/base"
                        | "https://json-schema.org/draft/2020-12/schema"
                )
            )
        }) {
            return Err("unsupported OpenAPI JSON Schema dialect".into());
        }
        let mut pending = vec![(&value, 0)];
        while let Some((node, depth)) = pending.pop() {
            if depth > IMPORT_MAX_SCHEMA_DEPTH {
                return Err("definition exceeds JSON depth limit".into());
            }
            match node {
                Value::Object(map) => pending.extend(map.values().map(|node| (node, depth + 1))),
                Value::Array(array) => pending.extend(array.iter().map(|node| (node, depth + 1))),
                _ => {}
            }
        }
        let paths = value
            .get("paths")
            .and_then(Value::as_object)
            .ok_or("paths must be an object")?;
        let mut operations = Vec::new();
        let mut counts = BTreeMap::new();
        for (path, item) in paths {
            if path.starts_with("x-") {
                continue;
            }
            let item = refs::object(&value, item, "pathItems")?;
            for method in METHODS {
                if let Some(operation) = item.get(method) {
                    if operations.len() >= 512 {
                        return Err("definition exceeds 512 operations".into());
                    }
                    operations.push((path.clone(), method.to_owned()));
                    if let Some(id) = operation
                        .get("operationId")
                        .and_then(Value::as_str)
                        .filter(|id| bounded(id, 256))
                    {
                        *counts.entry(id.to_owned()).or_insert(0) += 1;
                    }
                }
            }
        }
        let schemes = security_schemes(&value);
        let metadata = json!({"openapiVersion":version,"title":text(value.pointer("/info/title"),256),"version":text(value.pointer("/info/version"),256),"apiBaseUrl":definition.endpoint,
            "securitySchemes":schemes.iter().map(|s| { let mut v=json!({"name":s.scheme,"kind":s.kind}); if let Some(header)=&s.header { v["header"]=json!(header); } v }).collect::<Vec<_>>()});
        Ok(Self {
            value: Arc::new(value),
            operations,
            metadata,
            version,
            counts,
        })
    }
    pub fn operation(
        &self,
        definition: &ImportedServiceDefinition,
        path: &str,
        method: &str,
    ) -> ImportedDiscoveredTool {
        let item = refs::object(&self.value, &self.value["paths"][path], "pathItems")
            .expect("validated path reference");
        let operation = &item[method];
        let id = operation
            .get("operationId")
            .and_then(Value::as_str)
            .filter(|id| self.counts.get(*id) == Some(&1));
        let source = id
            .map(|id| json!({"operationId":id}))
            .unwrap_or_else(|| json!({"method":method.to_ascii_uppercase(),"path":path}));
        let label = text(operation.get("summary"), 256).or_else(|| id.map(str::to_owned));
        let description = text(operation.get("description"), IMPORT_MAX_DESCRIPTION_BYTES)
            .or_else(|| label.clone())
            .unwrap_or_else(|| format!("{} {path}", method.to_ascii_uppercase()));
        let built = if operation.get("operationId").is_some_and(|value| {
            value
                .as_str()
                .is_none_or(|id| !bounded(id, 256) || self.counts.get(id) != Some(&1))
        }) {
            Err("operationId must be a unique bounded string".into())
        } else {
            self.plan(definition, item, operation, path, method)
        };
        let (input_schema, annotations, unsupported_reason) = match built {
            Ok((schema, plan)) => (schema, json!({"openapi":plan}), None),
            Err(reason) => (
                json!({"type":"object","additionalProperties":false}),
                json!({"openapi":{"method":method.to_ascii_uppercase(),"path":path}}),
                Some(reason),
            ),
        };
        let definition = ImportedActionDefinition {
            action: id
                .map(str::to_owned)
                .unwrap_or_else(|| format!("{method}_{path}")),
            source,
            label,
            description,
            input_schema,
            output_schema: None,
            annotations,
            read_only: false,
            download: false,
        };
        ImportedDiscoveredTool {
            definition,
            unsupported_reason,
            read_only_hint: None,
        }
    }
    fn plan(
        &self,
        definition: &ImportedServiceDefinition,
        item: &Value,
        operation: &Value,
        path: &str,
        method: &str,
    ) -> Result<(Value, Plan), String> {
        operation.as_object().ok_or("operation must be an object")?;
        let settings = Settings::parse(definition)?;
        validate_path(path)?;
        if method == "trace" {
            return Err("TRACE operations are unsupported".into());
        }
        if operation
            .get("callbacks")
            .is_some_and(|callbacks| callbacks.as_object().is_none_or(|map| !map.is_empty()))
        {
            return Err("callback operations are unsupported".into());
        }
        validate_servers(
            &self.value,
            item,
            operation,
            &settings.document,
            &definition.endpoint,
        )?;
        let scheme = settings
            .scheme
            .ok_or("select an execution security scheme, save the draft, and refresh discovery")?;
        let security = security_schemes(&self.value)
            .into_iter()
            .find(|candidate| candidate.scheme == scheme)
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
            .get("security")
            .or_else(|| self.value.get("security"))
            .and_then(Value::as_array)
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
            return Err("operation security requires unsupported or combined credentials; a single selected bearer/header-key alternative is required".into());
        }
        let mut effective = BTreeMap::new();
        for level in [item, operation] {
            let Some(parameters) = level.get("parameters") else {
                continue;
            };
            let mut seen = BTreeSet::new();
            for value in parameters.as_array().ok_or("parameters must be an array")? {
                let value = refs::object(&self.value, value, "parameters")?;
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
        if effective.len() > 128 {
            return Err("operation exceeds 128 parameters".into());
        }
        let mut groups: BTreeMap<&str, Map<String, Value>> = BTreeMap::new();
        let mut required: BTreeMap<&str, Vec<Value>> = BTreeMap::new();
        let mut parameters = Vec::new();
        let mut path_parameters = BTreeSet::new();
        for value in effective.values() {
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
            let style =
                value
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
            let resolved = schema_type(&self.value, schema)?;
            let kind = resolved
                .get("type")
                .and_then(Value::as_str)
                .ok_or("parameter must declare a primitive type")?;
            let value_type = if kind == "array" && location == "query" {
                let item = schema_type(
                    &self.value,
                    resolved.get("items").ok_or("query array needs items")?,
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
        let request_body = operation.get("requestBody").is_some();
        if let Some(body) = operation.get("requestBody") {
            if matches!(method, "get" | "head" | "options") {
                return Err("request bodies on GET, HEAD or OPTIONS are unsupported".into());
            }
            let body = refs::object(&self.value, body, "requestBodies")?;
            let media = body
                .pointer("/content/application~1json")
                .ok_or("request body must support application/json")?;
            properties.insert(
                "body".into(),
                media.get("schema").cloned().unwrap_or(json!(true)),
            );
            if body
                .get("required")
                .and_then(Value::as_bool)
                .unwrap_or(false)
            {
                root_required.push(json!("body"));
            }
        }
        let input = refs::schema(
            &self.value,
            json!({"type":"object","properties":properties,"required":root_required,"additionalProperties":false}),
        )?;
        let mut responses = BTreeMap::new();
        for (status, response) in operation
            .get("responses")
            .and_then(Value::as_object)
            .ok_or("responses must be an object")?
        {
            if status.starts_with("x-") {
                continue;
            }
            if !valid_status(status) {
                return Err("invalid response status selector".into());
            }
            let response = refs::object(&self.value, response, "responses")?;
            let spec = if let Some(content) = response.get("content") {
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
                        .or_else(|| {
                            content.iter().find(|(key, _)| {
                                key.starts_with("application/") && key.ends_with("+json")
                            })
                        })
                        .ok_or("response must support JSON or explicitly have no content")?;
                    Response {
                        content_type: Some(media.clone()),
                        schema: Some(refs::schema(
                            &self.value,
                            json!({"allOf":[value.get("schema").cloned().unwrap_or(json!(true))]}),
                        )?),
                    }
                }
            } else {
                Response {
                    content_type: None,
                    schema: None,
                }
            };
            responses.insert(status.clone(), spec);
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
}
fn text(value: Option<&Value>, max: usize) -> Option<String> {
    value
        .and_then(Value::as_str)
        .filter(|v| bounded(v, max))
        .map(str::to_owned)
}
fn primitive(kind: Option<&str>) -> bool {
    matches!(kind, Some("string" | "integer" | "number" | "boolean"))
}
fn schema_type<'a>(document: &'a Value, schema: &'a Value) -> Result<&'a Value, String> {
    refs::object(document, schema, "schemas")
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
fn security_schemes(document: &Value) -> Vec<Security> {
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
fn validate_servers(
    document: &Value,
    item: &Value,
    operation: &Value,
    definition_url: &Url,
    endpoint: &str,
) -> Result<(), String> {
    let endpoint = crate::config::endpoint(endpoint)?;
    let Some(servers) = operation
        .get("servers")
        .or_else(|| item.get("servers"))
        .or_else(|| document.get("servers"))
    else {
        return Ok(());
    };
    let servers = servers.as_array().ok_or("servers must be an array")?;
    if servers.is_empty() {
        return Err(
            "empty server overrides are unsupported; configure an explicit matching server".into(),
        );
    }
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
            && url.as_str().trim_end_matches('/') == endpoint.as_str().trim_end_matches('/')
        {
            return Ok(());
        }
    }
    Err("operation servers do not include the independently approved API base URL".into())
}
