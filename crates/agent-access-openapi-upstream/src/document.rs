//! Bounded source admission, version dispatch and stable discovered identities.
pub(crate) use crate::compile::{valid_status, validate_path};
pub(crate) use crate::model::Plan;
use crate::{config::bounded, model::Dialect, readers, refs};
use agent_access_core::imports::*;
use serde_json::{Value, json};
use std::{collections::BTreeMap, sync::Arc};
const METHODS: [&str; 8] = [
    "get", "put", "post", "delete", "patch", "head", "options", "trace",
];
pub(crate) struct Document {
    pub value: Arc<Value>,
    pub operations: Vec<(String, String)>,
    pub metadata: Value,
    pub version: String,
    counts: BTreeMap<String, usize>,
    dialect: Dialect,
}
impl Document {
    pub fn new(value: Value, definition: &ImportedServiceDefinition) -> Result<Self, String> {
        value
            .as_object()
            .ok_or("definition must be a JSON object")?;
        let (dialect, version) = match (value.get("openapi"), value.get("swagger")) {
            (Some(Value::String(version)), None)
                if version.strip_prefix("3.1.").is_some_and(|patch| {
                    !patch.is_empty() && patch.len() <= 4 && patch.bytes().all(|b| b.is_ascii_digit())
                }) => (Dialect::OpenApi31, version.clone()),
            (None, Some(Value::String(version))) if version == "2.0" => {
                (Dialect::Swagger2, version.clone())
            }
            _ => return Err(
                "definition requires exactly one supported version marker: swagger 2.0 or openapi 3.1.x"
                    .into(),
            ),
        };
        if dialect == Dialect::OpenApi31
            && value.get("jsonSchemaDialect").is_some_and(|v| {
                !matches!(
                    v.as_str(),
                    Some(
                        "https://spec.openapis.org/oas/3.1/dialect/base"
                            | "https://json-schema.org/draft/2020-12/schema"
                    )
                )
            })
        {
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
            let item = if dialect == Dialect::OpenApi31 {
                refs::object(&value, item, "pathItems")?
            } else {
                item.as_object().ok_or("path item must be an object")?;
                item
            };
            if dialect == Dialect::Swagger2
                && item.get("$ref").is_some()
                && !METHODS.iter().any(|method| item.get(*method).is_some())
            {
                return Err("Swagger path-item references are unsupported".into());
            }
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
        let schemes = match dialect {
            Dialect::OpenApi31 => readers::openapi31::security_schemes(&value),
            Dialect::Swagger2 => readers::swagger2::security_schemes(&value),
        };
        let metadata = json!({"openapiVersion":version,"title":text(value.pointer("/info/title"),256),"version":text(value.pointer("/info/version"),256),"apiBaseUrl":definition.endpoint,
            "securitySchemes":schemes.iter().map(|s| { let mut v=json!({"name":s.scheme,"kind":s.kind}); if let Some(header)=&s.header { v["header"]=json!(header); } v }).collect::<Vec<_>>()});
        Ok(Self {
            value: Arc::new(value),
            operations,
            metadata,
            version,
            counts,
            dialect,
        })
    }
    pub fn operation(
        &self,
        definition: &ImportedServiceDefinition,
        path: &str,
        method: &str,
    ) -> ImportedDiscoveredTool {
        let item = if self.dialect == Dialect::OpenApi31 {
            refs::object(&self.value, &self.value["paths"][path], "pathItems")
                .expect("validated path reference")
        } else {
            &self.value["paths"][path]
        };
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
            let normalized = match self.dialect {
                Dialect::OpenApi31 => {
                    readers::openapi31::operation(&self.value, item, operation, definition)
                }
                Dialect::Swagger2 => {
                    readers::swagger2::operation(&self.value, item, operation, definition)
                }
            };
            normalized.and_then(|normalized| {
                crate::compile::operation(
                    &self.value,
                    self.dialect,
                    definition,
                    &normalized,
                    path,
                    method,
                )
            })
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
}
fn text(value: Option<&Value>, max: usize) -> Option<String> {
    value
        .and_then(Value::as_str)
        .filter(|v| bounded(v, max))
        .map(str::to_owned)
}
