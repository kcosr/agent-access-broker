use crate::{
    source::{self, Dialect},
    *,
};
use serde_json::{Value, json};
use std::collections::BTreeMap;

mod bodies;
mod parameters;
mod security;

const METHODS: &[&str] = &[
    "get", "head", "post", "put", "patch", "delete", "options", "trace", "connect",
];

/// Compile one complete Swagger 2.0 or OpenAPI 3.1 JSON document without network access.
/// Unsafe source guards fail the complete refresh; unsupported operations retain denial routes.
pub fn compile_gateway_document(
    bytes: &[u8],
    options: &GatewayCompileOptions,
) -> Result<GatewayCompilation, String> {
    validate_endpoint(&options.endpoint)?;
    validate_endpoint(&options.document_base)?;
    if let GatewayAuthenticationSelection::Static {
        scheme: Some(scheme),
    } = &options.authentication
        && !bounded(scheme, 256)
    {
        return Err("selected gateway security scheme is invalid".into());
    }
    let document =
        decode_bounded_document_json(bytes, GATEWAY_MAX_DOCUMENT_BYTES, GATEWAY_MAX_DEPTH)?;
    let (dialect, version) = Dialect::identify(&document)?;
    let schemes_collection = match dialect {
        Dialect::OpenApi31 => document.pointer("/components/securitySchemes"),
        Dialect::Swagger2 => document.get("securityDefinitions"),
    };
    if schemes_collection.is_some_and(|v| v.as_object().is_none_or(|v| v.len() > 128)) {
        return Err("security schemes must be a bounded object".into());
    }
    let paths = document
        .get("paths")
        .and_then(Value::as_object)
        .ok_or("paths must be an object")?;
    let mut items = BTreeMap::new();
    let mut counts = BTreeMap::new();
    let mut count = 0usize;
    for (path, item) in paths {
        if path.starts_with("x-") {
            continue;
        }
        if items.len() == GATEWAY_MAX_PATHS {
            return Err("gateway source exceeds its path guard limit".into());
        }
        validate_path_template(path)?;
        let item = match dialect {
            Dialect::OpenApi31 => dialect.object(&document, item, "pathItems")?,
            Dialect::Swagger2 => {
                item.as_object().ok_or("path item must be an object")?;
                if item.get("$ref").is_some() {
                    return Err(
                        "Swagger path-item references cannot form safe gateway guards".into(),
                    );
                }
                item
            }
        };
        if item
            .as_object()
            .expect("validated object")
            .keys()
            .any(|key| {
                !METHODS.contains(&key.as_str())
                    && !matches!(
                        key.as_str(),
                        "summary" | "description" | "servers" | "parameters"
                    )
                    && !key.starts_with("x-")
            })
        {
            return Err("path item contains an unsupported routing field".into());
        }
        for method in METHODS {
            if let Some(operation) = item.get(*method) {
                count += 1;
                if count > GATEWAY_MAX_OPERATIONS {
                    return Err("gateway definition exceeds its operation limit".into());
                }
                if let Some(id) = operation
                    .get("operationId")
                    .and_then(Value::as_str)
                    .filter(|v| bounded(v, 256))
                {
                    *counts.entry(id.to_owned()).or_insert(0usize) += 1;
                }
            }
        }
        items.insert(path.clone(), item);
    }
    let schemes = security::schemes(dialect, &document);
    let mut routes = GatewayRouteManifestV1::empty();
    let mut operations = Vec::new();
    let mut manifest_bytes = 0usize;
    for (path, item) in items {
        let mut methods = BTreeMap::new();
        for method in METHODS {
            let Some(operation) = item.get(*method) else {
                continue;
            };
            let id = operation
                .get("operationId")
                .and_then(Value::as_str)
                .filter(|id| counts.get(*id) == Some(&1));
            let source = id
                .map(|id| json!({"operationId":id}))
                .unwrap_or_else(|| json!({"method":method.to_ascii_uppercase(),"path":path}));
            let label = text(operation.get("summary"), 256).or_else(|| id.map(str::to_owned));
            let description = text(operation.get("description"), 16 * 1024)
                .or_else(|| label.clone())
                .unwrap_or_else(|| format!("{} {path}", method.to_ascii_uppercase()));
            let built = if operation.get("operationId").is_some_and(|v| {
                v.as_str()
                    .is_none_or(|id| !bounded(id, 256) || counts.get(id) != Some(&1))
            }) {
                Err("operationId must be a unique bounded string".into())
            } else {
                operation_plan(
                    dialect,
                    &document,
                    item,
                    operation,
                    method,
                    &path,
                    source.clone(),
                    options,
                )
            };
            let (plan, unsupported_reason) = match built {
                Ok(plan) => (Some(plan), None),
                Err(reason) => (None, Some(reason)),
            };
            manifest_bytes = manifest_bytes.saturating_add(
                serde_json::to_vec(&plan)
                    .map_err(|_| "invalid compiled operation")?
                    .len()
                    + description.len()
                    + label.as_ref().map_or(0, String::len)
                    + path.len()
                    + 1024,
            );
            if manifest_bytes > 16 * 1024 * 1024 {
                return Err("gateway discovery exceeds its operation manifest byte limit".into());
            }
            methods.insert(
                method.to_ascii_uppercase(),
                GatewayRouteV1 {
                    source: source.clone(),
                    current: true,
                    supported: plan.is_some(),
                },
            );
            operations.push(GatewayCompiledOperation {
                action: id
                    .map(str::to_owned)
                    .unwrap_or_else(|| format!("{method}_{path}")),
                source,
                label,
                description,
                plan,
                unsupported_reason,
            });
        }
        routes.paths.insert(path, GatewayPathV1 { methods });
    }
    routes.validate()?;
    let metadata = json!({
        "openapiVersion":version,"title":text(document.pointer("/info/title"),256),
        "version":text(document.pointer("/info/version"),256),"apiBaseUrl":options.endpoint,
        "securitySchemes":schemes.iter().map(|s| { let mut value=json!({"name":s.scheme,"kind":s.kind});if let Some(header)=&s.header{value["header"]=json!(header);}value }).collect::<Vec<_>>(),
        "bodyValidation":"none", "templateCoverageNotice":GATEWAY_TEMPLATE_COVERAGE_NOTICE,
    });
    Ok(GatewayCompilation {
        version,
        metadata,
        operations,
        routes,
    })
}

#[allow(clippy::too_many_arguments)]
fn operation_plan(
    dialect: Dialect,
    document: &Value,
    item: &Value,
    operation: &Value,
    method: &str,
    path: &str,
    source: Value,
    options: &GatewayCompileOptions,
) -> Result<GatewayPlanV1, String> {
    operation.as_object().ok_or("operation must be an object")?;
    if matches!(method, "trace" | "connect") {
        return Err("gateway operation method is unsupported".into());
    }
    if operation
        .get("callbacks")
        .is_some_and(|v| v.as_object().is_none_or(|m| !m.is_empty()))
    {
        return Err("callback operations are unsupported".into());
    }
    source::destinations(dialect, document, item, operation, options)?;
    let security = security::select(dialect, document, operation, &options.authentication)?;
    let (parameters, swagger_body) = parameters::parameters(dialect, document, item, operation)?;
    let request_body = bodies::request(dialect, document, operation, swagger_body)?;
    let responses = bodies::responses(dialect, document, operation)?;
    security::reject_credential_parameters(dialect, document, &parameters, &responses)?;
    let plan = GatewayPlanV1 {
        version: 1,
        source,
        method: method.to_ascii_uppercase(),
        path: path.into(),
        security,
        parameters,
        request_body,
        responses,
    };
    plan.validate()?;
    Ok(plan)
}

fn text(value: Option<&Value>, max: usize) -> Option<String> {
    value
        .and_then(Value::as_str)
        .filter(|v| bounded(v, max))
        .map(str::to_owned)
}
