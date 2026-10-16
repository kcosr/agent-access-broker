use crate::ExecutionContext;
use agent_access_provider::{
    ActionDescriptor, ActionIo, MultipartUploadSpec, RESULT_METADATA_HEADER, ServiceDescriptor,
    ServiceSurface, is_action_name, is_service_name,
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::collections::{BTreeMap, BTreeSet};
mod imports;
mod schema_refs;
pub(crate) use schema_refs::relocate_local_schema_refs;

pub const API_CATALOG_VERSION: &str = "agent-access.catalog.v2";
pub const SEND_SCHEMA_VERSION: &str = "agent-access.send.v1";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct ApiCatalog {
    pub version: String,
    pub identity: Value,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub execution_context: Option<ExecutionContext>,
    /// Every resource type this broker understands, whether or not a visible
    /// service uses it.
    #[serde(default)]
    pub resource_types: Vec<agent_access_provider::ResourceTypeMetadata>,
    pub services: Vec<ApiServiceSpec>,
    pub routes: Vec<HttpRouteSpec>,
    pub send: SendCatalogSpec,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct SendCatalogSpec {
    pub version: String,
    pub catalog_required: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct ApiServiceSpec {
    /// Present for caller discovery; absent from the administrative catalog.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub availability: Option<crate::ServiceAvailability>,
    pub scoped_mcp_ready: bool,
    pub service: String,
    pub display_name: String,
    pub surface: String,
    pub scope_types: Vec<String>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub resource_scopes: BTreeMap<String, ApiResourceScopeSpec>,
    pub actions: Vec<ApiActionSpec>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct ApiResourceScopeSpec {
    pub resource_type: agent_access_provider::ResourceType,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub selectors: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct ApiActionSpec {
    /// Required even when null. Missing metadata is a catalog contract error.
    #[serde(deserialize_with = "required_nullable_name")]
    pub scoped_mcp_name: Option<String>,
    pub action: String,
    /// Provider-declared read semantics; never inferred from the action name.
    pub read_only: bool,
    pub description: String,
    /// Extended usage details, omitted from MCP tools/list definitions.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub documentation: Option<Value>,
    pub required_scope_types: Vec<String>,
    pub credential_modes: Vec<String>,
    #[serde(default)]
    pub lookup_required: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub upstream_resource_ownership: Option<agent_access_provider::UpstreamResourceOwnership>,
    pub input_schema: Value,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub sensitive_input_pointers: Vec<String>,
    /// JSON pointers into sensitive values, including secret exports and opaque imported payloads.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub sensitive_output_pointers: Vec<String>,
    pub io: ActionIo,
    pub response_kind: ResponseKind,
    pub exit_policy: ExitPolicy,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub read_content_formats: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub response_formats: Vec<String>,
    /// JSON pointers into the response envelope to the objects that carry a
    /// `renderedBody` companion under a non-native `readContentFormat`; a `*`
    /// segment matches every element of an array.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub rendered_body_owners: Vec<String>,
}

fn required_nullable_name<'de, D>(deserializer: D) -> Result<Option<String>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    Option::<String>::deserialize(deserializer)
}

/// Whether this host serves `io`: JSON, multipart uploads and raw downloads.
/// An action with any other I/O kind is never published or admitted.
pub(crate) fn supported_action_io(io: &ActionIo) -> bool {
    matches!(
        io,
        ActionIo::Json | ActionIo::MultipartUpload { .. } | ActionIo::RawDownload { .. }
    )
}

impl ApiActionSpec {
    /// Whether this build serves the action's I/O kind; see
    /// [`supported_action_io`]. Clients refuse any other kind.
    pub fn supports_io(&self) -> bool {
        supported_action_io(&self.io)
    }

    /// JSON responses can be saved locally without changing execution permissions or bounds.
    pub fn supports_json_file_output(&self) -> bool {
        matches!(self.io, ActionIo::Json | ActionIo::MultipartUpload { .. })
    }

    /// Local destinations support JSON responses and dedicated raw downloads.
    pub fn supports_file_output(&self) -> bool {
        self.supports_json_file_output() || matches!(self.io, ActionIo::RawDownload { .. })
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ResponseKind {
    RawJson,
    ResponseEnvelope,
    ManagementEnvelope,
    AuthEnvelope,
    RawStream,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ExitPolicy {
    HttpStatus,
    InvokeDecision,
    ManagementOk,
    RawStream,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct HttpRouteSpec {
    pub method: String,
    pub route: String,
    pub operation: String,
    pub access: RouteAccess,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub path_params: Vec<RouteParamSpec>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub query_params: Vec<RouteParamSpec>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub request_body_schema: Option<Value>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub sensitive_request_pointers: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub sensitive_response_pointers: Vec<String>,
    pub response_kind: ResponseKind,
    pub exit_policy: ExitPolicy,
    #[serde(default)]
    pub body_allowed: bool,
    #[serde(default)]
    pub null_body_allowed: bool,
    /// A runtime feature the route needs. The caller-filtered catalog, and
    /// so the OpenAPI projection and send schema, omit the route when this
    /// broker's configuration does not provide the feature.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub required_feature: Option<RouteFeature>,
    /// The typed `result` of a successful management envelope, when the
    /// route documents one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub result_schema: Option<Value>,
}

/// Runtime features a route can require (see
/// [`HttpRouteSpec::required_feature`]).
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum RouteFeature {
    /// Audit queries: management is enabled and `audit.type = "sqlite"`.
    AuditQuery,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct RouteParamSpec {
    pub name: String,
    #[serde(default)]
    pub required: bool,
    #[serde(default = "string_schema")]
    pub schema: Value,
}

fn string_schema() -> Value {
    json!({ "type": "string" })
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum RouteAccess {
    Authenticated,
    AgentInvoke,
    UserManagement,
    BrowserManagement,
    UserTokenManagement,
    PolicyRead,
    PolicyWrite,
    AdminRead,
    AdminWrite,
    Spec,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum RenderAuthMode {
    Include,
    Omit,
}

pub fn empty_catalog(identity: Value) -> ApiCatalog {
    ApiCatalog {
        version: API_CATALOG_VERSION.to_string(),
        identity,
        execution_context: None,
        resource_types: Vec::new(),
        services: Vec::new(),
        routes: Vec::new(),
        send: SendCatalogSpec {
            version: SEND_SCHEMA_VERSION.to_string(),
            catalog_required: true,
        },
    }
}

/// Projects an invoke service descriptor into its runtime-catalog entry.
/// Gateway services are not invocable through the catalog.
pub fn api_service_spec(
    descriptor: &ServiceDescriptor,
    scoped_mcp_ready: bool,
) -> Option<ApiServiceSpec> {
    if !matches!(descriptor.surface, ServiceSurface::Invoke) {
        return None;
    }
    let actions = descriptor
        .actions
        .iter()
        .filter_map(|action| api_action_spec(&descriptor.service, action))
        .collect::<Vec<_>>();
    Some(ApiServiceSpec {
        availability: None,
        scoped_mcp_ready,
        service: descriptor.service.clone(),
        display_name: descriptor.display_name.clone(),
        surface: "invoke".to_string(),
        scope_types: descriptor.resource_scopes.keys().cloned().collect(),
        resource_scopes: descriptor
            .resource_scopes
            .iter()
            .map(|(name, scope)| {
                (
                    name.clone(),
                    ApiResourceScopeSpec {
                        resource_type: scope.resource_type.clone(),
                        selectors: scope.selectors.clone(),
                    },
                )
            })
            .collect(),
        actions,
    })
}

fn api_action_spec(service: &str, action: &ActionDescriptor) -> Option<ApiActionSpec> {
    if !is_service_name(service) || !is_action_name(&action.action) {
        return None;
    }
    let io = action.io.clone();
    let (response_kind, exit_policy) = match io {
        ActionIo::Json | ActionIo::MultipartUpload { .. } => {
            (ResponseKind::ResponseEnvelope, ExitPolicy::InvokeDecision)
        }
        ActionIo::RawDownload { .. } => (ResponseKind::RawStream, ExitPolicy::RawStream),
        // An I/O kind this host does not serve is never published.
        _ => return None,
    };
    let sensitive_input_pointers = sensitive_input_pointers_from_schema(&action.input_schema);
    let response_capabilities =
        agent_access_provider::presentation::response_capabilities(action.presentation.as_ref());
    let mut rendered_body_owners = Vec::new();
    for body in action
        .presentation
        .iter()
        .flat_map(|presentation| presentation.embedded_bodies())
    {
        let pointer = format!("/result{}", body.owner_pointer());
        if !rendered_body_owners.contains(&pointer) {
            rendered_body_owners.push(pointer);
        }
    }
    Some(ApiActionSpec {
        scoped_mcp_name: action
            .raw_scoped_mcp_name()
            .filter(|name| crate::mcp::valid_scoped_name(name))
            .map(str::to_owned),
        action: action.action.clone(),
        read_only: action.read_only,
        description: action.description.clone(),
        documentation: action.documentation.clone(),
        required_scope_types: action.required_scope_types(),
        credential_modes: action.credential_modes.clone(),
        lookup_required: action.lookup.credential_required(),
        upstream_resource_ownership: action.upstream_resource_ownership,
        input_schema: action.input_schema.clone(),
        sensitive_input_pointers,
        sensitive_output_pointers: action.sensitive_output_pointers.clone(),
        io,
        response_kind,
        exit_policy,
        read_content_formats: response_capabilities
            .read_content_formats
            .unwrap_or_default()
            .iter()
            .map(|format| (*format).to_string())
            .collect(),
        response_formats: response_capabilities
            .response_formats
            .unwrap_or_default()
            .iter()
            .map(|format| (*format).to_string())
            .collect(),
        rendered_body_owners,
    })
}

fn sensitive_input_pointers_from_schema(input_schema: &Value) -> Vec<String> {
    let mut pointers = BTreeSet::new();
    collect_sensitive_schema_pointers(input_schema, "/inputs", &mut pointers);

    // Configured HTTP actions historically infer sensitive request headers from
    // their names. Keep that behavior in addition to explicit schema metadata.
    if let Some(headers) = input_schema
        .pointer("/properties/headers/properties")
        .and_then(Value::as_object)
    {
        pointers.extend(
            headers
                .keys()
                .filter(|header| sensitive_header_name(header))
                .map(|header| format!("/inputs/headers/{}", json_pointer_escape(header))),
        );
    }

    pointers.into_iter().collect()
}

fn collect_sensitive_schema_pointers(
    schema: &Value,
    pointer: &str,
    pointers: &mut BTreeSet<String>,
) -> bool {
    if schema
        .get("x-agent-access-sensitive")
        .and_then(Value::as_bool)
        == Some(true)
    {
        pointers.insert(pointer.to_string());
        return true;
    }

    let mut contains_sensitive = false;
    if let Some(properties) = schema.get("properties").and_then(Value::as_object) {
        for (name, property) in properties {
            let child_pointer = format!("{pointer}/{}", json_pointer_escape(name));
            contains_sensitive |=
                collect_sensitive_schema_pointers(property, &child_pointer, pointers);
        }
    }

    if let Some(items) = schema.get("items") {
        // A catalog pointer must address the request before its runtime array
        // indices are known. If an item contains sensitive material, mark the
        // whole array so secret-source authorization covers every descendant.
        let mut item_pointers = BTreeSet::new();
        if collect_sensitive_schema_pointers(items, pointer, &mut item_pointers) {
            pointers.insert(pointer.to_string());
            contains_sensitive = true;
        }
    }

    contains_sensitive
}

fn sensitive_header_name(header: &str) -> bool {
    let normalized = header.to_ascii_lowercase();
    normalized == "authorization"
        || normalized == "cookie"
        || normalized == "private-token"
        || normalized.contains("api-key")
        || normalized.contains("apikey")
        || normalized.contains("auth-token")
        || normalized.contains("token")
        || normalized.contains("key")
        || normalized.contains("private")
        || normalized.contains("password")
        || normalized.contains("passwd")
        || normalized.contains("pwd")
        || normalized.contains("credential")
        || normalized.contains("cred")
        || normalized.contains("bearer")
        || normalized.contains("session")
        || normalized.contains("auth")
        || normalized.contains("secret")
}

fn json_pointer_escape(value: &str) -> String {
    value.replace('~', "~0").replace('/', "~1")
}

pub fn openapi_from_catalog(
    catalog: &ApiCatalog,
    auth: RenderAuthMode,
    identity_headers: &[String],
    browser_cookie_name: &str,
) -> Value {
    let resource_type_ids = catalog
        .resource_types
        .iter()
        .map(|resource_type| resource_type.id.as_str().to_string())
        .collect::<Vec<_>>();
    let mut paths = serde_json::Map::new();
    for service in &catalog.services {
        for action in &service.actions {
            let path = format!("/v1/invoke/{}/{}", service.service, action.action);
            let (media, schema_path) = match &action.io {
                ActionIo::MultipartUpload { .. } => (
                    "multipart/form-data",
                    "/schema/properties/request/contentSchema/properties/inputs",
                ),
                ActionIo::Json | ActionIo::RawDownload { .. } => {
                    ("application/json", "/schema/properties/inputs")
                }
                // An I/O kind this host does not serve gets no operation.
                _ => continue,
            };
            let mut request_content = action_request_body_content(action);
            if let Some(inputs) = request_content
                .get_mut(media)
                .and_then(|content| content.pointer_mut(schema_path))
            {
                relocate_local_schema_refs(
                    inputs,
                    &format!(
                        "#/paths/{}/post/requestBody/content/{}{schema_path}",
                        json_pointer_escape(&path),
                        json_pointer_escape(media)
                    ),
                );
            }
            let mut responses = json!({
                "200": {
                    "description": "Broker response",
                    "content": {
                        "application/json": {
                            "schema": envelope_schema(action.response_kind)
                        }
                    }
                }
            });
            if matches!(action.io, ActionIo::RawDownload { .. }) {
                responses = json!({
                    "200": {
                        "description": "Raw download stream",
                        "headers": {
                            RESULT_METADATA_HEADER: {
                                "description": "Base64-encoded JSON ResponseEnvelope metadata",
                                "schema": { "type": "string" }
                            }
                        },
                        "content": {
                            "application/octet-stream": {
                                "schema": { "type": "string", "format": "binary" }
                            }
                        }
                    },
                    "4XX": {
                        "description": "Broker error envelope",
                        "content": {
                            "application/json": {
                                "schema": envelope_schema(ResponseKind::ResponseEnvelope)
                            }
                        }
                    }
                });
            }
            let mut operation = json!({
                "post": {
                    "operationId": format!("invoke.{}.{}", service.service, action.action),
                    "x-agent-access-read-only": action.read_only,
                    "x-agent-access-sensitive-output-pointers": action.sensitive_output_pointers,
                    "requestBody": {
                        "required": true,
                        "content": request_content
                    },
                    "responses": responses
                }
            });
            if let Some(documentation) = &action.documentation {
                operation["post"]["x-agent-access-documentation"] = documentation.clone();
            }
            operation["post"]["description"] = json!(action.description);
            paths.insert(path, operation);
        }
    }
    for route in &catalog.routes {
        let method = route.method.to_ascii_lowercase();
        let entry = paths
            .entry(route.route.clone())
            .or_insert_with(|| json!({}));
        if let Value::Object(object) = entry {
            let mut operation = serde_json::Map::from_iter([
                ("operationId".to_string(), json!(route.operation)),
                ("parameters".to_string(), route_parameters(route)),
                (
                    "responses".to_string(),
                    json!({
                        "200": {
                            "description": "Broker response",
                            "content": {
                                "application/json": {
                                    "schema": route_response_schema(route, &resource_type_ids)
                                }
                            }
                        }
                    }),
                ),
            ]);
            if route
                .operation
                .starts_with("admin.principals.identity_access.")
                || route
                    .operation
                    .starts_with("admin.principals.identity_bindings.")
            {
                let responses = operation.get_mut("responses").expect("route responses");
                for (status, description) in [
                    (
                        "400",
                        "Invalid fields, username or configured namespace; input_invalid.",
                    ),
                    ("401", "Management authentication required."),
                    (
                        "403",
                        "Administrator mutation or admin/auditor metadata access denied; browser writes require CSRF.",
                    ),
                    (
                        "404",
                        "Unknown principal or binding owned by another principal; principal_not_found or identity_binding_not_found.",
                    ),
                    (
                        "409",
                        "Stale expectedVersion (identity_version_conflict) or reserved namespace/username (identity_binding_conflict). Reload state before a new mutation.",
                    ),
                    (
                        "503",
                        "Managed storage or mandatory audit preflight is unavailable.",
                    ),
                ] {
                    responses[status] = json!({"description":description,"content":{"application/json":{"schema":envelope_schema(ResponseKind::ManagementEnvelope)}}});
                }
            }
            if route.access == RouteAccess::BrowserManagement {
                operation.insert("description".into(), json!("Requires a signed-in browser session; writes require the configured CSRF header. Broker API tokens cannot manage OAuth connections."));
                if matches!(auth, RenderAuthMode::Include) {
                    operation.insert("security".into(), json!([{"browserSession": []}]));
                }
            }
            if let Some(schema) = &route.request_body_schema {
                operation.insert(
                    "requestBody".to_string(),
                    json!({
                        "required": true,
                        "content": {
                            "application/json": { "schema": schema }
                        }
                    }),
                );
            }
            if !route.sensitive_response_pointers.is_empty() {
                operation.insert(
                    "x-agent-access-sensitive-output-pointers".to_string(),
                    json!(route.sensitive_response_pointers),
                );
            }
            object.insert(method, Value::Object(operation));
        }
    }
    let (components, security) = if matches!(auth, RenderAuthMode::Include) {
        let mut headers = identity_headers.iter().cloned().collect::<BTreeSet<_>>();
        if headers.is_empty() {
            headers.insert("Authorization".to_string());
        }
        let mut schemes = serde_json::Map::new();
        let mut security = Vec::new();
        for (index, header) in headers.into_iter().enumerate() {
            let key = if index == 0 {
                "brokerIdentity".to_string()
            } else {
                format!("brokerIdentity{index}")
            };
            schemes.insert(
                key.clone(),
                json!({
                    "type": "apiKey",
                    "in": "header",
                    "name": header
                }),
            );
            security.push(json!({ (key): [] }));
        }
        if catalog
            .routes
            .iter()
            .any(|r| r.access == RouteAccess::BrowserManagement)
        {
            schemes.insert(
                "browserSession".into(),
                json!({"type":"apiKey","in":"cookie","name":browser_cookie_name}),
            );
        }
        (
            json!({
                "securitySchemes": schemes
            }),
            security,
        )
    } else {
        (json!({}), Vec::new())
    };
    json!({
        "openapi": "3.1.0",
        "info": {
            "title": "Agent Access Broker Runtime API",
            "version": catalog.version
        },
        "paths": paths,
        "components": components,
        "security": security
    })
}

fn action_request_body_content(action: &ApiActionSpec) -> Value {
    match &action.io {
        ActionIo::MultipartUpload { plan } => json!({
            "multipart/form-data": {
                "schema": {
                    "type": "object",
                    "required": ["request"],
                    "properties": {
                        "request": {
                            "type": "string",
                            "description": "JSON InvokeRequest part",
                            "contentMediaType": "application/json",
                            "contentSchema": invoke_request_schema(action)
                        },
                        (format!("{}0", plan.field_name_prefix)): {
                            "type": "string",
                            "format": "binary",
                            "description": format!("First {} file part", plan.role)
                        }
                    },
                    "additionalProperties": {
                        "type": "string",
                        "format": "binary"
                    }
                },
                "encoding": {
                    "request": { "contentType": "application/json" }
                },
                "x-agent-access-upload-plan": plan
            }
        }),
        ActionIo::Json | ActionIo::RawDownload { .. } => json!({
            "application/json": {
                "schema": invoke_request_schema(action)
            }
        }),
        // Never projected: see `supported_action_io`.
        _ => json!({}),
    }
}

fn invoke_request_schema(action: &ApiActionSpec) -> Value {
    let mut properties =
        serde_json::Map::from_iter([("inputs".to_string(), action.input_schema.clone())]);
    properties.insert(
        "readContentFormat".to_string(),
        invoke_format_schema(&action.read_content_formats, "native"),
    );
    properties.insert(
        "responseFormat".to_string(),
        invoke_format_schema(&action.response_formats, "json"),
    );
    json!({
        "type": "object",
        "additionalProperties": false,
        "properties": properties
    })
}

fn invoke_format_schema(advertised: &[String], default: &str) -> Value {
    if advertised.is_empty() {
        json!({ "enum": [default] })
    } else {
        json!({ "enum": advertised })
    }
}

fn route_parameters(route: &HttpRouteSpec) -> Value {
    let mut parameters = Vec::new();
    for param in &route.path_params {
        parameters.push(json!({
            "name": param.name,
            "in": "path",
            "required": true,
            "schema": param.schema
        }));
    }
    for param in &route.query_params {
        parameters.push(json!({
            "name": param.name,
            "in": "query",
            "required": param.required,
            "schema": param.schema
        }));
    }
    Value::Array(parameters)
}

pub fn send_schema_from_catalog(catalog: &ApiCatalog) -> Value {
    let mut variants = Vec::new();
    for service in &catalog.services {
        for action in service
            .actions
            .iter()
            .filter(|action| supported_action_io(&action.io))
        {
            let mut variant = invoke_send_variant(&service.service, action);
            if let Some(inputs) = variant.pointer_mut("/properties/inputs") {
                relocate_local_schema_refs(
                    inputs,
                    &format!("#/oneOf/{}/properties/inputs", variants.len()),
                );
            }
            variants.push(variant);
        }
    }
    for route in &catalog.routes {
        variants.push(http_send_variant(route));
    }
    json!({
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "title": "Agent Access CLI send request",
        "oneOf": variants,
        "definitions": generic_send_definitions()
    })
}

pub fn generic_send_schema() -> Value {
    json!({
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "title": "Agent Access CLI send request",
        "oneOf": [
            {
                "type": "object",
                "additionalProperties": false,
                "required": ["version", "kind", "service", "action"],
                "dependentRequired": { "metadataOutput": ["output"] },
                "properties": {
                    "version": { "const": SEND_SCHEMA_VERSION },
                    "kind": { "const": "invoke" },
                    "service": { "type": "string" },
                    "action": { "type": "string" },
                    "inputs": { "type": "object", "default": {} },
                    "files": { "type": "array", "items": { "$ref": "#/definitions/fileDescriptor" } },
                    "secretSources": { "$ref": "#/definitions/secretSources" },
                    "responseMode": { "enum": ["json", "stream"], "default": "json" },
                    "readContentFormat": { "enum": ["native", "markdown", "text"] },
                    "responseFormat": { "enum": ["json", "markdown"] },
                    "output": { "$ref": "#/definitions/output" },
                    "metadataOutput": { "$ref": "#/definitions/metadataOutput" }
                }
            },
            {
                "type": "object",
                "additionalProperties": false,
                "required": ["version", "kind", "method", "route"],
                "properties": {
                    "version": { "const": SEND_SCHEMA_VERSION },
                    "kind": { "const": "http" },
                    "method": { "type": "string" },
                    "route": { "type": "string", "pattern": "^/v1/" },
                    "pathParams": { "type": "object", "additionalProperties": { "type": "string" } },
                    "query": { "type": "object" },
                    "body": {},
                    "secretSources": { "$ref": "#/definitions/secretSources" }
                }
            }
        ],
        "definitions": generic_send_definitions()
    })
}

/// Every HTTP route the broker serves. Resource mutation schemas enumerate
/// the registered resource types and their selector forms.
pub fn http_route_specs(
    resource_types: &agent_access_provider::ResourceTypeRegistry,
) -> Vec<HttpRouteSpec> {
    let mut routes = Vec::new();
    routes.extend(discovery_route_specs());
    routes.extend(spec_route_specs());
    routes.extend(user_management_route_specs());
    routes.extend(oauth_route_specs());
    routes.extend(admin_management_route_specs());
    routes.extend(resource_policy_route_specs(resource_types));
    routes.extend(audit_query_route_specs());
    routes.extend(imports::route_specs());
    routes
}

pub fn route_path_params(route: &str) -> Vec<RouteParamSpec> {
    let mut params = Vec::new();
    let mut seen = BTreeSet::new();
    for segment in route.split('/') {
        if let Some(name) = segment
            .strip_prefix('{')
            .and_then(|value| value.strip_suffix('}'))
            && seen.insert(name.to_string())
        {
            params.push(RouteParamSpec {
                name: name.to_string(),
                required: true,
                schema: json!({ "type": "string" }),
            });
        }
    }
    params
}

fn discovery_route_specs() -> Vec<HttpRouteSpec> {
    vec![
        get_route(
            "/v1/me",
            "me",
            RouteAccess::Authenticated,
            ResponseKind::RawJson,
        ),
        get_route(
            "/v1/broker/status",
            "broker.status",
            RouteAccess::Authenticated,
            ResponseKind::RawJson,
        ),
        get_route(
            "/v1/resource-types",
            "resource_types.list",
            RouteAccess::Authenticated,
            ResponseKind::RawJson,
        ),
        get_route(
            "/v1/capabilities",
            "capabilities",
            RouteAccess::Authenticated,
            ResponseKind::RawJson,
        ),
        get_route(
            "/v1/services",
            "services.list",
            RouteAccess::Authenticated,
            ResponseKind::RawJson,
        ),
        get_route(
            "/v1/services/{service}",
            "services.describe",
            RouteAccess::Authenticated,
            ResponseKind::RawJson,
        ),
        discovery_route(
            "resources",
            vec![
                RouteParamSpec {
                    name: "resourceType".into(),
                    required: false,
                    schema: json!({"type":"string", "minLength":1, "description":"Registered resource type to list. Required when the service authorizes more than one resource type."}),
                },
                RouteParamSpec {
                    name: "prefix".into(),
                    required: false,
                    schema: json!({"type":"string", "minLength":1}),
                },
                RouteParamSpec {
                    name: "limit".into(),
                    required: false,
                    schema: json!({"type":"integer", "minimum":1, "maximum":100, "default":50}),
                },
                RouteParamSpec {
                    name: "cursor".into(),
                    required: false,
                    schema: json!({"type":"string", "minLength":1, "description":"Opaque continuation; repeat service, prefix and limit. Restart without cursor after discovery changes."}),
                },
            ],
        ),
        discovery_route(
            "actions",
            vec![
                RouteParamSpec {
                    name: "resource".into(),
                    required: false,
                    schema: json!({"type":"string", "minLength":1, "description":"Concrete canonical locator, not a broker resource ID. Performs a singleton policy check, not full request authorization."}),
                },
                RouteParamSpec {
                    name: "resourceType".into(),
                    required: false,
                    schema: json!({"type":"string", "minLength":1, "description":"Resource type of the locator. Requires resource; required when the service authorizes more than one resource type."}),
                },
                RouteParamSpec {
                    name: "prefix".into(),
                    required: false,
                    schema: json!({"type":"string", "minLength":1}),
                },
            ],
        ),
    ]
}

fn discovery_route(kind: &str, query_params: Vec<RouteParamSpec>) -> HttpRouteSpec {
    let mut route = get_route(
        &format!("/v1/services/{{service}}/{kind}"),
        &format!("{kind}.list"),
        RouteAccess::Authenticated,
        ResponseKind::RawJson,
    );
    route.query_params = query_params;
    route
}

fn route_response_schema(route: &HttpRouteSpec, resource_type_ids: &[String]) -> Value {
    match route.operation.as_str() {
        "resource_types.list" => json!({
            "type":"object","additionalProperties":false,"required":["resourceTypes"],
            "description":"Every resource type this broker registers, in registration order.",
            "properties":{"resourceTypes":{"type":"array","items":{
                "type":"object","additionalProperties":false,
                "required":["id","label","pluralLabel","example","selectors"],
                "properties":{
                    "id":{"enum":resource_type_ids},
                    "label":{"type":"string"},"pluralLabel":{"type":"string"},"example":{"type":"string"},
                    "selectors":{"type":"array","items":{"enum":["exact","namespace","all"]}},
                    "namespace":{"type":"object","additionalProperties":false,
                        "required":["label","membersLabel","example"],
                        "properties":{"label":{"type":"string"},"membersLabel":{"type":"string"},"example":{"type":"string"}}},
                    "attributes":{"type":"array","items":{"type":"object","additionalProperties":false,
                        "required":["name","label","description","required","secret"],
                        "properties":{"name":{"type":"string"},"label":{"type":"string"},"description":{"type":"string"},
                            "required":{"type":"boolean"},"secret":{"type":"boolean"}}}},
                    "removed":{"type":"boolean","const":true,
                        "description":"Present when the imported service that declared the type no longer does: it accepts no new resources."},
                    "importedService":{"type":"string","description":"The imported service that declares the type."}
                }
            }}}
        }),
        "resources.list" => json!({
            "type":"object", "additionalProperties":false,
            "description":"Registered enabled concrete resources, plus the caller's broader namespace or all-resource coverage on the first page. An empty resources list with coverage means broad access, not no access; check known locators with actions.list.",
            "required":["service","resources","nextCursor"],
            "properties": {
                "service":{"type":"string"},
                "resources":{"type":"array","items":{
                    "type":"object","additionalProperties":false,"required":["id","type","value"],
                    "properties":{
                        "id":{"type":"string"},"type":{"enum":resource_type_ids},
                        "value":{"type":"string"},"displayName":{"type":"string"},
                        "inputs":{"type":"object","description":"Action inputs that address this resource."}
                    }
                }},
                "coverage":{"type":"array","description":"First page only; omitted when empty. Resources inside are not enumerated.","items":{
                    "type":"object","additionalProperties":false,"required":["type","selector","restricted"],
                    "properties":{
                        "type":{"enum":resource_type_ids},
                        "selector":{"oneOf":[
                            {"type":"object","additionalProperties":false,"required":["kind","value"],
                                "properties":{"kind":{"const":"namespace"},"value":{"type":"string"}}},
                            {"type":"object","additionalProperties":false,"required":["kind"],
                                "properties":{"kind":{"const":"all"}}}
                        ]},
                        "inputs":{"type":"object","description":"Action inputs shared by resources inside, such as a controller."},
                        "restricted":{"type":"boolean","description":"Some resources inside are withheld; they are not named."}
                    }
                }},
                "nextCursor":{"type":["string","null"]}
            }
        }),
        "actions.list" => json!({
            "type":"object","additionalProperties":false,"required":["service","actions"],
            "description":"Caller-visible actions; optional resource filtering checks one locator against effective policy. Actual execution reauthorizes all targets and credentials.",
            "properties":{"service":{"type":"string"},"resource":{"type":"string"},"actions":{"type":"array","items":{"type":"string"}}}
        }),
        _ => match (&route.result_schema, route.response_kind) {
            (Some(result), ResponseKind::ManagementEnvelope) => {
                let mut schema = envelope_schema(route.response_kind);
                schema["properties"] = json!({ "result": result });
                schema
            }
            _ => envelope_schema(route.response_kind),
        },
    }
}

/// The audit query routes: the admin tier (all records for admins, managed
/// services for service policy managers) and the self tier (the caller's
/// own records). All six need SQLite audit storage.
fn audit_query_route_specs() -> Vec<HttpRouteSpec> {
    const ADMIN_LIST: &str = "/v1/admin/audit/events";
    const ADMIN_TIMELINE: &str = "/v1/admin/audit/requests/{brokerRequestId}";
    const SELF_LIST: &str = "/v1/audit/events";
    const SELF_TIMELINE: &str = "/v1/audit/requests/{brokerRequestId}";
    let mut routes = vec![
        get_management_route(
            "/v1/admin/audit/options",
            "admin.audit.options",
            RouteAccess::PolicyRead,
        ),
        get_management_route(
            "/v1/audit/options",
            "audit.options",
            RouteAccess::UserTokenManagement,
        ),
        get_management_route(
            ADMIN_LIST,
            "admin.audit.events.list",
            RouteAccess::PolicyRead,
        ),
        get_management_route(
            ADMIN_TIMELINE,
            "admin.audit.requests.inspect",
            RouteAccess::PolicyRead,
        ),
        get_management_route(
            SELF_LIST,
            "audit.events.list",
            RouteAccess::UserTokenManagement,
        ),
        get_management_route(
            SELF_TIMELINE,
            "audit.requests.inspect",
            RouteAccess::UserTokenManagement,
        ),
    ];
    for route in &mut routes {
        route.required_feature = Some(RouteFeature::AuditQuery);
        if route.route.ends_with("/options") {
            route.result_schema = Some(json!({
                "type": "object", "additionalProperties": false,
                "required": ["services"],
                "description": "Canonical broker audit actions available before any records exist. Service-manager suggestions contain operations that can produce records about their services. Suggestions do not depend on audit history or grant permission to invoke an operation.",
                "properties": {
                    "services": { "type": "array", "items": {
                        "type": "object", "additionalProperties": false, "required": ["service", "actions"],
                        "properties": {
                            "service": {"type": "string"},
                            "actions": {"type": "array", "uniqueItems": true, "items": {"type": "string"}}
                        }
                    }}
                }
            }));
        } else if route.route.ends_with("/events") {
            route.query_params = audit_list_query_params(route.route == ADMIN_LIST);
            route.result_schema = Some(json!({
                "type": "object",
                "additionalProperties": false,
                "required": ["items", "nextCursor"],
                "properties": {
                    "items": {
                        "type": "array",
                        "maxItems": crate::AUDIT_QUERY_MAX_LIMIT,
                        "description": "Visible records, newest first by timestamp then insertion order; each exactly as written.",
                        "items": audit_record_schema()
                    },
                    "nextCursor": {
                        "type": ["string", "null"],
                        "description": "Pass as cursor (optionally with limit, and nothing else) for the next page; null on the last page."
                    }
                }
            }));
        } else {
            route.path_params = vec![RouteParamSpec {
                name: "brokerRequestId".to_string(),
                required: true,
                schema: json!({ "type": "string", "format": "uuid" }),
            }];
            route.result_schema = Some(json!({
                "type": "object",
                "additionalProperties": false,
                "required": ["brokerRequestId", "items"],
                "properties": {
                    "brokerRequestId": { "type": "string", "format": "uuid" },
                    "items": {
                        "type": "array",
                        "minItems": 1,
                        "maxItems": crate::AUDIT_TIMELINE_MAX_ITEMS,
                        "description": "The request's visible records, oldest first; each exactly as written.",
                        "items": audit_record_schema()
                    }
                }
            }));
        }
    }
    routes
}

fn audit_list_query_params(include_principal: bool) -> Vec<RouteParamSpec> {
    let text = |description: &str| json!({ "type": "string", "minLength": 1, "maxLength": 256, "description": description });
    let mut params = vec![
        (
            "from",
            json!({ "type": "string", "format": "date-time", "description": "Inclusive lower bound (RFC 3339)." }),
        ),
        (
            "to",
            json!({ "type": "string", "format": "date-time", "description": "Exclusive upper bound (RFC 3339); not before from." }),
        ),
        ("principal", text("Exact principal ID.")),
        (
            "service",
            text("Exact record service, such as jira or broker."),
        ),
        (
            "scopeService",
            text("Exact scope service: the configured service a record is about."),
        ),
        (
            "action",
            text("Exact action, or a prefix ending in .* such as admin.policy.*."),
        ),
        (
            "decision",
            json!({ "type": "string", "enum": ["allow", "deny", "error"] }),
        ),
        (
            "reasonCode",
            json!({ "type": "string", "pattern": "^[a-z][a-z0-9_]{0,63}$" }),
        ),
        (
            "phase",
            json!({ "type": "string", "enum": crate::AUDIT_PHASES }),
        ),
        ("tokenId", text("Exact identitySource.tokenId.")),
        ("grantId", text("Exact matched grant ID.")),
        (
            "node",
            json!({ "type": "string", "pattern": "^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$" }),
        ),
        (
            "requestId",
            text("Matches brokerRequestId or agentRequestId."),
        ),
        (
            "q",
            json!({
                "type": "string", "minLength": 1, "maxLength": crate::AUDIT_SEARCH_MAX_CHARS,
                "description": "Full-text search: whitespace-separated terms (at most 16), a double-quoted segment is one phrase, a trailing * makes a term a prefix. Every term must match; operators are never interpreted."
            }),
        ),
        (
            "limit",
            json!({
                "type": "integer", "minimum": 1, "maximum": crate::AUDIT_QUERY_MAX_LIMIT,
                "default": crate::AUDIT_QUERY_DEFAULT_LIMIT
            }),
        ),
        (
            "cursor",
            json!({
                "type": "string", "minLength": 1, "maxLength": crate::AUDIT_CURSOR_MAX_CHARS,
                "description": "A previous page's nextCursor. Only limit may accompany it."
            }),
        ),
    ];
    if !include_principal {
        params.retain(|(name, _)| *name != "principal");
    }
    params
        .into_iter()
        .map(|(name, schema)| RouteParamSpec {
            name: name.to_string(),
            required: false,
            schema,
        })
        .collect()
}

/// A stored audit record: open-ended, with the fields every record has.
fn audit_record_schema() -> Value {
    json!({
        "type": "object",
        "additionalProperties": true,
        "required": [
            "auditId", "nodeId", "timestamp", "agentRequestId", "brokerRequestId",
            "principal", "groups", "service", "action", "resourceScopes", "decision", "source"
        ],
        "properties": {
            "auditId": { "type": "string", "format": "uuid" },
            "nodeId": { "type": "string" },
            "timestamp": { "type": "string", "format": "date-time" },
            "agentRequestId": { "type": "string" },
            "brokerRequestId": { "type": "string" },
            "principal": { "type": "string" },
            "groups": { "type": "array", "items": { "type": "string" } },
            "service": { "type": "string" },
            "action": { "type": "string" },
            "resourceScopes": { "type": "object" },
            "decision": { "enum": ["allow", "deny", "error"] },
            "reasonCode": { "type": "string" },
            "upstreamStatus": { "type": "integer" },
            "upstreamDurationMs": { "type": "integer" },
            "identitySource": { "type": "object" },
            "source": { "type": "object" },
            "providerAudit": { "type": "object" }
        }
    })
}

fn spec_route_specs() -> Vec<HttpRouteSpec> {
    [
        "/v1/spec/catalog",
        "/v1/spec/openapi.json",
        "/v1/spec/send-schema.json",
    ]
    .into_iter()
    .map(|route| {
        let mut spec = get_route(
            route,
            route.trim_start_matches("/v1/spec/"),
            RouteAccess::Spec,
            ResponseKind::RawJson,
        );
        spec.query_params = vec![
            route_param("auth", false),
            route_param("visibility", false),
            route_param("format", false),
        ];
        spec
    })
    .collect()
}

fn oauth_route_specs() -> Vec<HttpRouteSpec> {
    let mut routes = vec![
        get_management_route(
            "/v1/oauth/connections",
            "oauth.connections.list",
            RouteAccess::BrowserManagement,
        ),
        body_route(
            "POST",
            "/v1/oauth/connect",
            "oauth.connections.connect",
            RouteAccess::BrowserManagement,
            ResponseKind::ManagementEnvelope,
            ExitPolicy::ManagementOk,
            Vec::new(),
        ),
        no_body_route(
            "DELETE",
            "/v1/oauth/connections/{registration}",
            "oauth.connections.disconnect",
            RouteAccess::BrowserManagement,
            ResponseKind::ManagementEnvelope,
            ExitPolicy::ManagementOk,
        ),
    ];
    set_request_body_schema(
        &mut routes,
        "POST",
        "/v1/oauth/connect",
        json!({
            "type":"object", "required":["registration"], "additionalProperties":false,
            "properties":{
                "registration":{"type":"string"},
                "importedService":{"type":"string","description":"The imported service whose administrator discovery or catalog page the connection serves; required with returnPath /ui/admin/catalog."},
                "intent":{"type":"string","enum":["connect","reconnect","replace_account"]},
                "returnPath":{"type":"string","enum":["/ui/credentials","/ui/admin/catalog"]}
            }
        }),
    );
    let connection_schema = json!({
        "type":["object","null"],"additionalProperties":false,
        "required":["registration","connectionId","subjectId","displayName","status","reason","targets"],
        "properties":{
            "registration":{"type":"string"},
            "connectionId":{"type":["string","null"]},
            "subjectId":{"type":["string","null"]},
            "displayName":{"type":["string","null"]},
            "status":{"enum":["ready","reconnect_required","operator_action_required","disconnected"]},
            "reason":{"type":["string","null"]},
            "targets":{"type":"array","items":{
                "type":"object","additionalProperties":false,
                "required":["id","name","audience","scopes"],
                "properties":{
                    "id":{"type":"string"},"name":{"type":"string"},
                    "audience":{"type":"string"},
                    "scopes":{"type":"array","items":{"type":"string"}}
                }
            }}
        }
    });
    routes[0].result_schema = Some(json!({
        "type":"array",
        "description":"One row per OAuth registration the caller's credential connections select: registrations available for setup, plus existing owned connections available for local disconnect. Setup requires self-service and a matching per-user grant on a consuming service or the administrator import-discovery exception; it does not authorize invocation.",
        "items":{
            "type":"object","additionalProperties":false,
            "required":["registration","displayName","connectionDescription","consumers","otherConsumers","permissionProfile","scopeMode","requestedScopes","target","canConnect","canDisconnect","connectUnavailableReason","connection"],
            "properties":{
                "registration":{"type":"string"},
                "displayName":{"type":"string"},
                "connectionDescription":{"type":["string","null"]},
                "consumers":connection_consumers_schema(),
                "otherConsumers":{"type":"integer","minimum":0,"description":"Consuming services the caller is not entitled to; the connection serves them too."},
                "permissionProfile":{"type":"string"},
                "scopeMode":{"enum":["explicit","server_default"]},
                "requestedScopes":{"type":"array","items":{"type":"string"}},
                "target":{"type":"string"},
                "canConnect":{"type":"boolean"},
                "canDisconnect":{"type":"boolean","description":"An owned connection exists. Local disconnect remains available after setup entitlement is removed."},
                "connectUnavailableReason":{"enum":[null,"no_personal_access","service_unavailable"]},
                "connection":connection_schema
            }
        }
    }));
    routes[1].sensitive_response_pointers = vec!["/result/authorizationUrl".into()];
    // The redirect callback is a browser protocol endpoint, like /v1/auth/*,
    // rather than an envelope-based JSON send route. See docs/oauth.md.
    routes
}

fn user_management_route_specs() -> Vec<HttpRouteSpec> {
    let mut routes = vec![
        get_management_route(
            "/v1/credentials",
            "credentials.list",
            RouteAccess::UserManagement,
        ),
        get_management_route(
            "/v1/credentials/targets",
            "credentials.targets",
            RouteAccess::UserManagement,
        ),
        get_management_route(
            "/v1/credentials/connections/{connection}",
            "credentials.inspect",
            RouteAccess::UserManagement,
        ),
        body_route(
            "PUT",
            "/v1/credentials/connections/{connection}",
            "credentials.put",
            RouteAccess::UserManagement,
            ResponseKind::ManagementEnvelope,
            ExitPolicy::ManagementOk,
            vec!["/body/secret".to_string()],
        ),
        no_body_route(
            "DELETE",
            "/v1/credentials/connections/{connection}",
            "credentials.delete",
            RouteAccess::UserManagement,
            ResponseKind::ManagementEnvelope,
            ExitPolicy::ManagementOk,
        ),
        body_route(
            "POST",
            "/v1/credentials/connections/{connection}/verify",
            "credentials.verify",
            RouteAccess::UserManagement,
            ResponseKind::ManagementEnvelope,
            ExitPolicy::ManagementOk,
            Vec::new(),
        ),
        get_management_route(
            "/v1/credentials/connections/{connection}/input-schema",
            "credentials.input_schema",
            RouteAccess::UserManagement,
        ),
        no_body_route(
            "DELETE",
            "/v1/credentials/retained/{credential_id}",
            "credentials.retained.delete",
            RouteAccess::UserManagement,
            ResponseKind::ManagementEnvelope,
            ExitPolicy::ManagementOk,
        ),
        get_management_route(
            "/v1/tokens/options",
            "tokens.options",
            RouteAccess::UserTokenManagement,
        ),
        get_management_route(
            "/v1/tokens",
            "tokens.list",
            RouteAccess::UserTokenManagement,
        ),
        body_route(
            "POST",
            "/v1/tokens",
            "tokens.issue",
            RouteAccess::UserTokenManagement,
            ResponseKind::ManagementEnvelope,
            ExitPolicy::ManagementOk,
            Vec::new(),
        ),
        get_management_route(
            "/v1/tokens/{token_id}",
            "tokens.inspect",
            RouteAccess::UserTokenManagement,
        ),
        no_body_route(
            "DELETE",
            "/v1/tokens/{token_id}",
            "tokens.revoke",
            RouteAccess::UserTokenManagement,
            ResponseKind::ManagementEnvelope,
            ExitPolicy::ManagementOk,
        ),
        no_body_route(
            "POST",
            "/v1/tokens/{token_id}/pause",
            "tokens.pause",
            RouteAccess::UserTokenManagement,
            ResponseKind::ManagementEnvelope,
            ExitPolicy::ManagementOk,
        ),
        no_body_route(
            "POST",
            "/v1/tokens/{token_id}/resume",
            "tokens.resume",
            RouteAccess::UserTokenManagement,
            ResponseKind::ManagementEnvelope,
            ExitPolicy::ManagementOk,
        ),
    ];
    add_query_params(
        &mut routes,
        "GET",
        "/v1/credentials/connections/{connection}/input-schema",
        &["profile"],
    );
    set_request_body_schema(
        &mut routes,
        "PUT",
        "/v1/credentials/connections/{connection}",
        credential_put_body_schema(),
    );
    set_request_body_schema(
        &mut routes,
        "POST",
        "/v1/credentials/connections/{connection}/verify",
        credential_verify_body_schema(),
    );
    set_result_schema(
        &mut routes,
        "GET",
        "/v1/credentials",
        personal_credentials_result_schema(),
    );
    set_result_schema(
        &mut routes,
        "GET",
        "/v1/credentials/targets",
        credential_targets_result_schema(),
    );
    add_query_params(
        &mut routes,
        "GET",
        "/v1/tokens",
        &["includeRevoked", "includeExpired"],
    );
    set_request_body_schema(
        &mut routes,
        "POST",
        "/v1/tokens",
        agent_token_issue_body_schema(),
    );
    routes
}

fn resource_policy_route_specs(
    resource_types: &agent_access_provider::ResourceTypeRegistry,
) -> Vec<HttpRouteSpec> {
    let mut routes = Vec::new();
    for (path, operation) in [
        ("resources", "resources"),
        ("resource-groups", "resource_groups"),
    ] {
        let base = format!("/v1/admin/policy/{path}");
        let detail = format!("{base}/{{id}}");
        routes.push(get_management_route(
            &base,
            &format!("admin.policy.{operation}.list"),
            RouteAccess::PolicyRead,
        ));
        routes.push(get_management_route(
            &detail,
            &format!("admin.policy.{operation}.get"),
            RouteAccess::PolicyRead,
        ));
        routes.push(get_management_route(
            &format!("{detail}/used-by"),
            &format!("admin.policy.{operation}.used_by"),
            RouteAccess::AdminRead,
        ));
        for (method, route, action) in [
            ("POST", base.as_str(), "create"),
            ("PATCH", detail.as_str(), "patch"),
        ] {
            routes.push(body_route(
                method,
                route,
                &format!("admin.policy.{operation}.{action}"),
                RouteAccess::AdminWrite,
                ResponseKind::ManagementEnvelope,
                ExitPolicy::ManagementOk,
                if path == "resources" {
                    vec!["/body/attributes".to_string()]
                } else {
                    Vec::new()
                },
            ));
            set_request_body_schema(
                &mut routes,
                method,
                route,
                resource_mutation_schema(
                    path == "resource-groups",
                    method == "PATCH",
                    resource_types,
                ),
            );
        }
        routes.push(no_body_route(
            "DELETE",
            &detail,
            &format!("admin.policy.{operation}.delete"),
            RouteAccess::AdminWrite,
            ResponseKind::ManagementEnvelope,
            ExitPolicy::ManagementOk,
        ));
        add_required_integer_query_params(&mut routes, "DELETE", &detail, &["expectedVersion"], 1);
    }
    let mut reveal = no_body_route(
        "POST",
        "/v1/admin/policy/resources/{id}/attributes/{attribute}/reveal",
        "admin.policy.resources.attribute.reveal",
        RouteAccess::AdminWrite,
        ResponseKind::ManagementEnvelope,
        ExitPolicy::ManagementOk,
    );
    reveal.sensitive_response_pointers = vec!["/result/value".to_string()];
    routes.push(reveal);
    for (path, operation, access) in [
        (
            "/v1/admin/policy/effective-access",
            "admin.policy.effective_access",
            RouteAccess::PolicyRead,
        ),
        (
            "/v1/tokens/effective-access",
            "tokens.effective_access",
            RouteAccess::UserManagement,
        ),
        (
            "/v1/admin/principals/{principal}/agent-token-effective-access",
            "admin.tokens.effective_access_principal_agent",
            RouteAccess::AdminRead,
        ),
    ] {
        routes.push(body_route(
            "POST",
            path,
            operation,
            access,
            ResponseKind::ManagementEnvelope,
            ExitPolicy::ManagementOk,
            Vec::new(),
        ));
        let schema = if path == "/v1/admin/policy/effective-access" {
            json!({"type":"object","additionalProperties":false,"required":["service","actions","executionContexts","resources"],"properties":{
                "service":service_name_schema(),"actions":{"type":"array","items":{"type":"string"},"minItems":1,"uniqueItems":true},
                "executionContexts":execution_contexts_schema(),"resources":resource_selection_schema()
            }})
        } else {
            agent_invoke_scopes_schema()
        };
        set_request_body_schema(&mut routes, "POST", path, schema);
    }
    routes
}

fn policy_grant_schema(patch: bool) -> Value {
    let strings =
        json!({"type":"array","uniqueItems":true,"items":{"type":"string","minLength":1}});
    let mut properties = json!({
        "subjects":strings, "executionContexts":execution_contexts_schema(), "service":service_name_schema(),
        "actions":strings, "resources":resource_selection_schema(), "credentialMode":{"type":"string"},
        "priority":{"type":["integer","null"]}, "status":{"enum":["active","disabled"]},
        "description":{"type":["string","null"]}
    });
    let required = if patch {
        properties["expectedVersion"] = json!({"type":"integer","minimum":1});
        json!(["expectedVersion"])
    } else {
        properties["grantId"] = json!({"type":"string","minLength":1});
        json!([
            "subjects",
            "executionContexts",
            "service",
            "actions",
            "resources",
            "credentialMode"
        ])
    };
    json!({"type":"object","additionalProperties":false,"required":required,"properties":properties})
}

fn resource_mutation_schema(
    group: bool,
    patch: bool,
    resource_types: &agent_access_provider::ResourceTypeRegistry,
) -> Value {
    let type_ids = resource_types
        .ids()
        .map(|id| id.as_str().to_string())
        .collect::<Vec<_>>();
    let without_namespace = resource_types
        .descriptors()
        .filter(|descriptor| descriptor.namespace().is_none())
        .map(|descriptor| descriptor.id().as_str().to_string())
        .collect::<Vec<_>>();
    let ids = json!({"type":"array","uniqueItems":true,"items":resource_id_schema()});
    let mut properties = if group {
        json!({"name":{"type":"string","minLength":1},"includedResourceIds":ids,"excludedResourceIds":ids})
    } else {
        json!({
            "displayName":{"type":["string","null"]},
            "resourceType":{"type":"string","enum":type_ids},
            "selector":{"oneOf":[
                {"type":"object","additionalProperties":false,"required":["kind","value"],"properties":{"kind":{"enum":["exact","namespace"]},"value":{"type":"string","minLength":1}}},
                {"type":"object","additionalProperties":false,"required":["kind"],"properties":{"kind":{"const":"all"}}}
            ]},
            "allowedExecutionContexts":execution_contexts_schema(),"enabled":{"type":"boolean"},
            "attributes":{"type":"object","additionalProperties":{"type":"string","minLength":1,"maxLength":8192,"writeOnly":true},"writeOnly":true}
        })
    };
    let required = if patch {
        properties["expectedVersion"] = json!({"type":"integer","minimum":1});
        json!(["expectedVersion"])
    } else {
        properties["id"] = resource_id_schema();
        if group {
            json!(["name"])
        } else {
            json!(["resourceType", "selector", "allowedExecutionContexts"])
        }
    };
    let mut schema = json!({"type":"object","additionalProperties":false,"required":required,"properties":properties});
    if !group {
        let attribute_schema = |descriptor: &agent_access_provider::ResourceTypeDescriptor| {
            let properties = descriptor.attributes().iter().map(|attribute| (
                attribute.name().to_string(),
                json!({"type":"string","minLength":1,"maxLength":8192,"writeOnly":true,"description":attribute.description()}),
            )).collect::<serde_json::Map<_,_>>();
            json!({"type":"object","additionalProperties":false,"properties":properties,"writeOnly":true})
        };
        let properties =
            resource_types
                .descriptors()
                .flat_map(|descriptor| {
                    descriptor.attributes().iter().map(|attribute| (
                attribute.name().to_string(),
                json!({"type":"string","minLength":1,"maxLength":8192,"writeOnly":true}),
            ))
                })
                .collect::<serde_json::Map<_, _>>();
        schema["properties"]["attributes"] = json!({"type":"object","additionalProperties":false,"properties":properties,"writeOnly":true});
        let mut conditions = vec![
            json!({
                "if":{"required":["resourceType"],"properties":{"resourceType":{"enum":without_namespace}}},
                "then":{"properties":{"selector":{"properties":{"kind":{"enum":["exact","all"]}}}}}
            }),
            json!({
                "if":{"required":["selector"],"properties":{"selector":{"properties":{"kind":{"enum":["all","namespace"]}}}}},
                "then":{"properties":{"attributes":{"maxProperties":0}}}
            }),
        ];
        for descriptor in resource_types.descriptors() {
            conditions.push(json!({
                "if":{"required":["resourceType"],"properties":{"resourceType":{"const":descriptor.id().as_str()}}},
                "then":{"properties":{"attributes":attribute_schema(descriptor)}}
            }));
            let required = descriptor
                .attributes()
                .iter()
                .filter(|attribute| attribute.is_required())
                .map(|attribute| attribute.name())
                .collect::<Vec<_>>();
            if !patch && !required.is_empty() {
                conditions.push(json!({
                    "if":{"required":["resourceType","selector"],"properties":{"resourceType":{"const":descriptor.id().as_str()},"selector":{"properties":{"kind":{"const":"exact"}}}}},
                    "then":{"required":["attributes"],"properties":{"attributes":{"required":required}}}
                }));
            }
        }
        schema["allOf"] = Value::Array(conditions);
    }
    schema
}

fn admin_management_route_specs() -> Vec<HttpRouteSpec> {
    let mut routes = vec![
        get_management_route(
            "/v1/admin/store/status",
            "admin.store.status",
            RouteAccess::AdminRead,
        ),
        get_management_route(
            "/v1/admin/config/status",
            "admin.config.status",
            RouteAccess::AdminRead,
        ),
        no_body_route(
            "POST",
            "/v1/admin/config/reload",
            "admin.config.reload",
            RouteAccess::AdminWrite,
            ResponseKind::ManagementEnvelope,
            ExitPolicy::ManagementOk,
        ),
        get_management_route(
            "/v1/admin/policy/status",
            "admin.policy.status",
            RouteAccess::PolicyRead,
        ),
        get_management_route(
            "/v1/admin/policy/catalog",
            "admin.policy.catalog",
            RouteAccess::PolicyRead,
        ),
    ];
    routes.extend(policy_admin_routes());
    routes.extend(principal_group_admin_routes());
    routes.extend(right_token_credential_admin_routes());
    set_request_body_schema(
        &mut routes,
        "PUT",
        "/v1/admin/principals/{principal}/login-methods/local-password",
        json!({
            "type": "object", "additionalProperties": false,
            "required": ["password"],
            "properties": {
                "password": {"type": "string", "minLength": 1},
                "mustChangePassword": {"type": "boolean", "default": true}
            }
        }),
    );
    set_request_body_schema(
        &mut routes,
        "POST",
        "/v1/admin/principals/{principal}/login-methods/local-password/enable",
        json!({
            "type": "object", "additionalProperties": false,
            "required": ["password", "acknowledgeSeparateSignIn"],
            "properties": {
                "password": {"type": "string", "minLength": 1},
                "mustChangePassword": {"type": "boolean", "default": true},
                "acknowledgeSeparateSignIn": {"type": "boolean", "const": true}
            }
        }),
    );
    routes
}

fn policy_admin_routes() -> Vec<HttpRouteSpec> {
    let mut routes = vec![
        get_management_route(
            "/v1/admin/policy/grants",
            "admin.policy.grants.list",
            RouteAccess::PolicyRead,
        ),
        body_route(
            "POST",
            "/v1/admin/policy/grants",
            "admin.policy.grants.create",
            RouteAccess::PolicyWrite,
            ResponseKind::ManagementEnvelope,
            ExitPolicy::ManagementOk,
            Vec::new(),
        ),
        get_management_route(
            "/v1/admin/policy/grants/export",
            "admin.policy.grants.export",
            RouteAccess::AdminRead,
        ),
        body_route(
            "POST",
            "/v1/admin/policy/grants/validate",
            "admin.policy.grants.validate",
            RouteAccess::PolicyRead,
            ResponseKind::ManagementEnvelope,
            ExitPolicy::ManagementOk,
            Vec::new(),
        ),
        get_management_route(
            "/v1/admin/policy/grants/{grant_ref}",
            "admin.policy.grants.inspect",
            RouteAccess::PolicyRead,
        ),
        body_route(
            "PATCH",
            "/v1/admin/policy/grants/{grant_ref}",
            "admin.policy.grants.patch",
            RouteAccess::PolicyWrite,
            ResponseKind::ManagementEnvelope,
            ExitPolicy::ManagementOk,
            Vec::new(),
        ),
        no_body_route(
            "DELETE",
            "/v1/admin/policy/grants/{grant_ref}",
            "admin.policy.grants.delete",
            RouteAccess::PolicyWrite,
            ResponseKind::ManagementEnvelope,
            ExitPolicy::ManagementOk,
        ),
        body_route(
            "POST",
            "/v1/admin/policy/grants/{grant_ref}/enable",
            "admin.policy.grants.enable",
            RouteAccess::PolicyWrite,
            ResponseKind::ManagementEnvelope,
            ExitPolicy::ManagementOk,
            Vec::new(),
        ),
        body_route(
            "POST",
            "/v1/admin/policy/grants/{grant_ref}/disable",
            "admin.policy.grants.disable",
            RouteAccess::PolicyWrite,
            ResponseKind::ManagementEnvelope,
            ExitPolicy::ManagementOk,
            Vec::new(),
        ),
        body_route(
            "POST",
            "/v1/admin/policy/grants/{grant_ref}/subjects",
            "admin.policy.grants.subjects.add",
            RouteAccess::PolicyWrite,
            ResponseKind::ManagementEnvelope,
            ExitPolicy::ManagementOk,
            Vec::new(),
        ),
        body_route(
            "POST",
            "/v1/admin/policy/grants/{grant_ref}/subjects/remove",
            "admin.policy.grants.subjects.remove",
            RouteAccess::PolicyWrite,
            ResponseKind::ManagementEnvelope,
            ExitPolicy::ManagementOk,
            Vec::new(),
        ),
        get_management_route(
            "/v1/admin/policy/service-managers",
            "admin.policy.service_managers.list",
            RouteAccess::AdminRead,
        ),
        no_body_route(
            "PUT",
            "/v1/admin/policy/services/{service}/managers/{principal}",
            "admin.policy.service_managers.grant",
            RouteAccess::AdminWrite,
            ResponseKind::ManagementEnvelope,
            ExitPolicy::ManagementOk,
        ),
        no_body_route(
            "DELETE",
            "/v1/admin/policy/services/{service}/managers/{principal}",
            "admin.policy.service_managers.revoke",
            RouteAccess::AdminWrite,
            ResponseKind::ManagementEnvelope,
            ExitPolicy::ManagementOk,
        ),
    ];
    set_query_params(
        &mut routes,
        "GET",
        "/v1/admin/policy/grants",
        vec![
            RouteParamSpec {
                name: "subject".to_string(),
                required: false,
                schema: json!({ "type": "string", "minLength": 1 }),
            },
            RouteParamSpec {
                name: "service".to_string(),
                required: false,
                schema: service_name_schema(),
            },
            RouteParamSpec {
                name: "executionContext".to_string(),
                required: false,
                schema: execution_context_schema(),
            },
            RouteParamSpec {
                name: "status".to_string(),
                required: false,
                schema: json!({ "type": "string", "enum": ["active", "disabled", "deleted"] }),
            },
        ],
    );
    set_query_params(
        &mut routes,
        "GET",
        "/v1/admin/policy/service-managers",
        vec![RouteParamSpec {
            name: "service".to_string(),
            required: false,
            schema: service_name_schema(),
        }],
    );
    for method in ["PUT", "DELETE"] {
        for (param, schema) in [
            ("service", service_name_schema()),
            (
                "principal",
                json!({ "type": "string", "minLength": 1, "maxLength": 256 }),
            ),
        ] {
            set_path_param_schema(
                &mut routes,
                method,
                "/v1/admin/policy/services/{service}/managers/{principal}",
                param,
                schema,
            );
        }
    }
    set_request_body_schema(
        &mut routes,
        "POST",
        "/v1/admin/policy/grants",
        policy_grant_schema(false),
    );
    set_request_body_schema(
        &mut routes,
        "PATCH",
        "/v1/admin/policy/grants/{grant_ref}",
        policy_grant_schema(true),
    );
    add_required_integer_query_params(
        &mut routes,
        "DELETE",
        "/v1/admin/policy/grants/{grant_ref}",
        &["expectedVersion"],
        1,
    );
    routes
}

fn principal_group_admin_routes() -> Vec<HttpRouteSpec> {
    let mut routes = vec![
        get_management_route(
            "/v1/admin/groups",
            "admin.groups.list",
            RouteAccess::AdminRead,
        ),
        body_route(
            "POST",
            "/v1/admin/groups",
            "admin.groups.create",
            RouteAccess::AdminWrite,
            ResponseKind::ManagementEnvelope,
            ExitPolicy::ManagementOk,
            Vec::new(),
        ),
        get_management_route(
            "/v1/admin/groups/{group}",
            "admin.groups.inspect",
            RouteAccess::AdminRead,
        ),
        body_route(
            "PATCH",
            "/v1/admin/groups/{group}",
            "admin.groups.patch",
            RouteAccess::AdminWrite,
            ResponseKind::ManagementEnvelope,
            ExitPolicy::ManagementOk,
            Vec::new(),
        ),
        get_management_route(
            "/v1/admin/groups/{group}/members",
            "admin.groups.members.list",
            RouteAccess::AdminRead,
        ),
        no_body_route(
            "PUT",
            "/v1/admin/groups/{group}/members/{principal}",
            "admin.groups.members.add",
            RouteAccess::AdminWrite,
            ResponseKind::ManagementEnvelope,
            ExitPolicy::ManagementOk,
        ),
        no_body_route(
            "DELETE",
            "/v1/admin/groups/{group}/members/{principal}",
            "admin.groups.members.delete",
            RouteAccess::AdminWrite,
            ResponseKind::ManagementEnvelope,
            ExitPolicy::ManagementOk,
        ),
        get_management_route(
            "/v1/admin/groups/{group}/external-group-bindings",
            "admin.groups.external_group_bindings.list",
            RouteAccess::AdminRead,
        ),
        body_route(
            "POST",
            "/v1/admin/groups/{group}/external-group-bindings",
            "admin.groups.external_group_bindings.create",
            RouteAccess::AdminWrite,
            ResponseKind::ManagementEnvelope,
            ExitPolicy::ManagementOk,
            Vec::new(),
        ),
        body_route(
            "PATCH",
            "/v1/admin/groups/{group}/external-group-bindings/{binding}",
            "admin.groups.external_group_bindings.patch",
            RouteAccess::AdminWrite,
            ResponseKind::ManagementEnvelope,
            ExitPolicy::ManagementOk,
            Vec::new(),
        ),
        no_body_route(
            "DELETE",
            "/v1/admin/groups/{group}/external-group-bindings/{binding}",
            "admin.groups.external_group_bindings.delete",
            RouteAccess::AdminWrite,
            ResponseKind::ManagementEnvelope,
            ExitPolicy::ManagementOk,
        ),
        get_management_route(
            "/v1/admin/principals",
            "admin.principals.list",
            RouteAccess::AdminRead,
        ),
        body_route(
            "POST",
            "/v1/admin/principals",
            "admin.principals.create",
            RouteAccess::AdminWrite,
            ResponseKind::ManagementEnvelope,
            ExitPolicy::ManagementOk,
            Vec::new(),
        ),
        get_management_route(
            "/v1/admin/principals/{principal}",
            "admin.principals.inspect",
            RouteAccess::AdminRead,
        ),
        body_route(
            "PATCH",
            "/v1/admin/principals/{principal}",
            "admin.principals.patch",
            RouteAccess::AdminWrite,
            ResponseKind::ManagementEnvelope,
            ExitPolicy::ManagementOk,
            Vec::new(),
        ),
        no_body_route(
            "PUT",
            "/v1/admin/principals/{principal}/groups/{group}",
            "admin.principals.groups.add",
            RouteAccess::AdminWrite,
            ResponseKind::ManagementEnvelope,
            ExitPolicy::ManagementOk,
        ),
        no_body_route(
            "DELETE",
            "/v1/admin/principals/{principal}/groups/{group}",
            "admin.principals.groups.delete",
            RouteAccess::AdminWrite,
            ResponseKind::ManagementEnvelope,
            ExitPolicy::ManagementOk,
        ),
        body_route(
            "PATCH",
            "/v1/admin/principals/{principal}/access",
            "admin.principals.access.patch",
            RouteAccess::AdminWrite,
            ResponseKind::ManagementEnvelope,
            ExitPolicy::ManagementOk,
            Vec::new(),
        ),
        get_management_route(
            "/v1/admin/principals/{principal}/identity-token",
            "admin.principals.identity_token.inspect",
            RouteAccess::AdminRead,
        ),
        body_route(
            "PUT",
            "/v1/admin/principals/{principal}/identity-token",
            "admin.principals.identity_token.set",
            RouteAccess::AdminWrite,
            ResponseKind::ManagementEnvelope,
            ExitPolicy::ManagementOk,
            vec!["/body/token".to_string()],
        ),
        no_body_route(
            "DELETE",
            "/v1/admin/principals/{principal}/identity-token",
            "admin.principals.identity_token.remove",
            RouteAccess::AdminWrite,
            ResponseKind::ManagementEnvelope,
            ExitPolicy::ManagementOk,
        ),
        no_body_route(
            "POST",
            "/v1/admin/principals/{principal}/identity-token/reveal",
            "admin.principals.identity_token.reveal",
            RouteAccess::AdminWrite,
            ResponseKind::ManagementEnvelope,
            ExitPolicy::ManagementOk,
        ),
        no_body_route(
            "POST",
            "/v1/admin/principals/{principal}/identity-token/generate",
            "admin.principals.identity_token.generate",
            RouteAccess::AdminWrite,
            ResponseKind::ManagementEnvelope,
            ExitPolicy::ManagementOk,
        ),
        get_management_route(
            "/v1/admin/principals/{principal}/identity-access",
            "admin.principals.identity_access.inspect",
            RouteAccess::AdminRead,
        ),
        body_route(
            "PATCH",
            "/v1/admin/principals/{principal}/identity-access",
            "admin.principals.identity_access.patch",
            RouteAccess::AdminWrite,
            ResponseKind::ManagementEnvelope,
            ExitPolicy::ManagementOk,
            Vec::new(),
        ),
        get_management_route(
            "/v1/admin/principals/{principal}/identity-bindings",
            "admin.principals.identity_bindings.list",
            RouteAccess::AdminRead,
        ),
        body_route(
            "POST",
            "/v1/admin/principals/{principal}/identity-bindings",
            "admin.principals.identity_bindings.create",
            RouteAccess::AdminWrite,
            ResponseKind::ManagementEnvelope,
            ExitPolicy::ManagementOk,
            Vec::new(),
        ),
        body_route(
            "PATCH",
            "/v1/admin/principals/{principal}/identity-bindings/{binding}",
            "admin.principals.identity_bindings.patch",
            RouteAccess::AdminWrite,
            ResponseKind::ManagementEnvelope,
            ExitPolicy::ManagementOk,
            Vec::new(),
        ),
        no_body_route(
            "DELETE",
            "/v1/admin/principals/{principal}/identity-bindings/{binding}",
            "admin.principals.identity_bindings.delete",
            RouteAccess::AdminWrite,
            ResponseKind::ManagementEnvelope,
            ExitPolicy::ManagementOk,
        ),
        get_management_route(
            "/v1/admin/principals/{principal}/login-methods",
            "admin.principals.login_methods.list",
            RouteAccess::AdminRead,
        ),
        body_route(
            "PUT",
            "/v1/admin/principals/{principal}/login-methods/local-password",
            "admin.principals.local_password.reset",
            RouteAccess::AdminWrite,
            ResponseKind::ManagementEnvelope,
            ExitPolicy::ManagementOk,
            vec!["/body/password".to_string()],
        ),
        body_route(
            "POST",
            "/v1/admin/principals/{principal}/login-methods/local-password/enable",
            "admin.principals.local_password.enable",
            RouteAccess::AdminWrite,
            ResponseKind::ManagementEnvelope,
            ExitPolicy::ManagementOk,
            vec!["/body/password".to_string()],
        ),
        no_body_route(
            "DELETE",
            "/v1/admin/principals/{principal}/login-methods/local-password",
            "admin.principals.local_password.disable",
            RouteAccess::AdminWrite,
            ResponseKind::ManagementEnvelope,
            ExitPolicy::ManagementOk,
        ),
        no_body_route(
            "POST",
            "/v1/admin/principals/{principal}/login-methods/local-password/unlock",
            "admin.principals.local_password.unlock",
            RouteAccess::AdminWrite,
            ResponseKind::ManagementEnvelope,
            ExitPolicy::ManagementOk,
        ),
        body_route(
            "PUT",
            "/v1/admin/principals/{principal}/login-methods/oidc/microsoft",
            "admin.principals.login_methods.oidc.microsoft.link",
            RouteAccess::AdminWrite,
            ResponseKind::ManagementEnvelope,
            ExitPolicy::ManagementOk,
            Vec::new(),
        ),
        no_body_route(
            "DELETE",
            "/v1/admin/principals/{principal}/login-methods/oidc/microsoft",
            "admin.principals.login_methods.oidc.microsoft.unlink",
            RouteAccess::AdminWrite,
            ResponseKind::ManagementEnvelope,
            ExitPolicy::ManagementOk,
        ),
        get_management_route(
            "/v1/admin/principals/{principal}/services",
            "admin.principals.services",
            RouteAccess::AdminRead,
        ),
        get_management_route(
            "/v1/admin/principals/{principal}/service-limits",
            "admin.principals.service_limits.list",
            RouteAccess::AdminRead,
        ),
        body_route(
            "PUT",
            "/v1/admin/principals/{principal}/service-limits/{service}",
            "admin.principals.service_limits.set",
            RouteAccess::AdminWrite,
            ResponseKind::ManagementEnvelope,
            ExitPolicy::ManagementOk,
            Vec::new(),
        ),
        no_body_route(
            "DELETE",
            "/v1/admin/principals/{principal}/service-limits/{service}",
            "admin.principals.service_limits.clear",
            RouteAccess::AdminWrite,
            ResponseKind::ManagementEnvelope,
            ExitPolicy::ManagementOk,
        ),
    ];
    set_request_body_schema(
        &mut routes,
        "POST",
        "/v1/admin/groups/{group}/external-group-bindings",
        external_group_binding_create_body_schema(),
    );
    set_request_body_schema(
        &mut routes,
        "PATCH",
        "/v1/admin/groups/{group}/external-group-bindings/{binding}",
        external_group_binding_patch_body_schema(),
    );
    set_request_body_schema(
        &mut routes,
        "PATCH",
        "/v1/admin/principals/{principal}/identity-access",
        json!({"type":"object", "additionalProperties":false, "required":["paused","expectedVersion"],
            "properties":{"paused":{"type":"boolean"}, "expectedVersion":{"type":"integer","minimum":1}}}),
    );
    set_request_body_schema(
        &mut routes,
        "POST",
        "/v1/admin/principals/{principal}/identity-bindings",
        json!({"type":"object", "additionalProperties":false, "required":["namespace","username"],
            "properties":{"namespace":identity_namespace_schema(), "username":identity_username_schema()}}),
    );
    set_request_body_schema(
        &mut routes,
        "PATCH",
        "/v1/admin/principals/{principal}/identity-bindings/{binding}",
        json!({"type":"object", "additionalProperties":false, "required":["enabled","expectedVersion"],
            "properties":{"enabled":{"type":"boolean"}, "expectedVersion":{"type":"integer","minimum":1}}}),
    );
    add_required_integer_query_params(
        &mut routes,
        "DELETE",
        "/v1/admin/principals/{principal}/identity-bindings/{binding}",
        &["expectedVersion"],
        1,
    );
    for route in &mut routes {
        route.result_schema = match route.operation.as_str() {
            "admin.principals.identity_access.inspect"
            | "admin.principals.identity_access.patch" => Some(identity_access_schema()),
            "admin.principals.identity_bindings.list" => Some(json!({
                "title":"PrincipalIdentityBindingsResponse", "type":"object", "additionalProperties":false,
                "required":["bindings","configuredNamespaces"], "properties":{
                    "bindings":{"type":"array", "items":identity_binding_schema()},
                    "configuredNamespaces":{"type":"array", "items":{
                        "type":"object", "additionalProperties":false, "required":["namespace","credentialTransports"],
                        "properties":{"namespace":identity_namespace_schema(), "credentialTransports":{"type":"array","uniqueItems":true,
                            "items":{"enum":["authorization_user","caller_authorization"]}}}
                    }}
                }
            })),
            "admin.principals.identity_bindings.create"
            | "admin.principals.identity_bindings.patch" => Some(identity_binding_schema()),
            "admin.principals.identity_bindings.delete" => {
                Some(json!({"type":"object", "additionalProperties":false,
                "required":["deleted"], "properties":{"deleted":{"const":true}}}))
            }
            "admin.principals.identity_token.inspect"
            | "admin.principals.identity_token.set"
            | "admin.principals.identity_token.generate"
            | "admin.principals.identity_token.remove" => Some(json!({
                "type":"object", "additionalProperties":false, "required":["principalId","configured"],
                "properties":{"principalId":{"type":"string"}, "configured":{"type":"boolean"},
                    "revision":{"type":["integer","null"],"minimum":1}, "updatedAt":{"type":["string","null"],"format":"date-time"}}
            })),
            _ => route.result_schema.take(),
        };
    }
    for route in &mut routes {
        if route.operation == "admin.principals.identity_token.reveal" {
            route.sensitive_response_pointers = vec!["/result/token".to_string()];
        }
    }
    set_request_body_schema(
        &mut routes,
        "PUT",
        "/v1/admin/principals/{principal}/identity-token",
        json!({"type": "object", "additionalProperties": false, "required": ["token"],
            "properties": {"token": {"type": "string", "minLength": 32, "maxLength": 4096, "pattern": "^[!#$%&'*+.^_`|~0-9A-Za-z-]+$", "writeOnly": true}}}),
    );
    set_request_body_schema(
        &mut routes,
        "PUT",
        "/v1/admin/principals/{principal}/login-methods/oidc/microsoft",
        microsoft_oidc_link_body_schema(),
    );
    set_request_body_schema(
        &mut routes,
        "PUT",
        "/v1/admin/principals/{principal}/service-limits/{service}",
        service_limit_put_body_schema(),
    );
    for method in ["PUT", "DELETE"] {
        set_path_param_schema(
            &mut routes,
            method,
            "/v1/admin/principals/{principal}/service-limits/{service}",
            "service",
            service_name_schema(),
        );
    }
    let role_schema =
        json!({"type":"string", "enum":["user", "auditor", "service_policy_manager", "admin"]});
    set_request_body_schema(
        &mut routes,
        "PATCH",
        "/v1/admin/principals/{principal}/access",
        json!({"type":"object", "additionalProperties":false, "minProperties":1,
            "properties":{"role":role_schema, "selfServiceEnabled":{"type":"boolean"}}}),
    );
    set_request_body_schema(
        &mut routes,
        "POST",
        "/v1/admin/principals",
        json!({"type":"object", "additionalProperties":false, "required":["principalId"],
        "properties":{
            "principalId":{"type":"string","minLength":1},
            "kind":{"type":"string","enum":["user","system","service_account"],"default":"user"},
            "displayName":{"type":["string","null"]}, "email":{"type":["string","null"]},
            "externalSubject":{"type":["string","null"]},
            "role":role_schema, "selfServiceEnabled":{"type":"boolean"}
        }}),
    );
    routes
}

fn identity_namespace_schema() -> Value {
    json!({"type":"string", "minLength":1, "maxLength":128, "pattern":"^[A-Za-z0-9._\\-]{1,128}$"})
}

fn identity_username_schema() -> Value {
    json!({"type":"string", "minLength":1, "maxLength":128, "pattern":"^[A-Za-z0-9._@+-]+$",
        "description":"Exact, case-sensitive username. No trimming, normalization, account lookup or enrollment is implied."})
}

fn identity_access_schema() -> Value {
    json!({"type":"object", "additionalProperties":false,
        "required":["principalId","incarnation","paused","version","updatedAt","updatedBy"],
        "properties":{"principalId":{"type":"string"}, "incarnation":{"type":"string"},
            "paused":{"type":"boolean","description":"Blocks trusted username and fingerprint access; independent Broker tokens and sign-in remain available."},
            "version":{"type":"integer","minimum":1}, "updatedAt":{"type":"string","format":"date-time"}, "updatedBy":{"type":"string"}}})
}

fn identity_binding_schema() -> Value {
    json!({"type":"object", "additionalProperties":false,
        "required":["bindingId","principalId","namespace","username","enabled","version","createdAt","createdBy","updatedAt","updatedBy","namespaceAvailable"],
        "properties":{"bindingId":{"type":"string","format":"uuid"}, "principalId":{"type":"string"},
            "namespace":identity_namespace_schema(), "username":identity_username_schema(), "enabled":{"type":"boolean"},
            "version":{"type":"integer","minimum":1}, "createdAt":{"type":"string","format":"date-time"}, "createdBy":{"type":"string"},
            "updatedAt":{"type":"string","format":"date-time"}, "updatedBy":{"type":"string"}, "namespaceAvailable":{"type":"boolean"}}})
}

/// A per-principal service invocation limit override, bounded like
/// `[limits.invocations]` configuration.
fn service_limit_put_body_schema() -> Value {
    json!({
        "type": "object",
        "additionalProperties": false,
        "required": ["requests", "windowSeconds"],
        "properties": {
            "requests": {
                "type": "integer",
                "minimum": crate::INVOCATION_LIMIT_MIN_REQUESTS,
                "maximum": crate::INVOCATION_LIMIT_MAX_REQUESTS
            },
            "windowSeconds": {
                "type": "integer",
                "minimum": crate::INVOCATION_LIMIT_MIN_WINDOW_SECONDS,
                "maximum": crate::INVOCATION_LIMIT_MAX_WINDOW_SECONDS
            }
        }
    })
}

fn external_group_binding_create_body_schema() -> Value {
    json!({
        "type": "object",
        "additionalProperties": false,
        "required": ["externalGroupId"],
        "properties": {
            "externalGroupId": { "type": "string", "format": "uuid" }
        }
    })
}

fn external_group_binding_patch_body_schema() -> Value {
    json!({
        "type": "object",
        "additionalProperties": false,
        "required": ["status"],
        "properties": {
            "status": { "enum": ["active", "disabled"] }
        }
    })
}

fn microsoft_oidc_link_body_schema() -> Value {
    json!({
        "type": "object",
        "additionalProperties": false,
        "required": ["userObjectId"],
        "properties": {
            "userObjectId": { "type": "string", "format": "uuid" }
        }
    })
}

fn right_token_credential_admin_routes() -> Vec<HttpRouteSpec> {
    let mut routes = vec![
        get_management_route(
            "/v1/admin/principals/{principal}/credentials/targets",
            "admin.principals.credentials.targets",
            RouteAccess::AdminRead,
        ),
        get_management_route(
            "/v1/admin/principals/{principal}/agent-token-options",
            "admin.principals.agent_tokens.options",
            RouteAccess::AdminRead,
        ),
        get_management_route(
            "/v1/admin/principals/{principal}/agent-tokens",
            "admin.principals.agent_tokens.list",
            RouteAccess::AdminRead,
        ),
        body_route(
            "POST",
            "/v1/admin/principals/{principal}/agent-tokens",
            "admin.principals.agent_tokens.issue",
            RouteAccess::AdminWrite,
            ResponseKind::ManagementEnvelope,
            ExitPolicy::ManagementOk,
            Vec::new(),
        ),
        get_management_route(
            "/v1/admin/principals/{principal}/agent-tokens/{token_id}",
            "admin.principals.agent_tokens.inspect",
            RouteAccess::AdminRead,
        ),
        no_body_route(
            "DELETE",
            "/v1/admin/principals/{principal}/agent-tokens/{token_id}",
            "admin.principals.agent_tokens.revoke",
            RouteAccess::AdminWrite,
            ResponseKind::ManagementEnvelope,
            ExitPolicy::ManagementOk,
        ),
        no_body_route(
            "POST",
            "/v1/admin/principals/{principal}/agent-tokens/{token_id}/pause",
            "admin.principals.agent_tokens.pause",
            RouteAccess::AdminWrite,
            ResponseKind::ManagementEnvelope,
            ExitPolicy::ManagementOk,
        ),
        no_body_route(
            "POST",
            "/v1/admin/principals/{principal}/agent-tokens/{token_id}/resume",
            "admin.principals.agent_tokens.resume",
            RouteAccess::AdminWrite,
            ResponseKind::ManagementEnvelope,
            ExitPolicy::ManagementOk,
        ),
        body_route(
            "POST",
            "/v1/admin/principals/{principal}/tokens",
            "admin.principals.tokens.issue",
            RouteAccess::AdminWrite,
            ResponseKind::ManagementEnvelope,
            ExitPolicy::ManagementOk,
            Vec::new(),
        ),
        get_management_route(
            "/v1/admin/principals/{principal}/credentials/connections/{connection}",
            "admin.principals.credentials.inspect",
            RouteAccess::AdminRead,
        ),
        body_route(
            "PUT",
            "/v1/admin/principals/{principal}/credentials/connections/{connection}",
            "admin.principals.credentials.put",
            RouteAccess::AdminWrite,
            ResponseKind::ManagementEnvelope,
            ExitPolicy::ManagementOk,
            vec!["/body/secret".to_string()],
        ),
        no_body_route(
            "DELETE",
            "/v1/admin/principals/{principal}/credentials/connections/{connection}",
            "admin.principals.credentials.delete",
            RouteAccess::AdminWrite,
            ResponseKind::ManagementEnvelope,
            ExitPolicy::ManagementOk,
        ),
        body_route(
            "POST",
            "/v1/admin/principals/{principal}/credentials/connections/{connection}/verify",
            "admin.principals.credentials.verify",
            RouteAccess::AdminWrite,
            ResponseKind::ManagementEnvelope,
            ExitPolicy::ManagementOk,
            Vec::new(),
        ),
        get_management_route(
            "/v1/admin/principals/{principal}/credentials/connections/{connection}/input-schema",
            "admin.principals.credentials.input_schema",
            RouteAccess::AdminRead,
        ),
        get_management_route(
            "/v1/admin/rights",
            "admin.rights.list",
            RouteAccess::AdminRead,
        ),
        body_route(
            "POST",
            "/v1/admin/rights",
            "admin.rights.grant",
            RouteAccess::AdminWrite,
            ResponseKind::ManagementEnvelope,
            ExitPolicy::ManagementOk,
            Vec::new(),
        ),
        no_body_route(
            "DELETE",
            "/v1/admin/rights/{right_id}",
            "admin.rights.revoke",
            RouteAccess::AdminWrite,
            ResponseKind::ManagementEnvelope,
            ExitPolicy::ManagementOk,
        ),
        get_management_route(
            "/v1/admin/tokens",
            "admin.tokens.list",
            RouteAccess::AdminRead,
        ),
        get_management_route(
            "/v1/admin/tokens/{token_id}",
            "admin.tokens.inspect",
            RouteAccess::AdminRead,
        ),
        no_body_route(
            "DELETE",
            "/v1/admin/tokens/{token_id}",
            "admin.tokens.revoke",
            RouteAccess::AdminWrite,
            ResponseKind::ManagementEnvelope,
            ExitPolicy::ManagementOk,
        ),
        no_body_route(
            "POST",
            "/v1/admin/tokens/{token_id}/pause",
            "admin.tokens.pause",
            RouteAccess::AdminWrite,
            ResponseKind::ManagementEnvelope,
            ExitPolicy::ManagementOk,
        ),
        no_body_route(
            "POST",
            "/v1/admin/tokens/{token_id}/resume",
            "admin.tokens.resume",
            RouteAccess::AdminWrite,
            ResponseKind::ManagementEnvelope,
            ExitPolicy::ManagementOk,
        ),
        get_management_route(
            "/v1/admin/credentials",
            "admin.credentials.list",
            RouteAccess::AdminRead,
        ),
        body_route(
            "POST",
            "/v1/admin/credentials/rewrap",
            "admin.credentials.rewrap",
            RouteAccess::AdminWrite,
            ResponseKind::ManagementEnvelope,
            ExitPolicy::ManagementOk,
            Vec::new(),
        ),
        get_management_route(
            "/v1/admin/credentials/{credential_id}",
            "admin.credentials.inspect",
            RouteAccess::AdminRead,
        ),
        no_body_route(
            "DELETE",
            "/v1/admin/credentials/{credential_id}",
            "admin.credentials.delete",
            RouteAccess::AdminWrite,
            ResponseKind::ManagementEnvelope,
            ExitPolicy::ManagementOk,
        ),
    ];
    add_query_params(
        &mut routes,
        "GET",
        "/v1/admin/principals/{principal}/agent-tokens",
        &["includeRevoked", "includeExpired"],
    );
    add_query_params(
        &mut routes,
        "GET",
        "/v1/admin/principals/{principal}/credentials/connections/{connection}/input-schema",
        &["profile"],
    );
    set_request_body_schema(
        &mut routes,
        "PUT",
        "/v1/admin/principals/{principal}/credentials/connections/{connection}",
        credential_put_body_schema(),
    );
    set_request_body_schema(
        &mut routes,
        "POST",
        "/v1/admin/principals/{principal}/credentials/connections/{connection}/verify",
        credential_verify_body_schema(),
    );
    set_result_schema(
        &mut routes,
        "GET",
        "/v1/admin/principals/{principal}/credentials/targets",
        credential_targets_result_schema(),
    );
    add_query_params(&mut routes, "GET", "/v1/admin/tokens", &["principal"]);
    add_query_params(&mut routes, "GET", "/v1/admin/credentials", &["principal"]);
    set_request_body_schema(
        &mut routes,
        "POST",
        "/v1/admin/principals/{principal}/agent-tokens",
        agent_token_issue_body_schema(),
    );
    set_request_body_schema(
        &mut routes,
        "POST",
        "/v1/admin/principals/{principal}/tokens",
        admin_token_issue_body_schema(),
    );
    routes
}

fn add_query_params(routes: &mut [HttpRouteSpec], method: &str, route: &str, params: &[&str]) {
    if let Some(spec) = routes
        .iter_mut()
        .find(|spec| spec.method == method && spec.route == route)
    {
        spec.query_params = params
            .iter()
            .map(|param| route_param(param, false))
            .collect();
    }
}

fn set_query_params(
    routes: &mut [HttpRouteSpec],
    method: &str,
    route: &str,
    params: Vec<RouteParamSpec>,
) {
    if let Some(spec) = routes
        .iter_mut()
        .find(|spec| spec.method == method && spec.route == route)
    {
        spec.query_params = params;
    }
}

fn set_path_param_schema(
    routes: &mut [HttpRouteSpec],
    method: &str,
    route: &str,
    param: &str,
    schema: Value,
) {
    if let Some(path_param) = routes
        .iter_mut()
        .find(|spec| spec.method == method && spec.route == route)
        .and_then(|spec| {
            spec.path_params
                .iter_mut()
                .find(|candidate| candidate.name == param)
        })
    {
        path_param.schema = schema;
    }
}

fn service_name_schema() -> Value {
    json!({ "type": "string", "pattern": "^[a-z][a-z0-9_-]{0,62}$" })
}

fn execution_context_schema() -> Value {
    json!({ "type": "string", "pattern": "^[a-z][a-z0-9_-]{0,63}$" })
}

fn set_request_body_schema(routes: &mut [HttpRouteSpec], method: &str, route: &str, schema: Value) {
    if let Some(spec) = routes
        .iter_mut()
        .find(|spec| spec.method == method && spec.route == route)
    {
        spec.request_body_schema = Some(schema);
    }
}

fn set_result_schema(routes: &mut [HttpRouteSpec], method: &str, route: &str, schema: Value) {
    if let Some(spec) = routes
        .iter_mut()
        .find(|spec| spec.method == method && spec.route == route)
    {
        spec.result_schema = Some(schema);
    }
}

/// The consuming services of a credential connection the caller is
/// entitled to.
fn connection_consumers_schema() -> Value {
    json!({
        "type": "array",
        "description": "Consuming services the caller (or, on administrator routes, the principal) holds a per_user grant on, in configured order.",
        "items": {
            "type": "object", "additionalProperties": false,
            "required": ["service", "displayName", "credentialVerificationInputs"],
            "properties": {
                "service": {"type": "string"},
                "displayName": {"type": "string"},
                "credentialVerificationInputs": {
                    "type": "array", "items": {"type": "string"},
                    "description": "Inputs verifying through this service needs besides the credential, such as repository for a Git gateway."
                }
            }
        }
    })
}

fn credential_put_body_schema() -> Value {
    json!({
        "type": "object", "additionalProperties": false, "required": ["secret"],
        "properties": {
            "profile": {"type": "string", "description": "Optional; must equal the connection's token profile."},
            "secret": {"type": "object", "description": "The fields of the connection's input schema."},
            "metadata": {"type": "object"}
        }
    })
}

fn credential_verify_body_schema() -> Value {
    json!({
        "type": "object", "additionalProperties": false,
        "properties": {
            "service": {"type": "string", "description": "The consuming service whose probe verifies the token, run as the credential owner; by default the first one the owner holds a per_user grant on that has a probe."},
            "repository": {"type": "string", "description": "The repository a Git gateway probe fetches under the owner's repo.fetch policy."}
        }
    })
}

fn credential_input_schema_schema() -> Value {
    json!({
        "type": "object", "additionalProperties": false,
        "required": ["connection", "profile", "credentialKind", "fields"],
        "properties": {
            "connection": {"type": "string"},
            "profile": {"type": "string"},
            "credentialKind": {"type": "string"},
            "fields": {"type": "array", "items": {"type": "object"}}
        }
    })
}

fn credential_targets_result_schema() -> Value {
    json!({
        "type": "array",
        "description": "Credential connections whose token can be stored now: the connection selects the token method for the principal's kind and, for Broker-issued callers, the principal holds a per_user grant on a consuming service.",
        "items": {
            "type": "object", "additionalProperties": false,
            "required": ["connection", "displayName", "consumers", "otherConsumers", "profile", "credentialKind", "inputSchema"],
            "properties": {
                "connection": {"type": "string"},
                "displayName": {"type": "string"},
                "consumers": connection_consumers_schema(),
                "otherConsumers": {"type": "integer", "minimum": 0},
                "profile": {"type": "string"},
                "credentialKind": {"type": "string"},
                "inputSchema": credential_input_schema_schema()
            }
        }
    })
}

fn personal_credentials_result_schema() -> Value {
    json!({
        "type": "object", "additionalProperties": false,
        "required": ["connections", "retained"],
        "properties": {
            "connections": {
                "type": "array",
                "description": "Credential connections the caller is entitled to through a consuming service, plus any connection whose active token the caller still owns.",
                "items": {
                    "type": "object", "additionalProperties": false,
                    "required": ["connection", "displayName", "method", "consumers", "otherConsumers", "profile", "credentialKind", "registration", "credential"],
                    "properties": {
                        "connection": {"type": "string"},
                        "displayName": {"type": "string"},
                        "method": {"enum": ["token", "oauth", "unavailable"]},
                        "consumers": connection_consumers_schema(),
                        "otherConsumers": {"type": "integer", "minimum": 0},
                        "profile": {"type": ["string", "null"]},
                        "credentialKind": {"type": ["string", "null"]},
                        "registration": {"type": ["string", "null"]},
                        "credential": {"type": ["object", "null"], "description": "The active token's metadata, keyed by connection."}
                    }
                }
            },
            "retained": {
                "type": "array",
                "description": "Stored rows the current configuration does not select, read-only; delete them by credentialId.",
                "items": {"type": "object"}
            }
        }
    })
}

fn execution_contexts_schema() -> Value {
    json!({
        "type": "array",
        "minItems": 1,
        "maxItems": 64,
        "uniqueItems": true,
        "items": {
            "type": "string",
            "pattern": "^[a-z][a-z0-9_-]{0,63}$"
        }
    })
}

fn allowed_services_schema() -> Value {
    json!({
        "type": "array",
        "minItems": 1,
        "uniqueItems": true,
        "items": {
            "type": "string",
            "pattern": "^[a-z][a-z0-9_-]{0,62}$"
        }
    })
}

fn resource_id_schema() -> Value {
    json!({"type":"string","minLength":1,"maxLength":128,"pattern":"^[A-Za-z0-9._-]{1,128}$","not":{"enum":[".",".."]}})
}

fn resource_selection_schema() -> Value {
    let ids = json!({"type":"array", "uniqueItems":true, "items":resource_id_schema()});
    json!({"type":"object","additionalProperties":false,"properties":{
        "resourceIds":ids,"resourceGroupIds":ids
    }})
}

fn service_restrictions_schema() -> Value {
    json!({
        "type":"object", "minProperties":1, "propertyNames":service_name_schema(),
        "additionalProperties": {
            "type":"object", "additionalProperties":false, "required":["actions"],
            "properties": {
                "actions":{"type":"array","minItems":1,"uniqueItems":true,
                    "items":{"type":"string","pattern":"^[a-z][a-z0-9_-]*(\\.[a-z][a-z0-9_-]*)*$"}},
                "resources":resource_selection_schema()
            }
        }
    })
}

fn agent_invoke_scopes_schema() -> Value {
    json!({
        "type": "object",
        "additionalProperties": false,
        "required": ["allowedExecutionContexts"],
        "properties": {
            "allowedExecutionContexts": execution_contexts_schema(),
            "allowedServices": allowed_services_schema(),
            "serviceRestrictions": service_restrictions_schema()
        },
        "allOf": [{
            "if": { "required": ["serviceRestrictions"] },
            "then": { "required": ["allowedServices"] }
        }]
    })
}

fn agent_token_issue_body_schema() -> Value {
    json!({
        "type": "object",
        "additionalProperties": false,
        "required": ["name", "allowedExecutionContexts"],
        "properties": {
            "name": { "type": "string", "minLength": 1 },
            "ttl": { "type": "string", "pattern": "^[0-9]+[smhd]$" },
            "expiresAt": { "type": "string", "format": "date-time" },
            "never": { "type": "boolean" },
            "allowedExecutionContexts": execution_contexts_schema(),
            "allowedServices": allowed_services_schema(),
            "serviceRestrictions": service_restrictions_schema()
        },
        "allOf": expiry_input_exclusions(false).into_iter().chain([json!({
            "if": { "required": ["serviceRestrictions"] },
            "then": { "required": ["allowedServices"] }
        })]).collect::<Vec<_>>()
    })
}

fn admin_token_issue_body_schema() -> Value {
    let mut all_of = expiry_input_exclusions(true);
    all_of.push(json!({
        "if": {
            "required": ["tokenClass"],
            "properties": { "tokenClass": { "const": "agent_invoke" } }
        },
        "then": {
            "required": ["scopes"],
            "properties": {
                "scopes": agent_invoke_scopes_schema()
            }
        },
        "else": {
            "properties": {
                "scopes": {
                    "type": "object",
                    "not": {
                        "anyOf": [
                            { "required": ["allowedExecutionContexts"] },
                            { "required": ["allowedServices"] },
                            { "required": ["serviceRestrictions"] }
                        ]
                    }
                }
            }
        }
    }));
    json!({
        "type": "object",
        "additionalProperties": false,
        "required": ["name", "tokenClass"],
        "properties": {
            "name": { "type": "string", "minLength": 1 },
            "tokenClass": { "enum": ["agent_invoke", "user_manage", "admin"] },
            "scopes": { "type": "object" },
            "ttl": { "type": "string", "pattern": "^[0-9]+[smhd]$" },
            "ttlSeconds": { "type": "integer", "minimum": 1 },
            "expiresAt": { "type": "string", "format": "date-time" },
            "never": { "type": "boolean" }
        },
        "allOf": all_of
    })
}

fn expiry_input_exclusions(include_ttl_seconds: bool) -> Vec<Value> {
    let mut inputs = vec!["ttl", "expiresAt", "never"];
    if include_ttl_seconds {
        inputs.push("ttlSeconds");
    }
    let mut exclusions = Vec::new();
    for (index, left) in inputs.iter().enumerate() {
        for right in inputs.iter().skip(index + 1) {
            exclusions.push(json!({
                "not": {
                    "allOf": [
                        expiry_input_active_schema(left),
                        expiry_input_active_schema(right)
                    ]
                }
            }));
        }
    }
    if include_ttl_seconds {
        exclusions.push(json!({
            "if": {
                "required": ["never"],
                "properties": { "never": { "const": true } }
            },
            "then": {
                "properties": { "tokenClass": { "const": "agent_invoke" } }
            }
        }));
    }
    exclusions
}

fn expiry_input_active_schema(input: &str) -> Value {
    if input == "never" {
        json!({
            "required": ["never"],
            "properties": { "never": { "const": true } }
        })
    } else {
        json!({ "required": [input] })
    }
}

fn add_required_integer_query_params(
    routes: &mut [HttpRouteSpec],
    method: &str,
    route: &str,
    params: &[&str],
    minimum: i64,
) {
    if let Some(spec) = routes
        .iter_mut()
        .find(|spec| spec.method == method && spec.route == route)
    {
        spec.query_params = params
            .iter()
            .map(|param| RouteParamSpec {
                name: (*param).to_string(),
                required: true,
                schema: json!({ "type": "integer", "minimum": minimum }),
            })
            .collect();
    }
}

fn get_management_route(route: &str, operation: &str, access: RouteAccess) -> HttpRouteSpec {
    get_route(route, operation, access, ResponseKind::ManagementEnvelope)
}

fn get_route(
    route: &str,
    operation: &str,
    access: RouteAccess,
    response_kind: ResponseKind,
) -> HttpRouteSpec {
    HttpRouteSpec {
        method: "GET".to_string(),
        route: route.to_string(),
        operation: operation.to_string(),
        access,
        path_params: route_path_params(route),
        query_params: Vec::new(),
        request_body_schema: None,
        sensitive_request_pointers: Vec::new(),
        sensitive_response_pointers: Vec::new(),
        response_kind,
        exit_policy: match response_kind {
            ResponseKind::ManagementEnvelope => ExitPolicy::ManagementOk,
            _ => ExitPolicy::HttpStatus,
        },
        body_allowed: false,
        null_body_allowed: false,
        required_feature: None,
        result_schema: None,
    }
}

fn no_body_route(
    method: &str,
    route: &str,
    operation: &str,
    access: RouteAccess,
    response_kind: ResponseKind,
    exit_policy: ExitPolicy,
) -> HttpRouteSpec {
    HttpRouteSpec {
        method: method.to_string(),
        route: route.to_string(),
        operation: operation.to_string(),
        access,
        path_params: route_path_params(route),
        query_params: Vec::new(),
        request_body_schema: None,
        sensitive_request_pointers: Vec::new(),
        sensitive_response_pointers: Vec::new(),
        response_kind,
        exit_policy,
        body_allowed: false,
        null_body_allowed: false,
        required_feature: None,
        result_schema: None,
    }
}

fn body_route(
    method: &str,
    route: &str,
    operation: &str,
    access: RouteAccess,
    response_kind: ResponseKind,
    exit_policy: ExitPolicy,
    sensitive_request_pointers: Vec<String>,
) -> HttpRouteSpec {
    HttpRouteSpec {
        method: method.to_string(),
        route: route.to_string(),
        operation: operation.to_string(),
        access,
        path_params: route_path_params(route),
        query_params: Vec::new(),
        request_body_schema: Some(permissive_object_schema()),
        sensitive_request_pointers,
        sensitive_response_pointers: Vec::new(),
        response_kind,
        exit_policy,
        body_allowed: true,
        null_body_allowed: false,
        required_feature: None,
        result_schema: None,
    }
}

fn route_param(name: &str, required: bool) -> RouteParamSpec {
    RouteParamSpec {
        name: name.to_string(),
        required,
        schema: json!({ "type": "string" }),
    }
}

fn permissive_object_schema() -> Value {
    json!({
        "type": "object",
        "additionalProperties": true
    })
}

fn invoke_send_variant(service: &str, action: &ApiActionSpec) -> Value {
    let mut required = vec!["version", "kind", "service", "action"];
    let inputs_schema = send_inputs_schema_for_action(action);
    if schema_requires_property_inputs(&inputs_schema) {
        required.push("inputs");
    }
    if matches!(action.io, ActionIo::RawDownload { .. }) {
        required.push("responseMode");
        required.push("output");
    }
    if matches!(action.io, ActionIo::MultipartUpload { .. }) {
        required.push("files");
    }
    let mut properties = serde_json::Map::from_iter([
        (
            "version".to_string(),
            json!({ "const": SEND_SCHEMA_VERSION }),
        ),
        ("kind".to_string(), json!({ "const": "invoke" })),
        ("service".to_string(), json!({ "const": service })),
        ("action".to_string(), json!({ "const": action.action })),
        ("inputs".to_string(), inputs_schema),
        (
            "responseMode".to_string(),
            if matches!(action.io, ActionIo::RawDownload { .. }) {
                json!({ "const": "stream" })
            } else {
                json!({ "enum": ["json"], "default": "json" })
            },
        ),
    ]);
    if action.supports_file_output() {
        properties.insert(
            "output".to_string(),
            json!({ "$ref": "#/definitions/output" }),
        );
        properties.insert(
            "metadataOutput".to_string(),
            json!({ "$ref": "#/definitions/metadataOutput" }),
        );
    }
    if !action.sensitive_input_pointers.is_empty() {
        properties.insert(
            "secretSources".to_string(),
            json!({ "$ref": "#/definitions/secretSources" }),
        );
    }
    if let ActionIo::MultipartUpload { plan } = &action.io {
        properties.insert("files".to_string(), multipart_upload_files_schema(plan));
    }
    properties.insert(
        "readContentFormat".to_string(),
        invoke_format_schema(&action.read_content_formats, "native"),
    );
    properties.insert(
        "responseFormat".to_string(),
        invoke_format_schema(&action.response_formats, "json"),
    );
    let mut schema = json!({
        "type": "object",
        "additionalProperties": false,
        "required": required,
        "properties": properties,
        "dependentRequired": { "metadataOutput": ["output"] },
        "x-agent-access-read-only": action.read_only,
        "x-agent-access-response-kind": action.response_kind,
        "x-agent-access-exit-policy": action.exit_policy,
        "x-agent-access-io": action.io,
        "x-agent-access-sensitive-pointers": action.sensitive_input_pointers,
        "x-agent-access-sensitive-output-pointers": action.sensitive_output_pointers
    });
    if let Some(documentation) = &action.documentation {
        schema["x-agent-access-documentation"] = documentation.clone();
    }
    schema
}

fn schema_requires_property_inputs(schema: &Value) -> bool {
    schema
        .get("required")
        .and_then(Value::as_array)
        .is_some_and(|required| !required.is_empty())
}

fn send_inputs_schema_for_action(action: &ApiActionSpec) -> Value {
    let mut schema = action.input_schema.clone();
    if let ActionIo::MultipartUpload { plan } = &action.io {
        remove_upload_metadata_schema_property(&mut schema, &plan.metadata_pointer);
    }
    schema
}

fn remove_upload_metadata_schema_property(schema: &mut Value, pointer: &str) {
    let segments = pointer
        .trim_start_matches('/')
        .split('/')
        .filter(|segment| !segment.is_empty())
        .map(unescape_json_pointer_segment)
        .collect::<Vec<_>>();
    if segments.is_empty() {
        return;
    }
    remove_schema_property_path(schema, &segments);
}

fn unescape_json_pointer_segment(segment: &str) -> String {
    segment.replace("~1", "/").replace("~0", "~")
}

fn remove_schema_property_path(schema: &mut Value, path: &[String]) {
    let Value::Object(schema_object) = schema else {
        return;
    };
    let Some(property) = path.first() else {
        return;
    };
    if path.len() == 1 {
        if let Some(Value::Object(properties)) = schema_object.get_mut("properties") {
            properties.remove(property);
        }
        if let Some(Value::Array(required)) = schema_object.get_mut("required") {
            required.retain(|value| value.as_str() != Some(property));
            if required.is_empty() {
                schema_object.remove("required");
            }
        }
        return;
    }
    let Some(Value::Object(properties)) = schema_object.get_mut("properties") else {
        return;
    };
    let Some(child) = properties.get_mut(property) else {
        return;
    };
    remove_schema_property_path(child, &path[1..]);
}

fn multipart_upload_files_schema(plan: &MultipartUploadSpec) -> Value {
    let mut schema = serde_json::Map::from_iter([
        ("type".to_string(), json!("array")),
        ("minItems".to_string(), json!(plan.min_files)),
        (
            "items".to_string(),
            json!({
                "type": "object",
                "additionalProperties": false,
                "required": ["role", "path"],
                "properties": {
                    "role": { "const": plan.role },
                    "path": { "type": "string" },
                    "filename": { "type": "string" }
                }
            }),
        ),
    ]);
    if let Some(max_files) = plan.max_files {
        schema.insert("maxItems".to_string(), json!(max_files));
    }
    if plan.caller_content_type_allowed
        && let Some(Value::Object(items)) = schema.get_mut("items")
        && let Some(Value::Object(properties)) = items.get_mut("properties")
    {
        properties.insert("contentType".to_string(), json!({ "type": "string" }));
    }
    Value::Object(schema)
}

fn http_send_variant(route: &HttpRouteSpec) -> Value {
    let mut required = vec!["version", "kind", "method", "route"];
    if !route.path_params.is_empty() {
        required.push("pathParams");
    }
    let mut properties = serde_json::Map::from_iter([
        (
            "version".to_string(),
            json!({ "const": SEND_SCHEMA_VERSION }),
        ),
        ("kind".to_string(), json!({ "const": "http" })),
        ("method".to_string(), json!({ "const": route.method })),
        ("route".to_string(), json!({ "const": route.route })),
        (
            "pathParams".to_string(),
            object_schema_for_params(&route.path_params, true),
        ),
        (
            "query".to_string(),
            object_schema_for_params(&route.query_params, false),
        ),
    ]);
    if !route.sensitive_request_pointers.is_empty() {
        properties.insert(
            "secretSources".to_string(),
            json!({ "$ref": "#/definitions/secretSources" }),
        );
    }
    if route.body_allowed {
        properties.insert(
            "body".to_string(),
            route
                .request_body_schema
                .clone()
                .unwrap_or_else(|| json!({ "type": "object" })),
        );
    }
    json!({
        "type": "object",
        "additionalProperties": false,
        "required": required,
        "properties": properties,
        "x-agent-access-response-kind": route.response_kind,
        "x-agent-access-exit-policy": route.exit_policy,
        "x-agent-access-sensitive-pointers": route.sensitive_request_pointers,
        "x-agent-access-sensitive-output-pointers": route.sensitive_response_pointers
    })
}

fn object_schema_for_params(params: &[RouteParamSpec], all_required: bool) -> Value {
    let properties = params
        .iter()
        .map(|param| (param.name.clone(), param.schema.clone()))
        .collect::<serde_json::Map<_, _>>();
    let required = params
        .iter()
        .filter(|param| all_required || param.required)
        .map(|param| Value::String(param.name.clone()))
        .collect::<Vec<_>>();
    json!({
        "type": "object",
        "additionalProperties": false,
        "required": required,
        "properties": properties
    })
}

fn generic_send_definitions() -> Value {
    json!({
        "secretSources": {
            "type": "array",
            "items": {
                "type": "object",
                "additionalProperties": false,
                "required": ["pointer", "source"],
                "properties": {
                    "pointer": { "type": "string", "pattern": "^/" },
                    "source": {
                        "oneOf": [
                            {
                                "type": "object",
                                "additionalProperties": false,
                                "required": ["type", "name"],
                                "properties": {
                                    "type": { "const": "env" },
                                    "name": { "type": "string" }
                                }
                            },
                            {
                                "type": "object",
                                "additionalProperties": false,
                                "required": ["type", "path"],
                                "properties": {
                                    "type": { "const": "file" },
                                    "path": { "type": "string" }
                                }
                            },
                            {
                                "type": "object",
                                "additionalProperties": false,
                                "required": ["type"],
                                "properties": {
                                    "type": { "const": "stdin" }
                                }
                            }
                        ]
                    }
                }
            }
        },
        "fileDescriptor": {
            "type": "object",
            "additionalProperties": false,
            "required": ["role", "path"],
            "properties": {
                "role": { "type": "string" },
                "path": { "type": "string" },
                "filename": { "type": "string" },
                "contentType": { "type": "string" }
            }
        },
        "output": {
            "oneOf": [
                {
                    "type": "object",
                    "additionalProperties": false,
                    "required": ["type", "path"],
                    "properties": {
                        "type": { "const": "file" },
                        "path": { "type": "string", "not": { "const": "-" } }
                    }
                },
                {
                    "type": "object",
                    "additionalProperties": false,
                    "required": ["type"],
                    "properties": { "type": { "const": "stdout" } }
                }
            ]
        },
        "metadataOutput": {
            "oneOf": [
                {
                    "type": "object",
                    "additionalProperties": false,
                    "required": ["type"],
                    "properties": { "type": { "const": "stderr" } }
                },
                {
                    "type": "object",
                    "additionalProperties": false,
                    "required": ["type", "path"],
                    "properties": {
                        "type": { "const": "file" },
                        "path": { "type": "string" }
                    }
                }
            ]
        }
    })
}

fn envelope_schema(kind: ResponseKind) -> Value {
    let required = match kind {
        ResponseKind::ManagementEnvelope => vec!["requestId", "brokerRequestId", "decision"],
        ResponseKind::AuthEnvelope => vec!["requestId", "brokerRequestId", "decision"],
        ResponseKind::RawJson => Vec::new(),
        ResponseKind::ResponseEnvelope | ResponseKind::RawStream => {
            vec!["agentRequestId", "brokerRequestId", "decision"]
        }
    };
    if required.is_empty() {
        json!({ "type": ["object", "array"] })
    } else {
        json!({
            "type": "object",
            "required": required,
            "additionalProperties": true
        })
    }
}

#[cfg(test)]
mod tests;

#[cfg(test)]
mod managed_identity_contract_tests {
    use super::*;

    #[test]
    fn identity_management_schemas_require_versions_and_keep_inventory_separate() {
        let routes = principal_group_admin_routes();
        let route = |operation: &str| {
            routes
                .iter()
                .find(|route| route.operation == operation)
                .unwrap()
        };
        for (operation, field) in [
            ("admin.principals.identity_access.patch", "paused"),
            ("admin.principals.identity_bindings.patch", "enabled"),
        ] {
            let route = route(operation);
            assert_eq!(route.access, RouteAccess::AdminWrite);
            let validator =
                jsonschema::validator_for(route.request_body_schema.as_ref().unwrap()).unwrap();
            assert!(validator.is_valid(&json!({field:true,"expectedVersion":1})));
            assert!(!validator.is_valid(&json!({field:true})));
            assert!(!validator.is_valid(&json!({field:true,"expectedVersion":0})));
            assert!(
                !validator
                    .is_valid(&json!({field:true,"expectedVersion":1,"username":"replacement"}))
            );
        }
        let create = route("admin.principals.identity_bindings.create");
        let validator =
            jsonschema::validator_for(create.request_body_schema.as_ref().unwrap()).unwrap();
        assert!(
            validator.is_valid(
                &json!({"namespace":"Managed.Linux","username":"Alice+team@example.test"})
            )
        );
        for username in ["", " alice", "alice,bob", "alice/bob", "alîce"] {
            assert!(!validator.is_valid(&json!({"namespace":"managed_linux","username":username})));
        }
        assert!(!validator.is_valid(
            &json!({"namespace":"managed_linux","username":"alice","bindingId":"chosen"})
        ));
        let delete = route("admin.principals.identity_bindings.delete");
        assert_eq!(delete.query_params[0].name, "expectedVersion");
        assert!(delete.query_params[0].required);
        assert_eq!(delete.query_params[0].schema["minimum"], 1);
        for operation in [
            "admin.principals.identity_access.inspect",
            "admin.principals.identity_bindings.list",
        ] {
            assert_eq!(route(operation).access, RouteAccess::AdminRead);
        }
        let inventory = route("admin.principals.identity_token.inspect")
            .result_schema
            .as_ref()
            .unwrap();
        assert!(inventory["properties"].get("paused").is_none());
        assert!(inventory["properties"].get("revision").is_some());
        assert!(
            routes
                .iter()
                .all(|route| !route.route.ends_with("identity-token/pause")
                    && !route.route.ends_with("identity-token/resume"))
        );
        let listed = route("admin.principals.identity_bindings.list")
            .result_schema
            .as_ref()
            .unwrap();
        assert!(listed["properties"].get("configuredNamespaces").is_some());
        assert!(
            listed["properties"]["bindings"]["items"]["properties"]
                .get("namespaceAvailable")
                .is_some()
        );
    }

    #[test]
    fn identity_inventory_routes_are_admin_only_and_mark_secrets() {
        let routes = principal_group_admin_routes();
        let inventory: Vec<_> = routes
            .iter()
            .filter(|r| r.operation.starts_with("admin.principals.identity_token."))
            .collect();
        assert_eq!(inventory.len(), 5);
        for route in &inventory {
            assert_eq!(
                route.access,
                if route.method == "GET" {
                    RouteAccess::AdminRead
                } else {
                    RouteAccess::AdminWrite
                }
            );
        }
        let set = inventory
            .iter()
            .find(|r| r.operation.ends_with(".set"))
            .unwrap();
        assert_eq!(set.sensitive_request_pointers, ["/body/token"]);
        let schema = set.request_body_schema.as_ref().unwrap();
        assert_eq!(schema["additionalProperties"], false);
        assert_eq!(schema["properties"]["token"]["minLength"], 32);
        assert_eq!(schema["properties"]["token"]["writeOnly"], true);
        let reveal = inventory
            .iter()
            .find(|r| r.operation.ends_with(".reveal"))
            .unwrap();
        assert_eq!(reveal.method, "POST");
        assert_eq!(reveal.sensitive_response_pointers, ["/result/token"]);
        let send = http_send_variant(reveal);
        assert_eq!(
            send["x-agent-access-sensitive-output-pointers"],
            json!(["/result/token"])
        );
    }
}
