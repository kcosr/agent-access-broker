//! Pure MCP tool projections and discovery shapes shared by HTTP and local stdio adapters.
//! No transport, credentials, filesystem access, or policy decisions belong here.
use crate::{ApiActionSpec, ApiCatalog};
use agent_access_provider::ActionIo;
use serde_json::{Map, Value, json};
mod registry;
pub use registry::*;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProjectionMode {
    Stdio,
    Http,
}

#[derive(Debug, thiserror::Error)]
#[error("{0}")]
pub struct ProjectionError(pub &'static str);

/// Whether `mode` can serve the action: HTTP serves JSON I/O only, and stdio
/// also stages multipart uploads and raw downloads locally. An I/O kind this
/// build does not know is never served.
pub fn action_eligible(action: &ApiActionSpec, mode: ProjectionMode) -> bool {
    match action.io {
        ActionIo::Json => true,
        ActionIo::MultipartUpload { .. } | ActionIo::RawDownload { .. } => {
            mode == ProjectionMode::Stdio
        }
        _ => false,
    }
}

fn json_pointer_unescape(value: &str) -> String {
    value.replace("~1", "/").replace("~0", "~")
}

fn add_presentation_properties(properties: &mut Value, action: &ApiActionSpec) {
    if !action.read_content_formats.is_empty() {
        properties["readContentFormat"] =
            json!({"type":"string", "enum":action.read_content_formats});
    }
    if !action.response_formats.is_empty() {
        properties["responseFormat"] = json!({"type":"string", "enum":action.response_formats});
    }
}

fn helper_description<'a>(name: &str, local: &'a str, mode: ProjectionMode) -> &'a str {
    if mode == ProjectionMode::Stdio {
        return local;
    }
    match name {
        "services_list" => {
            "List services visible to the current identity, including display names, access surfaces, canonical action names, and local credential availability. Unavailable services retain a status with empty actions. Resolve setup requirements and refresh discovery. Actions may be restricted to particular resources. Eligible caller-visible invoke actions with JSON I/O have executable provider tools in this HTTP MCP interface. Use actions_describe to check tool availability and local stdio MCP for multipart uploads and raw downloads. Use services_describe for detailed service capabilities."
        }
        "actions_describe" => {
            "Describe one visible action, including extended usage documentation, its input schema, and execution requirements. For an eligible caller-visible JSON invoke action, also return its exact HTTP MCP tool name and complete argument schema. Naming conflicts and overlong names omit mcpTool and report mcpToolUnavailable. Multipart uploads and raw downloads remain describable but require local stdio MCP and omit mcpTool here. Use actions_list to check resource-specific policy. Invoke detail requires current caller-visible runtime catalog eligibility; retry discovery after permission changes."
        }
        _ => local,
    }
}

pub fn project_catalog(
    catalog: &ApiCatalog,
    mode: ProjectionMode,
) -> Result<Vec<Value>, ProjectionError> {
    project_catalog_bounded(catalog, mode, STDIO_MAX_CATALOG_BYTES)
}

/// Bound the complete definition projection, including tools not in the first page.
pub fn project_catalog_bounded(
    catalog: &ApiCatalog,
    mode: ProjectionMode,
    max_bytes: usize,
) -> Result<Vec<Value>, ProjectionError> {
    ToolRegistry::build(catalog, &McpView::Aggregate, mode, max_bytes)
        .map(|registry| registry.definitions())
}

pub fn validate_catalog_action(
    service: &str,
    action: &ApiActionSpec,
) -> Result<(), ProjectionError> {
    if !agent_access_provider::is_service_name(service)
        || !agent_access_provider::is_action_name(&action.action)
    {
        return Err(ProjectionError(
            "runtime catalog contains an invalid action identifier",
        ));
    }
    Ok(())
}

pub fn tool_name(service: &str, action: &str) -> String {
    format!("{service}_{action}")
        .chars()
        .map(|ch| if ch.is_ascii_alphanumeric() { ch } else { '_' })
        .collect()
}

pub fn input_schema(action: &ApiActionSpec, mode: ProjectionMode) -> Value {
    if mode == ProjectionMode::Http {
        let mut inputs = action.input_schema.clone();
        crate::api::relocate_local_schema_refs(&mut inputs, "#/properties/inputs");
        let mut properties = json!({"inputs": inputs});
        add_presentation_properties(&mut properties, action);
        return json!({"type":"object", "additionalProperties":false, "properties":properties, "required":["inputs"]});
    }
    let mut inputs = action.input_schema.clone();
    // Metadata is produced from local file snapshots, never supplied by the agent.
    if let ActionIo::MultipartUpload { plan } = &action.io {
        remove_generated_input(&mut inputs, &plan.metadata_pointer);
    }
    for pointer in &action.sensitive_input_pointers {
        if let Some(pointer) = pointer.strip_prefix("/inputs") {
            omit_required_pointer(&mut inputs, pointer);
        }
    }
    crate::api::relocate_local_schema_refs(&mut inputs, "#/properties/inputs");
    let mut properties = json!({
        "inputs": inputs,
        "requestFile": {"type":"string", "description":"Absolute local path to a JSON object containing action inputs (not an invoke envelope). Maximum 16 MiB. Mutually exclusive with inputs."}
    });
    if !action.sensitive_input_pointers.is_empty() {
        properties["secretSources"] = json!({"type":"array","description":"Inject catalog-declared sensitive fields from local environment variables or files; pointers address /inputs/... . stdin is unavailable.", "items": {
            "type":"object","additionalProperties":false,"required":["pointer","source"],"properties":{
                "pointer":{"type":"string","description":format!("Declared sensitive pointers (descendants also accepted): {}", action.sensitive_input_pointers.join(", "))},
                "source":{"oneOf":[
                    {"type":"object","additionalProperties":false,"required":["type","name"],"properties":{"type":{"const":"env"},"name":{"type":"string"}}},
                    {"type":"object","additionalProperties":false,"required":["type","path"],"properties":{"type":{"const":"file"},"path":{"type":"string","description":"Absolute local file path; maximum 1 MiB."}}}
                ]}
            }
        }});
    }
    let mut required = Vec::new();
    match &action.io {
        ActionIo::MultipartUpload { plan } => {
            let mut file_properties = json!({"role":{"const":plan.role},"path":{"type":"string","description":"Absolute local regular-file path."},"filename":{"type":"string"}});
            if plan.caller_content_type_allowed {
                file_properties["contentType"] = json!({"type":"string"});
            }
            properties["files"] = json!({"type":"array","minItems":plan.min_files,"description":"Upload files; combined maximum 512 MiB. File metadata is generated locally.","items":{"type":"object","additionalProperties":false,"required":["role","path"],"properties":file_properties}});
            if let Some(maximum) = plan.max_files {
                properties["files"]["maxItems"] = json!(maximum);
            }
            required.push("files");
        }
        ActionIo::RawDownload { .. } => {
            properties["outputPath"] = json!({"type":"string","description":"Absolute local destination path. Verified downloads atomically replace the destination. The Broker's configured download cap applies."});
            required.push("outputPath");
        }
        ActionIo::Json => {}
        // Never eligible for projection: see `action_eligible`.
        _ => {}
    }
    if action.supports_json_file_output() {
        properties["outputPath"] = json_output_path_schema();
    }
    if !action.read_content_formats.is_empty() {
        properties["readContentFormat"] =
            json!({"type":"string","enum":action.read_content_formats});
    }
    if !action.response_formats.is_empty() {
        properties["responseFormat"] = json!({"type":"string","enum":action.response_formats});
    }
    json!({"type":"object","additionalProperties":false,"properties":properties,"required":required,
        "oneOf":[{"required":["inputs"],"not":{"required":["requestFile"]}},{"required":["requestFile"],"not":{"required":["inputs"]}}]})
}

fn remove_generated_input(schema: &mut Value, pointer: &str) {
    omit_required_pointer(schema, pointer);
    let parts: Vec<_> = pointer
        .trim_start_matches('/')
        .split('/')
        .map(json_pointer_unescape)
        .collect();
    let Some((property, parents)) = parts.split_last() else {
        return;
    };
    let mut current = schema;
    for parent in parents {
        let Some(child) = current
            .get_mut("properties")
            .and_then(|properties| properties.get_mut(parent))
        else {
            return;
        };
        current = child;
    }
    if let Some(properties) = current.get_mut("properties").and_then(Value::as_object_mut) {
        properties.remove(property);
    }
}

fn omit_required_pointer(schema: &mut Value, pointer: &str) {
    let parts: Vec<_> = pointer
        .trim_start_matches('/')
        .split('/')
        .map(json_pointer_unescape)
        .collect();
    omit_required_path(schema, &parts);
}

fn omit_required_path(schema: &mut Value, parts: &[String]) {
    let Some((part, remaining)) = parts.split_first() else {
        return;
    };
    // A secret supplied outside inputs may satisfy a positive requirement in
    // any conjunction/disjunction. Preserve negative and conditional schemas:
    // blindly removing requirements beneath `not`, `if`, or `oneOf` changes
    // their meaning (and can make formerly exclusive branches overlap).
    // The broker validates the complete request after local secret injection.
    for keyword in ["allOf", "anyOf"] {
        if let Some(branches) = schema.get_mut(keyword).and_then(Value::as_array_mut) {
            for branch in branches {
                omit_required_path(branch, parts);
            }
        }
    }
    if remaining.is_empty() {
        if let Some(required) = schema.get_mut("required").and_then(Value::as_array_mut) {
            required.retain(|value| value.as_str() != Some(part));
        }
    } else if let Some(child) = schema
        .get_mut("properties")
        .and_then(|properties| properties.get_mut(part))
    {
        omit_required_path(child, remaining);
    }
}

const NAMES: [&str; 5] = [
    "services_list",
    "resource_access_describe",
    "actions_list",
    "actions_describe",
    "services_describe",
];

pub fn is_helper(name: &str) -> bool {
    NAMES.contains(&name)
}

fn json_output_path_schema() -> Value {
    json!({"type":"string","minLength":1,"description":"Optional absolute local destination path. Saves the complete successful JSON response and returns a compact file receipt. Atomically replaces the destination. Existing read limits and pagination still apply; this does not fetch additional content."})
}

pub fn helper_definitions(mode: ProjectionMode) -> Vec<Value> {
    let string = json!({"type":"string","minLength":1});
    let service = json!({"type":"string","minLength":1,"description":"Canonical configured service ID, not its display name."});
    let definitions = [
        (
            "services_list",
            "List services visible to the current identity, including display names, access surfaces, canonical action names, and local credential availability. Unavailable services retain a status with empty actions. Resolve setup requirements and refresh discovery. Actions may be restricted to particular resources. Only services with surface invoke have executable provider tools in this MCP interface. Use services_describe for detailed service capabilities.",
            json!({"prefix":string}),
            json!([]),
        ),
        (
            "resource_access_describe",
            "Describe local single-target access by action and resource type for one visible service. Filter by exact action or resourceType. Coverage includes exact, namespace, and all selectors; restricted:true means some targets are withheld without identifying them. Unscoped actions have scope:unscoped. registeredResources contains configured references, not upstream inventory; inputs address each reference. Optional liveListings names separately authorized enumeration actions. This does not prove upstream access or authorize a complete multi-resource request. Coverage repeats on every page. prefix, limit, and cursor page only registeredResources.items; repeat identical filters with registeredResources.nextCursor. Default limit 50, maximum 100.",
            json!({"service":service,"action":string,"resourceType":string,"prefix":string,"limit":{"type":"integer","minimum":1,"maximum":100,"default":50},"cursor":string}),
            json!(["service"]),
        ),
        (
            "actions_list",
            "List canonical action names for one visible service, optionally filtered to a concrete resource value (project key, space key, or repository path, not a broker resource ID). With a resource on a service that authorizes several resource types, also pass resourceType. A resource filter checks single-target policy and local credentials; invocation still checks upstream access and the complete multi-resource request. Coverage shown by resource_access_describe can permit values absent from its registeredResources.items. Use actions_describe for a selected action's schema.",
            json!({"service":service,"resource":string,"resourceType":string,"prefix":string}),
            json!(["service"]),
        ),
        (
            "actions_describe",
            "Describe one visible action, including extended usage documentation, its input schema, and execution requirements. For an MCP-callable action, also return its exact MCP tool name and complete MCP argument schema. Naming conflicts and overlong names omit mcpTool and report mcpToolUnavailable. Use this when preparing a call; use actions_list to check resource-specific policy. Invoke detail requires authentication and caller-visible runtime catalog eligibility. Anonymous callers receive the catalog's HTTP 401 as a tool error; use services_describe for raw capabilities where anonymous service discovery is allowed. Catalog absence can also reflect changed permissions: retry discovery.",
            json!({"service":service,"action":{"type":"string","minLength":1,"description":"Canonical action ID within the service, such as search or issue.view. Do not include the service prefix or use a client-renamed MCP tool name. Use the service/action values in the tool description or actions_list."}}),
            json!(["service", "action"]),
        ),
        (
            "services_describe",
            "Return detailed capabilities for one visible service, including its surface, resource scope types, and action definitions. This response can be large; prefer actions_describe when you need details for one action. Gateway services use their own execution interfaces.",
            json!({"service":service}),
            json!(["service"]),
        ),
    ];
    definitions.into_iter().map(|(name, description, mut properties, required)| {
        if mode == ProjectionMode::Stdio {
            properties["outputPath"] = json_output_path_schema();
        }
        json!({
            "name":name,"description":helper_description(name, description, mode),
            "inputSchema":{"type":"object","additionalProperties":false,"properties":properties,"required":required},
            // Stdio callers may overwrite a local file through outputPath. Tool hints
            // cover every supported argument combination, including that side effect.
            "annotations":{"readOnlyHint":mode == ProjectionMode::Http,"destructiveHint":mode == ProjectionMode::Stdio,"idempotentHint":true,"openWorldHint":false}
        })
    }).collect()
}

pub fn helper_definitions_for_view(mode: ProjectionMode, view: &McpView) -> Vec<Value> {
    let mut definitions = helper_definitions(mode);
    if let McpView::Service(service) = view {
        for definition in &mut definitions {
            let description = definition["description"]
                .as_str()
                .expect("static helper description");
            definition["description"] = json!(format!(
                "{description} This connection exposes only service {service}. Action IDs in discovery are canonical Broker IDs; executable mcpTool names use this connection's provider names."
            ));
            if let Some(schema) = definition["inputSchema"]["properties"].get_mut("service") {
                schema["const"] = json!(service);
            }
        }
    }
    definitions
}

pub fn validate_helper_arguments_for_view(
    name: &str,
    arguments: &Map<String, Value>,
    mode: ProjectionMode,
    view: &McpView,
) -> Result<(), ProjectionError> {
    validate_helper_arguments(name, arguments, mode)?;
    if view.service().is_some_and(|service| {
        arguments
            .get("service")
            .and_then(Value::as_str)
            .is_some_and(|requested| requested != service)
    }) {
        return Err(ProjectionError("service is outside this MCP view"));
    }
    Ok(())
}

pub fn validate_helper_arguments(
    name: &str,
    arguments: &Map<String, Value>,
    mode: ProjectionMode,
) -> Result<(), ProjectionError> {
    let definition = helper_definitions(mode)
        .into_iter()
        .find(|tool| tool["name"] == name)
        .ok_or(ProjectionError("unknown discovery helper"))?;
    let schema = &definition["inputSchema"];
    let properties = schema["properties"].as_object().expect("static properties");
    if arguments.keys().any(|key| !properties.contains_key(key)) {
        return Err(ProjectionError(
            "argument is not supported by this tool's schema",
        ));
    }
    for key in schema["required"]
        .as_array()
        .expect("static required fields")
    {
        if !arguments.contains_key(key.as_str().expect("static field name")) {
            return Err(ProjectionError(
                "invalid tool arguments: required field is missing",
            ));
        }
    }
    for (key, value) in arguments {
        if key == "limit" {
            if !value
                .as_u64()
                .is_some_and(|value| (1..=100).contains(&value))
            {
                return Err(ProjectionError("limit must be between 1 and 100"));
            }
        } else if !value.is_string() {
            return Err(ProjectionError("invalid tool arguments: expected a string"));
        }
    }
    if arguments
        .get("service")
        .and_then(Value::as_str)
        .is_some_and(|value| !agent_access_provider::is_service_name(value))
    {
        return Err(ProjectionError("service name is invalid"));
    }
    if arguments
        .get("action")
        .and_then(Value::as_str)
        .is_some_and(|value| !agent_access_provider::is_action_name(value))
    {
        return Err(ProjectionError("action name is invalid"));
    }
    for (key, message) in [
        ("prefix", "prefix must not be empty"),
        ("resource", "resource must not be empty"),
        ("resourceType", "resourceType must not be empty"),
        ("cursor", "cursor must not be empty"),
        ("outputPath", "outputPath must not be empty"),
    ] {
        if arguments.get(key).and_then(Value::as_str) == Some("") {
            return Err(ProjectionError(message));
        }
    }
    Ok(())
}

/// A validated capability value retaining fields unknown to this client version.
#[derive(Debug)]
pub struct DiscoveryServiceValue {
    pub capabilities: agent_access_provider::ServiceCapabilities,
    pub raw: Value,
}

pub fn project_service_list(
    value: Value,
    prefix: Option<&str>,
    verbose: bool,
) -> Result<Value, ProjectionError> {
    let mut services = parse_discovery_services(value)?;
    if let Some(prefix) = prefix {
        services.retain(|service| service.capabilities.service.starts_with(prefix));
    }
    services.sort_by(|left, right| left.capabilities.service.cmp(&right.capabilities.service));
    if verbose {
        return Ok(Value::Array(
            services.into_iter().map(|service| service.raw).collect(),
        ));
    }
    Ok(json!({"services":
        services
            .into_iter()
            .map(|service| {
                let mut names: Vec<_> = service.capabilities.actions.into_iter().map(|action| action.action).collect();
                names.sort();
                json!({
                    "service": service.capabilities.service,
                    "displayName": service.capabilities.display_name,
                    "surface": service.capabilities.surface,
                    "actions": names,
                    "availability": service.raw["availability"],
                })
            })
            .collect::<Vec<_>>()
    }))
}

fn parse_discovery_services(value: Value) -> Result<Vec<DiscoveryServiceValue>, ProjectionError> {
    let raw_services = value
        .as_array()
        .ok_or(ProjectionError("services response must be an array"))?
        .clone();
    let capabilities =
        serde_json::from_value::<Vec<agent_access_provider::ServiceCapabilities>>(value)
            .map_err(|_| ProjectionError("services response contains an invalid service"))?;
    capabilities
        .into_iter()
        .zip(raw_services)
        .map(|(capabilities, raw)| validate_discovery_service(capabilities, raw))
        .collect()
}

pub fn parse_discovery_service(value: Value) -> Result<DiscoveryServiceValue, ProjectionError> {
    let capabilities =
        serde_json::from_value::<agent_access_provider::ServiceCapabilities>(value.clone())
            .map_err(|_| ProjectionError("service response is invalid"))?;
    validate_discovery_service(capabilities, value)
}

fn validate_discovery_service(
    capabilities: agent_access_provider::ServiceCapabilities,
    raw: Value,
) -> Result<DiscoveryServiceValue, ProjectionError> {
    if !agent_access_provider::is_service_name(&capabilities.service) {
        return Err(ProjectionError(
            "service response contains an invalid service name",
        ));
    }
    if capabilities
        .actions
        .iter()
        .any(|action| !agent_access_provider::is_action_name(&action.action))
    {
        return Err(ProjectionError(
            "service response contains an invalid action name",
        ));
    }
    serde_json::from_value::<crate::ServiceAvailability>(raw["availability"].clone())
        .map_err(|_| ProjectionError("service response availability is invalid"))?;
    Ok(DiscoveryServiceValue { capabilities, raw })
}

pub fn discovery_actions(
    service: DiscoveryServiceValue,
) -> Result<Vec<(agent_access_provider::ActionCapabilities, Value)>, ProjectionError> {
    let raw_actions = service
        .raw
        .get("actions")
        .and_then(Value::as_array)
        .ok_or(ProjectionError("service response actions must be an array"))?;
    if raw_actions.len() != service.capabilities.actions.len() {
        return Err(ProjectionError("service response actions are inconsistent"));
    }
    Ok(service
        .capabilities
        .actions
        .into_iter()
        .zip(raw_actions.iter().cloned())
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn action(name: &str, io: Value) -> ApiActionSpec {
        serde_json::from_value(json!({
            "action":name,"scopedMcpName":name,"description":"Read or change project data","readOnly":false,"requiredScopeTypes":["project"],"credentialModes":["service"],
            "inputSchema":{"type":"object","additionalProperties":false,"required":["project","secret"],"$defs":{"Secret":{"type":"string","minLength":1}},"properties":{"project":{"type":"string"},"secret":{"$ref":"#/$defs/Secret","writeOnly":true}}},
            "sensitiveInputPointers":["/inputs/secret"],"sensitiveOutputPointers":["/result/issuedToken"],
            "io":io,"responseKind":"response_envelope","exitPolicy":"invoke_decision", "responseFormats":["json"]
        })).unwrap()
    }

    fn catalog() -> ApiCatalog {
        let mut catalog = crate::empty_catalog(json!({}));
        catalog.services.push(crate::ApiServiceSpec {
            availability: None,
            scoped_mcp_ready: true,
            service:"gitlab".into(), display_name:"GitLab".into(), surface:"invoke".into(), scope_types:vec!["project".into()], resource_scopes:Default::default(),
            actions:vec![
                action("file.write", json!({"type":"json"})),
                action("project.download",json!({"type":"raw_download", "metadataHeader":"X-Metadata", "metadataEncoding":"base64_json"})),
                action("project.upload",json!({"type":"multipart_upload", "plan":{"role":"attachment","metadataPointer":"/attachments","fieldNamePrefix":"file","minFiles":1,"maxFiles":1,"locatorInputs":["project"],"metadataFields":[],"callerContentTypeAllowed":false}})),
            ],
        });
        catalog
    }

    #[test]
    fn http_schema_preserves_required_sensitive_values_and_rejects_local_sources() {
        let action = action("file.write", json!({"type":"json"}));
        let schema = input_schema(&action, ProjectionMode::Http);
        let validator = jsonschema::validator_for(&schema).unwrap();
        assert!(validator.is_valid(&json!({"inputs":{"project":"team/repo","secret":"new secret"}, "responseFormat":"json"})));
        for invalid in [
            json!({"inputs":{"project":"team/repo"}}),
            json!({"inputs":{"project":"team/repo","secret":""}}),
            json!({"requestFile":"/tmp/input.json"}),
            json!({"inputs":{"project":"team/repo","secret":"value"}, "secretSources":[]}),
            json!({"inputs":{"project":"team/repo","secret":"value"}, "outputPath":"/tmp/output"}),
            json!({"inputs":{"project":"team/repo","secret":"value"}, "files":[]}),
            json!({"inputs":{"project":"team/repo","secret":"value"}, "responseFormat":"unsupported"}),
        ] {
            assert!(!validator.is_valid(&invalid), "accepted {invalid}");
        }
        assert_eq!(
            schema["properties"]["inputs"]["properties"]["secret"]["writeOnly"],
            true
        );
        let local = input_schema(&action, ProjectionMode::Stdio);
        let local_validator = jsonschema::validator_for(&local).unwrap();
        assert!(local_validator.is_valid(&json!({"requestFile":"/tmp/input.json"})));
        assert!(local_validator.is_valid(&json!({"inputs":{"project":"team/repo"},"secretSources":[{"pointer":"/inputs/secret","source":{"type":"env","name":"SECRET"}}]})));
    }

    #[test]
    fn http_catalog_filters_io_by_metadata_and_matches_action_details() {
        let mut catalog = catalog();
        let mut gateway = catalog.services[0].clone();
        gateway.service = "git".into();
        gateway.surface = "gateway".into();
        catalog.services.push(gateway);
        let http = project_catalog(&catalog, ProjectionMode::Http).unwrap();
        let local = project_catalog(&catalog, ProjectionMode::Stdio).unwrap();
        assert_eq!(http.len(), 6);
        assert_eq!(local.len(), 8);
        let http_registry = ToolRegistry::build(
            &catalog,
            &McpView::Aggregate,
            ProjectionMode::Http,
            STDIO_MAX_CATALOG_BYTES,
        )
        .unwrap();
        let local_registry = ToolRegistry::build(
            &catalog,
            &McpView::Aggregate,
            ProjectionMode::Stdio,
            STDIO_MAX_CATALOG_BYTES,
        )
        .unwrap();
        let action = &catalog.services[0].actions[0];
        let name = tool_name("gitlab", &action.action);
        let tool = http.iter().find(|value| value["name"] == name).unwrap();
        // A JSON action with "file" in its name is still callable remotely.
        assert_eq!(tool["_meta"]["agent-access/action"], "file.write");
        assert_eq!(
            tool["_meta"]["agent-access/sensitive-output-pointers"],
            json!(["/result/issuedToken"])
        );
        assert_eq!(
            http_registry
                .action_detail("gitlab", &action.action)
                .unwrap(),
            json!({"name":name,"inputSchema":tool["inputSchema"]})
        );
        for action in &catalog.services[0].actions[1..] {
            assert!(
                http_registry
                    .action_detail("gitlab", &action.action)
                    .is_none()
            );
            assert!(
                local_registry
                    .action_detail("gitlab", &action.action)
                    .is_some()
            );
        }
        catalog.services.push(catalog.services[0].clone());
        assert!(project_catalog(&catalog, ProjectionMode::Http).is_err());
    }

    #[test]
    fn helper_contracts_are_shared_with_transport_specific_execution_guidance() {
        let http = helper_definitions(ProjectionMode::Http);
        let local = helper_definitions(ProjectionMode::Stdio);
        assert!(!is_helper("resources_list"));
        assert!(!http.iter().any(|helper| helper["name"] == "resources_list"));
        for (http, local) in http.iter().zip(&local) {
            assert_eq!(http["name"], local["name"]);
            let mut local_schema = local["inputSchema"].clone();
            assert!(
                local_schema["properties"]
                    .as_object_mut()
                    .unwrap()
                    .remove("outputPath")
                    .is_some()
            );
            assert_eq!(http["inputSchema"], local_schema);
            assert_eq!(
                http["annotations"],
                json!({"readOnlyHint":true,"destructiveHint":false,"idempotentHint":true,"openWorldHint":false})
            );
            assert_eq!(
                local["annotations"],
                json!({"readOnlyHint":false,"destructiveHint":true,"idempotentHint":true,"openWorldHint":false})
            );
            let name = http["name"].as_str().unwrap();
            assert!(is_helper(name));
            if matches!(name, "services_list" | "actions_describe") {
                assert!(http["description"].as_str().unwrap().contains("stdio MCP"));
            } else {
                assert_eq!(http["description"], local["description"]);
            }
        }
        for invalid in [
            json!({"service":"gitlab","limit":0}),
            json!({"service":"gitlab","limit":101}),
            json!({"service":"gitlab","limit":1.5}),
            json!({"service":"gitlab","cursor":""}),
            json!({"service":"gitlab","action":""}),
            json!({"service":"gitlab","unexpected":true}),
            json!({"service":""}),
            json!({}),
        ] {
            assert!(
                validate_helper_arguments(
                    "resource_access_describe",
                    invalid.as_object().unwrap(),
                    ProjectionMode::Http
                )
                .is_err()
            );
        }
        assert!(
            validate_helper_arguments(
                "resource_access_describe",
                json!({"service":"gitlab","action":"project.view","limit":100})
                    .as_object()
                    .unwrap(),
                ProjectionMode::Http
            )
            .is_ok()
        );
    }

    #[test]
    fn local_json_tools_and_discovery_offer_file_output_independent_of_read_only() {
        let mut action = action("project.view", json!({"type":"json"}));
        action.read_only = true;
        let request = json!({"inputs":{"project":"team/repo","secret":"value"},"outputPath":"/tmp/result.json"});
        let stdio = input_schema(&action, ProjectionMode::Stdio);
        assert!(
            jsonschema::validator_for(&stdio)
                .unwrap()
                .is_valid(&request)
        );
        assert!(
            !jsonschema::validator_for(&input_schema(&action, ProjectionMode::Http))
                .unwrap()
                .is_valid(&request)
        );
        action.read_only = false;
        assert!(
            jsonschema::validator_for(&input_schema(&action, ProjectionMode::Stdio))
                .unwrap()
                .is_valid(&request)
        );
        let helper = json!({"outputPath":"/tmp/services.json"});
        assert!(
            validate_helper_arguments(
                "services_list",
                helper.as_object().unwrap(),
                ProjectionMode::Stdio
            )
            .is_ok()
        );
        assert!(
            validate_helper_arguments(
                "services_list",
                helper.as_object().unwrap(),
                ProjectionMode::Http
            )
            .is_err()
        );
    }

    #[test]
    fn discovery_projection_preserves_raw_metadata_but_keeps_compact_results_small() {
        let service = json!({"service":"gitlab","displayName":"GitLab","surface":"invoke","scopeTypes":["project"],"availability":{"state":"available","requirements":[],"message":"Locally available"},"futureServiceField":42,"actions":[{
            "action":"file.write","readOnly":false,"description":"Write content","requiredScopeTypes":[],"credentialModes":[],"lookupRequired":false,"inputSchema":{"type":"object"},"futureField":"preserved"
        }]});
        assert_eq!(
            project_service_list(json!([service.clone()]), None, false).unwrap(),
            json!({"services":[{"service":"gitlab","displayName":"GitLab","surface":"invoke","actions":["file.write"],"availability":{"state":"available","requirements":[],"message":"Locally available"}}]})
        );
        assert_eq!(
            project_service_list(json!([service.clone()]), None, true).unwrap(),
            json!([service.clone()])
        );
        let parsed = parse_discovery_service(service).unwrap();
        assert_eq!(
            discovery_actions(parsed).unwrap()[0].1["futureField"],
            "preserved"
        );
    }
}
