//! The `describe` manifest: parsing, validation and bounds.
//!
//! A manifest is one JSON document in the `agent-access-command/1` format.
//! Service-level problems (format, version, credential, verify, resource types,
//! action identities, unknown fields, OAuth block) fail discovery; a problem
//! confined to one action leaves that action listed as unsupported with its
//! reason.
use agent_access_core::imports::{
    COMMAND_FORMAT, IMPORT_MAX_DESCRIPTION_BYTES, IMPORT_MAX_MANIFEST_BYTES, IMPORT_MAX_TOOL_BYTES,
    IMPORT_MAX_TOOLS, ImportedCredentialDeclaration, ImportedCredentialKind,
    ImportedCredentialMode, ImportedResourceAttributeDeclaration,
};
use agent_access_provider::{AuditInputProjection, ResourcePattern};
use serde_json::{Map, Value};
use std::collections::BTreeSet;

/// Largest `describe` output.
pub(crate) const MAX_DESCRIBE_BYTES: usize = IMPORT_MAX_MANIFEST_BYTES;
const MAX_VERSION_BYTES: usize = 64;
const MAX_RESOURCE_TYPES: usize = 16;
const MAX_ATTRIBUTES: usize = 16;
const MAX_LABEL_BYTES: usize = 64;
const DEFAULT_MAX_LENGTH: u32 = 256;
/// The manifest's `maxLength` bound in bytes, within the SDK's 8,192.
const MAX_MAX_LENGTH: u32 = 1024;
/// The longest private attribute value, which bounds attribute patterns.
const MAX_ATTRIBUTE_VALUE_BYTES: usize = 8 * 1024;
const MAX_ATTRIBUTE_DESCRIPTION_BYTES: usize = 1024;
const MAX_RESOURCE_INPUTS: usize = 4;
const MAX_POINTER_BYTES: usize = 256;
const MAX_ACTION_NAME_BYTES: usize = 256;
const MAX_OAUTH_BYTES: usize = 16 * 1024;

/// A validated manifest.
#[derive(Debug, Clone, PartialEq)]
pub(crate) struct Manifest {
    pub version: String,
    pub credential: Option<ImportedCredentialDeclaration>,
    pub verify: bool,
    pub resource_types: Vec<ResourceType>,
    pub actions: Vec<ManifestAction>,
    /// The manifest declares phase-2 OAuth, which this Broker ignores.
    pub oauth_declared: bool,
}

/// A declared resource type, before the Broker assigns its type ID.
#[derive(Debug, Clone, PartialEq)]
pub(crate) struct ResourceType {
    pub id: String,
    pub supports_exclusions: bool,
    pub label: String,
    pub plural_label: String,
    pub pattern: String,
    pub max_length: u32,
    pub example: String,
    pub attributes: Vec<ImportedResourceAttributeDeclaration>,
}

/// One manifest action: its source identity and either its declaration or
/// the reason it is unsupported.
#[derive(Debug, Clone, PartialEq)]
pub(crate) struct ManifestAction {
    pub name: String,
    pub read_only_hint: Option<bool>,
    pub declaration: Result<ActionDeclaration, String>,
}

#[derive(Debug, Clone, PartialEq)]
pub(crate) struct ActionDeclaration {
    pub download: bool,
    pub description: String,
    pub input_schema: Value,
    pub output_schema: Option<Value>,
    /// The effective modes: the action's subset, else every declared mode;
    /// empty for a command without a credential.
    pub credential_modes: Vec<ImportedCredentialMode>,
    pub resources: Option<ResourceDeclaration>,
    /// Source type ID this action explicitly enumerates live.
    pub listing_of: Option<String>,
    /// Reviewed original caller inputs to retain in invocation audit.
    pub audit_inputs: Option<AuditInputProjection>,
}

/// `resources`: the declared type and, for a Broker-enforced action, the
/// input pointers that name the resources.
#[derive(Debug, Clone, PartialEq)]
pub(crate) struct ResourceDeclaration {
    pub resource_type: String,
    pub inputs: Vec<String>,
}

fn object<'a>(value: &'a Value, label: &str) -> Result<&'a Map<String, Value>, String> {
    value
        .as_object()
        .ok_or_else(|| format!("{label} must be an object"))
}

fn only_fields(object: &Map<String, Value>, allowed: &[&str], label: &str) -> Result<(), String> {
    match object.keys().find(|key| !allowed.contains(&key.as_str())) {
        Some(key) => Err(format!(
            "{label} has the unsupported field {:?}",
            truncate(key, 64)
        )),
        None => Ok(()),
    }
}

fn truncate(value: &str, max: usize) -> String {
    value.chars().take(max).collect()
}

fn text(value: Option<&Value>, label: &str, max: usize) -> Result<String, String> {
    let text = value
        .and_then(Value::as_str)
        .ok_or_else(|| format!("{label} must be a string"))?;
    if text.is_empty() || text.len() > max || text.chars().any(char::is_control) {
        return Err(format!(
            "{label} must have 1 to {max} bytes and no control characters"
        ));
    }
    Ok(text.to_owned())
}

fn identifier(value: &str, max: usize) -> bool {
    let bytes = value.as_bytes();
    (1..=max).contains(&bytes.len())
        && bytes[0].is_ascii_lowercase()
        && bytes
            .iter()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || *b == b'_')
}

fn attribute_name(value: &str) -> bool {
    let bytes = value.as_bytes();
    (1..=64).contains(&bytes.len())
        && bytes[0].is_ascii_lowercase()
        && bytes
            .iter()
            .all(|b| b.is_ascii_alphanumeric() || *b == b'_')
}

/// Compiles a declared pattern as the SDK resource pattern the Broker
/// registers, matching whole values of at most `max_length` bytes: the
/// `regex` crate dialect (linear time, no lookaround or backreferences), a
/// complete expression of 1 byte to 8 KiB, and 256 KiB program and lazy DFA
/// budgets.
pub(crate) fn resource_pattern(
    pattern: &str,
    max_length: usize,
) -> Result<ResourcePattern, String> {
    ResourcePattern::new(pattern, max_length)
}

fn modes(value: &Value, label: &str) -> Result<Vec<ImportedCredentialMode>, String> {
    let values = value
        .as_array()
        .filter(|values| !values.is_empty())
        .ok_or_else(|| format!("{label} must be a nonempty array"))?;
    let mut modes = BTreeSet::new();
    for value in values {
        let mode = match value.as_str() {
            Some("service") => ImportedCredentialMode::Service,
            Some("per_user") => ImportedCredentialMode::PerUser,
            _ => return Err(format!("{label} accepts only service and per_user")),
        };
        if !modes.insert(mode) {
            return Err(format!("{label} repeats a mode"));
        }
    }
    Ok(modes.into_iter().collect())
}

fn credential(value: &Value) -> Result<ImportedCredentialDeclaration, String> {
    let object = object(value, "credential")?;
    only_fields(object, &["kind", "modes"], "credential")?;
    let kind = match object.get("kind").and_then(Value::as_str) {
        Some("token") => ImportedCredentialKind::Token,
        Some("username_token") => ImportedCredentialKind::UsernameToken,
        _ => return Err("credential.kind must be token or username_token".into()),
    };
    let modes = modes(
        object.get("modes").unwrap_or(&Value::Null),
        "credential.modes",
    )?;
    Ok(ImportedCredentialDeclaration { kind, modes })
}

fn resource_type(value: &Value, index: usize) -> Result<ResourceType, String> {
    let label = format!("resourceTypes[{index}]");
    let object = object(value, &label)?;
    only_fields(
        object,
        &[
            "id",
            "label",
            "pluralLabel",
            "supportsExclusions",
            "pattern",
            "maxLength",
            "example",
            "attributes",
        ],
        &label,
    )?;
    let id = object
        .get("id")
        .and_then(Value::as_str)
        .filter(|id| identifier(id, 32))
        .ok_or_else(|| format!("{label}.id must match ^[a-z][a-z0-9_]{{0,31}}$"))?
        .to_owned();
    let pattern = object
        .get("pattern")
        .and_then(Value::as_str)
        .ok_or_else(|| format!("{label}.pattern must be a string"))?
        .to_owned();
    let max_length = match object.get("maxLength") {
        None => DEFAULT_MAX_LENGTH,
        Some(value) => value
            .as_u64()
            .filter(|length| (1..=u64::from(MAX_MAX_LENGTH)).contains(length))
            .map(|length| length as u32)
            .ok_or_else(|| format!("{label}.maxLength must be 1 to {MAX_MAX_LENGTH}"))?,
    };
    let grammar = resource_pattern(&pattern, max_length as usize)
        .map_err(|reason| format!("{label}.pattern: {reason}"))?;
    let example = object
        .get("example")
        .and_then(Value::as_str)
        .filter(|example| !example.is_empty())
        .ok_or_else(|| format!("{label}.example must be a nonempty string"))?
        .to_owned();
    if !grammar.is_match(&example) {
        return Err(format!(
            "{label}.example must match its pattern and maxLength"
        ));
    }
    let attributes = match object.get("attributes") {
        None => Vec::new(),
        Some(value) => {
            let values = value
                .as_array()
                .filter(|values| values.len() <= MAX_ATTRIBUTES)
                .ok_or_else(|| {
                    format!("{label}.attributes must be an array of at most {MAX_ATTRIBUTES}")
                })?;
            let mut names = BTreeSet::new();
            let mut attributes = Vec::new();
            for (position, value) in values.iter().enumerate() {
                let attribute = attribute(value, &format!("{label}.attributes[{position}]"))?;
                if !names.insert(attribute.name.clone()) {
                    return Err(format!("{label}.attributes repeat a name"));
                }
                attributes.push(attribute);
            }
            attributes
        }
    };
    let supports_exclusions = match object.get("supportsExclusions") {
        None => true,
        Some(value) => value
            .as_bool()
            .ok_or_else(|| format!("{label}.supportsExclusions must be a boolean"))?,
    };
    Ok(ResourceType {
        id,
        supports_exclusions,
        label: text(
            object.get("label"),
            &format!("{label}.label"),
            MAX_LABEL_BYTES,
        )?,
        plural_label: text(
            object.get("pluralLabel"),
            &format!("{label}.pluralLabel"),
            MAX_LABEL_BYTES,
        )?,
        pattern,
        max_length,
        example,
        attributes,
    })
}

fn attribute(value: &Value, label: &str) -> Result<ImportedResourceAttributeDeclaration, String> {
    let object = object(value, label)?;
    only_fields(
        object,
        &["name", "label", "description", "required", "pattern"],
        label,
    )?;
    let name = object
        .get("name")
        .and_then(Value::as_str)
        .filter(|name| attribute_name(name))
        .ok_or_else(|| format!("{label}.name must match ^[a-z][A-Za-z0-9_]{{0,63}}$"))?
        .to_owned();
    let description = object
        .get("description")
        .and_then(Value::as_str)
        .filter(|value| {
            value.len() <= MAX_ATTRIBUTE_DESCRIPTION_BYTES && !value.chars().any(char::is_control)
        })
        .ok_or_else(|| {
            format!(
                "{label}.description must be a string of at most {MAX_ATTRIBUTE_DESCRIPTION_BYTES} bytes"
            )
        })?
        .to_owned();
    let required = object
        .get("required")
        .and_then(Value::as_bool)
        .ok_or_else(|| format!("{label}.required must be a boolean"))?;
    let pattern = object
        .get("pattern")
        .map(|value| {
            let pattern = value
                .as_str()
                .ok_or_else(|| format!("{label}.pattern must be a string"))?;
            resource_pattern(pattern, MAX_ATTRIBUTE_VALUE_BYTES)
                .map_err(|reason| format!("{label}.pattern: {reason}"))?;
            Ok::<_, String>(pattern.to_owned())
        })
        .transpose()?;
    Ok(ImportedResourceAttributeDeclaration {
        name,
        label: text(
            object.get("label"),
            &format!("{label}.label"),
            MAX_LABEL_BYTES,
        )?,
        description,
        required,
        pattern,
    })
}

/// Parses and validates one `describe` document.
pub(crate) fn parse(bytes: &[u8]) -> Result<Manifest, String> {
    if bytes.len() > MAX_DESCRIBE_BYTES {
        return Err("the manifest exceeds 16 MiB".into());
    }
    let value: Value =
        serde_json::from_slice(bytes).map_err(|_| "the manifest is not one JSON document")?;
    let root = object(&value, "the manifest")?;
    only_fields(
        root,
        &[
            "format",
            "version",
            "credential",
            "verify",
            "resourceTypes",
            "actions",
            "oauth",
        ],
        "the manifest",
    )?;
    if root.get("format").and_then(Value::as_str) != Some(COMMAND_FORMAT) {
        return Err(format!("the manifest format must be {COMMAND_FORMAT}"));
    }
    let version = text(root.get("version"), "version", MAX_VERSION_BYTES)?;
    let credential = root.get("credential").map(credential).transpose()?;
    let verify = match root.get("verify") {
        None => false,
        Some(value) => value.as_bool().ok_or("verify must be a boolean")?,
    };
    if verify && credential.is_none() {
        return Err("verify requires a declared credential".into());
    }
    let oauth_declared = match root.get("oauth") {
        None => false,
        Some(value) => {
            object(value, "oauth")?;
            if serde_json::to_vec(value).map_or(true, |bytes| bytes.len() > MAX_OAUTH_BYTES) {
                return Err("oauth exceeds 16 KiB".into());
            }
            true
        }
    };
    let mut resource_types = Vec::new();
    if let Some(value) = root.get("resourceTypes") {
        let values = value
            .as_array()
            .filter(|values| values.len() <= MAX_RESOURCE_TYPES)
            .ok_or_else(|| {
                format!("resourceTypes must be an array of at most {MAX_RESOURCE_TYPES}")
            })?;
        let mut ids = BTreeSet::new();
        for (index, value) in values.iter().enumerate() {
            let declared = resource_type(value, index)?;
            if !ids.insert(declared.id.clone()) {
                return Err("resourceTypes repeat an id".into());
            }
            resource_types.push(declared);
        }
    }
    let values = root
        .get("actions")
        .and_then(Value::as_array)
        .filter(|values| values.len() <= IMPORT_MAX_TOOLS)
        .ok_or_else(|| format!("actions must be an array of at most {IMPORT_MAX_TOOLS}"))?;
    let mut names = BTreeSet::new();
    let mut actions = Vec::new();
    for (index, value) in values.iter().enumerate() {
        let name = value
            .get("name")
            .and_then(Value::as_str)
            .filter(|name| {
                !name.is_empty()
                    && name.len() <= MAX_ACTION_NAME_BYTES
                    && !name.chars().any(char::is_control)
            })
            .ok_or_else(|| {
                format!(
                    "actions[{index}].name must be a string of 1 to {MAX_ACTION_NAME_BYTES} bytes"
                )
            })?
            .to_owned();
        if !names.insert(name.clone()) {
            return Err(format!("actions repeat the name {:?}", truncate(&name, 64)));
        }
        let read_only_hint = value.get("readOnly").and_then(Value::as_bool);
        let declaration = action(value, credential.as_ref(), &resource_types);
        actions.push(ManifestAction {
            name,
            read_only_hint,
            declaration,
        });
    }
    Ok(Manifest {
        version,
        credential,
        verify,
        resource_types,
        actions,
        oauth_declared,
    })
}

fn action(
    value: &Value,
    credential: Option<&ImportedCredentialDeclaration>,
    resource_types: &[ResourceType],
) -> Result<ActionDeclaration, String> {
    let object = object(value, "the action")?;
    only_fields(
        object,
        &[
            "name",
            "description",
            "inputSchema",
            "outputSchema",
            "readOnly",
            "download",
            "credentialModes",
            "resources",
            "listingOf",
            "auditInputs",
        ],
        "the action",
    )?;
    if serde_json::to_vec(value).map_or(true, |bytes| bytes.len() > IMPORT_MAX_TOOL_BYTES) {
        return Err("the action exceeds 256 KiB".into());
    }
    let description = object
        .get("description")
        .and_then(Value::as_str)
        .filter(|description| description.len() <= IMPORT_MAX_DESCRIPTION_BYTES)
        .ok_or("description must be a string of at most 16 KiB")?
        .to_owned();
    if object
        .get("readOnly")
        .is_some_and(|value| !value.is_boolean())
    {
        return Err("readOnly must be a boolean".into());
    }
    let download = match object.get("download") {
        None => false,
        Some(Value::Bool(true)) => true,
        Some(_) => return Err("download must be true when present".into()),
    };
    if download && object.contains_key("listingOf") {
        return Err("download actions cannot declare listingOf".into());
    }
    let input_schema = object
        .get("inputSchema")
        .cloned()
        .ok_or("inputSchema is required")?;
    if input_schema.get("type").and_then(Value::as_str) != Some("object") {
        return Err("inputSchema must describe an object".into());
    }
    agent_access_core::imports::validate_import_schema(&input_schema)
        .map_err(|reason| format!("inputSchema: {reason}"))?;
    let output_schema = object.get("outputSchema").cloned();
    if let Some(schema) = &output_schema {
        agent_access_core::imports::validate_import_schema(schema)
            .map_err(|reason| format!("outputSchema: {reason}"))?;
    }
    let credential_modes = match (object.get("credentialModes"), credential) {
        (None, Some(credential)) => credential.modes.clone(),
        (None, None) => Vec::new(),
        (Some(_), None) => {
            return Err("credentialModes requires a declared credential".into());
        }
        (Some(value), Some(credential)) => {
            let modes = modes(value, "credentialModes")?;
            if !modes.iter().all(|mode| credential.modes.contains(mode)) {
                return Err("credentialModes must be a subset of credential.modes".into());
            }
            modes
        }
    };
    let resources = object
        .get("resources")
        .map(|value| resources(value, &input_schema, resource_types))
        .transpose()?;
    let listing_of = object
        .get("listingOf")
        .map(|value| listing_type(value, resources.as_ref()))
        .transpose()?;
    let audit_inputs = crate::audit_inputs::parse(object.get("auditInputs"), &input_schema)?;
    Ok(ActionDeclaration {
        download,
        description,
        input_schema,
        output_schema,
        credential_modes,
        resources,
        listing_of,
        audit_inputs,
    })
}

/// Listing is a collection over the same type whose authority the command
/// receives. Resource input pointers instead describe ordinary scoped calls.
pub(crate) fn listing_type(
    value: &Value,
    resources: Option<&ResourceDeclaration>,
) -> Result<String, String> {
    let listing = value
        .as_str()
        .filter(|listing| !listing.is_empty())
        .ok_or("listingOf must name the action's command-enforced resource type")?;
    if resources
        .is_none_or(|resources| resources.resource_type != listing || !resources.inputs.is_empty())
    {
        return Err("listingOf requires resources of the same type without input pointers".into());
    }
    Ok(listing.to_owned())
}

fn resources(
    value: &Value,
    input_schema: &Value,
    resource_types: &[ResourceType],
) -> Result<ResourceDeclaration, String> {
    let object = object(value, "resources")?;
    only_fields(object, &["type", "inputs"], "resources")?;
    let resource_type = object
        .get("type")
        .and_then(Value::as_str)
        .filter(|id| resource_types.iter().any(|declared| declared.id == *id))
        .ok_or("resources.type must name a declared resource type")?
        .to_owned();
    let inputs = match object.get("inputs") {
        None => Vec::new(),
        Some(value) => {
            let values = value
                .as_array()
                .filter(|values| (1..=MAX_RESOURCE_INPUTS).contains(&values.len()))
                .ok_or_else(|| {
                    format!("resources.inputs must list 1 to {MAX_RESOURCE_INPUTS} JSON pointers")
                })?;
            let mut inputs = Vec::new();
            for value in values {
                let pointer = value
                    .as_str()
                    .ok_or("resources.inputs must be JSON pointers")?;
                resource_input(input_schema, pointer)?;
                if inputs.iter().any(|existing| existing == pointer) {
                    return Err("resources.inputs repeat a pointer".into());
                }
                inputs.push(pointer.to_owned());
            }
            inputs
        }
    };
    Ok(ResourceDeclaration {
        resource_type,
        inputs,
    })
}

/// A resource input pointer must name a required string or string-array
/// input through `properties` of object schemas, each step required.
pub(crate) fn resource_input(input_schema: &Value, pointer: &str) -> Result<(), String> {
    let invalid = || {
        format!(
            "resources.inputs pointer {:?} must name a required string or string-array input",
            truncate(pointer, 64)
        )
    };
    if pointer.len() > MAX_POINTER_BYTES || !pointer.starts_with('/') {
        return Err(invalid());
    }
    let mut node = input_schema;
    for raw in pointer[1..].split('/') {
        let segment = raw.replace("~1", "/").replace("~0", "~");
        if segment.is_empty()
            || node.get("type").and_then(Value::as_str) != Some("object")
            || !node
                .get("required")
                .and_then(Value::as_array)
                .is_some_and(|required| required.iter().any(|name| name == segment.as_str()))
        {
            return Err(invalid());
        }
        node = node
            .get("properties")
            .and_then(|properties| properties.get(&segment))
            .ok_or_else(invalid)?;
    }
    match node.get("type").and_then(Value::as_str) {
        Some("string") => Ok(()),
        Some("array")
            if node
                .get("items")
                .and_then(|items| items.get("type"))
                .and_then(Value::as_str)
                == Some("string") =>
        {
            Ok(())
        }
        _ => Err(invalid()),
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use serde_json::json;

    type Mutation = Box<dyn Fn(&mut Value)>;

    pub(crate) fn sample() -> Value {
        json!({
            "format": "agent-access-command/1",
            "version": "1.4.0",
            "credential": {"kind": "username_token", "modes": ["service", "per_user"]},
            "verify": true,
            "resourceTypes": [{
                "id": "project", "label": "Project", "pluralLabel": "Projects",
                "example": "OPS", "pattern": "[A-Z][A-Z0-9]{1,9}",
                "attributes": [
                    {"name": "region", "label": "Region", "description": "Hosting region.",
                     "required": false, "pattern": "[a-z0-9-]{1,32}"},
                    {"name": "webhookSecret", "label": "Webhook secret",
                     "description": "Per-project signing secret.", "required": false}
                ]
            }],
            "actions": [
                {
                    "name": "issue.view", "description": "Show one issue.", "readOnly": true,
                    "inputSchema": {"type": "object", "required": ["project", "issue"],
                        "properties": {"project": {"type": "string"},
                            "issue": {"type": "integer", "minimum": 1}},
                        "additionalProperties": false},
                    "resources": {"type": "project", "inputs": ["/project"]}
                },
                {
                    "name": "issue.search", "description": "Search issues with a query expression.",
                    "readOnly": true,
                    "inputSchema": {"type": "object", "required": ["query"],
                        "properties": {"query": {"type": "string", "maxLength": 2000}},
                        "additionalProperties": false},
                    "resources": {"type": "project"}
                }
            ]
        })
    }

    fn parse_value(value: &Value) -> Result<Manifest, String> {
        parse(&serde_json::to_vec(value).unwrap())
    }

    #[test]
    fn download_is_true_only_and_cannot_be_a_live_listing() {
        let mut value = sample();
        assert!(
            !parse_value(&value).unwrap().actions[1]
                .declaration
                .as_ref()
                .unwrap()
                .download
        );
        value["actions"][1]["download"] = json!(true);
        assert!(
            parse_value(&value).unwrap().actions[1]
                .declaration
                .as_ref()
                .unwrap()
                .download
        );
        for invalid in [
            json!(false),
            Value::Null,
            json!("true"),
            json!(1),
            json!({}),
            json!([]),
        ] {
            value["actions"][1]["download"] = invalid;
            assert_eq!(
                parse_value(&value).unwrap().actions[1]
                    .declaration
                    .as_ref()
                    .unwrap_err(),
                "download must be true when present"
            );
        }
        value["actions"][1]["download"] = json!(true);
        value["actions"][1]["listingOf"] = json!("project");
        assert_eq!(
            parse_value(&value).unwrap().actions[1]
                .declaration
                .as_ref()
                .unwrap_err(),
            "download actions cannot declare listingOf"
        );
        value["actions"][1]
            .as_object_mut()
            .unwrap()
            .remove("listingOf");
        value["actions"][1]["responseEncoding"] = json!("base64");
        assert!(
            parse_value(&value).unwrap().actions[1]
                .declaration
                .as_ref()
                .unwrap_err()
                .contains("unsupported field")
        );
    }

    #[test]
    fn listing_declarations_require_the_same_command_enforced_resource_type() {
        let mut value = sample();
        value["actions"][1]["name"] = json!("project.list");
        value["actions"][1]["listingOf"] = json!("project");
        let parsed = parse_value(&value).unwrap();
        assert_eq!(
            parsed.actions[1]
                .declaration
                .as_ref()
                .unwrap()
                .listing_of
                .as_deref(),
            Some("project")
        );
        assert!(
            parsed.actions[0]
                .declaration
                .as_ref()
                .unwrap()
                .listing_of
                .is_none()
        );
        for invalid in [json!("other"), json!(""), json!(true), Value::Null] {
            value["actions"][1]["listingOf"] = invalid;
            assert!(
                parse_value(&value).unwrap().actions[1]
                    .declaration
                    .as_ref()
                    .unwrap_err()
                    .contains("listingOf")
            );
        }
        value["actions"][0]["listingOf"] = json!("project");
        assert!(
            parse_value(&value).unwrap().actions[0]
                .declaration
                .as_ref()
                .unwrap_err()
                .contains("without input pointers")
        );
        value["actions"][1]["listingOf"] = json!("project");
        value["actions"][1]
            .as_object_mut()
            .unwrap()
            .remove("resources");
        assert!(
            parse_value(&value).unwrap().actions[1]
                .declaration
                .as_ref()
                .unwrap_err()
                .contains("same type")
        );
    }

    #[test]
    fn resource_exclusions_default_true_and_require_boolean_when_present() {
        assert!(parse_value(&sample()).unwrap().resource_types[0].supports_exclusions);
        for supported in [true, false] {
            let mut value = sample();
            value["resourceTypes"][0]["supportsExclusions"] = json!(supported);
            assert_eq!(
                parse_value(&value).unwrap().resource_types[0].supports_exclusions,
                supported
            );
        }
        for invalid in [Value::Null, json!("false"), json!(0), json!([]), json!({})] {
            let mut value = sample();
            value["resourceTypes"][0]["supportsExclusions"] = invalid;
            assert_eq!(
                parse_value(&value).unwrap_err(),
                "resourceTypes[0].supportsExclusions must be a boolean"
            );
        }
    }

    #[test]
    fn the_design_example_parses() {
        let manifest = parse_value(&sample()).unwrap();
        assert_eq!(manifest.version, "1.4.0");
        assert!(manifest.verify);
        assert!(!manifest.oauth_declared);
        let credential = manifest.credential.unwrap();
        assert_eq!(credential.kind, ImportedCredentialKind::UsernameToken);
        assert_eq!(
            credential.modes,
            [
                ImportedCredentialMode::Service,
                ImportedCredentialMode::PerUser
            ]
        );
        assert_eq!(manifest.resource_types[0].max_length, 256);
        assert_eq!(manifest.resource_types[0].attributes.len(), 2);
        let view = manifest.actions[0].declaration.as_ref().unwrap();
        assert_eq!(
            view.resources,
            Some(ResourceDeclaration {
                resource_type: "project".into(),
                inputs: vec!["/project".into()]
            })
        );
        assert_eq!(view.credential_modes.len(), 2);
        let search = manifest.actions[1].declaration.as_ref().unwrap();
        assert!(search.resources.as_ref().unwrap().inputs.is_empty());
        assert_eq!(manifest.actions[1].read_only_hint, Some(true));
    }

    #[test]
    fn service_level_errors_fail_the_manifest() {
        let cases: Vec<(Mutation, &str)> = vec![
            (
                Box::new(|m| m["format"] = json!("agent-access-command/2")),
                "format",
            ),
            (Box::new(|m| m["version"] = json!("")), "version"),
            (
                Box::new(|m| m["version"] = json!("x".repeat(65))),
                "version",
            ),
            (
                Box::new(|m| m["credential"]["kind"] = json!("oauth")),
                "credential.kind",
            ),
            (
                Box::new(|m| m["credential"]["modes"] = json!([])),
                "credential.modes",
            ),
            (
                Box::new(|m| m["credential"]["modes"] = json!(["service", "service"])),
                "repeats",
            ),
            (Box::new(|m| m["verify"] = json!("yes")), "verify"),
            (
                Box::new(|m| {
                    m.as_object_mut().unwrap().remove("credential");
                }),
                "verify requires",
            ),
            (Box::new(|m| m["extra"] = json!(1)), "unsupported field"),
            (Box::new(|m| m["oauth"] = json!("token")), "oauth"),
            (
                Box::new(|m| m["oauth"] = json!({"padding": "x".repeat(16 * 1024)})),
                "oauth exceeds",
            ),
            (
                Box::new(|m| m["resourceTypes"][0]["id"] = json!("Project")),
                ".id",
            ),
            (
                Box::new(|m| m["resourceTypes"][0]["example"] = json!("ops")),
                "example",
            ),
            (
                Box::new(|m| m["resourceTypes"][0]["pattern"] = json!("[")),
                "pattern",
            ),
            (
                Box::new(|m| m["resourceTypes"][0]["maxLength"] = json!(1025)),
                "maxLength",
            ),
            (
                Box::new(|m| m["resourceTypes"][0]["attributes"][0]["name"] = json!("Region")),
                ".name",
            ),
            (
                Box::new(|m| m["resourceTypes"][0]["attributes"][0]["required"] = json!("no")),
                "required",
            ),
            (
                Box::new(|m| {
                    let first = m["resourceTypes"][0].clone();
                    m["resourceTypes"].as_array_mut().unwrap().push(first);
                }),
                "repeat an id",
            ),
            (Box::new(|m| m["actions"] = json!({})), "actions"),
            (Box::new(|m| m["actions"][0]["name"] = json!(7)), "name"),
            (
                Box::new(|m| m["actions"][1]["name"] = json!("issue.view")),
                "repeat the name",
            ),
        ];
        for (mutate, expected) in cases {
            let mut manifest = sample();
            mutate(&mut manifest);
            let error = parse_value(&manifest).unwrap_err();
            assert!(error.contains(expected), "{expected}: {error}");
        }
        assert!(parse(b"{} trailing").is_err());
        assert!(parse(b"[]").is_err());
        let mut types = sample();
        types["resourceTypes"] = json!(vec![sample()["resourceTypes"][0].clone(); 17]);
        assert!(parse_value(&types).is_err());
    }

    #[test]
    fn invalid_actions_are_unsupported_with_a_reason() {
        let cases: Vec<(Mutation, &str)> = vec![
            (Box::new(|a| a["extra"] = json!(true)), "unsupported field"),
            (Box::new(|a| a["description"] = json!(1)), "description"),
            (Box::new(|a| a["readOnly"] = json!("yes")), "readOnly"),
            (
                Box::new(|a| a["inputSchema"] = json!({"type": "string"})),
                "object",
            ),
            (
                Box::new(|a| {
                    a["inputSchema"]["properties"]["project"] =
                        json!({"$ref": "https://example.invalid/s"})
                }),
                "inputSchema",
            ),
            (
                Box::new(|a| a["outputSchema"] = json!({"$dynamicRef": "#x"})),
                "outputSchema",
            ),
            (
                Box::new(|a| a["credentialModes"] = json!(["per_user", "per_user"])),
                "repeats",
            ),
            (
                Box::new(|a| a["resources"]["type"] = json!("ticket")),
                "declared resource type",
            ),
            (Box::new(|a| a["resources"]["inputs"] = json!([])), "1 to 4"),
            (
                Box::new(|a| a["resources"]["inputs"] = json!(["/a", "/b", "/c", "/d", "/e"])),
                "1 to 4",
            ),
            (
                Box::new(|a| a["resources"]["inputs"] = json!(["/issue"])),
                "required string",
            ),
            (
                Box::new(|a| a["resources"]["inputs"] = json!(["/missing"])),
                "required string",
            ),
            (
                Box::new(|a| a["resources"]["inputs"] = json!(["project"])),
                "required string",
            ),
            (
                Box::new(|a| a["resources"]["inputs"] = json!(["/project", "/project"])),
                "repeat",
            ),
            (
                Box::new(|a| a["description"] = json!("x".repeat(16 * 1024 + 1))),
                "description",
            ),
        ];
        for (mutate, expected) in cases {
            let mut manifest = sample();
            mutate(&mut manifest["actions"][0]);
            let parsed = parse_value(&manifest).unwrap();
            let reason = parsed.actions[0].declaration.as_ref().unwrap_err();
            assert!(reason.contains(expected), "{expected}: {reason}");
            assert!(parsed.actions[1].declaration.is_ok());
        }
        // Per-action modes are a subset of the declared ones; without a
        // credential they are absent.
        let mut manifest = sample();
        manifest["credential"]["modes"] = json!(["service"]);
        manifest["actions"][0]["credentialModes"] = json!(["per_user"]);
        let parsed = parse_value(&manifest).unwrap();
        assert!(
            parsed.actions[0]
                .declaration
                .as_ref()
                .unwrap_err()
                .contains("subset")
        );
        let mut manifest = sample();
        manifest.as_object_mut().unwrap().remove("credential");
        manifest["verify"] = json!(false);
        manifest["actions"][1]["credentialModes"] = json!(["service"]);
        let parsed = parse_value(&manifest).unwrap();
        assert!(
            parsed.actions[0]
                .declaration
                .as_ref()
                .unwrap()
                .credential_modes
                .is_empty()
        );
        assert!(
            parsed.actions[1]
                .declaration
                .as_ref()
                .unwrap_err()
                .contains("requires")
        );
    }

    #[test]
    fn resource_pointers_reach_required_strings_and_string_arrays() {
        let schema = json!({"type": "object", "required": ["scope", "tags"],
        "properties": {
            "scope": {"type": "object", "required": ["project", "a/b"],
                "properties": {"project": {"type": "string"}, "a/b": {"type": "string"},
                    "optional": {"type": "string"}}},
            "tags": {"type": "array", "items": {"type": "string"}},
            "counts": {"type": "array", "items": {"type": "integer"}}
        }});
        for pointer in ["/scope/project", "/scope/a~1b", "/tags"] {
            resource_input(&schema, pointer).unwrap();
        }
        for pointer in [
            "",
            "/",
            "/scope",
            "/scope/optional",
            "/counts",
            "/scope/project/x",
        ] {
            assert!(resource_input(&schema, pointer).is_err(), "{pointer}");
        }
    }

    #[test]
    fn patterns_follow_the_resource_pattern_rules() {
        // Whole-value matches in the `regex` dialect.
        let regex = resource_pattern("[A-Z]{2,10}", 256).unwrap();
        assert!(regex.is_match("OPS"));
        assert!(!regex.is_match("OPS-1"));
        assert!(!regex.is_match("OPS\n"));
        // An 8 KiB source is accepted; one byte more, an empty source,
        // lookaround, backreferences and oversized programs are not.
        let padded = |bytes: usize| format!("(?x){}a", " ".repeat(bytes - 5));
        resource_pattern(&padded(8 * 1024), 256).unwrap();
        for pattern in [
            padded(8 * 1024 + 1),
            String::new(),
            "(?=a)a".into(),
            r"(a)\1".into(),
            "[a-z]{1000}{1000}".into(),
            "(unclosed".into(),
        ] {
            assert!(resource_pattern(&pattern, 256).is_err(), "{pattern:.32}");
        }
        // A source cannot close the anchoring group to escape the anchors.
        for escape in ["x)|(?s:.*", ").*(?:", "x)|(?:"] {
            assert!(resource_pattern(escape, 256).is_err(), "{escape}");
        }
        // The type's maxLength bounds its values; attribute patterns match
        // values of up to 8 KiB.
        let mut manifest = sample();
        manifest["resourceTypes"][0]["maxLength"] = json!(4);
        let parsed = parse_value(&manifest).unwrap();
        let declared = &parsed.resource_types[0];
        let grammar = resource_pattern(&declared.pattern, declared.max_length as usize).unwrap();
        assert!(grammar.is_match("OPSX"));
        assert!(!grammar.is_match("OPSXY"));
        let mut manifest = sample();
        manifest["resourceTypes"][0]["attributes"][0]["pattern"] = json!("[a-z]{1,2048}");
        assert!(parse_value(&manifest).is_ok());
        let mut manifest = sample();
        manifest["resourceTypes"][0]["pattern"] = json!("OPS)|(?s:.*");
        assert!(parse_value(&manifest).unwrap_err().contains("pattern"));
        let mut manifest = sample();
        manifest["resourceTypes"][0]["maxLength"] = json!(2);
        assert!(parse_value(&manifest).unwrap_err().contains("maxLength"));
        let mut manifest = sample();
        manifest["resourceTypes"][0]["attributes"][0]["pattern"] = json!("(?<=x)y");
        assert!(parse_value(&manifest).unwrap_err().contains("pattern"));
    }

    #[test]
    fn oauth_is_noted_and_otherwise_ignored() {
        let mut manifest = sample();
        manifest["oauth"] = json!({"issuer": "https://login.example.net", "scopes": ["read"]});
        let parsed = parse_value(&manifest).unwrap();
        assert!(parsed.oauth_declared);
        assert_eq!(parsed.actions.len(), 2);
    }
}
