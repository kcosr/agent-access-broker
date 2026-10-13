//! Vendor-independent, secret-free definitions shared by import adapters and the host.
use agent_access_provider::{is_action_name, is_service_name};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};
use url::Url;

pub const IMPORT_MAX_SERVICES: usize = 256;
pub const IMPORT_MAX_TOOLS: usize = 2048;
pub const IMPORT_MAX_MANIFEST_BYTES: usize = 16 * 1024 * 1024;
pub const IMPORT_MAX_TOOL_BYTES: usize = 256 * 1024;
pub const IMPORT_MAX_DESCRIPTION_BYTES: usize = 16 * 1024;
pub const IMPORT_MAX_SCHEMA_DEPTH: usize = 64;
pub const IMPORT_PREVIEW_TTL_SECONDS: i64 = 15 * 60;

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum ImportedCredentialMode {
    Service,
    PerUser,
}
impl ImportedCredentialMode {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Service => "service",
            Self::PerUser => "per_user",
        }
    }
}
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ImportedAuthMechanism {
    StaticToken,
    Oauth,
}
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ImportedBindingStatus {
    Configured,
    Unsupported,
}
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum ImportedCredentialDelivery {
    Bearer,
    RawHeader { name: String },
}
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ImportedCredentialBinding {
    pub owner_mode: ImportedCredentialMode,
    pub mechanism: ImportedAuthMechanism,
    pub delivery: ImportedCredentialDelivery,
    pub status: ImportedBindingStatus,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub adapter_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub registration_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub profile: Option<String>,
}
impl ImportedCredentialBinding {
    pub fn is_supported(&self) -> bool {
        self.status == ImportedBindingStatus::Configured
            && (self.mechanism == ImportedAuthMechanism::StaticToken
                || (self.mechanism == ImportedAuthMechanism::Oauth
                    && self.owner_mode == ImportedCredentialMode::PerUser
                    && self.delivery == ImportedCredentialDelivery::Bearer
                    && self.adapter_id.is_some()
                    && self.registration_id.is_some()
                    && self.profile.is_some()))
    }
    pub fn token(owner_mode: ImportedCredentialMode, delivery: ImportedCredentialDelivery) -> Self {
        Self {
            owner_mode,
            mechanism: ImportedAuthMechanism::StaticToken,
            delivery,
            status: ImportedBindingStatus::Configured,
            adapter_id: None,
            registration_id: None,
            profile: None,
        }
    }
}
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum ImportedDiscoveryCredential {
    Anonymous,
    Execution,
    Slot,
    PerUser { principal: String },
}
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum ImportedCredentialPurpose {
    Execution,
    Discovery,
    Transport,
}
impl ImportedCredentialPurpose {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Execution => "execution",
            Self::Discovery => "discovery",
            Self::Transport => "transport",
        }
    }
}
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ImportedInvocationLimit {
    pub requests: u32,
    pub window_seconds: u32,
}
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ImportedServiceDefinition {
    pub service: String,
    pub display_name: String,
    pub adapter_kind: String,
    pub endpoint: String,
    #[serde(default)]
    pub connection_settings: BTreeMap<String, String>,
    pub execution_bindings: Vec<ImportedCredentialBinding>,
    pub discovery: ImportedDiscoveryCredential,
    #[serde(default)]
    pub transport_auth: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub invocation_limit: Option<ImportedInvocationLimit>,
}
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ImportedActionDefinition {
    pub action: String,
    /// Adapter-specific identity, for example `{ "toolName": "search" }`.
    pub source: Value,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
    pub description: String,
    pub input_schema: Value,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub output_schema: Option<Value>,
    #[serde(default)]
    pub annotations: Value,
    /// Reviewed classification; never inferred from a source tool name.
    #[serde(default)]
    pub read_only: bool,
}

impl ImportedServiceDefinition {
    pub fn validate(&self) -> Result<(), String> {
        if self.service == "broker" || !is_service_name(&self.service) {
            return Err("import service name is invalid".into());
        }
        if self.display_name.trim().is_empty()
            || self.display_name.len() > 256
            || self.display_name.chars().any(char::is_control)
        {
            return Err("import display name is invalid".into());
        }
        if !is_service_name(&self.adapter_kind) {
            return Err("import adapter kind is invalid".into());
        }
        let endpoint = Url::parse(&self.endpoint).map_err(|_| "import endpoint is invalid")?;
        if !matches!(endpoint.scheme(), "http" | "https")
            || endpoint.host_str().is_none()
            || !endpoint.username().is_empty()
            || endpoint.password().is_some()
            || endpoint.fragment().is_some()
            || endpoint.query().is_some()
            || self.endpoint.len() > 4096
        {
            return Err(
                "import endpoint must be an HTTP(S) URL without userinfo, query, or fragment"
                    .into(),
            );
        }
        if self.execution_bindings.is_empty() || self.execution_bindings.len() > 2 {
            return Err("import requires one or two execution bindings".into());
        }
        let mut owners = BTreeSet::new();
        for binding in &self.execution_bindings {
            if !owners.insert(binding.owner_mode) {
                return Err("duplicate imported credential mode".into());
            }
            match (binding.mechanism, binding.status) {
                (ImportedAuthMechanism::StaticToken, ImportedBindingStatus::Configured)
                | (ImportedAuthMechanism::Oauth, ImportedBindingStatus::Unsupported) => {}
                (ImportedAuthMechanism::Oauth, ImportedBindingStatus::Configured)
                    if binding.is_supported() => {}
                _ => return Err("import authentication mechanism is unavailable".into()),
            }
            for value in [
                &binding.adapter_id,
                &binding.registration_id,
                &binding.profile,
            ]
            .into_iter()
            .flatten()
            {
                if value.is_empty() || value.len() > 256 || value.chars().any(char::is_control) {
                    return Err("import binding reference is invalid".into());
                }
            }
            binding.delivery.validate()?;
            if self.transport_auth && binding.delivery == ImportedCredentialDelivery::Bearer {
                return Err(
                    "transport bearer and execution bearer cannot share Authorization".into(),
                );
            }
        }
        if self
            .execution_bindings
            .windows(2)
            .any(|v| v[0].delivery != v[1].delivery)
        {
            return Err("imported credential modes must share a delivery destination".into());
        }
        if matches!(self.discovery, ImportedDiscoveryCredential::Execution)
            && !owners.contains(&ImportedCredentialMode::Service)
        {
            return Err("execution discovery requires a service credential binding".into());
        }
        if let ImportedDiscoveryCredential::PerUser { principal } = &self.discovery
            && (principal.is_empty()
                || principal.len() > 256
                || !principal
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"._@+-".contains(&b)))
        {
            return Err("import discovery principal is invalid".into());
        }
        if matches!(self.discovery, ImportedDiscoveryCredential::PerUser { .. })
            && !self.execution_bindings.iter().any(|binding| {
                binding.owner_mode == ImportedCredentialMode::PerUser && binding.is_supported()
            })
        {
            return Err(
                "personal discovery requires a supported per-user credential binding".into(),
            );
        }
        if self.invocation_limit.as_ref().is_some_and(|v| {
            v.requests == 0
                || v.requests > 1_000_000
                || v.window_seconds == 0
                || v.window_seconds > 86_400
        }) {
            return Err("import invocation limit must be non-zero".into());
        }
        // The compiled adapter owns semantics; the generic storage boundary owns bounds.
        if self.connection_settings.len() > 16
            || self.connection_settings.iter().any(|(key, value)| {
                key.is_empty()
                    || key.len() > 64
                    || !key
                        .bytes()
                        .all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b))
                    || value.len() > 4096
                    || value.chars().any(char::is_control)
            })
        {
            return Err("import connection settings exceed supported bounds".into());
        }
        Ok(())
    }
    /// Service identity fixes where existing grants send their authority.
    pub fn same_base_destination(&self, other: &Self) -> bool {
        self.service == other.service
            && self.adapter_kind == other.adapter_kind
            && self.endpoint == other.endpoint
    }
    pub fn same_destination(&self, other: &Self) -> bool {
        self.same_base_destination(other)
            && self.connection_settings == other.connection_settings
            && self.execution_bindings.first().map(|b| &b.delivery)
                == other.execution_bindings.first().map(|b| &b.delivery)
    }
}
impl ImportedCredentialDelivery {
    pub fn validate(&self) -> Result<(), String> {
        if let Self::RawHeader { name } = self {
            let lower = name.to_ascii_lowercase();
            if name.is_empty()
                || name.len() > 128
                || !name
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&b))
                || lower.starts_with("mcp-")
                || lower.starts_with("x-agent-access-")
                || matches!(
                    lower.as_str(),
                    "authorization"
                        | "host"
                        | "cookie"
                        | "set-cookie"
                        | "content-length"
                        | "content-type"
                        | "transfer-encoding"
                        | "connection"
                        | "keep-alive"
                        | "proxy-authenticate"
                        | "proxy-authorization"
                        | "te"
                        | "trailer"
                        | "upgrade"
                        | "accept"
                        | "origin"
                        | "referer"
                        | "user-agent"
                        | "last-event-id"
                )
            {
                return Err("import credential header is reserved or invalid".into());
            }
        }
        Ok(())
    }
}
impl ImportedActionDefinition {
    pub fn validate(&self, service: &str) -> Result<(), String> {
        if self.action.len() > 256
            || !is_action_name(&self.action)
            || self.action.starts_with(&format!("{service}."))
        {
            return Err("import action name is invalid or repeats service prefix".into());
        }
        if !self.source.is_object() || self.source.as_object().is_some_and(|v| v.is_empty()) {
            return Err("import source identity must be an object".into());
        }
        if self.description.len() > IMPORT_MAX_DESCRIPTION_BYTES
            || self
                .label
                .as_ref()
                .is_some_and(|v| v.is_empty() || v.len() > 256 || v.chars().any(char::is_control))
        {
            return Err("import action description or label exceeds limits".into());
        }
        if self.input_schema.get("type").and_then(Value::as_str) != Some("object") {
            return Err("import input schema must describe an object".into());
        }
        validate_import_schema(&self.input_schema)?;
        if let Some(schema) = &self.output_schema {
            validate_import_schema(schema)?;
        }
        if serde_json::to_vec(self)
            .map_err(|_| "import action cannot be encoded")?
            .len()
            > IMPORT_MAX_TOOL_BYTES
        {
            return Err("import action exceeds size limit".into());
        }
        Ok(())
    }
}
/// Visit structurally reachable schema nodes. Literal data in defaults,
/// examples, enums and constants is not itself a schema. References into those
/// data locations are outside the initial import profile.
/// Bound the complete JSON tree separately, so literal data cannot evade limits.
pub fn visit_import_schema_nodes(
    schema: &Value,
    mut visitor: impl FnMut(&Value) -> Result<(), String>,
) -> Result<(), String> {
    let mut values = vec![(schema, 0)];
    while let Some((value, depth)) = values.pop() {
        if depth > IMPORT_MAX_SCHEMA_DEPTH {
            return Err("import schema exceeds depth limit".into());
        }
        match value {
            Value::Object(object) => values.extend(object.values().map(|child| (child, depth + 1))),
            Value::Array(array) => values.extend(array.iter().map(|child| (child, depth + 1))),
            _ => {}
        }
    }
    let mut pending = vec![schema];
    // References may revisit a node or form a cycle. Borrowed JSON nodes are
    // stable for this traversal; their addresses identify nodes without copying.
    let mut visited = BTreeSet::new();
    let mut schema_nodes = Vec::new();
    while let Some(node) = pending.pop() {
        if !visited.insert(std::ptr::from_ref(node)) {
            continue;
        }
        schema_nodes.push(node);
        let Some(object) = node.as_object() else {
            continue;
        };
        for key in [
            "$defs",
            "definitions",
            "properties",
            "patternProperties",
            "dependentSchemas",
            "dependencies",
        ] {
            if let Some(children) = object.get(key).and_then(Value::as_object) {
                pending.extend(
                    children
                        .values()
                        .filter(|child| child.is_object() || child.is_boolean()),
                );
            }
        }
        for key in ["allOf", "anyOf", "oneOf", "prefixItems"] {
            if let Some(children) = object.get(key).and_then(Value::as_array) {
                pending.extend(children);
            }
        }
        for key in [
            "additionalProperties",
            "unevaluatedProperties",
            "propertyNames",
            "contains",
            "items",
            "unevaluatedItems",
            "additionalItems",
            "not",
            "if",
            "then",
            "else",
            "contentSchema",
        ] {
            if let Some(child) = object.get(key) {
                if key == "items"
                    && let Some(children) = child.as_array()
                {
                    pending.extend(children);
                } else {
                    pending.push(child);
                }
            }
        }
    }
    for node in schema_nodes {
        visitor(node)?;
        let Some(object) = node.as_object() else {
            continue;
        };
        // The initial profile permits local references to schema locations only.
        // Projections can then relocate schemas without altering literal data.
        if let Some(reference) = object
            .get("$ref")
            .and_then(Value::as_str)
            .and_then(|value| value.strip_prefix('#'))
        {
            let fragment = percent_encoding::percent_decode_str(reference)
                .decode_utf8()
                .map_err(|_| "import schema reference is invalid".to_string())?;
            if fragment.is_empty() || fragment.starts_with('/') {
                let target = schema
                    .pointer(&fragment)
                    .ok_or_else(|| "import schema local reference was not found".to_string())?;
                if !visited.contains(&std::ptr::from_ref(target)) {
                    return Err(
                        "import schema references must target schema locations, not literal data"
                            .into(),
                    );
                }
            }
        }
    }
    Ok(())
}

/// Reject remote references before a JSON Schema implementation can resolve them.
pub fn validate_import_schema(schema: &Value) -> Result<(), String> {
    visit_import_schema_nodes(schema, |node| {
        let Some(values) = node.as_object() else {
            return Ok(());
        };
        if values.contains_key("$dynamicRef")
            || values.contains_key("$recursiveRef")
            || values.contains_key("$dynamicAnchor")
            || values.contains_key("$recursiveAnchor")
        {
            return Err("import schemas do not support dynamic references".into());
        }
        if let Some(dialect) = values.get("$schema")
            && !dialect.as_str().is_some_and(|v| {
                matches!(
                    v,
                    "https://json-schema.org/draft/2020-12/schema"
                        | "https://json-schema.org/draft/2019-09/schema"
                        | "http://json-schema.org/draft-07/schema#"
                        | "http://json-schema.org/draft-06/schema#"
                        | "http://json-schema.org/draft-04/schema#"
                )
            })
        {
            return Err("import schema dialect is unsupported".into());
        }
        if let Some(reference) = values.get("$ref")
            && !reference.as_str().is_some_and(|r| r.starts_with('#'))
        {
            return Err("import schemas support only local references".into());
        }
        for keyword in ["$id", "id"] {
            if let Some(id) = values.get(keyword)
                && !id.as_str().is_some_and(|v| v.starts_with('#'))
            {
                return Err("import schemas cannot establish external base URIs".into());
            }
        }
        Ok(())
    })?;
    super::BoundedImportSchema::compile(schema)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    #[test]
    fn broker_namespace_cannot_be_registered_as_an_import() {
        let mut service = definition();
        service.service = "broker".into();
        assert!(service.validate().is_err());
    }

    fn definition() -> ImportedServiceDefinition {
        ImportedServiceDefinition {
            service: "observability".into(),
            display_name: "Observability".into(),
            adapter_kind: "mcp_http".into(),
            endpoint: "https://tools.example/mcp".into(),
            connection_settings: BTreeMap::new(),
            execution_bindings: vec![ImportedCredentialBinding::token(
                ImportedCredentialMode::Service,
                ImportedCredentialDelivery::Bearer,
            )],
            discovery: ImportedDiscoveryCredential::Execution,
            transport_auth: false,
            invocation_limit: None,
        }
    }
    #[test]
    fn credential_destination_profiles_reject_collisions_and_control_headers() {
        definition().validate().unwrap();
        let mut service = definition();
        service.transport_auth = true;
        assert!(service.validate().is_err());
        service.execution_bindings[0].delivery = ImportedCredentialDelivery::RawHeader {
            name: "X-Upstream-Token".into(),
        };
        service.validate().unwrap();
        for name in [
            "Authorization",
            "COOKIE",
            "Content-Length",
            "Mcp-Session-Id",
            "Mcp-Param-Token",
            "X-Agent-Access-Principal",
            "Host",
            "wrong\r\nname",
        ] {
            service.execution_bindings[0].delivery =
                ImportedCredentialDelivery::RawHeader { name: name.into() };
            assert!(service.validate().is_err(), "{name}");
        }
    }
    #[test]
    fn draft_oauth_metadata_is_explicitly_unsupported() {
        let mut service = definition();
        service.execution_bindings[0].mechanism = ImportedAuthMechanism::Oauth;
        assert!(service.validate().is_err());
        service.execution_bindings[0].status = ImportedBindingStatus::Unsupported;
        service.execution_bindings[0].adapter_id = Some("future-oauth-adapter".into());
        service.validate().unwrap();
        assert!(!service.execution_bindings[0].is_supported());
    }
    #[test]
    fn personal_discovery_requires_a_supported_personal_binding() {
        let mut service = definition();
        service.discovery = ImportedDiscoveryCredential::PerUser {
            principal: "admin".into(),
        };
        assert!(service.validate().is_err());
        service
            .execution_bindings
            .push(ImportedCredentialBinding::token(
                ImportedCredentialMode::PerUser,
                ImportedCredentialDelivery::Bearer,
            ));
        service.validate().unwrap();
        service.execution_bindings.last_mut().unwrap().status = ImportedBindingStatus::Unsupported;
        assert!(service.validate().is_err());
    }
    #[test]
    fn endpoint_and_invocation_limits_are_bounded() {
        for endpoint in [
            "file:///tmp/socket",
            "https://user:password@example/mcp",
            "https://example/mcp?token=secret",
            "https://example/mcp#fragment",
        ] {
            let mut service = definition();
            service.endpoint = endpoint.into();
            assert!(service.validate().is_err());
        }
        let mut service = definition();
        service.invocation_limit = Some(ImportedInvocationLimit {
            requests: 1_000_001,
            window_seconds: 60,
        });
        assert!(service.validate().is_err());
        service.invocation_limit = Some(ImportedInvocationLimit {
            requests: 1,
            window_seconds: 86_401,
        });
        assert!(service.validate().is_err());
    }
    #[test]
    fn schema_compilation_stays_local_and_honors_explicit_dialects() {
        validate_import_schema(&json!({"type":"object","$defs":{"query":{"type":"string"}},"properties":{"query":{"$ref":"#/$defs/query"}}})).unwrap();
        for schema in [
            json!({"type":"object","$ref":"https://example/schema"}),
            json!({"type":"object","$id":"https://example/schema"}),
            json!({"type":"object","$schema":"https://example/custom-dialect"}),
            json!({"type":"object","$dynamicRef":"#recursive"}),
            json!({"type":"object","properties":{"x":{"type":"not-a-type"}}}),
        ] {
            assert!(validate_import_schema(&schema).is_err());
        }
    }
    #[test]
    fn schema_literals_are_data_and_references_cannot_reinterpret_them() {
        let literal = json!({"$ref":"literal-not-a-reference","$schema":"literal-dialect","id":"literal-id","$dynamicRef":"literal-dynamic"});
        let schema = json!({"type":"object","properties":{"payload":{"const":literal,"default":literal,"enum":[literal],"examples":[literal]}}});
        validate_import_schema(&schema).unwrap();
        let hidden_reference = json!({"type":"object","default":{"hidden":{"$ref":"https://example.invalid/forbidden"}},"properties":{"payload":{"$ref":"#/default/hidden"}}});
        assert!(validate_import_schema(&hidden_reference).is_err());
        let referenced_literal = json!({"type":"object","default":{"hidden":{"type":"string"}},"properties":{"payload":{"$ref":"#/default/hidden"}}});
        assert_eq!(
            validate_import_schema(&referenced_literal).unwrap_err(),
            "import schema references must target schema locations, not literal data"
        );
        let legacy_id = json!({"$schema":"http://json-schema.org/draft-04/schema#","type":"object","properties":{"payload":{"id":"https://example.invalid/base","type":"string"}}});
        assert!(validate_import_schema(&legacy_id).is_err());
        let mut nested_literal = json!(null);
        for _ in 0..=IMPORT_MAX_SCHEMA_DEPTH {
            nested_literal = json!([nested_literal]);
        }
        assert!(
            validate_import_schema(&json!({"type":"object","default":nested_literal})).is_err()
        );
    }
}
