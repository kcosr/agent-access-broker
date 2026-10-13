//! Authoritative backend service descriptors.
//!
//! A backend builds its [`ServiceDescriptor`] from its typed configuration
//! alone. Configuration validation, managed policy, runtime admission, catalog
//! projection, and credential management all read this one definition instead
//! of keeping parallel per-service tables.

use crate::attribution::AttributionCapability;
use crate::presentation::ActionPresentation;
use crate::{
    ActionCapabilities, ResourceScopeCapabilities, ServiceCapabilities, UpstreamResourceOwnership,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};

#[derive(Debug, Clone, PartialEq)]
pub struct ServiceDescriptor {
    pub service: String,
    pub display_name: String,
    pub surface: ServiceSurface,
    /// Resource scope names mapped to the resource type each one authorizes.
    pub resource_scopes: BTreeMap<String, ResourceScopeCapabilities>,
    pub actions: Vec<ActionDescriptor>,
    pub credentials: CredentialDescriptor,
    /// Largest embedded upstream body the broker renders for this service.
    pub presentation_body_limit: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ServiceSurface {
    Invoke,
    Gateway {
        kind: String,
        broker_hosts: Vec<String>,
    },
}

#[derive(Debug, Clone, PartialEq)]
pub struct ActionDescriptor {
    pub action: String,
    /// Exact presentation name provenance; never an execution identity.
    pub scoped_mcp_name_source: ScopedMcpNameSource,
    pub description: String,
    /// Extended, public usage documentation. Kept outside MCP tool definitions.
    pub documentation: Option<Value>,
    /// Explicitly reviewed read operation; defaults to false for new actions.
    pub read_only: bool,
    pub input_schema: Value,
    /// Scope the action is authorized against; unscoped actions need an
    /// explicit grant without a resource selection.
    pub resource_scope: Option<String>,
    /// Resolve private attributes for exactly one admitted resource of this backend.
    pub requires_resource_attributes: bool,
    pub credential_modes: Vec<String>,
    pub lookup: LookupRequirement,
    /// The broker computes the search boundary from policy and hands it to
    /// the provider, which must constrain its upstream query and results.
    pub search_contained: bool,
    pub upstream_resource_ownership: Option<UpstreamResourceOwnership>,
    pub io: ActionIo,
    /// JSON pointers into sensitive response values, including deliberate secret
    /// exports and opaque imported payloads; these responses are never cached.
    pub sensitive_output_pointers: Vec<String>,
    pub attribution: Option<AttributionCapability>,
    /// Handles issued by this action must survive restarts and reloads, so
    /// the broker must hold a stable signing key.
    pub requires_stable_signing_key: bool,
    /// Read-content normalization and whole-result Markdown the action
    /// supports; `None` means JSON results only.
    pub presentation: Option<ActionPresentation>,
}

/// Imported source names cannot fall back to a built-in canonical action name.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ScopedMcpNameSource {
    CanonicalAction,
    Imported { name: Option<String> },
}

/// When a provider needs the broker's lookup credential for an action.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LookupRequirement {
    None,
    /// Only for execution-time confirmation after policy selection.
    Execution,
    /// Before policy, to resolve the action's resource scope from upstream
    /// metadata. Also implies execution-time lookup.
    ScopeResolution,
}

impl LookupRequirement {
    pub fn credential_required(self) -> bool {
        !matches!(self, Self::None)
    }

    pub fn before_policy(self) -> bool {
        matches!(self, Self::ScopeResolution)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CredentialDescriptor {
    /// Whether invocations need a broker-selected execution credential.
    pub execution_required: bool,
    /// Set when `credentials.per_user.<service>` may be a delegated (`oauth`)
    /// credential, which reaches the provider as
    /// `ExecutionAccess::Delegated` instead of a static credential.
    pub delegated: Option<DelegatedConnection>,
    /// Credential kinds accepted for `credentials.service.<service>`; empty
    /// means every generally supported kind.
    pub service_kinds: Vec<&'static str>,
    /// Managed-store credential profiles and the credential kind each stores.
    pub profiles: Vec<CredentialProfile>,
    /// Inputs credential verification needs besides the credential, such as
    /// `repository` for a check that reads one repository.
    pub verification_inputs: Vec<&'static str>,
}

impl CredentialDescriptor {
    /// A service whose invocations need no broker-selected execution
    /// credential (the provider obtains any authority itself).
    pub fn without_execution_credential() -> Self {
        Self {
            execution_required: false,
            ..Self::default()
        }
    }

    /// Accepts delegated credentials; `description` tells a person what
    /// connecting their account for this service allows.
    pub fn delegated(mut self, description: &'static str) -> Self {
        self.delegated = Some(DelegatedConnection { description });
        self
    }

    pub fn verification_input(mut self, input: &'static str) -> Self {
        self.verification_inputs.push(input);
        self
    }

    pub fn service_kinds(mut self, kinds: &[&'static str]) -> Self {
        self.service_kinds = kinds.to_vec();
        self
    }

    pub fn profile(mut self, name: impl Into<String>, kind: &'static str) -> Self {
        self.profiles.push(CredentialProfile::new(name, kind));
        self
    }
}

/// How a service that accepts delegated credentials presents the account
/// connection a person makes for it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DelegatedConnection {
    /// What connecting allows, shown where the person connects the account.
    pub description: &'static str,
}

impl Default for CredentialDescriptor {
    fn default() -> Self {
        Self {
            execution_required: true,
            delegated: None,
            service_kinds: Vec::new(),
            profiles: Vec::new(),
            verification_inputs: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CredentialProfile {
    pub name: String,
    pub kind: &'static str,
}

impl CredentialProfile {
    pub fn new(name: impl Into<String>, kind: &'static str) -> Self {
        Self {
            name: name.into(),
            kind,
        }
    }
}

impl ActionDescriptor {
    /// Raw adapter-selected name before the narrower scoped MCP profile is applied.
    pub fn raw_scoped_mcp_name(&self) -> Option<&str> {
        match &self.scoped_mcp_name_source {
            ScopedMcpNameSource::CanonicalAction => Some(&self.action),
            ScopedMcpNameSource::Imported { name } => name.as_deref(),
        }
    }

    /// An invoke action with JSON I/O and no scope, lookup, or extras.
    pub fn new(
        action: impl Into<String>,
        description: impl Into<String>,
        input_schema: Value,
    ) -> Self {
        Self {
            action: action.into(),
            scoped_mcp_name_source: ScopedMcpNameSource::CanonicalAction,
            description: description.into(),
            documentation: None,
            read_only: false,
            input_schema,
            resource_scope: None,
            requires_resource_attributes: false,
            credential_modes: Vec::new(),
            lookup: LookupRequirement::None,
            search_contained: false,
            upstream_resource_ownership: None,
            io: ActionIo::Json,
            sensitive_output_pointers: Vec::new(),
            attribution: None,
            requires_stable_signing_key: false,
            presentation: None,
        }
    }

    /// Request private attributes from one authorized exact resource at dispatch.
    pub fn resource_attributes(mut self) -> Self {
        self.requires_resource_attributes = true;
        self
    }

    /// Mark this action as reviewed read-only without changing authorization.
    pub fn read_only(mut self) -> Self {
        self.read_only = true;
        self
    }

    pub fn scope(mut self, scope: impl Into<String>) -> Self {
        self.resource_scope = Some(scope.into());
        self
    }

    pub fn credential_modes<I, S>(mut self, modes: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.credential_modes = modes.into_iter().map(Into::into).collect();
        self
    }

    pub fn lookup(mut self, lookup: LookupRequirement) -> Self {
        self.lookup = lookup;
        self
    }

    pub fn search_contained(mut self) -> Self {
        self.search_contained = true;
        self
    }

    pub fn upstream_resource_ownership(mut self, ownership: UpstreamResourceOwnership) -> Self {
        self.upstream_resource_ownership = Some(ownership);
        self
    }

    pub fn raw_download(mut self) -> Self {
        self.io = raw_download_io();
        self
    }

    pub fn multipart_upload(mut self, plan: MultipartUploadSpec) -> Self {
        self.io = ActionIo::MultipartUpload { plan };
        self
    }

    pub fn sensitive_output(mut self, pointer: impl Into<String>) -> Self {
        self.sensitive_output_pointers.push(pointer.into());
        self
    }

    pub fn attribution(mut self, capability: AttributionCapability) -> Self {
        self.attribution = Some(capability);
        self
    }

    pub fn requires_stable_signing_key(mut self) -> Self {
        self.requires_stable_signing_key = true;
        self
    }

    pub fn documentation(mut self, documentation: Value) -> Self {
        self.documentation = Some(documentation);
        self
    }

    pub fn presentation(mut self, presentation: Option<ActionPresentation>) -> Self {
        self.presentation = presentation;
        self
    }

    /// Scope types required by the action, as projected on the wire.
    pub fn required_scope_types(&self) -> Vec<String> {
        self.resource_scope.iter().cloned().collect()
    }

    pub fn capabilities(&self) -> ActionCapabilities {
        ActionCapabilities {
            action: self.action.clone(),
            read_only: self.read_only,
            description: self.description.clone(),
            documentation: self.documentation.clone(),
            required_scope_types: self.required_scope_types(),
            credential_modes: self.credential_modes.clone(),
            lookup_required: self.lookup.credential_required(),
            upstream_resource_ownership: self.upstream_resource_ownership,
            input_schema: self.input_schema.clone(),
        }
    }
}

/// Raw-download I/O: the result streams as the response body and the
/// envelope metadata travels in a base64 JSON header.
pub fn raw_download_io() -> ActionIo {
    ActionIo::RawDownload {
        metadata_header: RESULT_METADATA_HEADER.to_string(),
        metadata_encoding: HeaderEncoding::Base64Json,
    }
}

/// Standard attachment upload: one or more files described under
/// `/attachments`, located by the given action inputs.
pub fn attachment_upload_plan(
    locator_inputs: &[&str],
    max_files: Option<usize>,
) -> MultipartUploadSpec {
    MultipartUploadSpec {
        role: "attachment".to_string(),
        metadata_pointer: "/attachments".to_string(),
        field_name_prefix: "file".to_string(),
        min_files: 1,
        max_files,
        locator_inputs: locator_inputs
            .iter()
            .map(|input| input.to_string())
            .collect(),
        metadata_fields: vec![
            "field".to_string(),
            "filename".to_string(),
            "contentType".to_string(),
            "size".to_string(),
            "sha256".to_string(),
        ],
        caller_content_type_allowed: true,
    }
}

impl ServiceDescriptor {
    /// Built-in registrations may not claim imported naming provenance.
    pub fn validate_builtin_mcp_names(&self) -> Result<(), Vec<String>> {
        let errors: Vec<_> = self
            .actions
            .iter()
            .filter(|action| {
                !matches!(
                    action.scoped_mcp_name_source,
                    ScopedMcpNameSource::CanonicalAction
                )
            })
            .map(|action| {
                format!(
                    "service {} action {} must use canonical built-in MCP naming",
                    self.service, action.action
                )
            })
            .collect();
        if errors.is_empty() {
            Ok(())
        } else {
            Err(errors)
        }
    }

    pub fn action(&self, action: &str) -> Option<&ActionDescriptor> {
        self.actions
            .iter()
            .find(|candidate| candidate.action == action)
    }

    pub fn scope_types(&self) -> BTreeSet<String> {
        self.resource_scopes.keys().cloned().collect()
    }

    /// The resource scope an action is authorized against and its binding.
    pub fn action_resource_scope(
        &self,
        action: &str,
    ) -> Option<(&str, &ResourceScopeCapabilities)> {
        let scope = self.action(action)?.resource_scope.as_deref()?;
        self.resource_scopes
            .get_key_value(scope)
            .map(|(scope, binding)| (scope.as_str(), binding))
    }

    pub fn credential_profile_kind(&self, profile: &str) -> Option<&'static str> {
        self.credentials
            .profiles
            .iter()
            .find(|candidate| candidate.name == profile)
            .map(|candidate| candidate.kind)
    }

    /// Hosts agents use to reach a gateway service; empty for invoke services.
    pub fn broker_hosts(&self) -> Vec<String> {
        match &self.surface {
            ServiceSurface::Invoke => Vec::new(),
            ServiceSurface::Gateway { broker_hosts, .. } => broker_hosts.clone(),
        }
    }

    /// Inputs credential verification needs besides the credential, as
    /// projected on the wire by capability discovery and credential targets.
    pub fn credential_verification_inputs(&self) -> Vec<String> {
        self.credentials
            .verification_inputs
            .iter()
            .map(|input| (*input).to_string())
            .collect()
    }

    pub fn is_gateway(&self) -> bool {
        matches!(self.surface, ServiceSurface::Gateway { .. })
    }

    /// Wire projection returned by capability discovery.
    pub fn capabilities(&self) -> ServiceCapabilities {
        let (surface, gateway_kind) = match &self.surface {
            ServiceSurface::Invoke => ("invoke".to_string(), None),
            ServiceSurface::Gateway { kind, .. } => ("gateway".to_string(), Some(kind.clone())),
        };
        ServiceCapabilities {
            service: self.service.clone(),
            display_name: self.display_name.clone(),
            surface,
            gateway_kind,
            broker_hosts: self.broker_hosts(),
            credential_verification_inputs: self.credential_verification_inputs(),
            scope_types: self.resource_scopes.keys().cloned().collect(),
            resource_scopes: self.resource_scopes.clone(),
            actions: self
                .actions
                .iter()
                .map(ActionDescriptor::capabilities)
                .collect(),
        }
    }

    /// Structural checks every descriptor must pass before a runtime or
    /// validation catalog may use it.
    pub fn validate(&self) -> Result<(), Vec<String>> {
        let service = &self.service;
        let mut errors = Vec::new();
        if service == "broker" || !crate::is_service_name(service) {
            errors.push(format!("service {service} has an invalid service name"));
        }
        if let Some(connection) = &self.credentials.delegated
            && (connection.description.trim().is_empty() || connection.description.len() > 512)
        {
            errors.push(format!(
                "service {service} needs a delegated connection description of at most 512 bytes"
            ));
        }
        let mut actions = BTreeSet::new();
        for action in &self.actions {
            let name = &action.action;
            if action
                .documentation
                .as_ref()
                .is_some_and(|value| !value.is_object())
            {
                errors.push(format!("{service}.{name} documentation must be an object"));
            }
            if !crate::is_action_name(name) {
                errors.push(format!("{service}.{name} has an invalid action name"));
            }
            if !actions.insert(name.as_str()) {
                errors.push(format!("{service}.{name} is declared more than once"));
            }
            if let Some(scope) = &action.resource_scope
                && !self.resource_scopes.contains_key(scope)
            {
                errors.push(format!(
                    "{service}.{name} references undeclared resource scope {scope}"
                ));
            }
            if action.requires_resource_attributes
                && (action.resource_scope.is_none() || action.search_contained)
            {
                errors.push(format!(
                    "{service}.{name} private attributes require one exact scoped target"
                ));
            }
            if action.search_contained && action.resource_scope.is_none() {
                errors.push(format!(
                    "{service}.{name} is search-contained without a resource scope"
                ));
            }
            if action.credential_modes.is_empty() {
                errors.push(format!("{service}.{name} declares no credential modes"));
            }
            if action.input_schema.get("type").and_then(Value::as_str) != Some("object") {
                errors.push(format!(
                    "{service}.{name} input schema must describe an object"
                ));
            } else if let Err(error) = jsonschema::validator_for(&action.input_schema) {
                errors.push(format!("{service}.{name} input schema is invalid: {error}"));
            }
            if action.lookup == LookupRequirement::ScopeResolution
                && action.resource_scope.is_none()
            {
                errors.push(format!(
                    "{service}.{name} resolves its resource scope by lookup but declares no resource scope"
                ));
            }
            if action.presentation.is_some() && matches!(action.io, ActionIo::RawDownload { .. }) {
                errors.push(format!(
                    "{service}.{name} streams its result and cannot declare a response presentation"
                ));
            }
            if let ActionIo::MultipartUpload { plan } = &action.io {
                for input in &plan.locator_inputs {
                    if action
                        .input_schema
                        .pointer(&format!("/properties/{input}"))
                        .is_none()
                        && !schema_mentions_property(&action.input_schema, input)
                    {
                        errors.push(format!(
                            "{service}.{name} upload locator input {input} is not an input property"
                        ));
                    }
                }
            }
            for pointer in &action.sensitive_output_pointers {
                if !pointer.starts_with("/result/") {
                    errors.push(format!(
                        "{service}.{name} sensitive output {pointer} must point into /result"
                    ));
                } else if !is_json_pointer(pointer) {
                    errors.push(format!(
                        "{service}.{name} sensitive output {pointer} is not a JSON pointer"
                    ));
                }
            }
        }
        if errors.is_empty() {
            Ok(())
        } else {
            Err(errors)
        }
    }
}

impl ServiceDescriptor {
    /// Every resource scope must bind a registered resource type and offer
    /// only selector forms that type supports.
    pub fn validate_resource_types(&self, registry: &crate::ResourceTypeRegistry) -> Vec<String> {
        let mut errors = Vec::new();
        for (scope, binding) in &self.resource_scopes {
            let Some(resource_type) = registry.get(&binding.resource_type) else {
                errors.push(format!(
                    "service {} scope {scope} uses unregistered resource type {}",
                    self.service, binding.resource_type
                ));
                continue;
            };
            let supported = resource_type.selector_kinds();
            for selector in &binding.selectors {
                if !supported.contains(&selector.as_str()) {
                    errors.push(format!(
                        "service {} scope {scope} offers selector {selector} that resource type {} does not support",
                        self.service, binding.resource_type
                    ));
                }
            }
        }
        errors
    }
}

/// Whether every `~` in the pointer starts an RFC 6901 escape.
fn is_json_pointer(pointer: &str) -> bool {
    let mut characters = pointer.chars();
    while let Some(character) = characters.next() {
        if character == '~' && !matches!(characters.next(), Some('0' | '1')) {
            return false;
        }
    }
    true
}

/// Whether any `properties` object in a schema (including `oneOf`/`anyOf`
/// branches) declares the property.
fn schema_mentions_property(schema: &Value, property: &str) -> bool {
    match schema {
        Value::Object(object) => {
            object
                .get("properties")
                .and_then(Value::as_object)
                .is_some_and(|properties| properties.contains_key(property))
                || object
                    .values()
                    .any(|value| schema_mentions_property(value, property))
        }
        Value::Array(items) => items
            .iter()
            .any(|value| schema_mentions_property(value, property)),
        _ => false,
    }
}

/// Response header carrying a raw download's JSON metadata.
pub const RESULT_METADATA_HEADER: &str = "X-Agent-Access-Result-Metadata";

/// How an action exchanges data with callers beyond its JSON inputs and
/// result.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(
    tag = "type",
    rename_all = "snake_case",
    rename_all_fields = "camelCase"
)]
pub enum ActionIo {
    Json,
    MultipartUpload {
        plan: MultipartUploadSpec,
    },
    RawDownload {
        metadata_header: String,
        metadata_encoding: HeaderEncoding,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct MultipartUploadSpec {
    pub role: String,
    pub metadata_pointer: String,
    pub field_name_prefix: String,
    pub min_files: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_files: Option<usize>,
    pub locator_inputs: Vec<String>,
    pub metadata_fields: Vec<String>,
    pub caller_content_type_allowed: bool,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum HeaderEncoding {
    Base64Json,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{AttributionRepresentation, AttributionVerb, ResourceType, ServiceSurface};
    use serde_json::json;

    fn service(actions: Vec<ActionDescriptor>) -> ServiceDescriptor {
        ServiceDescriptor {
            service: "example".to_string(),
            display_name: "Example".to_string(),
            surface: ServiceSurface::Invoke,
            resource_scopes: BTreeMap::from([(
                "project".to_string(),
                ResourceScopeCapabilities {
                    resource_type: ResourceType::new("example_project").unwrap(),
                    selectors: vec!["exact".to_string()],
                },
            )]),
            actions,
            credentials: CredentialDescriptor::without_execution_credential(),
            presentation_body_limit: None,
        }
    }

    fn action(name: &str) -> ActionDescriptor {
        ActionDescriptor::new(
            name,
            "test action",
            json!({
                "type": "object",
                "properties": {"project": {"type": "string"}, "body": {"type": "string"}}
            }),
        )
        .scope("project")
        .credential_modes(["service"])
    }

    fn errors(actions: Vec<ActionDescriptor>) -> Vec<String> {
        service(actions).validate().err().unwrap_or_default()
    }

    #[test]
    fn extended_documentation_must_be_an_object() {
        assert!(
            errors(vec![
                action("item.view").documentation(json!({"examples": []}))
            ])
            .is_empty()
        );
        assert!(
            errors(vec![action("item.view").documentation(json!("invalid"))])
                .iter()
                .any(|error| error.contains("documentation must be an object"))
        );
    }

    #[test]
    fn capability_read_only_requires_explicit_backend_classification() {
        // Names do not classify tools: an unreviewed "read" remains potentially writable.
        let unreviewed = action("item.read").capabilities();
        let reviewed = action("item.view").read_only().capabilities();
        assert!(!unreviewed.read_only);
        assert!(reviewed.read_only);
        assert_eq!(serde_json::to_value(unreviewed).unwrap()["readOnly"], false);
        assert_eq!(serde_json::to_value(reviewed).unwrap()["readOnly"], true);
    }

    #[test]
    fn well_formed_descriptors_pass() {
        assert_eq!(
            errors(vec![
                action("item.view").lookup(LookupRequirement::ScopeResolution),
                action("item.comment").attribution(AttributionCapability::required(
                    AttributionVerb::Add,
                    "body",
                    AttributionRepresentation::GitlabMarkdown,
                )),
                action("item.token").sensitive_output("/result/token~1value"),
            ]),
            Vec::<String>::new()
        );
    }

    #[test]
    fn delegated_services_describe_their_connection() {
        let with = |description: &'static str| {
            let mut service = service(vec![action("item.view")]);
            service.credentials = CredentialDescriptor::default().delegated(description);
            service.validate().err().unwrap_or_default()
        };
        assert_eq!(with("Lets agents read items."), Vec::<String>::new());
        let too_long: &'static str = Box::leak("x".repeat(513).into_boxed_str());
        for description in ["", "   ", too_long] {
            assert_eq!(
                with(description),
                ["service example needs a delegated connection description of at most 512 bytes"]
            );
        }
    }

    #[test]
    fn input_schemas_must_compile_and_describe_objects() {
        let mut invalid_pattern = action("item.view");
        invalid_pattern.input_schema = json!({
            "type": "object",
            "properties": {"project": {"type": "string", "pattern": "("}}
        });
        let mut not_an_object = action("item.list");
        not_an_object.input_schema = json!({"type": "array"});
        let errors = errors(vec![invalid_pattern, not_an_object]);
        assert_eq!(errors.len(), 2, "{errors:?}");
        assert!(errors[0].starts_with("example.item.view input schema is invalid"));
        assert_eq!(
            errors[1],
            "example.item.list input schema must describe an object"
        );
    }

    #[test]
    fn impossible_combinations_are_rejected() {
        let mut unscoped_lookup = action("item.view").lookup(LookupRequirement::ScopeResolution);
        unscoped_lookup.resource_scope = None;
        let presented_download = action("item.download").raw_download().presentation(Some(
            crate::presentation::ActionPresentation {
                embedded_bodies: &[],
                whole: None,
            },
        ));
        let malformed_pointer = action("item.token").sensitive_output("/result/~2");
        assert_eq!(
            errors(vec![unscoped_lookup, presented_download, malformed_pointer,]),
            [
                "example.item.view resolves its resource scope by lookup but declares no resource scope",
                "example.item.download streams its result and cannot declare a response presentation",
                "example.item.token sensitive output /result/~2 is not a JSON pointer",
            ]
        );
    }
}
