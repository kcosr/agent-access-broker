//! The development fake backend: one `echo` action authorized against
//! `fake_project` resources, used by smoke tests and local fixtures.
use agent_access_provider::{
    ActionDescriptor, BackendConfig, BackendRegistration, BuildContext, CredentialDescriptor,
    EgressProxyConfig, Provider, ProviderBuildError, ProviderError, ProviderInvocation,
    ProviderResult, ReasonCode, ResourceScopeCapabilities, ResourceScopes, ResourceType,
    ResourceTypeDescriptor, ServiceDescriptor, ServiceProvider, ServiceSurface, ValidationContext,
    parse_backend_config,
};
use async_trait::async_trait;
use serde::Deserialize;
use serde_json::{Value, json};
use std::collections::BTreeMap;
use std::sync::Arc;

#[derive(Debug, Clone)]
pub struct FakeProvider;

impl Default for FakeProvider {
    fn default() -> Self {
        Self
    }
}

#[async_trait]
impl Provider for FakeProvider {
    fn resolve_scopes(
        &self,
        action: &str,
        inputs: &Value,
    ) -> Result<ResourceScopes, ProviderError> {
        if action != "echo" {
            return Err(ProviderError::deny(
                ReasonCode::ServiceActionDenied,
                "fake action is not supported",
            ));
        }
        let Some(object) = inputs.as_object() else {
            return Err(ProviderError::deny(
                ReasonCode::InputInvalid,
                "fake.echo inputs must be a JSON object",
            ));
        };
        for key in object.keys() {
            if key != "project" && key != "message" {
                return Err(ProviderError::deny(
                    ReasonCode::InputInvalid,
                    format!("fake.echo input {key} is not supported"),
                ));
            }
        }
        let Some(project) = inputs.get("project").and_then(Value::as_str) else {
            return Err(ProviderError::deny(
                ReasonCode::InputInvalid,
                "fake.echo requires project",
            ));
        };
        if inputs.get("message").and_then(Value::as_str).is_none() {
            return Err(ProviderError::deny(
                ReasonCode::InputInvalid,
                "fake.echo requires message",
            ));
        }
        if !is_fake_project_key(project) {
            return Err(ProviderError::deny(
                ReasonCode::InputInvalid,
                "fake.echo project is invalid",
            ));
        }
        let mut scopes = ResourceScopes::new();
        scopes.insert("project".to_string(), vec![project.to_string()]);
        Ok(scopes)
    }

    async fn invoke(&self, request: ProviderInvocation) -> Result<ProviderResult, ProviderError> {
        let Some(message) = request.inputs.get("message").and_then(Value::as_str) else {
            return Err(ProviderError::deny(
                ReasonCode::InputInvalid,
                "fake.echo requires message",
            ));
        };
        let project = request
            .resource_scopes
            .get("project")
            .and_then(|values| values.first())
            .cloned()
            .unwrap_or_default();
        Ok(ProviderResult {
            result: json!({
                "provider": "fake",
                "action": request.action,
                "project": project,
                "message": message,
                "credentialMode": request.credential_mode,
                "principal": request.identity.principal,
            }),
            stream: None,
            audit: Some(json!({
                "provider": "fake",
                "operation": "echo",
                "messageLength": message.len(),
            })),
            upstream_status: None,
            upstream_duration_ms: None,
            object_ids: None,
        })
    }
}

/// `[providers.fake]`: the fake backend has no settings.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FakeProviderConfig {}

/// The fake service: its projects, actions, and credential modes.
pub fn fake_descriptor() -> ServiceDescriptor {
    ServiceDescriptor {
        service: "fake".to_string(),
        display_name: "Fake Provider".to_string(),
        surface: ServiceSurface::Invoke,
        resource_scopes: BTreeMap::from([(
            "project".to_string(),
            ResourceScopeCapabilities {
                resource_type: FAKE_PROJECT_RESOURCE.id.clone(),
                selectors: vec!["exact".to_string(), "all".to_string()],
            },
        )]),
        actions: vec![
            ActionDescriptor::new(
                "echo",
                "Echo scalar inputs after policy and credential selection",
                json!({
                    "type": "object",
                    "required": ["project", "message"],
                    "properties": {
                        "project": { "type": "string" },
                        "message": { "type": "string" }
                    },
                    "additionalProperties": false
                }),
            )
            .read_only()
            .scope("project")
            .credential_modes(["service", "per_user"]),
        ],
        credentials: CredentialDescriptor::without_execution_credential(),
        presentation_body_limit: None,
    }
}

/// The fake provider paired with its descriptor, for runtimes built without
/// a `[providers.fake]` table.
pub fn fake_service_provider() -> ServiceProvider {
    ServiceProvider::new(fake_descriptor(), Arc::new(FakeProvider))
}

pub static FAKE_BACKEND: BackendRegistration = BackendRegistration {
    kind: "fake",
    resource_types: &[&FAKE_PROJECT_RESOURCE],
    parse: parse_backend_config::<FakeProviderConfig>,
    development_only: true,
};

impl BackendConfig for FakeProviderConfig {
    fn kind(&self) -> &'static str {
        "fake"
    }

    fn validate(&self, _context: &ValidationContext<'_>, _errors: &mut Vec<String>) {}

    fn descriptor(&self) -> ServiceDescriptor {
        fake_descriptor()
    }

    fn egress_proxies(&self) -> Vec<(String, &EgressProxyConfig)> {
        Vec::new()
    }

    fn build(&self, _host: &BuildContext<'_>) -> Result<Arc<dyn Provider>, ProviderBuildError> {
        Ok(Arc::new(FakeProvider))
    }
}

/// Projects of the development fake service.
pub static FAKE_PROJECT_RESOURCE: ResourceTypeDescriptor = ResourceTypeDescriptor {
    action_inputs: None,
    attributes: &[],
    id: ResourceType::from_static("fake_project"),
    label: "Fake project",
    plural_label: "Fake projects",
    example: "TEST",
    canonical: is_fake_project_key,
    namespace: None,
};

fn is_fake_project_key(value: &str) -> bool {
    let mut chars = value.chars();
    matches!(chars.next(), Some(first) if first.is_ascii_uppercase())
        && chars.all(|ch| ch.is_ascii_uppercase() || ch.is_ascii_digit() || ch == '_')
}
