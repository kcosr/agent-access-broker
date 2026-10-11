use crate::{
    BrokerBodyPartSpec, CorrelationContext, ExecutionCredential, ProviderCredentialVerification,
    ProviderError, ProviderInvocation, ProviderResult, ProviderScopeResolution, ReasonCode,
    ResourceScopes, ResourceType, ServiceDescriptor,
};
use async_trait::async_trait;
use serde_json::Value;
use std::sync::Arc;

/// A provider paired with the descriptor of the service it serves. The
/// runtime reads a service's definition only from here: for configured
/// backends the descriptor is the configuration's own, so validation,
/// admission, discovery, and the catalog all see the same one.
#[derive(Clone)]
pub struct ServiceProvider {
    pub descriptor: ServiceDescriptor,
    pub provider: Arc<dyn Provider>,
}

impl ServiceProvider {
    pub fn new(descriptor: ServiceDescriptor, provider: Arc<dyn Provider>) -> Self {
        Self {
            descriptor,
            provider,
        }
    }
}

impl std::fmt::Debug for ServiceProvider {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ServiceProvider")
            .field("service", &self.descriptor.service)
            .finish_non_exhaustive()
    }
}

#[async_trait]
pub trait Provider: Send + Sync {
    fn resolve_scopes(&self, action: &str, inputs: &Value)
    -> Result<ResourceScopes, ProviderError>;

    /// Configured top-level namespace values of a resource type, such as
    /// CloudBees CI controller aliases. Discovery reports only the roots a
    /// caller's effective coverage reaches; never return them to callers
    /// unfiltered.
    fn resource_roots(&self, _resource_type: &ResourceType) -> Vec<String> {
        Vec::new()
    }

    async fn resolve_scopes_with_lookup(
        &self,
        action: &str,
        inputs: &Value,
        _lookup_credential: Option<&ExecutionCredential>,
    ) -> Result<ResourceScopes, ProviderError> {
        self.resolve_scopes(action, inputs)
    }

    async fn resolve_scopes_with_lookup_context(
        &self,
        action: &str,
        inputs: &Value,
        lookup_credential: Option<&ExecutionCredential>,
    ) -> Result<ProviderScopeResolution, ProviderError> {
        Ok(ProviderScopeResolution {
            resource_scopes: self
                .resolve_scopes_with_lookup(action, inputs, lookup_credential)
                .await?,
            provider_preflight: None,
        })
    }

    async fn authorize_body_parts(
        &self,
        _request: &mut ProviderInvocation,
    ) -> Result<Vec<BrokerBodyPartSpec>, ProviderError> {
        Err(ProviderError::deny(
            ReasonCode::BodyMalformed,
            "action does not accept multipart body parts",
        ))
    }

    async fn verify_execution_credential(
        &self,
        _credential: &ExecutionCredential,
        _correlation: &CorrelationContext,
    ) -> Result<Option<ProviderCredentialVerification>, ProviderError> {
        Ok(None)
    }

    async fn invoke(&self, request: ProviderInvocation) -> Result<ProviderResult, ProviderError>;
}
