use crate::{
    AdmittedRequest, BodyAdmission, CorrelationContext, ExecutionCredential,
    ProviderCredentialVerification, ProviderError, ProviderInvocation, ProviderResult,
    ProviderState, ReasonCode, ResourceType, ScopeRequest, ScopeResolution, ServiceDescriptor,
};
use async_trait::async_trait;
use std::sync::Arc;

/// A provider paired with the descriptor of the service it serves. The
/// runtime reads a service's definition only from here: for configured
/// backends the descriptor is the configuration's own, so validation,
/// admission, discovery, and the catalog all see the same one.
#[non_exhaustive]
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
    /// Names the canonical resources an action operates on. A local
    /// resolver returns immediately; an action-only provider explicitly
    /// returns [`ScopeResolution::no_resources`]. Lookup uses only the
    /// host-selected credential in the request.
    async fn resolve_scopes(
        &self,
        request: ScopeRequest<'_>,
    ) -> Result<ScopeResolution, ProviderError>;

    /// Configured top-level namespace values of a resource type, such as
    /// CloudBees CI controller aliases. Discovery reports only the roots a
    /// caller's effective coverage reaches; never return them to callers
    /// unfiltered.
    fn resource_roots(&self, _resource_type: &ResourceType) -> Vec<String> {
        Vec::new()
    }

    /// Admits multipart body-part metadata before the host consumes the
    /// body, and states what happens to the operation's provider state. It
    /// sees the admitted request (no body data, no decrypted private
    /// attributes) and the current state, and cannot change the service,
    /// identity, authority, credential selection or policy.
    async fn authorize_body_parts(
        &self,
        _request: &AdmittedRequest,
        _state: Option<&ProviderState>,
    ) -> Result<BodyAdmission, ProviderError> {
        Err(ProviderError::deny(
            ReasonCode::BodyMalformed,
            "action does not accept multipart body parts",
        ))
    }

    /// Verifies selected credential material upstream. `None` means
    /// verification is unsupported, never that it succeeded.
    async fn verify_execution_credential(
        &self,
        _credential: &ExecutionCredential,
        _correlation: &CorrelationContext,
    ) -> Result<Option<ProviderCredentialVerification>, ProviderError> {
        Ok(None)
    }

    async fn invoke(&self, request: ProviderInvocation) -> Result<ProviderResult, ProviderError>;
}
