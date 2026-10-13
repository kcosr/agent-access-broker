//! Protocol-specific implementation seam for managed imported services.
use crate::{
    BuildContext, DelegatedCredential, ExecutionCredential, ImportedActionDefinition,
    ImportedServiceDefinition, Provider, ProviderBuildError, ProviderError,
};
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::sync::Arc;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct ImportedDiscoveredTool {
    /// The host assigns the canonical action name; adapters preserve source identity.
    pub definition: ImportedActionDefinition,
    /// An unsupported source row remains visible but cannot be accepted.
    pub unsupported_reason: Option<String>,
    /// Untrusted source suggestion, never an administrator's classification.
    pub read_only_hint: Option<bool>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct ImportedDiscovery {
    pub protocol_version: String,
    /// Bounded nonsecret source metadata; never arbitrary server instructions.
    pub metadata: Value,
    pub tools: Vec<ImportedDiscoveredTool>,
}

/// Host-authorized discovery identity. Delegated credentials retain their lease
/// so adapters revalidate every request instead of keeping a token snapshot.
pub enum ImportedDiscoveryAuthentication {
    Anonymous,
    Static(ExecutionCredential),
    Delegated(DelegatedCredential),
}

#[async_trait]
pub trait ImportedAdapter: Send + Sync + std::fmt::Debug {
    fn kind(&self) -> &'static str;
    /// A development fixture: the host accepts its kind only in a non-production
    /// deployment with `deployment.enable_fake_service`.
    fn development_only(&self) -> bool;
    /// Validate protocol-specific configuration without contacting upstream.
    fn validate_definition(&self, definition: &ImportedServiceDefinition) -> Result<(), String> {
        definition.validate()?;
        if !definition.connection_settings.is_empty()
            || matches!(
                definition.discovery,
                crate::ImportedDiscoveryCredential::Anonymous
            )
        {
            return Err(
                "import adapter does not support these connection settings or anonymous discovery"
                    .into(),
            );
        }
        Ok(())
    }
    /// Additional destinations must pass the same operator policy as the API endpoint.
    fn additional_destinations(
        &self,
        _definition: &ImportedServiceDefinition,
    ) -> Result<Vec<String>, String> {
        Ok(Vec::new())
    }
    /// Opaque upstream data is sensitive; adapters may leave effect receipts outside it.
    fn sensitive_output_pointers(&self) -> &'static [&'static str] {
        &["/result"]
    }
    fn validate_action(&self, action: &ImportedActionDefinition) -> Result<(), String>;
    /// Exact accepted source name, derived offline without applying the narrower
    /// scoped MCP profile. Must succeed for every action accepted by validation.
    fn scoped_mcp_name(&self, action: &ImportedActionDefinition) -> Result<String, String>;
    /// Construction compiles accepted schemas and host transports without network I/O.
    /// The host builds an adapter's clients in the ordinary routing category.
    fn build(
        &self,
        definition: &ImportedServiceDefinition,
        actions: &[ImportedActionDefinition],
        transport_credential: Option<ExecutionCredential>,
        host: &BuildContext<'_>,
    ) -> Result<Arc<dyn Provider>, ProviderBuildError>;
    /// The host resolves/authorizes both identities and gates the endpoint before calling.
    async fn discover(
        &self,
        definition: &ImportedServiceDefinition,
        authentication: &ImportedDiscoveryAuthentication,
        transport_credential: Option<ExecutionCredential>,
        host: &BuildContext<'_>,
    ) -> Result<ImportedDiscovery, ProviderError>;
}
