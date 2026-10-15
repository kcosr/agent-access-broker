//! Protocol-specific implementation seam for managed imported services.
use super::{
    CommandProvider, ImportEndpointForm, ImportedActionDefinition, ImportedDiscoveryCredential,
    ImportedServiceDefinition, ImportedServiceMetadata,
};
use crate::CommandImportConfig;
use agent_access_provider::{
    BuildContext, DelegatedCredential, ExecutionCredential, Provider, ProviderBuildError,
    ProviderError,
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
    /// The service-level metadata acceptance stores with the accepted
    /// actions (`imported_services.accepted_metadata_json`), as the adapter
    /// proposes it; `None` for adapters that record none. Omitted from the
    /// encoding when absent, so MCP and OpenAPI previews and their manifest
    /// hashes are unchanged.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub service_metadata: Option<ImportedServiceMetadata>,
    /// The host's decision for every resource type the source adds,
    /// changes, restores or removes, recorded when the preview is written;
    /// `service_metadata` then holds what acceptance stores. Adapters leave
    /// it empty, and an empty list is omitted from the encoding.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub resource_type_changes: Vec<super::ImportedResourceTypeChange>,
}

/// Core's inputs to [`ImportedAdapter::build`] and
/// [`ImportedAdapter::discover`] beyond the definition and the SDK build
/// context. Core resolves them for the import after its operator gate.
#[derive(Debug, Clone, Copy, Default)]
#[non_exhaustive]
pub struct ImportedAdapterContext<'a> {
    /// The service-level metadata accepted with the import's actions; `None`
    /// before the first acceptance and for adapters that record none.
    /// Discovery compares a refreshed source against it.
    pub accepted_metadata: Option<&'a ImportedServiceMetadata>,
    /// The operator's `[command_imports.<name>]` entry for a
    /// `command:<name>` endpoint; `None` for every other endpoint form. Core
    /// supplies it only while the entry approves the import.
    pub command: Option<&'a CommandImportConfig>,
}

impl<'a> ImportedAdapterContext<'a> {
    pub fn new(
        accepted_metadata: Option<&'a ImportedServiceMetadata>,
        command: Option<&'a CommandImportConfig>,
    ) -> Self {
        Self {
            accepted_metadata,
            command,
        }
    }
}

/// What an adapter builds for one enabled import.
#[derive(Clone)]
pub enum ImportedProvider {
    /// An import core invokes through [`Provider::invoke`].
    Upstream(Arc<dyn Provider>),
    /// A command import. Core uses its [`Provider`] half before dispatch and
    /// runs invocations and verification through the [`CommandProvider`]
    /// hook; see [`super::CommandProvider`].
    Command(Arc<dyn CommandProvider>),
}

impl ImportedProvider {
    /// The provider core publishes for the service.
    pub fn provider(&self) -> Arc<dyn Provider> {
        match self {
            Self::Upstream(provider) => provider.clone(),
            Self::Command(provider) => provider.clone(),
        }
    }

    /// The command hook, for a command import.
    pub fn command(&self) -> Option<&Arc<dyn CommandProvider>> {
        match self {
            Self::Command(provider) => Some(provider),
            Self::Upstream(_) => None,
        }
    }
}

impl std::fmt::Debug for ImportedProvider {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Upstream(_) => "ImportedProvider::Upstream",
            Self::Command(_) => "ImportedProvider::Command",
        })
    }
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
    /// The endpoint form this adapter's imports use. Core accepts a
    /// definition of this kind only when its endpoint has this form, and
    /// gates it accordingly: an HTTP(S) URL by `imports.allowed_endpoints`,
    /// `command:<name>` by the operator's `[command_imports.<name>]` entry.
    fn endpoint_form(&self) -> ImportEndpointForm {
        ImportEndpointForm::Http
    }
    /// Validate protocol-specific configuration without contacting upstream.
    fn validate_definition(&self, definition: &ImportedServiceDefinition) -> Result<(), String> {
        definition.validate()?;
        if !definition.connection_settings.is_empty()
            || matches!(definition.discovery, ImportedDiscoveryCredential::Anonymous)
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
    /// A command import never runs its command here: startup and reload stay
    /// offline. An adapter whose [`Self::endpoint_form`] is `Command` returns
    /// [`ImportedProvider::Command`]; every other adapter returns
    /// [`ImportedProvider::Upstream`], and core fails the import closed
    /// otherwise.
    fn build(
        &self,
        definition: &ImportedServiceDefinition,
        actions: &[ImportedActionDefinition],
        transport_credential: Option<ExecutionCredential>,
        import: &ImportedAdapterContext<'_>,
        host: &BuildContext<'_>,
    ) -> Result<ImportedProvider, ProviderBuildError>;
    /// The host resolves/authorizes both identities and gates the endpoint before calling.
    /// It runs discovery as a credential-verification hook of the imported
    /// service: a [`AdapterDiscoveryError::Failed`] outcome is checked like a
    /// verification failure, and configuration failures are the host's to
    /// report.
    async fn discover(
        &self,
        definition: &ImportedServiceDefinition,
        authentication: &ImportedDiscoveryAuthentication,
        transport_credential: Option<ExecutionCredential>,
        import: &ImportedAdapterContext<'_>,
        host: &BuildContext<'_>,
    ) -> Result<ImportedDiscovery, AdapterDiscoveryError>;
}

/// Why an adapter's administrative discovery produced no tools.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AdapterDiscoveryError {
    /// The import's settings or document destination cannot be prepared for
    /// discovery. Host management reports its `config_validation_failed`
    /// with this bounded, administrator-facing message.
    Configuration(String),
    /// Discovery failed upstream, or with its credential or protocol. The
    /// host checks it against the credential-verification contract.
    Failed(ProviderError),
}

impl From<ProviderError> for AdapterDiscoveryError {
    fn from(error: ProviderError) -> Self {
        Self::Failed(error)
    }
}
