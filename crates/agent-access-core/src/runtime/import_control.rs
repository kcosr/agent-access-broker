//! Host-side preparation for administrative discovery and catalog publication.
use super::*;
use crate::imports::{ImportedDiscovery, ImportedDiscoveryCredential};
use crate::{ImportedServiceStatus, assign_imported_action_names};

/// Why administrative discovery produced no preview.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ImportDiscoveryError {
    /// The host could not prepare discovery or its catalog publication.
    Preparation(ImportPreparationError),
    /// The adapter's discovery, or a host port acting for it such as a
    /// delegated OAuth lease, failed with its own outcome. Discovery runs as
    /// a credential-verification hook of the imported service, so an outcome
    /// outside that contract arrives as `broker_provider_contract_failed`.
    Discovery(ProviderError),
}

/// A host failure preparing discovery or its catalog publication: the import
/// is retired, its settings are invalid, its destination, discovery credential
/// or adapter is unavailable, the managed store could not provide the
/// credential, or the discovered tools cannot be named. It carries a reason
/// and a public message but no decision; host management reports it as its
/// own failure.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ImportPreparationError {
    reason_code: ReasonCode,
    message: std::borrow::Cow<'static, str>,
}

impl ImportPreparationError {
    fn new(reason_code: ReasonCode, message: impl Into<std::borrow::Cow<'static, str>>) -> Self {
        Self {
            reason_code,
            message: message.into(),
        }
    }

    pub fn reason_code(&self) -> ReasonCode {
        self.reason_code
    }

    pub fn message(&self) -> &str {
        &self.message
    }
}

impl From<ManagedStoreError> for ImportPreparationError {
    fn from(error: ManagedStoreError) -> Self {
        Self::new(error.reason_code(), managed_store_failure_message(&error))
    }
}

impl From<ImportPreparationError> for ImportDiscoveryError {
    fn from(error: ImportPreparationError) -> Self {
        Self::Preparation(error)
    }
}

impl BrokerRuntime {
    pub async fn discover_imported_service(
        &self,
        service: &str,
        administrator: &str,
    ) -> Result<(ImportedDiscovery, BTreeMap<String, String>), ImportDiscoveryError> {
        let record = self
            .imported_catalog
            .service(service)
            .cloned()
            .ok_or_else(import_control_unavailable)?;
        self.require_import_destination(&record.definition)
            .map_err(ImportPreparationError::from)?;
        if record.status == ImportedServiceStatus::Retired {
            return Err(ImportPreparationError::new(
                ReasonCode::InputInvalid,
                "retired imports cannot be discovered",
            )
            .into());
        }
        if let ImportedDiscoveryCredential::PerUser { principal } = &record.definition.discovery
            && principal != administrator
        {
            return Err(ImportPreparationError::new(
                ReasonCode::InputInvalid,
                "personal discovery must use the invoking administrator's credential",
            )
            .into());
        }
        let store = self
            .managed_store
            .clone()
            .ok_or_else(import_control_unavailable)?;
        let ring = self
            .credential_key_ring
            .clone()
            .ok_or_else(import_control_unavailable)?;
        let oauth_lease = if let ImportedDiscoveryCredential::PerUser { principal } =
            &record.definition.discovery
        {
            if let Some(binding) = record.definition.execution_bindings.iter().find(|b| {
                b.owner_mode == ImportedCredentialMode::PerUser
                    && b.mechanism == crate::imports::ImportedAuthMechanism::Oauth
            }) {
                if !self.import_binding_available(&record.definition, binding) {
                    return Err(import_control_unavailable().into());
                }
                let manager = self
                    .oauth_manager()
                    .ok_or_else(import_control_unavailable)?;
                let lease = crate::oauth::ManagedOAuthLease::acquire(
                    manager.clone(),
                    service.to_string(),
                    principal.clone(),
                    crate::OAuthBinding {
                        registration: binding
                            .registration_id
                            .clone()
                            .ok_or_else(import_control_unavailable)?,
                        permission_profile: binding
                            .profile
                            .clone()
                            .ok_or_else(import_control_unavailable)?,
                    },
                )
                .await
                .map_err(ImportDiscoveryError::Discovery)?;
                let access = lease.access();
                if access.target != record.definition.endpoint
                    || access.audience != record.definition.endpoint
                {
                    return Err(import_control_unavailable().into());
                }
                Some(lease)
            } else {
                None
            }
        } else {
            None
        };
        let selected = record.clone();
        let (execution, transport, versions) = managed_store_blocking(move || {
            let service = &selected.definition.service;
            let versions =
                store.imported_discovery_credential_versions(service, selected.version)?;
            let slot = |purpose| {
                store.resolve_imported_secret(
                    service,
                    purpose,
                    selected
                        .slot_versions
                        .get(&purpose)
                        .ok_or(ManagedStoreError::CredentialNotFound)?,
                    &ring,
                )
            };
            use crate::imports::ImportedDiscoveryAuthentication::{Delegated, Static};
            let execution = match &selected.definition.discovery {
                ImportedDiscoveryCredential::Anonymous => {
                    crate::imports::ImportedDiscoveryAuthentication::Anonymous
                }
                ImportedDiscoveryCredential::Execution => {
                    Static(slot(ImportedCredentialPurpose::Execution)?)
                }
                ImportedDiscoveryCredential::Slot => {
                    Static(slot(ImportedCredentialPurpose::Discovery)?)
                }
                ImportedDiscoveryCredential::PerUser { principal } => {
                    if let Some(credential) = oauth_lease {
                        Delegated(credential)
                    } else {
                        let candidate = store.resolve_user_credential_for_verification(
                            &ring,
                            principal,
                            service,
                            "default",
                            "token",
                            crate::CredentialManagementPurpose::Administrative,
                        )?;
                        if versions.get(&format!("user:{principal}"))
                            != Some(&candidate.target.material_version)
                        {
                            return Err(ManagedStoreError::VersionConflict);
                        }
                        Static(candidate.credential)
                    }
                }
            };
            let transport = selected
                .definition
                .transport_auth
                .then(|| slot(ImportedCredentialPurpose::Transport))
                .transpose()?;
            Ok((execution, transport, versions))
        })
        .await
        .map_err(ImportPreparationError::from)?;
        let adapter = self
            .config
            .providers
            .registry()
            .imported_adapter(&record.definition.adapter_kind)
            .ok_or_else(import_control_unavailable)?;
        let clients = self.network.client_factory(ClientCaller::ImportAdapter {
            kind: adapter.kind(),
        });
        let host = agent_access_provider::host::build_context(
            self.network.limits(),
            &clients,
            ProviderAttributionConfig::default(),
            None,
        );
        // Administrative discovery is an upstream check with stored
        // credentials outside any invocation, so it is held to the
        // credential-verification contract. Imported services register no
        // domain reasons.
        let hook = agent_access_provider::host::hook_context(
            service,
            "import.discover",
            HookPhase::CredentialVerification,
            &[],
        );
        let mut discovery = match agent_access_provider::host::with_hook_context(
            hook.clone(),
            adapter.discover(&record.definition, &execution, transport, &host),
        )
        .await
        {
            Ok(discovery) => discovery,
            Err(AdapterDiscoveryError::Configuration(message)) => {
                return Err(ImportPreparationError::new(
                    ReasonCode::ConfigValidationFailed,
                    message,
                )
                .into());
            }
            Err(AdapterDiscoveryError::Failed(error)) => {
                return Err(ImportDiscoveryError::Discovery(checked_hook_failure(
                    &hook, error,
                )));
            }
        };
        assign_imported_action_names(&record, &mut discovery).map_err(|_| {
            ImportPreparationError::new(
                ReasonCode::UpstreamProtocolFailed,
                "upstream returned duplicate or invalid tool identities",
            )
        })?;
        Ok((discovery, versions))
    }
}

fn import_control_unavailable() -> ImportPreparationError {
    ImportPreparationError::new(
        ReasonCode::CredentialNotProvisioned,
        "imported discovery credential is unavailable",
    )
}
