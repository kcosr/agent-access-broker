//! Host-side preparation for administrative discovery and catalog publication.
use super::*;
use crate::{ImportedServiceStatus, assign_imported_action_names};
use agent_access_provider::{ImportedDiscovery, ImportedDiscoveryCredential};

impl BrokerRuntime {
    pub async fn discover_imported_service(
        &self,
        service: &str,
        administrator: &str,
    ) -> Result<(ImportedDiscovery, BTreeMap<String, String>), ProviderError> {
        let record = self
            .imported_catalog
            .service(service)
            .cloned()
            .ok_or_else(import_control_unavailable)?;
        self.require_import_destination(&record.definition)
            .map_err(provider_error_from_managed_store)?;
        if record.status == ImportedServiceStatus::Retired {
            return Err(ProviderError::deny(
                ReasonCode::InputInvalid,
                "retired imports cannot be discovered",
            ));
        }
        if let ImportedDiscoveryCredential::PerUser { principal } = &record.definition.discovery
            && principal != administrator
        {
            return Err(ProviderError::deny(
                ReasonCode::InputInvalid,
                "personal discovery must use the invoking administrator's credential",
            ));
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
                    && b.mechanism == agent_access_provider::ImportedAuthMechanism::Oauth
            }) {
                if !self.import_binding_available(&record.definition, binding) {
                    return Err(import_control_unavailable());
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
                .await?;
                let access = lease.access();
                if access.target != record.definition.endpoint
                    || access.audience != record.definition.endpoint
                {
                    return Err(import_control_unavailable());
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
            use agent_access_provider::ImportedDiscoveryAuthentication::{Delegated, Static};
            let execution = match &selected.definition.discovery {
                ImportedDiscoveryCredential::Anonymous => {
                    agent_access_provider::ImportedDiscoveryAuthentication::Anonymous
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
        .map_err(provider_error_from_managed_store)?;
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
        let mut discovery = adapter
            .discover(&record.definition, &execution, transport, &host)
            .await?;
        assign_imported_action_names(&record, &mut discovery).map_err(|_| {
            ProviderError::error(
                ReasonCode::UpstreamProtocolFailed,
                "upstream returned duplicate or invalid tool identities",
            )
        })?;
        Ok((discovery, versions))
    }
}

fn import_control_unavailable() -> ProviderError {
    ProviderError::deny(
        ReasonCode::CredentialNotProvisioned,
        "imported discovery credential is unavailable",
    )
}
