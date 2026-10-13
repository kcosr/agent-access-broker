//! Immutable imported catalogs are published with the enclosing runtime snapshot.
//! Existing providers, identity, audit and OAuth state are shared across import edits.
use super::*;
use crate::{ImportedActionStatus, ImportedCatalog, ImportedServiceRecord, ImportedServiceStatus};
mod mcp_names;

/// Opaque provider preparation. Its provenance must match the committed catalog;
/// callers cannot substitute arbitrary providers or attest their own token writes.
pub struct PreparedImportedProviders {
    base_catalog: Arc<ImportedCatalog>,
    providers: BTreeMap<String, Arc<dyn Provider>>,
    service: String,
    definition: ImportedServiceDefinition,
    status: ImportedServiceStatus,
    enabled_actions: Vec<ImportedActionDefinition>,
    transport: PreparedTransport,
}

enum PreparedTransport {
    Existing(Option<String>),
    ReplacementPending([u8; 32]),
    ReplacementBound(String),
    Deleted,
}

impl PreparedImportedProviders {
    /// Bind a replacement to the exact plaintext/version accepted by the store.
    /// The proof is only available inside that secret write's transaction callback.
    pub fn bind_secret_write(
        mut self,
        proof: &crate::ImportedSecretWriteProof,
    ) -> Result<Self, ManagedStoreError> {
        let (service, purpose) = proof.target();
        if service != self.service {
            return Err(preparation_mismatch());
        }
        if purpose == ImportedCredentialPurpose::Transport {
            let PreparedTransport::ReplacementPending(digest) = &self.transport else {
                return Err(preparation_mismatch());
            };
            self.transport =
                PreparedTransport::ReplacementBound(proof.bind_transport(&self.service, digest)?);
        }
        Ok(self)
    }

    fn validate(
        self,
        runtime: &BrokerRuntime,
        catalog: &ImportedCatalog,
    ) -> Result<BTreeMap<String, Arc<dyn Provider>>, ManagedStoreError> {
        if !Arc::ptr_eq(&self.base_catalog, &runtime.imported_catalog) {
            return Err(preparation_mismatch());
        }
        let record = catalog
            .service(&self.service)
            .ok_or_else(preparation_mismatch)?;
        if record.definition != self.definition
            || record.status != self.status
            || enabled_definitions(record) != self.enabled_actions
        {
            return Err(preparation_mismatch());
        }
        let committed = record
            .slot_versions
            .get(&ImportedCredentialPurpose::Transport);
        let transport_matches = match &self.transport {
            PreparedTransport::Existing(version) => committed == version.as_ref(),
            PreparedTransport::ReplacementBound(version) => committed == Some(version),
            PreparedTransport::Deleted => committed.is_none(),
            PreparedTransport::ReplacementPending(_) => false,
        };
        if !transport_matches
            || (record.definition.transport_auth
                && committed.is_none()
                && self.providers.contains_key(&self.service))
        {
            return Err(preparation_mismatch());
        }
        // An imported mutation owns exactly one service. Other records and provider
        // Arcs remain those of its admitted runtime, including unavailable records.
        for old in &runtime.imported_catalog.services {
            let name = &old.definition.service;
            if name != &self.service && catalog.service(name) != Some(old) {
                return Err(preparation_mismatch());
            }
        }
        for candidate in &catalog.services {
            let name = &candidate.definition.service;
            if name == &self.service {
                continue;
            }
            if runtime.imported_catalog.service(name) != Some(candidate) {
                return Err(preparation_mismatch());
            }
            match (runtime.providers.get(name), self.providers.get(name)) {
                (None, None) => {}
                (Some(old), Some(prepared)) if Arc::ptr_eq(old, prepared) => {}
                _ => return Err(preparation_mismatch()),
            }
        }
        Ok(self.providers)
    }
}

fn enabled_definitions(record: &ImportedServiceRecord) -> Vec<ImportedActionDefinition> {
    let mut actions = record
        .actions
        .iter()
        .filter(|action| action.status == ImportedActionStatus::Enabled)
        .map(|action| action.definition.clone())
        .collect::<Vec<_>>();
    actions.sort_by(|left, right| left.action.cmp(&right.action));
    actions
}
fn preparation_mismatch() -> ManagedStoreError {
    ManagedStoreError::InputInvalid(
        "prepared imported provider does not match the committed definition or credential".into(),
    )
}

pub(super) fn descriptor(
    record: &ImportedServiceRecord,
    config: &BrokerConfig,
) -> ServiceDescriptor {
    let modes = record
        .definition
        .execution_bindings
        .iter()
        .map(|binding| binding.owner_mode.as_str())
        .collect::<Vec<_>>();
    // Arbitrary upstream content may contain private data or credentials.
    let sensitive_output_pointers: Vec<String> = config
        .providers
        .registry()
        .imported_adapter(&record.definition.adapter_kind)
        .map(|adapter| adapter.sensitive_output_pointers())
        .unwrap_or(&["/result"])
        .iter()
        .map(|pointer| (*pointer).to_owned())
        .collect();
    let adapter_kind = &record.definition.adapter_kind;
    let actions = record
        .actions
        .iter()
        .map(|record| {
            let definition = &record.definition;
            let mut action = ActionDescriptor::new(
                &definition.action,
                &definition.description,
                definition.input_schema.clone(),
            )
            .credential_modes(modes.iter().copied());
            action.scoped_mcp_name_source = ScopedMcpNameSource::Imported {
                name: config
                    .providers
                    .registry()
                    .imported_adapter(adapter_kind)
                    .and_then(|adapter| adapter.scoped_mcp_name(definition).ok()),
            };
            action.read_only = definition.read_only;
            action.sensitive_output_pointers = sensitive_output_pointers.clone();
            action
        })
        .collect();
    ServiceDescriptor {
        service: record.definition.service.clone(),
        display_name: record.definition.display_name.clone(),
        surface: ServiceSurface::Invoke,
        resource_scopes: BTreeMap::new(),
        actions,
        credentials: if record
            .definition
            .execution_bindings
            .iter()
            .any(|b| b.mechanism == agent_access_provider::ImportedAuthMechanism::Oauth)
        {
            CredentialDescriptor::default()
                .profile("token", "bearer_token")
                .delegated(
                    "Connect your account to authorize this imported service's reviewed actions.",
                )
        } else {
            CredentialDescriptor::default().profile("token", "bearer_token")
        },
        presentation_body_limit: None,
    }
}

fn destination_allowed(config: &BrokerConfig, definition: &ImportedServiceDefinition) -> bool {
    let Some(adapter) = config
        .providers
        .registry()
        .imported_adapter(&definition.adapter_kind)
    else {
        return false;
    };
    if adapter.development_only()
        && (config.deployment.environment == "production" || !config.deployment.enable_fake_service)
    {
        return false;
    }
    definition.validate().is_ok()
        && adapter.validate_definition(definition).is_ok()
        && config.imports.permits(
            &definition.service,
            &definition.adapter_kind,
            &definition.endpoint,
        )
        && adapter
            .additional_destinations(definition)
            .is_ok_and(|destinations| {
                destinations.iter().all(|destination| {
                    config.imports.permits(
                        &definition.service,
                        &definition.adapter_kind,
                        destination,
                    )
                })
            })
}

fn oauth_binding_allowed(
    config: &BrokerConfig,
    definition: &ImportedServiceDefinition,
    binding: &agent_access_provider::ImportedCredentialBinding,
) -> bool {
    if binding.mechanism != agent_access_provider::ImportedAuthMechanism::Oauth {
        return true;
    }
    let Some(registration) = binding
        .registration_id
        .as_ref()
        .and_then(|id| config.oauth.registrations.get(id))
    else {
        return false;
    };
    let Some(profile) = binding
        .profile
        .as_ref()
        .and_then(|id| registration.permission_profiles.get(id))
    else {
        return false;
    };
    binding.adapter_id.as_deref() == Some(registration.adapter.as_str())
        && config
            .providers
            .registry()
            .oauth_dialect(registration.adapter.as_str())
            .is_some()
        && profile.target == definition.endpoint
        && profile.audience == definition.endpoint
        && registration.adapter_settings.get("resource") == Some(&definition.endpoint)
}

pub(super) fn effective_credentials(config: &mut BrokerConfig, catalog: &ImportedCatalog) {
    config.credentials.imported_modes.clear();
    for record in &catalog.services {
        let service = &record.definition.service;
        let modes = record
            .definition
            .execution_bindings
            .iter()
            .filter(|binding| {
                binding.is_supported()
                    && oauth_binding_allowed(config, &record.definition, binding)
                    && (binding.owner_mode != ImportedCredentialMode::Service
                        || record
                            .slot_versions
                            .contains_key(&ImportedCredentialPurpose::Execution))
            })
            .map(|binding| binding.owner_mode.as_str().to_string())
            .collect::<Vec<_>>();
        config.credentials.per_user.remove(service);
        if modes.iter().any(|mode| mode == "per_user") {
            let binding = record
                .definition
                .execution_bindings
                .iter()
                .find(|binding| binding.owner_mode == ImportedCredentialMode::PerUser)
                .expect("selected mode");
            let oauth = binding.mechanism == agent_access_provider::ImportedAuthMechanism::Oauth;
            config.credentials.per_user.insert(
                service.clone(),
                CredentialConfig {
                    kind: if oauth { "oauth" } else { "managed_store" }.into(),
                    username_ref: None,
                    token_ref: None,
                    path: None,
                    read_only: None,
                    provider: oauth.then(|| binding.registration_id.clone()).flatten(),
                    credential_name: Some("default".into()),
                    profile: if oauth {
                        binding.profile.clone()
                    } else {
                        Some("token".into())
                    },
                },
            );
        }
        config
            .credentials
            .imported_modes
            .insert(service.clone(), modes);
        if let Some(limit) = &record.definition.invocation_limit {
            config.limits.invocations.services.insert(
                service.clone(),
                crate::InvocationLimitConfig {
                    requests: u64::from(limit.requests),
                    window: format!("{}s", limit.window_seconds),
                },
            );
        }
    }
}

/// Retained modes validate old references, but never determine execution availability.
pub(super) fn retention_config(config: &BrokerConfig, catalog: &ImportedCatalog) -> BrokerConfig {
    let mut retained = config.clone();
    effective_credentials(&mut retained, catalog);
    for record in &catalog.services {
        retained.credentials.imported_modes.insert(
            record.definition.service.clone(),
            record
                .definition
                .execution_bindings
                .iter()
                .map(|binding| binding.owner_mode.as_str().to_string())
                .collect(),
        );
    }
    retained
}

impl BrokerRuntime {
    pub fn imported_catalog(&self) -> &ImportedCatalog {
        &self.imported_catalog
    }
    pub fn import_operator_allowed(&self, definition: &ImportedServiceDefinition) -> bool {
        destination_allowed(&self.config, definition)
    }
    pub fn available_import_kinds(&self) -> Vec<String> {
        if !self.config.imports.enabled {
            return Vec::new();
        }
        self.config
            .imports
            .allowed_kinds
            .iter()
            .filter(|kind| {
                self.config
                    .providers
                    .registry()
                    .imported_adapter(kind)
                    .is_some_and(|adapter| {
                        !adapter.development_only()
                            || (self.config.deployment.environment != "production"
                                && self.config.deployment.enable_fake_service)
                    })
            })
            .cloned()
            .collect()
    }

    pub fn import_catalog_revision(&self) -> u64 {
        self.imported_catalog.revision
    }

    pub fn imported_service_unavailable_reason(&self, service: &str) -> Option<&'static str> {
        let record = self.imported_catalog.service(service)?;
        if record.status != ImportedServiceStatus::Enabled {
            return Some("Imported service is not enabled.");
        }
        if !destination_allowed(&self.config, &record.definition) {
            return Some("Imported service is disabled by operator policy.");
        }
        if self
            .config
            .providers
            .registry()
            .imported_adapter(&record.definition.adapter_kind)
            .is_none()
        {
            return Some("The imported adapter is not linked in this broker.");
        }
        if !self.providers.contains_key(service) {
            return Some(
                "The retained definition or transport credential is unavailable; review the import before enabling it.",
            );
        }
        if self
            .effective_credentials
            .imported_modes
            .get(service)
            .is_none_or(Vec::is_empty)
        {
            return Some("No supported execution credential mode is provisioned.");
        }
        if !record
            .actions
            .iter()
            .any(|action| action.status == ImportedActionStatus::Enabled)
        {
            return Some("No accepted actions are currently enabled.");
        }
        None
    }

    pub fn imported_action_available(&self, service: &str, action: &str) -> bool {
        let Some(record) = self.imported_catalog.service(service) else {
            return true;
        };
        self.import_dispatch
            .get(service)
            .is_some_and(|current| current.load(Ordering::Acquire))
            && record.status == ImportedServiceStatus::Enabled
            && destination_allowed(&self.config, &record.definition)
            && self.providers.contains_key(service)
            && record.actions.iter().any(|entry| {
                entry.definition.action == action && entry.status == ImportedActionStatus::Enabled
            })
    }

    pub fn imported_mode_available(&self, service: &str, mode: &str) -> bool {
        self.imported_catalog.service(service).is_none()
            || self
                .effective_credentials
                .imported_modes
                .get(service)
                .is_some_and(|modes| modes.iter().any(|available| available == mode))
    }

    pub fn shares_import_catalog(&self, replacement: &Self) -> bool {
        Arc::ptr_eq(&self.imported_catalog, &replacement.imported_catalog)
    }

    /// Reuse per-service fences across unrelated edits and configuration reloads.
    pub(super) fn initialize_import_dispatch(&mut self, previous: Option<&Self>) {
        self.import_dispatch = Arc::new(
            self.imported_catalog
                .services
                .iter()
                .map(|record| {
                    let name = &record.definition.service;
                    let prior = previous
                        .filter(|old| {
                            old.imported_catalog.service(name) == Some(record)
                                && ProviderLimits::from(&old.config.limits)
                                    == ProviderLimits::from(&self.config.limits)
                                && old.config.network.outbound_tls.trust
                                    == self.config.network.outbound_tls.trust
                                && old.config.network.outbound_tls.ca_certificate
                                    == self.config.network.outbound_tls.ca_certificate
                                && match (
                                    &old.config.network.egress_proxy,
                                    &self.config.network.egress_proxy,
                                ) {
                                    (None, None) => true,
                                    (Some(old), Some(new)) => {
                                        old.url == new.url
                                            && old.username_ref == new.username_ref
                                            && old.password_ref == new.password_ref
                                    }
                                    _ => false,
                                }
                                && destination_allowed(&old.config, &record.definition)
                                    == destination_allowed(&self.config, &record.definition)
                                && old.providers.contains_key(name)
                                    == self.providers.contains_key(name)
                        })
                        .and_then(|old| old.import_dispatch.get(name))
                        .filter(|flag| flag.load(Ordering::Acquire));
                    (
                        name.clone(),
                        prior
                            .cloned()
                            .unwrap_or_else(|| Arc::new(AtomicBool::new(true))),
                    )
                })
                .collect(),
        );
    }

    pub fn retire_import_dispatch(&self) {
        for flag in self.import_dispatch.values() {
            flag.store(false, Ordering::Release);
        }
    }

    pub fn retire_superseded_import_dispatch(&self, replacement: &Self) {
        for (service, old) in self.import_dispatch.iter() {
            if replacement
                .import_dispatch
                .get(service)
                .is_none_or(|new| !Arc::ptr_eq(old, new))
            {
                old.store(false, Ordering::Release);
            }
        }
    }

    /// Prepare a new coherent runtime without restarting any host subsystem.
    /// Supplied providers must have been built from these accepted definitions.
    /// No managed-store access occurs here, so this can finalize a DB candidate.
    pub fn with_imported_catalog(
        &self,
        catalog: ImportedCatalog,
        prepared: PreparedImportedProviders,
    ) -> Result<Self, ManagedStoreError> {
        self.validate_import_mcp_names(&catalog)?;
        let changed_service = prepared.service.clone();
        let imported_providers = prepared.validate(self, &catalog)?;
        let mut next = self.clone();
        let mut config = (*self.config).clone();
        let mut services = (*self.services).clone();
        let mut providers = (*self.providers).clone();
        for old in &self.imported_catalog.services {
            let name = &old.definition.service;
            services.remove(name);
            providers.remove(name);
            config.credentials.per_user.remove(name);
            config.limits.invocations.services.remove(name);
        }
        for record in &catalog.services {
            let name = &record.definition.service;
            if services.contains_key(name)
                || config.gateways.contains_key(name)
                || config.providers.registry().get(name).is_some()
                || name == "broker"
                || config.credentials.service.contains_key(name)
                || config.credentials.lookup.contains_key(name)
                || config.credentials.per_user.contains_key(name)
            {
                return Err(ManagedStoreError::InputInvalid(
                    "imported service identity collides with a configured service or credential"
                        .into(),
                ));
            }
            let old = self.imported_catalog.service(name);
            let newly_enabled = record.status == ImportedServiceStatus::Enabled
                && old.is_none_or(|old| old.status != ImportedServiceStatus::Enabled)
                || record.actions.iter().any(|action| {
                    action.status == ImportedActionStatus::Enabled
                        && old.is_none_or(|old| {
                            !old.actions.iter().any(|prior| {
                                prior.definition.action == action.definition.action
                                    && prior.status == ImportedActionStatus::Enabled
                            })
                        })
                });
            if (old.is_none() || newly_enabled) && !destination_allowed(&config, &record.definition)
            {
                return Err(ManagedStoreError::InputInvalid("import creation or enabling requires an allowed destination and linked adapter".into()));
            }
            if old.is_none_or(|old| old.definition != record.definition) || newly_enabled {
                record
                    .definition
                    .validate()
                    .map_err(ManagedStoreError::InputInvalid)?;
            }
            let definition = descriptor(record, &config);
            if imported_providers.contains_key(name) {
                definition
                    .validate()
                    .map_err(|errors| ManagedStoreError::InputInvalid(errors.join("; ")))?;
            }
            let required = record.status == ImportedServiceStatus::Enabled
                && destination_allowed(&config, &record.definition)
                && (!record.definition.transport_auth
                    || record
                        .slot_versions
                        .contains_key(&ImportedCredentialPurpose::Transport))
                && (self.providers.contains_key(name) || newly_enabled);
            if required && !imported_providers.contains_key(name) {
                return Err(ManagedStoreError::InputInvalid(
                    "prepared provider missing for available imported service".into(),
                ));
            }
            services.insert(name.clone(), Arc::new(definition));
        }
        for name in imported_providers.keys() {
            let record = catalog.service(name).ok_or_else(|| {
                ManagedStoreError::InputInvalid(
                    "prepared provider is not an imported service".into(),
                )
            })?;
            if record.status != ImportedServiceStatus::Enabled
                || !destination_allowed(&config, &record.definition)
            {
                return Err(ManagedStoreError::InputInvalid(
                    "prepared provider is not an enabled permitted import".into(),
                ));
            }
        }
        providers.extend(imported_providers);
        effective_credentials(&mut config, &catalog);
        next.effective_credentials = Arc::new(config.credentials.clone());
        next.invocation_limits = Arc::new(crate::ConfiguredInvocationLimits::from_config(&config));
        next.services = Arc::new(services);
        next.providers = Arc::new(providers);
        next.imported_catalog = Arc::new(catalog);
        next.initialize_import_dispatch(Some(self));
        next.initialize_scoped_mcp_readiness(Some(&changed_service));
        next.policy_snapshot = Arc::new(ArcSwap::from(self.policy_snapshot()));
        next.check_import_catalog_budgets()?;
        Ok(next)
    }

    pub(super) fn check_import_catalog_budgets(&self) -> Result<(), ManagedStoreError> {
        if self.imported_catalog.services.is_empty() {
            return Ok(());
        }
        let mut catalog = crate::empty_catalog(json!({}));
        catalog.resource_types = self.resource_type_metadata();
        catalog.services = self
            .services
            .values()
            .filter_map(|service| {
                let mut descriptor = (**service).clone();
                descriptor.actions.retain(|action| {
                    self.imported_action_available(&descriptor.service, &action.action)
                });
                (!descriptor.actions.is_empty())
                    .then(|| {
                        api_service_spec(&descriptor, self.scoped_mcp_ready(&descriptor.service))
                    })
                    .flatten()
            })
            .collect();
        for mode in [
            crate::mcp::ProjectionMode::Http,
            crate::mcp::ProjectionMode::Stdio,
        ] {
            crate::mcp::project_catalog_bounded(&catalog, mode, self.config.mcp.max_catalog_bytes)
                .map_err(|error| {
                    ManagedStoreError::InputInvalid(if error.0 == "catalog exceeds work limit" {
                        "import would exceed the complete MCP catalog budget".into()
                    } else {
                        format!("import catalog cannot be projected: {error}")
                    })
                })?;
        }
        struct BoundedWriter(usize);
        impl std::io::Write for BoundedWriter {
            fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
                self.0 = self
                    .0
                    .checked_sub(bytes.len())
                    .ok_or_else(|| std::io::Error::other("catalog budget"))?;
                Ok(bytes.len())
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }
        let openapi = crate::openapi_from_catalog(
            &catalog,
            crate::RenderAuthMode::Omit,
            &[],
            "broker_session",
        );
        let send = crate::send_schema_from_catalog(&catalog);
        for value in [
            serde_json::to_value(&catalog)
                .map_err(|_| ManagedStoreError::InputInvalid("catalog cannot be encoded".into()))?,
            openapi,
            send,
        ] {
            serde_json::to_writer(BoundedWriter(64 * 1024 * 1024), &value).map_err(|_| {
                ManagedStoreError::InputInvalid(
                    "import would exceed a runtime projection budget".into(),
                )
            })?;
        }
        Ok(())
    }

    pub(super) fn validate_new_imported_grants(
        &self,
        grants: &[ManagedPolicyGrantRecord],
        previous: &[ManagedPolicyGrantRecord],
    ) -> Result<(), ManagedStoreError> {
        for grant in grants {
            if self.imported_catalog.service(&grant.service).is_none() {
                continue;
            }
            for action in &grant.actions {
                let retained = previous.iter().any(|old| {
                    old.grant_id == grant.grant_id
                        && old.service == grant.service
                        && old.actions.contains(action)
                        && old.credential_mode == grant.credential_mode
                        && old.status != "deleted"
                        && (grant.status != "active" || old.status == "active")
                        && grant
                            .subjects
                            .iter()
                            .all(|subject| old.subjects.contains(subject))
                        && grant
                            .execution_contexts
                            .iter()
                            .all(|context| old.execution_contexts.contains(context))
                });
                if !retained
                    && (!self.imported_action_available(&grant.service, action)
                        || !self.imported_mode_available(&grant.service, &grant.credential_mode))
                {
                    return Err(ManagedStoreError::InputInvalid("new grant selections require an available imported action and credential mode".into()));
                }
            }
        }
        Ok(())
    }
}

/// Build a host-controlled adapter without contacting upstream. Call outside a
/// managed transaction; token material resolution must not reenter its DB lock.
pub(super) fn build_providers(
    config: &BrokerConfig,
    catalog: &ImportedCatalog,
    store: Option<&ManagedStore>,
    ring: Option<&CredentialKeyRing>,
    network: &HostNetwork,
) -> Result<BTreeMap<String, Arc<dyn Provider>>, RuntimeError> {
    let mut providers = BTreeMap::new();
    for record in &catalog.services {
        let definition = &record.definition;
        if record.status != ImportedServiceStatus::Enabled
            || !destination_allowed(config, definition)
        {
            continue;
        }
        if definition.validate().is_err() || descriptor(record, config).validate().is_err() {
            continue;
        }
        let Some(adapter) = config
            .providers
            .registry()
            .imported_adapter(&definition.adapter_kind)
        else {
            continue;
        };
        if adapter.development_only()
            && (config.deployment.environment == "production"
                || !config.deployment.enable_fake_service)
        {
            continue;
        }
        let transport = if definition.transport_auth {
            match record
                .slot_versions
                .get(&ImportedCredentialPurpose::Transport)
            {
                Some(version) => Some(
                    store
                        .ok_or_else(|| RuntimeError::ManagedStore {
                            message: "imported store unavailable".into(),
                        })?
                        .resolve_imported_secret(
                            &definition.service,
                            ImportedCredentialPurpose::Transport,
                            version,
                            ring.ok_or_else(|| RuntimeError::ManagedStore {
                                message: "import encryption unavailable".into(),
                            })?,
                        )
                        .map_err(runtime_managed_store_error)?,
                ),
                None => continue,
            }
        } else {
            None
        };
        let actions = record
            .actions
            .iter()
            .filter(|action| action.status == ImportedActionStatus::Enabled)
            .map(|action| action.definition.clone())
            .collect::<Vec<_>>();
        let clients = network.client_factory(ClientCaller::ImportAdapter {
            kind: adapter.kind(),
        });
        let host = agent_access_provider::host::build_context(
            network.limits(),
            &clients,
            ProviderAttributionConfig::default(),
            None,
        );
        if actions.iter().any(|action| {
            adapter.validate_action(action).is_err() || adapter.scoped_mcp_name(action).is_err()
        }) {
            continue;
        }
        if let Ok(provider) = adapter.build(definition, &actions, transport, &host) {
            providers.insert(definition.service.clone(), provider);
        }
    }
    Ok(providers)
}

impl BrokerRuntime {
    /// Only operator-approved, linked OAuth profiles are offered by import administration.
    pub fn imported_oauth_registrations(&self) -> serde_json::Value {
        serde_json::Value::Array(self.config.oauth.registrations.iter().filter_map(|(id, r)| {
            if r.adapter.as_str() != "mcp_oauth" || self.config.providers.registry().oauth_dialect(r.adapter.as_str()).is_none() { return None; }
            Some(serde_json::json!({"id":id,"adapterId":r.adapter.as_str(),"issuer":r.base_url,
                "resource":r.adapter_settings.get("resource"),"permissionProfiles":r.permission_profiles.iter()
                    .map(|(id,p)| serde_json::json!({"id":id,"scopeMode":p.scope_mode,"scopes":p.requested_scopes()})).collect::<Vec<_>>()}))
        }).collect())
    }

    /// Validate new or changed bindings. Retained unavailable bindings must not
    /// block administration of another credential mode on the same service.
    pub fn require_import_bindings(
        &self,
        definition: &ImportedServiceDefinition,
        previous: Option<&ImportedServiceDefinition>,
    ) -> Result<(), ManagedStoreError> {
        if definition.execution_bindings.iter().any(|binding| {
            binding.is_supported()
                && !previous.is_some_and(|old| old.execution_bindings.contains(binding))
                && !oauth_binding_allowed(&self.config, definition, binding)
        }) {
            return Err(ManagedStoreError::InputInvalid("import OAuth binding requires an approved adapter, registration, permission profile, and matching resource".into()));
        }
        Ok(())
    }

    pub fn import_binding_available(
        &self,
        definition: &ImportedServiceDefinition,
        binding: &agent_access_provider::ImportedCredentialBinding,
    ) -> bool {
        binding.is_supported() && oauth_binding_allowed(&self.config, definition, binding)
    }

    pub fn require_import_destination(
        &self,
        definition: &ImportedServiceDefinition,
    ) -> Result<(), ManagedStoreError> {
        definition
            .validate()
            .map_err(ManagedStoreError::InputInvalid)?;
        let adapter = self
            .config
            .providers
            .registry()
            .imported_adapter(&definition.adapter_kind)
            .ok_or_else(|| {
                ManagedStoreError::InputInvalid(
                    "import adapter is not linked in this broker".into(),
                )
            })?;
        adapter
            .validate_definition(definition)
            .map_err(ManagedStoreError::InputInvalid)?;
        if adapter.development_only()
            && (self.config.deployment.environment == "production"
                || !self.config.deployment.enable_fake_service)
        {
            return Err(ManagedStoreError::InputInvalid(
                "development import adapter is not permitted".into(),
            ));
        }
        if !destination_allowed(&self.config, definition) {
            return Err(ManagedStoreError::InputInvalid(
                "import destination is disabled by operator policy".into(),
            ));
        }
        Ok(())
    }

    /// Compile the changed service outside the DB transaction. Existing providers
    /// remain shared. An explicit transport override is used for slot rotation or
    /// deletion so no old secret can be paired with the newly published version.
    pub fn prepare_imported_service_change(
        &self,
        record: &ImportedServiceRecord,
        transport_override: Option<Option<ExecutionCredential>>,
    ) -> Result<PreparedImportedProviders, ManagedStoreError> {
        let mut providers = self
            .imported_catalog
            .services
            .iter()
            .filter_map(|old| {
                self.providers
                    .get(&old.definition.service)
                    .map(|provider| (old.definition.service.clone(), provider.clone()))
            })
            .collect::<BTreeMap<_, _>>();
        let definition = &record.definition;
        providers.remove(&definition.service);
        let transport_provenance = match &transport_override {
            None => PreparedTransport::Existing(
                record
                    .slot_versions
                    .get(&ImportedCredentialPurpose::Transport)
                    .cloned(),
            ),
            Some(None) => PreparedTransport::Deleted,
            Some(Some(credential)) => {
                if credential.kind != "bearer_token" || credential.username.is_some() {
                    return Err(preparation_mismatch());
                }
                let token = credential.token.as_ref().ok_or_else(preparation_mismatch)?;
                PreparedTransport::ReplacementPending(Sha256::digest(token.as_bytes()).into())
            }
        };
        let mut prepared = PreparedImportedProviders {
            base_catalog: self.imported_catalog.clone(),
            providers,
            service: definition.service.clone(),
            definition: definition.clone(),
            status: record.status,
            enabled_actions: enabled_definitions(record),
            transport: transport_provenance,
        };
        if record.status != ImportedServiceStatus::Enabled
            || !destination_allowed(&self.config, definition)
        {
            return Ok(prepared);
        }
        self.require_import_destination(definition)?;
        let transport = if definition.transport_auth {
            match transport_override {
                Some(value) => value,
                None => match record
                    .slot_versions
                    .get(&ImportedCredentialPurpose::Transport)
                {
                    Some(version) => Some(
                        self.managed_store
                            .as_ref()
                            .ok_or(ManagedStoreError::Unavailable(
                                "import storage or encryption unavailable".into(),
                            ))?
                            .resolve_imported_secret(
                                &definition.service,
                                ImportedCredentialPurpose::Transport,
                                version,
                                self.credential_key_ring.as_ref().ok_or(
                                    ManagedStoreError::Unavailable(
                                        "import storage or encryption unavailable".into(),
                                    ),
                                )?,
                            )?,
                    ),
                    None => None,
                },
            }
        } else {
            None
        };
        if definition.transport_auth && transport.is_none() {
            return Ok(prepared);
        }
        let adapter = self
            .config
            .providers
            .registry()
            .imported_adapter(&definition.adapter_kind)
            .ok_or_else(|| {
                ManagedStoreError::InputInvalid("import adapter is not linked".into())
            })?;
        let actions = record
            .actions
            .iter()
            .filter(|action| action.status == ImportedActionStatus::Enabled)
            .map(|action| action.definition.clone())
            .collect::<Vec<_>>();
        for action in &actions {
            adapter
                .validate_action(action)
                .map_err(ManagedStoreError::InputInvalid)?;
            adapter
                .scoped_mcp_name(action)
                .map_err(ManagedStoreError::InputInvalid)?;
        }
        let clients = self.network.client_factory(ClientCaller::ImportAdapter {
            kind: adapter.kind(),
        });
        let host = agent_access_provider::host::build_context(
            self.network.limits(),
            &clients,
            ProviderAttributionConfig::default(),
            None,
        );
        let provider = adapter
            .build(definition, &actions, transport, &host)
            .map_err(|_| {
                ManagedStoreError::InputInvalid("imported provider could not be prepared".into())
            })?;
        prepared
            .providers
            .insert(definition.service.clone(), provider);
        Ok(prepared)
    }

    pub(super) async fn resolve_imported_execution_credential(
        &self,
        service: &str,
        mode: &str,
        identity: &IdentityContext,
    ) -> Result<ExecutionCredential, ProviderError> {
        let record = self
            .imported_catalog
            .service(service)
            .ok_or_else(import_credential_unavailable)?;
        if !self.imported_mode_available(service, mode) {
            return Err(import_credential_unavailable());
        }
        if mode == "per_user" {
            let credential = self
                .effective_credentials
                .per_user
                .get(service)
                .ok_or_else(import_credential_unavailable)?;
            return self
                .resolve_managed_execution_credential(service, credential, identity)
                .await;
        }
        let store = self
            .managed_store
            .clone()
            .ok_or_else(import_credential_unavailable)?;
        let ring = self
            .credential_key_ring
            .clone()
            .ok_or_else(import_credential_unavailable)?;
        let version = record
            .slot_versions
            .get(&ImportedCredentialPurpose::Execution)
            .cloned()
            .ok_or_else(import_credential_unavailable)?;
        let service = service.to_string();
        managed_store_blocking(move || {
            store.resolve_imported_secret(
                &service,
                ImportedCredentialPurpose::Execution,
                &version,
                &ring,
            )
        })
        .await
        .map_err(provider_error_from_managed_store)
    }
}
fn import_credential_unavailable() -> ProviderError {
    ProviderError::deny(
        ReasonCode::CredentialNotProvisioned,
        "imported execution credential is unavailable",
    )
}
