use super::*;
use crate::imports::{
    ImportedCredentialContract, ImportedCredentialInput, ImportedCredentialRequirement,
};

/// Core-issued preparation for one imported slot or personal connection write.
/// The host also fences the exact admitted runtime snapshot around its transaction.
#[derive(Debug)]
pub struct PreparedImportedCredentialContract {
    catalog: Arc<ImportedCatalog>,
    service: String,
    purpose: ImportedCredentialPurpose,
    personal: bool,
    requirement: ImportedCredentialRequirement,
}
impl PreparedImportedCredentialContract {
    #[cfg(test)]
    pub(crate) fn for_test(
        catalog: ImportedCatalog,
        service: &str,
        purpose: ImportedCredentialPurpose,
        personal: bool,
    ) -> Result<Self, ManagedStoreError> {
        let record = catalog.service(service).ok_or_else(|| {
            ManagedStoreError::InputInvalid("imported credential slot is not declared".into())
        })?;
        let contract = crate::imports::test_credential_contract(
            &record.definition,
            &ImportedAdapterContext::new(record.accepted_metadata.as_ref(), None),
        )
        .map_err(ManagedStoreError::InputInvalid)?;
        let requirement = contract.requirement(purpose).cloned().ok_or_else(|| {
            ManagedStoreError::InputInvalid("imported credential slot is not declared".into())
        })?;
        requirement.require_kind()?;
        Ok(Self {
            catalog: Arc::new(catalog),
            service: service.into(),
            purpose,
            personal,
            requirement,
        })
    }
    pub(crate) fn validate(
        &self,
        catalog_revision: u64,
        record: &ImportedServiceRecord,
        purpose: ImportedCredentialPurpose,
        personal: bool,
    ) -> Result<&ImportedCredentialRequirement, ManagedStoreError> {
        let Some(admitted) = self.catalog.service(&self.service) else {
            return Err(ManagedStoreError::VersionConflict);
        };
        if catalog_revision != self.catalog.revision
            || record.definition.service != self.service
            || purpose != self.purpose
            || personal != self.personal
            || admitted.version != record.version
            || admitted.definition != record.definition
            || admitted.accepted_metadata != record.accepted_metadata
        {
            return Err(ManagedStoreError::VersionConflict);
        }
        if record.status == ImportedServiceStatus::Retired {
            return Err(ManagedStoreError::InputInvalid(
                "retired imports cannot receive new credentials".into(),
            ));
        }
        Ok(&self.requirement)
    }
}

pub(crate) fn credential_contract(
    config: &BrokerConfig,
    record: &ImportedServiceRecord,
) -> Result<ImportedCredentialContract, ManagedStoreError> {
    let adapter = config
        .providers
        .registry()
        .imported_adapter(&record.definition.adapter_kind)
        .ok_or_else(|| ManagedStoreError::InputInvalid("import adapter is unavailable".into()))?;
    adapter
        .validate_definition(&record.definition)
        .map_err(ManagedStoreError::InputInvalid)?;
    let contract = adapter
        .credential_contract(&record.definition, &adapter_context(config, record))
        .map_err(ManagedStoreError::InputInvalid)?;
    contract
        .validate(&record.definition)
        .map_err(ManagedStoreError::InputInvalid)?;
    Ok(contract)
}
pub(in crate::runtime) type ImportedCredentialContracts =
    BTreeMap<String, ImportedCredentialContract>;
pub(in crate::runtime) fn resolve_credential_contracts(
    config: &BrokerConfig,
    catalog: &ImportedCatalog,
) -> ImportedCredentialContracts {
    catalog
        .services
        .iter()
        .filter_map(|record| {
            credential_contract(config, record)
                .ok()
                .map(|contract| (record.definition.service.clone(), contract))
        })
        .collect()
}
fn slot_declared(
    definition: &ImportedServiceDefinition,
    purpose: ImportedCredentialPurpose,
) -> bool {
    match purpose {
        ImportedCredentialPurpose::Execution => definition.execution_bindings.iter().any(|b| {
            b.owner_mode == ImportedCredentialMode::Service
                && b.mechanism == ImportedAuthMechanism::StaticToken
        }),
        ImportedCredentialPurpose::Discovery => {
            matches!(definition.discovery, ImportedDiscoveryCredential::Slot)
        }
        ImportedCredentialPurpose::Transport => definition.transport_auth,
    }
}
impl BrokerRuntime {
    fn contract_for_record(
        &self,
        record: &ImportedServiceRecord,
    ) -> Option<&ImportedCredentialContract> {
        let admitted = self.imported_catalog.service(&record.definition.service)?;
        if admitted.definition != record.definition
            || admitted.accepted_metadata != record.accepted_metadata
        {
            return None;
        }
        self.imported_credential_contracts
            .get(&record.definition.service)
    }
    pub fn imported_credential_inputs(
        &self,
        record: &ImportedServiceRecord,
    ) -> BTreeMap<ImportedCredentialPurpose, ImportedCredentialInput> {
        let contract = self.contract_for_record(record);
        [
            ImportedCredentialPurpose::Execution,
            ImportedCredentialPurpose::Discovery,
            ImportedCredentialPurpose::Transport,
        ]
        .into_iter()
        .filter(|purpose| slot_declared(&record.definition, *purpose))
        .map(|purpose| {
            let input = if record.status == ImportedServiceStatus::Retired {
                ImportedCredentialInput::Unavailable {
                    reason: "Retired imports cannot receive credentials".into(),
                }
            } else {
                contract
                    .and_then(|contract| contract.requirement(purpose))
                    .map(ImportedCredentialRequirement::input)
                    .unwrap_or_else(|| ImportedCredentialInput::Unavailable {
                        reason: "Imported credential contract is unavailable".into(),
                    })
            };
            (purpose, input)
        })
        .collect()
    }
    pub fn imported_credential_input_schema(
        &self,
        connection: &str,
        profile: &str,
    ) -> Option<crate::CredentialInputSchema> {
        let record = self.imported_catalog.service(connection)?;
        if record.status == ImportedServiceStatus::Retired {
            return None;
        }
        let contract = self.contract_for_record(record)?;
        contract
            .requirement(ImportedCredentialPurpose::Execution)?
            .input_schema(connection, profile)
    }
    pub fn connection_credential_input_schema(
        &self,
        connection: &str,
        display_name: &str,
        profile: &str,
        kind: &str,
    ) -> Option<crate::CredentialInputSchema> {
        if self.imported_catalog.service(connection).is_some() {
            self.imported_credential_input_schema(connection, profile)
                .filter(|schema| schema.credential_kind == kind)
        } else {
            crate::credential_input_schema(connection, display_name, profile, kind)
        }
    }
    pub fn prepare_imported_secret_contract(
        &self,
        service: &str,
        purpose: ImportedCredentialPurpose,
    ) -> Result<PreparedImportedCredentialContract, ManagedStoreError> {
        let record = self.imported_catalog.service(service).ok_or_else(|| {
            ManagedStoreError::InputInvalid("imported service was not found".into())
        })?;
        if !slot_declared(&record.definition, purpose) {
            return Err(ManagedStoreError::InputInvalid(
                "imported credential slot is not declared".into(),
            ));
        }
        self.prepare_imported_contract(record, purpose, false)
    }
    pub fn prepare_imported_connection_contract(
        &self,
        connection: &str,
    ) -> Result<Option<PreparedImportedCredentialContract>, ManagedStoreError> {
        let Some(record) = self.imported_catalog.service(connection) else {
            return Ok(None);
        };
        if !record.definition.execution_bindings.iter().any(|b| {
            b.owner_mode == ImportedCredentialMode::PerUser
                && b.mechanism == ImportedAuthMechanism::StaticToken
                && b.is_supported()
        }) {
            return Err(ManagedStoreError::InputInvalid(
                "imported personal static credential is not declared".into(),
            ));
        }
        self.prepare_imported_contract(record, ImportedCredentialPurpose::Execution, true)
            .map(Some)
    }
    fn prepare_imported_contract(
        &self,
        record: &ImportedServiceRecord,
        purpose: ImportedCredentialPurpose,
        personal: bool,
    ) -> Result<PreparedImportedCredentialContract, ManagedStoreError> {
        if record.status == ImportedServiceStatus::Retired {
            return Err(ManagedStoreError::InputInvalid(
                "retired imports cannot receive new credentials".into(),
            ));
        }
        let requirement = self
            .contract_for_record(record)
            .ok_or(ManagedStoreError::CredentialNotFound)?
            .requirement(purpose)
            .cloned()
            .ok_or_else(|| {
                ManagedStoreError::InputInvalid(
                    "imported credential requirement is unavailable".into(),
                )
            })?;
        requirement.require_kind()?;
        Ok(PreparedImportedCredentialContract {
            catalog: self.imported_catalog.clone(),
            service: record.definition.service.clone(),
            purpose,
            personal,
            requirement,
        })
    }
    pub fn imported_connection_requirement(
        &self,
        connection: &str,
    ) -> Result<Option<ImportedCredentialRequirement>, ManagedStoreError> {
        let Some(record) = self.imported_catalog.service(connection) else {
            return Ok(None);
        };
        let requirement = self
            .contract_for_record(record)
            .ok_or(ManagedStoreError::CredentialNotFound)?
            .requirement(ImportedCredentialPurpose::Execution)
            .cloned()
            .ok_or(ManagedStoreError::CredentialNotFound)?;
        requirement.require_kind()?;
        Ok(Some(requirement))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::AtomicUsize;
    static CONTRACT_CALLS: AtomicUsize = AtomicUsize::new(0);
    #[derive(Debug)]
    struct CountingAdapter;
    static COUNTING_ADAPTER: CountingAdapter = CountingAdapter;
    #[async_trait::async_trait]
    impl ImportedAdapter for CountingAdapter {
        fn kind(&self) -> &'static str {
            "contract_fixture"
        }
        fn development_only(&self) -> bool {
            false
        }
        fn validate_definition(
            &self,
            definition: &ImportedServiceDefinition,
        ) -> Result<(), String> {
            definition.validate()
        }
        fn credential_contract(
            &self,
            definition: &ImportedServiceDefinition,
            import: &ImportedAdapterContext<'_>,
        ) -> Result<ImportedCredentialContract, String> {
            CONTRACT_CALLS.fetch_add(1, Ordering::SeqCst);
            crate::imports::test_credential_contract(definition, import)
        }
        fn validate_action(&self, _: &ImportedActionDefinition) -> Result<(), String> {
            Ok(())
        }
        fn scoped_mcp_name(&self, action: &ImportedActionDefinition) -> Result<String, String> {
            Ok(action.action.clone())
        }
        fn build(
            &self,
            _: &ImportedServiceDefinition,
            _: &[ImportedActionDefinition],
            _: Option<ExecutionCredential>,
            _: &ImportedAdapterContext<'_>,
            _: &BuildContext<'_>,
        ) -> Result<ImportedProvider, ProviderBuildError> {
            unreachable!("draft fixture never builds")
        }
        async fn discover(
            &self,
            _: &ImportedServiceDefinition,
            _: &ImportedDiscoveryAuthentication,
            _: Option<ExecutionCredential>,
            _: &ImportedAdapterContext<'_>,
            _: &BuildContext<'_>,
        ) -> Result<ImportedDiscovery, AdapterDiscoveryError> {
            unreachable!("offline fixture never discovers")
        }
    }
    #[test]
    fn publication_and_projections_use_the_prepared_contract_without_adapter_calls() {
        let mut runtime = BrokerRuntime::new(crate::runtime::tests::base_fake_config()).unwrap();
        let mut config = (*runtime.config).clone();
        config.providers = crate::ProvidersConfig::new(Arc::new(
            Arc::try_unwrap(crate::tests::test_backend_registry())
                .expect("fixture registry has one owner")
                .with_imported_adapters([crate::imports::imported_adapter_registration(
                    agent_access_provider::module_metadata!(),
                    &COUNTING_ADAPTER,
                    None,
                )])
                .unwrap(),
        ));
        config.imports = crate::ImportsConfig {
            enabled: true,
            allowed_kinds: vec!["contract_fixture".into()],
            allowed_endpoints: vec!["https://inventory.example.test/api".into()],
            disabled_services: vec![],
        };
        runtime.config = Arc::new(config);
        let record = ImportedServiceRecord {
            definition: ImportedServiceDefinition {
                service: "inventory".into(),
                display_name: "Inventory".into(),
                adapter_kind: "contract_fixture".into(),
                endpoint: "https://inventory.example.test/api".into(),
                connection_settings: BTreeMap::new(),
                execution_bindings: vec![ImportedCredentialBinding::token(
                    ImportedCredentialMode::Service,
                    ImportedCredentialDelivery::Basic,
                )],
                discovery: ImportedDiscoveryCredential::Anonymous,
                transport_auth: false,
                invocation_limit: None,
            },
            status: ImportedServiceStatus::Draft,
            version: 1,
            actions: vec![],
            slot_versions: BTreeMap::new(),
            accepted_metadata: None,
            created_at: String::new(),
            created_by: String::new(),
            updated_at: String::new(),
            updated_by: String::new(),
        };
        let before = CONTRACT_CALLS.load(Ordering::SeqCst);
        let prepared = runtime
            .prepare_imported_service_change(&record, None)
            .unwrap();
        assert_eq!(CONTRACT_CALLS.load(Ordering::SeqCst), before + 1);
        let runtime = runtime
            .with_imported_catalog(
                ImportedCatalog {
                    revision: 1,
                    services: vec![record.clone()],
                },
                prepared,
            )
            .unwrap();
        runtime
            .prepare_imported_secret_contract("inventory", ImportedCredentialPurpose::Execution)
            .unwrap();
        assert!(matches!(
            runtime
                .imported_credential_inputs(&record)
                .get(&ImportedCredentialPurpose::Execution),
            Some(ImportedCredentialInput::Ready { .. })
        ));
        let mut mismatched = record.clone();
        mismatched.definition.execution_bindings[0].delivery = ImportedCredentialDelivery::Bearer;
        assert!(matches!(
            runtime
                .imported_credential_inputs(&mismatched)
                .get(&ImportedCredentialPurpose::Execution),
            Some(ImportedCredentialInput::Unavailable { .. })
        ));
        assert_eq!(CONTRACT_CALLS.load(Ordering::SeqCst), before + 1);
    }
}
