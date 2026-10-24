use super::*;
use crate::imports::ImportedDiscoverySource;

/// Runtime-issued source preparation bound to the exact admitted service and
/// catalog. Raw bytes are never included in Debug or ordinary catalog reads.
#[derive(Clone)]
pub struct PreparedImportedDocumentUpload {
    base_catalog: Arc<ImportedCatalog>,
    service: String,
    bytes: Arc<[u8]>,
    metadata: crate::ImportedDocumentMetadata,
}

impl std::fmt::Debug for PreparedImportedDocumentUpload {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("PreparedImportedDocumentUpload")
            .field("service", &self.service)
            .field("metadata", &self.metadata)
            .finish_non_exhaustive()
    }
}

impl PreparedImportedDocumentUpload {
    #[cfg(test)]
    pub(crate) fn for_test(
        catalog: ImportedCatalog,
        service: &str,
        filename: Option<String>,
        bytes: Vec<u8>,
    ) -> Result<Self, ManagedStoreError> {
        crate::managed_store::validate_document_filename(filename.as_deref())?;
        crate::managed_store::validate_document_bytes(&bytes)?;
        let metadata = crate::ImportedDocumentMetadata {
            filename,
            byte_length: bytes.len() as u64,
            sha256: format!("{:x}", Sha256::digest(&bytes)),
        };
        Ok(Self {
            base_catalog: Arc::new(catalog),
            service: service.into(),
            bytes: bytes.into(),
            metadata,
        })
    }
    pub fn metadata(&self) -> &crate::ImportedDocumentMetadata {
        &self.metadata
    }
    pub(crate) fn bytes(&self) -> &[u8] {
        &self.bytes
    }
    pub(crate) fn validate(
        &self,
        record: &ImportedServiceRecord,
        catalog_revision: u64,
    ) -> Result<(), ManagedStoreError> {
        if self.service != record.definition.service
            || self.base_catalog.revision != catalog_revision
            || self.base_catalog.service(&self.service) != Some(record)
        {
            return Err(ManagedStoreError::VersionConflict);
        }
        Ok(())
    }
}

impl BrokerRuntime {
    /// Resolve source policy before entering a managed-store transaction.
    pub fn imported_discovery_source(
        &self,
        definition: &ImportedServiceDefinition,
    ) -> Result<ImportedDiscoverySource, ManagedStoreError> {
        let adapter = self
            .config
            .providers
            .registry()
            .imported_adapter(&definition.adapter_kind)
            .ok_or_else(|| {
                ManagedStoreError::InputInvalid("import adapter is unavailable".into())
            })?;
        adapter
            .discovery_source(definition)
            .map_err(ManagedStoreError::InputInvalid)
    }

    pub fn prepare_imported_document_upload(
        &self,
        service: &str,
        filename: Option<String>,
        bytes: Vec<u8>,
    ) -> Result<PreparedImportedDocumentUpload, ManagedStoreError> {
        let record = self.imported_catalog.service(service).ok_or_else(|| {
            ManagedStoreError::InputInvalid("imported service was not found".into())
        })?;
        self.require_import_destination(&record.definition)?;
        if record.status == ImportedServiceStatus::Retired
            || self.imported_discovery_source(&record.definition)?
                != ImportedDiscoverySource::StoredDocument
        {
            return Err(ManagedStoreError::InputInvalid(
                "import does not accept uploaded documents".into(),
            ));
        }
        crate::managed_store::validate_document_filename(filename.as_deref())?;
        crate::managed_store::validate_document_bytes(&bytes)?;
        let metadata = crate::ImportedDocumentMetadata {
            filename,
            byte_length: bytes.len() as u64,
            sha256: format!("{:x}", Sha256::digest(&bytes)),
        };
        Ok(PreparedImportedDocumentUpload {
            base_catalog: self.imported_catalog.clone(),
            service: service.to_string(),
            bytes: bytes.into(),
            metadata,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::imports::{
        ImportedCredentialContract, ImportedDiscovery, ImportedDiscoveryAuthentication,
    };

    #[derive(Debug)]
    struct DocumentAdapter;
    static DOCUMENT_ADAPTER: DocumentAdapter = DocumentAdapter;
    #[async_trait::async_trait]
    impl ImportedAdapter for DocumentAdapter {
        fn kind(&self) -> &'static str {
            "document_fixture"
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
            context: &ImportedAdapterContext<'_>,
        ) -> Result<ImportedCredentialContract, String> {
            crate::imports::test_credential_contract(definition, context)
        }
        fn discovery_source(
            &self,
            definition: &ImportedServiceDefinition,
        ) -> Result<ImportedDiscoverySource, String> {
            Ok(if definition.connection_settings.contains_key("stored") {
                ImportedDiscoverySource::StoredDocument
            } else {
                ImportedDiscoverySource::Remote
            })
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
            unreachable!("preparation never discovers")
        }
    }

    fn runtime() -> BrokerRuntime {
        let mut runtime = BrokerRuntime::new(crate::runtime::tests::base_fake_config()).unwrap();
        let mut config = (*runtime.config).clone();
        config.providers = crate::ProvidersConfig::new(Arc::new(
            Arc::try_unwrap(crate::tests::test_backend_registry())
                .expect("one registry owner")
                .with_imported_adapters([crate::imports::imported_adapter_registration(
                    agent_access_provider::module_metadata!(),
                    &DOCUMENT_ADAPTER,
                    None,
                )])
                .unwrap(),
        ));
        config.imports = crate::ImportsConfig {
            enabled: true,
            allowed_kinds: vec!["document_fixture".into()],
            allowed_endpoints: vec!["https://inventory.example.test/api".into()],
            disabled_services: vec![],
        };
        runtime.config = Arc::new(config);
        runtime.imported_catalog = Arc::new(ImportedCatalog {
            revision: 7,
            services: vec![ImportedServiceRecord {
                definition: ImportedServiceDefinition {
                    service: "inventory".into(),
                    display_name: "Inventory".into(),
                    adapter_kind: "document_fixture".into(),
                    endpoint: "https://inventory.example.test/api".into(),
                    connection_settings: BTreeMap::from([("stored".into(), "yes".into())]),
                    execution_bindings: vec![ImportedCredentialBinding::token(
                        ImportedCredentialMode::Service,
                        ImportedCredentialDelivery::Bearer,
                    )],
                    discovery: crate::imports::ImportedDiscoveryCredential::Anonymous,
                    transport_auth: false,
                    invocation_limit: None,
                },
                status: ImportedServiceStatus::Draft,
                version: 3,
                actions: vec![],
                slot_versions: BTreeMap::new(),
                accepted_metadata: None,
                document: None,
                created_at: String::new(),
                created_by: String::new(),
                updated_at: String::new(),
                updated_by: String::new(),
            }],
        });
        runtime
    }

    #[test]
    fn document_preparation_is_source_and_operator_gated_and_redacts_context_bytes() {
        let mut runtime = runtime();
        let bytes = b"{ \"private-document-content\": true }\n".to_vec();
        let prepared = runtime
            .prepare_imported_document_upload("inventory", None, bytes.clone())
            .unwrap();
        assert_eq!(prepared.bytes(), bytes);
        assert!(prepared.metadata().filename.is_none());
        prepared
            .validate(&runtime.imported_catalog.services[0], 7)
            .unwrap();
        assert!(
            prepared
                .validate(&runtime.imported_catalog.services[0], 8)
                .is_err()
        );
        let context = ImportedAdapterContext::default().with_document(&bytes);
        assert_eq!(context.document(), Some(bytes.as_slice()));
        assert!(!format!("{context:?}").contains("private-document-content"));
        assert!(!format!("{prepared:?}").contains("private-document-content"));
        let mut catalog = (*runtime.imported_catalog).clone();
        catalog.services[0].definition.connection_settings.clear();
        runtime.imported_catalog = Arc::new(catalog);
        assert!(
            runtime
                .prepare_imported_document_upload("inventory", None, bytes.clone())
                .is_err()
        );
        let mut runtime = self::runtime();
        Arc::make_mut(&mut runtime.config)
            .imports
            .allowed_endpoints
            .clear();
        assert!(
            runtime
                .prepare_imported_document_upload("inventory", None, bytes)
                .is_err()
        );
    }

    #[test]
    fn document_receipt_must_match_prepared_provider_publication() {
        let runtime = runtime();
        let source = runtime
            .prepare_imported_document_upload("inventory", Some("api.json".into()), b"{}".to_vec())
            .unwrap();
        let mut candidate = runtime.imported_catalog.services[0].clone();
        candidate.document = Some(source.metadata().clone());
        let providers = runtime
            .prepare_imported_service_change(&candidate, None)
            .unwrap();
        let mut mismatched = candidate.clone();
        mismatched.document = None;
        assert!(
            runtime
                .with_imported_catalog(
                    ImportedCatalog {
                        revision: 8,
                        services: vec![mismatched]
                    },
                    providers
                )
                .is_err()
        );
        let providers = runtime
            .prepare_imported_service_change(&candidate, None)
            .unwrap();
        let published = runtime
            .with_imported_catalog(
                ImportedCatalog {
                    revision: 8,
                    services: vec![candidate],
                },
                providers,
            )
            .unwrap();
        assert_eq!(
            published.imported_catalog.services[0].document.as_ref(),
            Some(source.metadata())
        );
    }
}
