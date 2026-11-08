//! Host-owned executable assembly and dispatch proofs for managed gateways.
use super::*;
use agent_access_provider::{
    GatewayManagedAction, GatewayManagedInput, GatewayProtocol, GatewayVersionedData,
};

/// Only host-owned fixed classifications may reach management or warning events.
/// Adapter and protocol errors can contain private source or destination data.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(in crate::runtime) enum ImportedGatewayDiagnostic {
    DefinitionInvalid,
    CredentialContractUnavailable,
    ActionPlanInvalid,
    IdentityHeaderCollision,
    AdapterBuildRejected,
    ExecutableContractInvalid,
    RouteManifestMissing,
    RouteManifestVersionUnsupported,
    RouteManifestInvalid,
    ProtocolUnavailable,
    BindingUnavailable,
    BindingInvalid,
    AllowlistMismatch,
    BuilderRejected,
}
impl ImportedGatewayDiagnostic {
    pub(in crate::runtime) fn code(self) -> &'static str {
        match self {
            Self::DefinitionInvalid => "retained_definition_invalid",
            Self::CredentialContractUnavailable => "credential_contract_unavailable",
            Self::ActionPlanInvalid => "retained_action_plan_invalid",
            Self::IdentityHeaderCollision => "identity_header_collision",
            Self::AdapterBuildRejected => "adapter_build_rejected",
            Self::ExecutableContractInvalid => "executable_contract_invalid",
            Self::RouteManifestMissing => "route_manifest_missing",
            Self::RouteManifestVersionUnsupported => "route_manifest_version_unsupported",
            Self::RouteManifestInvalid => "route_manifest_invalid",
            Self::ProtocolUnavailable => "protocol_unavailable",
            Self::BindingUnavailable => "binding_unavailable",
            Self::BindingInvalid => "binding_invalid",
            Self::AllowlistMismatch => "binding_allowlist_mismatch",
            Self::BuilderRejected => "retained_contract_rejected",
        }
    }
    pub(in crate::runtime) fn message(self) -> &'static str {
        match self {
            Self::DefinitionInvalid => "The retained gateway definition is invalid.",
            Self::CredentialContractUnavailable => {
                "The retained gateway credential contract is unavailable."
            }
            Self::ActionPlanInvalid => "A retained gateway action plan is unsupported or invalid.",
            Self::IdentityHeaderCollision => {
                "A gateway action declares a header reserved for configured identity."
            }
            Self::AdapterBuildRejected => {
                "The gateway adapter rejected the retained definition or action plans."
            }
            Self::ExecutableContractInvalid => {
                "The gateway adapter returned an inconsistent executable contract."
            }
            Self::RouteManifestMissing => "The retained gateway route manifest is missing.",
            Self::RouteManifestVersionUnsupported => {
                "The retained gateway route manifest version is not supported by this broker."
            }
            Self::RouteManifestInvalid => "The retained gateway route manifest is invalid.",
            Self::ProtocolUnavailable => {
                "The imported gateway protocol module or managed builder is not linked in this broker."
            }
            Self::BindingUnavailable => "The operator gateway binding is unavailable.",
            Self::BindingInvalid => "The operator gateway binding endpoint is invalid.",
            Self::AllowlistMismatch => {
                "The operator gateway binding allowlist does not cover its endpoint."
            }
            Self::BuilderRejected => "The gateway protocol rejected the retained routing contract.",
        }
    }
    pub(in crate::runtime) fn warn(self, service: &str) {
        tracing::warn!(
            event = "imported_gateway_unavailable",
            service,
            reason = self.code(),
            "retained imported gateway is unavailable"
        );
    }
}

#[derive(Clone)]
pub(in crate::runtime) enum ImportedExecutable {
    Invoke(ImportedProvider),
    Gateway(Arc<dyn GatewayProtocol>),
}
impl ImportedExecutable {
    pub(in crate::runtime) fn provider(&self) -> Option<Arc<dyn Provider>> {
        match self {
            Self::Invoke(value) => value.provider(),
            Self::Gateway(_) => None,
        }
    }
    pub(in crate::runtime) fn command(&self) -> Option<&Arc<dyn crate::imports::CommandProvider>> {
        match self {
            Self::Invoke(value) => value.command(),
            Self::Gateway(_) => None,
        }
    }
    pub(in crate::runtime) fn gateway(&self) -> Option<&Arc<dyn GatewayProtocol>> {
        match self {
            Self::Gateway(value) => Some(value),
            Self::Invoke(_) => None,
        }
    }
}

/// The immutable credential presentation selected by the admitted import.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum GatewayExecutionBinding {
    Anonymous,
    Static(crate::imports::ImportedCredentialDelivery),
}

/// A publication fence for the exact admitted service/action and routing generation.
/// Any relevant catalog, binding, service-slot or network change retires this flag;
/// it never resolves an old request against a replacement generation.
#[derive(Clone)]
pub struct ImportedGatewayDispatchFence {
    current: Arc<AtomicBool>,
}
impl ImportedGatewayDispatchFence {
    pub fn validate(&self) -> Result<(), ProviderError> {
        if self.current.load(Ordering::Acquire) {
            Ok(())
        } else {
            Err(gateway_generation_unavailable())
        }
    }
}

fn gateway_generation_unavailable() -> ProviderError {
    ProviderError::deny(
        ReasonCode::ServiceActionDenied,
        "imported gateway generation is no longer available",
    )
}
impl std::fmt::Debug for ImportedGatewayDispatchFence {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ImportedGatewayDispatchFence")
            .finish_non_exhaustive()
    }
}

impl BrokerRuntime {
    pub fn imported_gateway_execution_binding(
        &self,
        service: &str,
        mode: &str,
    ) -> Result<GatewayExecutionBinding, ProviderError> {
        let record = self
            .imported_catalog
            .service(service)
            .ok_or_else(import_credential_unavailable)?;
        if !self.gateways.contains_key(service) || !self.imported_service_dispatchable(service) {
            return Err(gateway_generation_unavailable());
        }
        if self.import_credential_free(&record.definition) && mode == "service" {
            return Ok(GatewayExecutionBinding::Anonymous);
        }
        let binding = record
            .definition
            .execution_bindings
            .iter()
            .find(|binding| binding.owner_mode.as_str() == mode)
            .filter(|binding| {
                binding.mechanism == ImportedAuthMechanism::StaticToken && binding.is_supported()
            })
            .ok_or_else(import_credential_unavailable)?;
        if !self.imported_mode_available(service, mode) {
            return Err(if self.imported_service_dispatchable(service) {
                import_credential_unavailable()
            } else {
                gateway_generation_unavailable()
            });
        }
        Ok(GatewayExecutionBinding::Static(binding.delivery.clone()))
    }
    pub fn imported_gateway_dispatch_fence(
        &self,
        service: &str,
        action: &str,
    ) -> Result<ImportedGatewayDispatchFence, ProviderError> {
        if self.imported_catalog.service(service).is_none()
            || !self.gateways.contains_key(service)
            || !self.imported_action_available(service, action)
        {
            return Err(gateway_generation_unavailable());
        }
        Ok(ImportedGatewayDispatchFence {
            current: self
                .import_dispatch
                .get(service)
                .ok_or_else(gateway_generation_unavailable)?
                .clone(),
        })
    }
    pub(in crate::runtime) fn imported_executable_available(&self, service: &str) -> bool {
        self.providers.contains_key(service) || self.gateways.contains_key(service)
    }
}

pub(in crate::runtime) fn managed_gateway_configs(
    config: &BrokerConfig,
    catalog: &ImportedCatalog,
) -> BTreeMap<String, GatewayConfig> {
    config
        .imports
        .gateway_bindings
        .iter()
        .map(|(service, binding)| {
            let record = catalog.service(service);
            let kind = record
                .and_then(|record| {
                    config
                        .providers
                        .registry()
                        .imported_adapter(&record.definition.adapter_kind)
                })
                .and_then(|adapter| adapter.gateway_kind())
                .unwrap_or("unavailable");
            let mut gateway = GatewayConfig::new(
                kind,
                record.map_or(service.as_str(), |r| &r.definition.display_name),
                &binding.endpoint,
            );
            gateway.broker_hosts = binding.broker_hosts.clone();
            gateway.allow_forwarded_identity = binding.allow_forwarded_identity;
            gateway.auth_modes = binding.auth_modes.clone();
            gateway.basic_broker_token_username = binding.basic_broker_token_username.clone();
            gateway.credential_modes = record
                .map(|record| {
                    declared_modes(&record.definition)
                        .into_iter()
                        .map(str::to_owned)
                        .collect()
                })
                .unwrap_or_default();
            gateway.egress_proxy = binding.egress_proxy.clone();
            gateway.redirect_policy = binding.redirect_policy.clone();
            gateway.request_body_max_bytes = binding.request_body_max_bytes;
            gateway.response_body_max_bytes = binding.response_body_max_bytes;
            gateway.streaming_idle_timeout_ms = binding.streaming_idle_timeout_ms;
            gateway.correlation_headers = binding.correlation_headers;
            if let Ok(mut url) = crate::imports_config::managed_gateway_endpoint(&binding.endpoint)
            {
                let base = url.path().trim_end_matches('/');
                url.set_path(&format!("{base}/**"));
                gateway.allowed_upstream_hosts = vec![url.into()];
            }
            (service.clone(), gateway)
        })
        .collect()
}

pub(in crate::runtime) fn compile_executable(
    config: &BrokerConfig,
    record: &ImportedServiceRecord,
    built: ImportedProvider,
) -> Result<ImportedExecutable, ImportedGatewayDiagnostic> {
    use ImportedGatewayDiagnostic as Diagnostic;
    let adapter = config
        .providers
        .registry()
        .imported_adapter(&record.definition.adapter_kind)
        .ok_or(Diagnostic::ExecutableContractInvalid)?;
    match built {
        ImportedProvider::Gateway { kind, plans } => {
            if adapter.gateway_kind() != Some(kind.as_str()) {
                return Err(Diagnostic::ExecutableContractInvalid);
            }
            let routes = record
                .gateway_routes
                .as_ref()
                .ok_or(Diagnostic::RouteManifestMissing)?;
            if !routes.manifest.is_supported() {
                return Err(Diagnostic::RouteManifestVersionUnsupported);
            }
            if routes
                .manifest
                .content_hash()
                .map_err(|_| Diagnostic::RouteManifestInvalid)?
                != routes.content_hash
                || routes.generation == 0
            {
                return Err(Diagnostic::RouteManifestInvalid);
            }
            let registration = config
                .providers
                .registry()
                .gateway(&kind)
                .ok_or(Diagnostic::ProtocolUnavailable)?;
            let builder = registration
                .managed_builder()
                .ok_or(Diagnostic::ProtocolUnavailable)?;
            if plans.len() != record.actions.len() {
                return Err(Diagnostic::ActionPlanInvalid);
            }
            let actions = record
                .actions
                .iter()
                .map(|action| {
                    let encoded = serde_json::to_vec(&action.definition)
                        .map_err(|_| Diagnostic::ActionPlanInvalid)?;
                    if action.version == 0
                        || format!("{:x}", Sha256::digest(&encoded)) != action.definition_hash
                    {
                        return Err(Diagnostic::ActionPlanInvalid);
                    }
                    let plan = plans
                        .get(&action.definition.action)
                        .ok_or(Diagnostic::ActionPlanInvalid)?;
                    if plan.version == 0
                        || serde_json::to_vec(&plan.data)
                            .map_err(|_| Diagnostic::ActionPlanInvalid)?
                            .len()
                            > crate::imports::IMPORT_MAX_TOOL_BYTES
                    {
                        return Err(Diagnostic::ActionPlanInvalid);
                    }
                    Ok(GatewayManagedAction::new(
                        &action.definition.action,
                        action.version,
                        &action.definition_hash,
                        action.status == ImportedActionStatus::Enabled,
                        plan.clone(),
                    ))
                })
                .collect::<Result<Vec<_>, ImportedGatewayDiagnostic>>()?;
            let input = GatewayManagedInput::new(
                GatewayVersionedData::new(routes.manifest.version, routes.manifest.data.clone()),
                actions,
            )
            .with_manifest_revision(routes.generation, &routes.content_hash);
            let gateway = managed_gateway_configs(
                config,
                &ImportedCatalog {
                    revision: 0,
                    services: vec![record.clone()],
                },
            )
            .remove(&record.definition.service)
            .ok_or(Diagnostic::BindingUnavailable)?;
            let endpoint =
                crate::imports_config::managed_gateway_endpoint(&gateway.upstream_base_url)
                    .map_err(|_| Diagnostic::BindingInvalid)?;
            if !agent_access_provider::base_covered_by_patterns(
                &endpoint,
                &gateway.allowed_upstream_hosts,
            ) {
                return Err(Diagnostic::AllowlistMismatch);
            }
            let protocol = builder(&gateway.service_context(&record.definition.service), &input)
                .map_err(|_| Diagnostic::BuilderRejected)?;
            Ok(ImportedExecutable::Gateway(protocol))
        }
        value
            if adapter.gateway_kind().is_none()
                && provider_matches_endpoint(&record.definition, &value) =>
        {
            Ok(ImportedExecutable::Invoke(value))
        }
        _ => Err(Diagnostic::ExecutableContractInvalid),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use agent_access_provider::{base_covered_by_patterns, url_allowed_by_patterns};

    fn config() -> BrokerConfig {
        crate::parse_broker_config_raw(
            "imports.toml",
            "[identity]\nmode = \"anonymous\"\nauthority = \"toml\"\n[policy]\nauthority = \"toml\"\ndefault_decision = \"deny\"\n[limits]\nupload_spool_dir = \"upload-spool\"\n",
            &Arc::new(crate::BackendRegistry::empty()),
        )
        .unwrap()
    }

    fn gateway_record() -> ImportedServiceRecord {
        let mut record = ImportedServiceRecord {
            definition: ImportedServiceDefinition {
                service: "inventory".into(),
                display_name: "Inventory".into(),
                adapter_kind: "openapi_gateway".into(),
                endpoint: "https://api.example/api".into(),
                connection_settings: BTreeMap::new(),
                execution_bindings: Vec::new(),
                discovery: ImportedDiscoveryCredential::Anonymous,
                transport_auth: false,
                invocation_limit: None,
            },
            status: ImportedServiceStatus::Enabled,
            version: 1,
            actions: vec![crate::ImportedActionRecord {
                definition: ImportedActionDefinition {
                    action: "read_item".into(),
                    source: json!({"operationId":"read_item"}),
                    label: None,
                    description: "Read an inventory item".into(),
                    input_schema: json!({"type":"object","additionalProperties":false}),
                    output_schema: None,
                    annotations: json!({}),
                    read_only: true,
                    download: false,
                },
                status: ImportedActionStatus::Enabled,
                version: 1,
                definition_hash: "0".repeat(64),
            }],
            slot_versions: BTreeMap::new(),
            accepted_metadata: None,
            document: None,
            gateway_routes: Some(
                crate::imports::ImportedGatewayRouteRecord::next(
                    None,
                    crate::imports::ImportedGatewayRouteCandidate::new(
                        json!({"version":1,"paths":{}}),
                    )
                    .unwrap(),
                )
                .unwrap(),
            ),
            created_at: String::new(),
            created_by: String::new(),
            updated_at: String::new(),
            updated_by: String::new(),
        };
        record.actions[0].definition_hash = format!(
            "{:x}",
            Sha256::digest(serde_json::to_vec(&record.actions[0].definition).unwrap())
        );
        record
    }

    #[test]
    fn gateway_descriptors_do_not_claim_json_result_sensitivity_pointers() {
        let config = config();
        let record = gateway_record();
        let descriptor = descriptor_with_contract(
            &record,
            &config,
            config.providers.registry().resource_types(),
            None,
        );
        descriptor.validate().unwrap();
        assert!(descriptor.is_gateway());
        assert!(!descriptor.credentials.verification_supported);
        assert!(descriptor.actions[0].sensitive_output_pointers.is_empty());

        // Ordinary invoke descriptors keep the existing JSON pointer rule.
        let mut ordinary = descriptor;
        ordinary.surface = ServiceSurface::Invoke;
        ordinary.actions[0].sensitive_output_pointers = vec!["/result".into()];
        assert!(ordinary.validate().unwrap_err().iter().any(|error| {
            error == "inventory.read_item sensitive output /result must point into /result"
        }));
        ordinary.actions[0].sensitive_output_pointers = vec!["/result/value".into()];
        ordinary.validate().unwrap();
    }

    #[test]
    fn managed_gateway_allowlist_pins_endpoint_origin_and_base() {
        for (endpoint, allowed, sibling) in [
            (
                "https://api.example/api",
                "https://api.example/api/items/1?detail=true",
                Some("https://api.example/api-other/items/1"),
            ),
            (
                "https://api.example:8443/api/",
                "https://api.example:8443/api/items/1",
                Some("https://api.example:8443/other/items/1"),
            ),
            (
                "https://api.example/v1/items:lookup/",
                "https://api.example/v1/items:lookup/items/1",
                Some("https://api.example/v1/items/items/1"),
            ),
            ("https://api.example/", "https://api.example/items/1", None),
        ] {
            let mut config = config();
            config.imports.gateway_bindings.insert(
                "inventory".into(),
                toml::from_str(&format!(
                    "endpoint = {endpoint:?}\nbroker_hosts = [\"inventory.gateway.example\"]\nauth_modes = [\"bearer_broker_token\"]\n"
                ))
                .unwrap(),
            );
            let configs = managed_gateway_configs(&config, &ImportedCatalog::default());
            let patterns = &configs["inventory"].allowed_upstream_hosts;
            let endpoint = url::Url::parse(endpoint).unwrap();
            assert!(base_covered_by_patterns(&endpoint, patterns));
            let operation = url::Url::parse(allowed).unwrap();
            assert!(url_allowed_by_patterns(&operation, patterns));
            let forwarded = configs["inventory"].upstream_url("/items/1").unwrap();
            assert_eq!(forwarded.path(), operation.path());
            assert!(url_allowed_by_patterns(&forwarded, patterns));
            if let Some(sibling) = sibling {
                assert!(!url_allowed_by_patterns(
                    &url::Url::parse(sibling).unwrap(),
                    patterns
                ));
            }
            let mut other = operation.clone();
            other.set_host(Some("other.example")).unwrap();
            assert!(!url_allowed_by_patterns(&other, patterns));
            other = operation.clone();
            other.set_scheme("http").unwrap();
            assert!(!url_allowed_by_patterns(&other, patterns));
            other = operation;
            other.set_port(Some(9443)).unwrap();
            assert!(!url_allowed_by_patterns(&other, patterns));
        }
    }

    const PRIVATE_BUILD_ERROR: &str = "https://private.invalid/build-secret?token=private-sentinel";

    #[derive(Debug)]
    struct DiagnosticAdapter;
    static DIAGNOSTIC_ADAPTER: DiagnosticAdapter = DiagnosticAdapter;
    static DIAGNOSTIC_GATEWAY: agent_access_provider::GatewayRegistration =
        agent_access_provider::GatewayRegistration::new(
            agent_access_provider::module_metadata!(),
            "diagnostic_gateway",
            |_| unreachable!("managed fixture never parses static configuration"),
        )
        .with_managed_builder(|_, _| Err(ProviderBuildError::invalid(PRIVATE_BUILD_ERROR)));

    #[async_trait::async_trait]
    impl ImportedAdapter for DiagnosticAdapter {
        fn kind(&self) -> &'static str {
            "diagnostic_gateway"
        }
        fn gateway_kind(&self) -> Option<&'static str> {
            Some("diagnostic_gateway")
        }
        fn development_only(&self) -> bool {
            false
        }
        fn supports_credential_free_execution(&self) -> bool {
            true
        }
        fn validate_definition(
            &self,
            definition: &ImportedServiceDefinition,
        ) -> Result<(), String> {
            definition.validate()
        }
        fn credential_contract(
            &self,
            _: &ImportedServiceDefinition,
            _: &ImportedAdapterContext<'_>,
        ) -> Result<ImportedCredentialContract, String> {
            Ok(ImportedCredentialContract::new(None, None, None))
        }
        fn validate_action(&self, action: &ImportedActionDefinition) -> Result<(), String> {
            if action.annotations.get("reject_action").is_some() {
                Err(PRIVATE_BUILD_ERROR.into())
            } else {
                Ok(())
            }
        }
        fn request_header_names(
            &self,
            action: &ImportedActionDefinition,
        ) -> Result<Vec<String>, String> {
            Ok(if action.annotations.get("identity_header").is_some() {
                vec!["x-fixture-identity".into()]
            } else {
                Vec::new()
            })
        }
        fn scoped_mcp_name(&self, _: &ImportedActionDefinition) -> Result<String, String> {
            Err("gateway actions have no scoped MCP name".into())
        }
        fn build(
            &self,
            definition: &ImportedServiceDefinition,
            actions: &[ImportedActionDefinition],
            _: Option<ExecutionCredential>,
            _: &ImportedAdapterContext<'_>,
            _: &BuildContext<'_>,
        ) -> Result<ImportedProvider, ProviderBuildError> {
            if definition.connection_settings.contains_key("reject_build") {
                return Err(ProviderBuildError::invalid(PRIVATE_BUILD_ERROR));
            }
            Ok(ImportedProvider::Gateway {
                kind: self.kind().into(),
                plans: actions
                    .iter()
                    .map(|action| {
                        (
                            action.action.clone(),
                            GatewayVersionedData::new(1, json!({})),
                        )
                    })
                    .collect(),
            })
        }
        async fn discover(
            &self,
            _: &ImportedServiceDefinition,
            _: &crate::imports::ImportedDiscoveryAuthentication,
            _: Option<ExecutionCredential>,
            _: &ImportedAdapterContext<'_>,
            _: &BuildContext<'_>,
        ) -> Result<crate::imports::ImportedDiscovery, crate::imports::AdapterDiscoveryError>
        {
            unreachable!("retained gateway startup never discovers")
        }
    }

    #[test]
    fn retained_gateway_diagnostics_are_specific_without_exposing_adapter_errors() {
        use crate::runtime::tests::{CapturedEvents, EventCaptureLayer};
        use tracing_subscriber::prelude::*;
        for (stage, expected) in [
            (
                "version",
                ImportedGatewayDiagnostic::RouteManifestVersionUnsupported,
            ),
            ("action", ImportedGatewayDiagnostic::ActionPlanInvalid),
            (
                "identity_header",
                ImportedGatewayDiagnostic::IdentityHeaderCollision,
            ),
            ("adapter", ImportedGatewayDiagnostic::AdapterBuildRejected),
            ("builder", ImportedGatewayDiagnostic::BuilderRejected),
        ] {
            let mut runtime =
                BrokerRuntime::new(crate::runtime::tests::base_fake_config()).unwrap();
            let mut config = config();
            config.providers = crate::ProvidersConfig::new(Arc::new(
                crate::BackendRegistry::empty()
                    .with_imported_adapters([crate::imports::imported_adapter_registration(
                        agent_access_provider::module_metadata!(),
                        &DIAGNOSTIC_ADAPTER,
                        None,
                    )])
                    .unwrap()
                    .with_gateways([&DIAGNOSTIC_GATEWAY])
                    .unwrap(),
            ));
            config.imports.enabled = true;
            config.imports.allowed_kinds = vec!["diagnostic_gateway".into()];
            config.imports.allowed_endpoints = vec!["https://api.example/**".into()];
            config.imports.gateway_bindings.insert("inventory".into(), toml::from_str(
                "endpoint = \"https://api.example/api\"\nbroker_hosts = [\"inventory.gateway.example\"]\nauth_modes = [\"bearer_broker_token\"]\n"
            ).unwrap());
            let mut record = gateway_record();
            record.definition.adapter_kind = "diagnostic_gateway".into();
            match stage {
                "version" => {
                    let routes = record.gateway_routes.as_mut().unwrap();
                    routes.manifest.version = 2;
                    routes.content_hash = routes.manifest.content_hash().unwrap();
                }
                "action" => {
                    record.actions[0].definition.annotations = json!({"reject_action":true})
                }
                "identity_header" => {
                    record.actions[0].definition.annotations = json!({"identity_header":true});
                    config.identity.sources.push(crate::IdentitySourceConfig {
                        name: "fixture_identity".into(),
                        kind: "broker_tokens".into(),
                        header: "X-Fixture-Identity".into(),
                        scheme: "Bearer".into(),
                        principals: Vec::new(),
                    });
                }
                "adapter" => {
                    record
                        .definition
                        .connection_settings
                        .insert("reject_build".into(), "true".into());
                }
                "builder" => {}
                _ => unreachable!(),
            }
            let catalog = ImportedCatalog {
                revision: 1,
                services: vec![record],
            };
            let contracts = resolve_credential_contracts(&config, &catalog);
            let events = CapturedEvents::default();
            let subscriber = tracing_subscriber::registry().with(EventCaptureLayer {
                events: events.clone(),
            });
            let built = tracing::subscriber::with_default(subscriber, || {
                build_providers(
                    &config,
                    &catalog,
                    &contracts,
                    config.providers.registry().resource_types(),
                    None,
                    None,
                    &runtime.network,
                )
            })
            .unwrap();
            assert!(built.providers.is_empty(), "{stage}");
            assert_eq!(
                built.gateway_diagnostics.get("inventory"),
                Some(&expected),
                "{stage}"
            );
            let captured = events.take();
            assert_eq!(captured.len(), 1, "{stage}: {captured:?}");
            assert_eq!(captured[0]["event"], "imported_gateway_unavailable");
            assert_eq!(captured[0]["service"], "inventory");
            assert_eq!(captured[0]["reason"], expected.code());
            let rendered = serde_json::to_string(&captured).unwrap();
            assert!(!rendered.contains("private-sentinel"));
            assert!(!rendered.contains("private.invalid"));
            assert!(!rendered.contains("api.example"));
            assert!(!rendered.contains("fixture-identity"));
            runtime.config = Arc::new(config);
            runtime.imported_catalog = Arc::new(catalog);
            runtime.imported_gateway_diagnostics = Arc::new(built.gateway_diagnostics);
            assert_eq!(
                runtime.imported_service_unavailable_reason("inventory"),
                Some(expected.message())
            );
        }
    }
}
