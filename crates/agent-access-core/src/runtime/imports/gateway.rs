//! Host-owned executable assembly and dispatch proofs for managed gateways.
use super::*;
use agent_access_provider::{
    GatewayManagedAction, GatewayManagedInput, GatewayProtocol, GatewayVersionedData,
};

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
            Err(ProviderError::deny(
                ReasonCode::ServiceActionDenied,
                "imported gateway generation is no longer available",
            ))
        }
    }
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
            return Err(import_credential_unavailable());
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
            return Err(import_credential_unavailable());
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
            return Err(import_credential_unavailable());
        }
        Ok(ImportedGatewayDispatchFence {
            current: self
                .import_dispatch
                .get(service)
                .ok_or_else(import_credential_unavailable)?
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
            if let Ok(mut url) = url::Url::parse(&binding.endpoint) {
                let base = url.path().strip_suffix('/').unwrap_or(url.path());
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
) -> Result<ImportedExecutable, String> {
    let adapter = config
        .providers
        .registry()
        .imported_adapter(&record.definition.adapter_kind)
        .ok_or("import adapter unavailable")?;
    match built {
        ImportedProvider::Gateway { kind, plans } => {
            if adapter.gateway_kind() != Some(kind.as_str()) {
                return Err("import adapter returned the wrong gateway kind".into());
            }
            let routes = record
                .gateway_routes
                .as_ref()
                .filter(|record| record.manifest.is_supported())
                .ok_or("gateway route manifest unavailable")?;
            if routes.manifest.content_hash()? != routes.content_hash || routes.generation == 0 {
                return Err("gateway route manifest is invalid".into());
            }
            let registration = config
                .providers
                .registry()
                .gateway(&kind)
                .ok_or("gateway module is not linked")?;
            let builder = registration
                .managed_builder()
                .ok_or("gateway module has no managed plan builder")?;
            if plans.len() != record.actions.len() {
                return Err("gateway operation plans do not match the retained actions".into());
            }
            let actions = record
                .actions
                .iter()
                .map(|action| {
                    let encoded = serde_json::to_vec(&action.definition)
                        .map_err(|_| "invalid gateway action definition")?;
                    if action.version == 0
                        || format!("{:x}", Sha256::digest(&encoded)) != action.definition_hash
                    {
                        return Err("gateway accepted action version or hash is invalid");
                    }
                    let plan = plans
                        .get(&action.definition.action)
                        .ok_or("gateway operation plan missing")?;
                    if plan.version == 0
                        || serde_json::to_vec(&plan.data)
                            .map_err(|_| "invalid gateway operation plan")?
                            .len()
                            > crate::imports::IMPORT_MAX_TOOL_BYTES
                    {
                        return Err("gateway operation plan is invalid or oversized");
                    }
                    Ok(GatewayManagedAction::new(
                        &action.definition.action,
                        action.version,
                        &action.definition_hash,
                        action.status == ImportedActionStatus::Enabled,
                        plan.clone(),
                    ))
                })
                .collect::<Result<Vec<_>, &str>>()?;
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
            .ok_or("gateway binding unavailable")?;
            let endpoint = url::Url::parse(&gateway.upstream_base_url)
                .map_err(|_| "gateway binding endpoint is invalid")?;
            if !agent_access_provider::base_covered_by_patterns(
                &endpoint,
                &gateway.allowed_upstream_hosts,
            ) {
                return Err("gateway binding allowlist does not cover its endpoint".into());
            }
            let protocol = builder(&gateway.service_context(&record.definition.service), &input)
                .map_err(|_| "gateway builder rejected the retained routing contract")?;
            Ok(ImportedExecutable::Gateway(protocol))
        }
        value
            if adapter.gateway_kind().is_none()
                && provider_matches_endpoint(&record.definition, &value) =>
        {
            Ok(ImportedExecutable::Invoke(value))
        }
        _ => Err("import adapter returned an inconsistent executable".into()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use agent_access_provider::{base_covered_by_patterns, url_allowed_by_patterns};

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
                "https://api.example/api//",
                "https://api.example/api//items/1",
                Some("https://api.example/api/items/1"),
            ),
            ("https://api.example/", "https://api.example/items/1", None),
        ] {
            let mut config = crate::parse_broker_config_raw(
                "imports.toml",
                "[identity]\nmode = \"anonymous\"\nauthority = \"toml\"\n[policy]\nauthority = \"toml\"\ndefault_decision = \"deny\"\n[limits]\nupload_spool_dir = \"upload-spool\"\n",
                &Arc::new(crate::BackendRegistry::empty()),
            )
            .unwrap();
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
}
