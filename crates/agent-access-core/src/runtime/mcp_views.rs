//! Scoped MCP readiness belongs to the immutable runtime publication. It never
//! rejects an otherwise valid aggregate catalog or resolves credentials.
use super::*;
use crate::mcp::{ScopedMcpReadiness, evaluate_projected_scoped_mcp_readiness};

impl BrokerRuntime {
    pub fn scoped_mcp_diagnostics(&self, service: &str) -> ScopedMcpReadiness {
        self.scoped_mcp
            .get(service)
            .cloned()
            .unwrap_or_else(ScopedMcpReadiness::unavailable)
    }

    pub fn scoped_mcp_ready(&self, service: &str) -> bool {
        self.scoped_mcp
            .get(service)
            .is_some_and(|state| state.ready)
    }

    /// Derive an accepted or preview name using the registered adapter's pure
    /// source-identity rule. This is not a normalization or alias operation.
    pub fn imported_scoped_mcp_name(
        &self,
        definition: &ImportedServiceDefinition,
        action: &ImportedActionDefinition,
    ) -> Result<String, String> {
        self.config
            .providers
            .registry()
            .imported_adapter(&definition.adapter_kind)
            .ok_or_else(|| "import adapter is unavailable".to_owned())?
            .scoped_mcp_name(action)
    }

    fn service_scoped_mcp_readiness(&self, service: &str) -> ScopedMcpReadiness {
        let Some(descriptor) = self.services.get(service) else {
            return ScopedMcpReadiness::unavailable();
        };
        if descriptor.surface != ServiceSurface::Invoke
            || self.service_registration(service).is_none()
        {
            return ScopedMcpReadiness::unavailable();
        }
        let mut descriptor = (**descriptor).clone();
        descriptor
            .actions
            .retain(|action| self.imported_action_available(service, &action.action));
        if descriptor.actions.is_empty() {
            return ScopedMcpReadiness::unavailable();
        }
        let Some(projected) = self.project_service_spec(&descriptor) else {
            return ScopedMcpReadiness::unavailable();
        };
        evaluate_projected_scoped_mcp_readiness(
            &descriptor,
            projected,
            self.config.mcp.max_catalog_bytes,
        )
    }

    /// A prepared import mutation proves every other record/provider unchanged,
    /// so only its service needs another complete projection. Construction and
    /// configuration reload pass None and recompute every service, even when no
    /// imports exist or the HTTP MCP endpoint is disabled.
    pub(super) fn initialize_scoped_mcp_readiness(&mut self, changed: Option<&str>) {
        let states = if let Some(service) = changed {
            let mut states = (*self.scoped_mcp).clone();
            states.insert(
                service.to_owned(),
                self.service_scoped_mcp_readiness(service),
            );
            states
        } else {
            self.services
                .keys()
                .map(|service| (service.clone(), self.service_scoped_mcp_readiness(service)))
                .collect()
        };
        self.scoped_mcp = Arc::new(states);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builtin_only_runtime_computes_readiness_with_http_disabled() {
        let config = crate::runtime::tests::base_fake_config();
        assert!(!config.mcp.enabled);
        let runtime = BrokerRuntime::new(config).unwrap();
        assert!(runtime.scoped_mcp_diagnostics("fake").ready);
        assert!(runtime.scoped_mcp_diagnostics("broker_management").ready);
        assert!(!runtime.scoped_mcp_diagnostics("unknown").ready);
        let all = runtime.api_services_all();
        let fake = all
            .iter()
            .find(|service| service.service == "fake")
            .unwrap();
        assert!(fake.scoped_mcp_ready);
        let visible = runtime.api_services_for_identity(
            &IdentityContext::anonymous(),
            &ExecutionContext::new(DEFAULT_EXECUTION_CONTEXT).unwrap(),
        );
        let fake = visible
            .iter()
            .find(|service| service.service == "fake")
            .unwrap();
        assert!(fake.scoped_mcp_ready);
        assert!(
            fake.actions
                .iter()
                .all(|a| a.scoped_mcp_name.as_deref() == Some(&a.action))
        );
    }

    #[test]
    fn scoped_budget_failure_does_not_reject_builtin_startup_or_aggregate_catalog() {
        let mut config = crate::runtime::tests::base_fake_config();
        // Disabled HTTP still computes readiness with the configured bound.
        config.mcp.max_catalog_bytes = 1;
        let runtime = BrokerRuntime::new(config).unwrap();
        let state = runtime.scoped_mcp_diagnostics("fake");
        assert!(!state.ready);
        assert_eq!(
            serde_json::to_value(&state).unwrap()["issues"][0]["code"],
            "projection_budget"
        );
        let all = runtime.api_services_all();
        let fake = all
            .iter()
            .find(|service| service.service == "fake")
            .unwrap();
        assert!(!fake.actions.is_empty());
    }
}
