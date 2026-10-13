//! Synthetic imported adapter: exercises the real DB loader without a network.
//! Only test registries select it; the broker binary never links it.
use agent_access_core::BackendRegistry;
use agent_access_core::imports::*;
use agent_access_provider::test_support::credential_token;
use agent_access_provider::*;
use async_trait::async_trait;
use serde_json::{Value, json};
use std::collections::BTreeMap;
use std::sync::Arc;

#[derive(Debug)]
pub struct ConformanceImportAdapter;
pub static CONFORMANCE_IMPORT_ADAPTER: ConformanceImportAdapter = ConformanceImportAdapter;

/// The broker's linked backends, dialects and adapters, plus the synthetic
/// import adapter.
pub fn registry() -> BackendRegistry {
    crate::backend_registry()
        .with_imported_adapters([imported_adapter_registration(
            &CONFORMANCE_IMPORT_ADAPTER,
            None,
        )])
        .expect("test import adapter registers consistently")
}

/// The fixture deliberately has a source identity unlike its grant action ID.
pub fn conformance_import_action() -> ImportedActionDefinition {
    ImportedActionDefinition {
        action: "inspect".into(),
        source: json!({"fixtureOperation":"upstream_inspect"}),
        label: None,
        description: "Inspect the synthetic imported service".into(),
        input_schema: json!({"type":"object","properties":{"message":{"type":"string"}},"required":["message"],"additionalProperties":false}),
        output_schema: None,
        annotations: json!({"readOnlyHint":true}),
        read_only: true,
    }
}
#[async_trait]
impl ImportedAdapter for ConformanceImportAdapter {
    fn sensitive_output_pointers(&self) -> &'static [&'static str] {
        &["/result/upstreamMcp"]
    }
    fn kind(&self) -> &'static str {
        "conformance_import"
    }
    fn development_only(&self) -> bool {
        true
    }
    fn validate_action(&self, action: &ImportedActionDefinition) -> Result<(), String> {
        if action.source != json!({"fixtureOperation":"upstream_inspect"}) {
            return Err("unknown conformance imported operation".into());
        }
        Ok(())
    }
    fn scoped_mcp_name(&self, action: &ImportedActionDefinition) -> Result<String, String> {
        self.validate_action(action)?;
        Ok("upstream_inspect".into())
    }
    fn build(
        &self,
        definition: &ImportedServiceDefinition,
        actions: &[ImportedActionDefinition],
        transport: Option<ExecutionCredential>,
        _host: &BuildContext<'_>,
    ) -> Result<Arc<dyn Provider>, ProviderBuildError> {
        definition.validate().map_err(ProviderBuildError::invalid)?;
        for action in actions {
            action
                .validate(&definition.service)
                .map_err(ProviderBuildError::invalid)?;
            self.validate_action(action)
                .map_err(ProviderBuildError::invalid)?;
            self.scoped_mcp_name(action)
                .map_err(ProviderBuildError::invalid)?;
        }
        let transport_authority = if definition.transport_auth {
            Some(match transport.as_ref().map(credential_token) {
                Some("import-transport-initial") => "initial",
                Some("import-transport-rotated") => "rotated",
                _ => {
                    return Err(ProviderBuildError::invalid(
                        "conformance transport credential is unavailable",
                    ));
                }
            })
        } else {
            None
        };
        Ok(Arc::new(ImportedConformanceProvider {
            actions: actions.to_vec(),
            transport_authority,
        }))
    }
    async fn discover(
        &self,
        _definition: &ImportedServiceDefinition,
        _authentication: &ImportedDiscoveryAuthentication,
        _transport: Option<ExecutionCredential>,
        _host: &BuildContext<'_>,
    ) -> Result<ImportedDiscovery, ProviderError> {
        Ok(ImportedDiscovery {
            protocol_version: "conformance-v1".into(),
            metadata: json!({}),
            tools: vec![ImportedDiscoveredTool {
                definition: conformance_import_action(),
                unsupported_reason: None,
                read_only_hint: Some(true),
            }],
        })
    }
}
struct ImportedConformanceProvider {
    actions: Vec<ImportedActionDefinition>,
    transport_authority: Option<&'static str>,
}
impl ImportedConformanceProvider {
    fn local_scopes(&self, action: &str, inputs: &Value) -> Result<ResourceScopes, ProviderError> {
        if !self.actions.iter().any(|item| item.action == action) {
            return Err(ProviderError::deny(
                ReasonCode::ServiceActionDenied,
                "unknown conformance action",
            ));
        }
        if inputs.get("message").and_then(Value::as_str).is_none() {
            return Err(ProviderError::deny(
                ReasonCode::InputInvalid,
                "message is required",
            ));
        }
        Ok(BTreeMap::new())
    }
}

#[async_trait]
impl Provider for ImportedConformanceProvider {
    async fn resolve_scopes(
        &self,
        request: ScopeRequest<'_>,
    ) -> Result<ScopeResolution, ProviderError> {
        self.local_scopes(request.action(), request.inputs())
            .map(ScopeResolution::resources)
    }
    async fn invoke(&self, request: ProviderInvocation) -> Result<ProviderResult, ProviderError> {
        self.local_scopes(&request.action, &request.inputs)?;
        let token = request.execution.static_credential().map(credential_token);
        // Tokens are synthetic test sentinels; responses never expose material.
        let authority = match token {
            Some("import-service-token") => "service",
            Some("import-user-token") => "per_user",
            _ => {
                return Err(ProviderError::deny(
                    ReasonCode::CredentialNotProvisioned,
                    "conformance credential is unavailable",
                ));
            }
        };
        Ok(ProviderResult {
            result: json!({"upstreamMcp":{"principal":request.identity.principal,"credentialMode":request.credential_mode,"authority":authority,"transportAuthority":self.transport_authority,"message":request.inputs["message"]}}),
            stream: None,
            audit: None,
            upstream_status: Some(200),
            upstream_duration_ms: Some(0),
            object_ids: None,
        })
    }
}

#[cfg(test)]
mod scoped_name_tests {
    use super::*;
    #[test]
    fn fixture_name_has_explicit_imported_provenance() {
        let mut action = conformance_import_action();
        assert_eq!(
            CONFORMANCE_IMPORT_ADAPTER.scoped_mcp_name(&action).unwrap(),
            "upstream_inspect"
        );
        assert_ne!(action.action, "upstream_inspect");
        action.source = json!({});
        assert!(CONFORMANCE_IMPORT_ADAPTER.scoped_mcp_name(&action).is_err());
    }

    #[test]
    fn only_test_registries_select_the_synthetic_adapter() {
        let kind = CONFORMANCE_IMPORT_ADAPTER.kind();
        assert!(crate::backend_registry().imported_adapter(kind).is_none());
        assert!(registry().imported_adapter(kind).is_some());
    }
}
