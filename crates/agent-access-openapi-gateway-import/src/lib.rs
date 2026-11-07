//! Administrative OpenAPI gateway imports. Builds bounded protocol data only;
//! core resolves the separately linked gateway module and owns execution.
mod config;
mod source;

use agent_access_core::imports::*;
use agent_access_openapi_common::*;
use agent_access_provider::*;
use async_trait::async_trait;
use config::{DefinitionSource, Settings};
use serde_json::json;
use std::collections::BTreeMap;

pub fn registration() -> ImportedAdapterRegistration {
    imported_adapter_registration(
        agent_access_provider::module_metadata!(),
        &OpenApiGatewayAdapter,
        None,
    )
}
#[derive(Debug)]
struct OpenApiGatewayAdapter;

fn requirement(
    delivery: &ImportedCredentialDelivery,
) -> Result<ImportedCredentialRequirement, String> {
    match delivery {
        ImportedCredentialDelivery::Basic => Ok(ImportedCredentialRequirement::http_basic()),
        ImportedCredentialDelivery::Bearer | ImportedCredentialDelivery::RawHeader { .. } => {
            Ok(ImportedCredentialRequirement::token_header())
        }
        ImportedCredentialDelivery::Stdin => {
            Err("gateway credentials require HTTP delivery".into())
        }
    }
}
fn plan(action: &ImportedActionDefinition) -> Result<GatewayPlanV1, String> {
    if serde_json::to_vec(action)
        .map_err(|_| "gateway action cannot be encoded")?
        .len()
        > IMPORT_MAX_TOOL_BYTES
    {
        return Err("gateway action exceeds the byte limit".into());
    }
    if action.download
        || action.output_schema.is_some()
        || action.input_schema != json!({"type":"object","additionalProperties":false})
    {
        return Err("gateway operations use native HTTP inputs and output".into());
    }
    let annotations = action
        .annotations
        .as_object()
        .filter(|annotations| annotations.len() == 1)
        .ok_or("gateway operation requires exactly one accepted plan")?;
    let plan: GatewayPlanV1 = serde_json::from_value(
        annotations
            .get("openapiGateway")
            .ok_or("gateway operation plan missing")?
            .clone(),
    )
    .map_err(|_| "gateway operation plan is invalid")?;
    plan.validate()?;
    if plan.source != action.source {
        return Err("gateway operation source differs from its accepted plan".into());
    }
    Ok(plan)
}
fn security_matches(
    settings: &Settings,
    definition: &ImportedServiceDefinition,
    security: &GatewaySecurityV1,
) -> bool {
    match &settings.authentication {
        GatewayAuthenticationSelection::Anonymous => {
            security.kind == "anonymous" && security.scheme.is_none() && security.header.is_none()
        }
        GatewayAuthenticationSelection::Static { scheme } => {
            let delivery = match security.kind.as_str() {
                "basic" => Some(ImportedCredentialDelivery::Basic),
                "bearer" => Some(ImportedCredentialDelivery::Bearer),
                "raw_header" => security
                    .header
                    .as_ref()
                    .map(|name| ImportedCredentialDelivery::RawHeader { name: name.clone() }),
                _ => None,
            };
            scheme.is_some()
                && &security.scheme == scheme
                && delivery.as_ref().is_some_and(|delivery| {
                    definition.execution_bindings.iter().all(|binding| {
                        match (&binding.delivery, delivery) {
                            (
                                ImportedCredentialDelivery::RawHeader { name: binding },
                                ImportedCredentialDelivery::RawHeader { name: plan },
                            ) => binding.eq_ignore_ascii_case(plan),
                            _ => &binding.delivery == delivery,
                        }
                    })
                })
        }
    }
}

#[async_trait]
impl ImportedAdapter for OpenApiGatewayAdapter {
    fn kind(&self) -> &'static str {
        "openapi_gateway"
    }
    fn gateway_kind(&self) -> Option<&'static str> {
        Some("openapi_gateway")
    }
    fn initial_gateway_routes(&self) -> Result<Option<ImportedGatewayRouteCandidate>, String> {
        Ok(Some(ImportedGatewayRouteCandidate::new(
            serde_json::to_value(GatewayRouteManifestV1::empty())
                .map_err(|_| "invalid initial gateway routes")?,
        )?))
    }
    fn supports_credential_free_execution(&self) -> bool {
        true
    }
    fn development_only(&self) -> bool {
        false
    }
    fn validate_definition(&self, definition: &ImportedServiceDefinition) -> Result<(), String> {
        Settings::parse(definition).map(|_| ())
    }
    fn credential_contract(
        &self,
        definition: &ImportedServiceDefinition,
        _: &ImportedAdapterContext<'_>,
    ) -> Result<ImportedCredentialContract, String> {
        let settings = Settings::parse(definition)?;
        let contract = ImportedCredentialContract::new(
            definition
                .execution_bindings
                .first()
                .map(|binding| requirement(&binding.delivery))
                .transpose()?,
            settings
                .document_delivery
                .as_ref()
                .map(requirement)
                .transpose()?,
            None,
        );
        contract.validate(definition)?;
        Ok(contract)
    }
    fn discovery_source(
        &self,
        definition: &ImportedServiceDefinition,
    ) -> Result<ImportedDiscoverySource, String> {
        Ok(match Settings::parse(definition)?.source {
            DefinitionSource::Url(_) => ImportedDiscoverySource::Remote,
            DefinitionSource::Upload => ImportedDiscoverySource::StoredDocument,
        })
    }
    fn additional_destinations(
        &self,
        definition: &ImportedServiceDefinition,
    ) -> Result<Vec<String>, String> {
        Ok(match Settings::parse(definition)?.source {
            DefinitionSource::Url(url) => vec![url.to_string()],
            DefinitionSource::Upload => Vec::new(),
        })
    }
    fn validate_action(&self, action: &ImportedActionDefinition) -> Result<(), String> {
        plan(action).map(|_| ())
    }
    fn scoped_mcp_name(&self, _: &ImportedActionDefinition) -> Result<String, String> {
        Err("gateway actions have no executable MCP name".into())
    }
    fn build(
        &self,
        definition: &ImportedServiceDefinition,
        actions: &[ImportedActionDefinition],
        transport: Option<ExecutionCredential>,
        _: &ImportedAdapterContext<'_>,
        _: &BuildContext<'_>,
    ) -> Result<ImportedProvider, ProviderBuildError> {
        let settings = Settings::parse(definition).map_err(ProviderBuildError::invalid)?;
        if transport.is_some() {
            return Err(ProviderBuildError::invalid(
                "gateway imports do not use transport credentials",
            ));
        }
        let mut plans = BTreeMap::new();
        for action in actions {
            let plan = plan(action).map_err(ProviderBuildError::invalid)?;
            if !security_matches(&settings, definition, &plan.security) {
                return Err(ProviderBuildError::invalid(
                    "accepted gateway security differs from its execution bindings",
                ));
            }
            let data = serde_json::to_value(&plan)
                .map_err(|_| ProviderBuildError::invalid("invalid gateway plan"))?;
            if plans
                .insert(
                    action.action.clone(),
                    GatewayVersionedData::new(plan.version, data),
                )
                .is_some()
            {
                return Err(ProviderBuildError::invalid("duplicate gateway action"));
            }
        }
        Ok(ImportedProvider::Gateway {
            kind: self.kind().into(),
            plans,
        })
    }
    async fn discover(
        &self,
        definition: &ImportedServiceDefinition,
        authentication: &ImportedDiscoveryAuthentication,
        transport: Option<ExecutionCredential>,
        import: &ImportedAdapterContext<'_>,
        host: &BuildContext<'_>,
    ) -> Result<ImportedDiscovery, AdapterDiscoveryError> {
        let settings = Settings::parse(definition).map_err(AdapterDiscoveryError::Configuration)?;
        if transport.is_some() {
            return Err(source::credential_error().into());
        }
        let operation = async {
            let bytes = source::read(
                &definition.service,
                &settings,
                authentication,
                import.document(),
                host,
            )
            .await?;
            let options = GatewayCompileOptions {
                endpoint: definition.endpoint.clone(),
                document_base: settings.document_base.to_string(),
                authentication: settings.authentication,
            };
            let mut compiled =
                tokio::task::spawn_blocking(move || compile_gateway_document(&bytes, &options))
                    .await
                    .map_err(|_| source::protocol_error())?
                    .map_err(AdapterDiscoveryError::Configuration)?;
            if let Some(old) = import.gateway_routes() {
                if !old.manifest.is_supported() {
                    return Err(AdapterDiscoveryError::Configuration(
                        "retained gateway route envelope is unsupported".into(),
                    ));
                }
                let retained: GatewayRouteManifestV1 =
                    serde_json::from_value(old.manifest.data.clone()).map_err(|_| {
                        AdapterDiscoveryError::Configuration(
                            "retained gateway routes are invalid".into(),
                        )
                    })?;
                compiled
                    .routes
                    .merge_retained(&retained)
                    .map_err(AdapterDiscoveryError::Configuration)?;
            }
            let routes = ImportedGatewayRouteCandidate::new(
                serde_json::to_value(compiled.routes).map_err(|_| source::protocol_error())?,
            )
            .map_err(AdapterDiscoveryError::Configuration)?;
            let tools = compiled
                .operations
                .into_iter()
                .map(|operation| {
                    let annotations = operation
                        .plan
                        .map(|plan| json!({"openapiGateway":plan}))
                        .unwrap_or_else(|| json!({}));
                    ImportedDiscoveredTool {
                        definition: ImportedActionDefinition {
                            action: operation.action,
                            source: operation.source,
                            label: operation.label,
                            description: operation.description,
                            input_schema: json!({"type":"object","additionalProperties":false}),
                            output_schema: None,
                            annotations,
                            read_only: false,
                            download: false,
                        },
                        unsupported_reason: operation.unsupported_reason,
                        read_only_hint: None,
                    }
                })
                .collect();
            let discovery = ImportedDiscovery {
                protocol_version: compiled.version,
                metadata: compiled.metadata,
                tools,
                gateway_routes: Some(routes),
                service_metadata: None,
                resource_type_changes: Vec::new(),
            };
            if serde_json::to_vec(&discovery)
                .map_err(|_| source::protocol_error())?
                .len()
                > IMPORT_MAX_MANIFEST_BYTES
            {
                return Err(AdapterDiscoveryError::Configuration(
                    "gateway discovery exceeds the preview byte limit".into(),
                ));
            }
            Ok(discovery)
        };
        tokio::time::timeout(std::time::Duration::from_secs(60), operation)
            .await
            .map_err(|_| {
                ProviderError::error(
                    ReasonCode::UpstreamTimeout,
                    "gateway discovery exceeded its deadline",
                )
            })?
    }
}

#[cfg(test)]
mod tests;
