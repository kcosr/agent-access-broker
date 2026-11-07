//! SDK-only linked protocol example; it owns no transport or credential access.
use agent_access_provider::{
    ActionDescriptor, CredentialDescriptor, GatewayBody, GatewayClassification, GatewayConfig,
    GatewayForwardPlan, GatewayProtocol, GatewayRegistration, GatewayRequest, GatewayRequestHead,
    GatewayServiceContext, ProviderBuildError, ProviderError, ReasonCode, ResourceScopes,
    ServiceDescriptor, ServiceSurface,
    deps::{async_trait, http::Method, serde_json::Value, toml},
};
use std::sync::Arc;

pub static REGISTRATION: GatewayRegistration = GatewayRegistration::new(
    agent_access_provider::module_metadata!(),
    "example_http",
    parse,
);

fn parse(value: toml::Value) -> Result<Arc<dyn GatewayConfig>, String> {
    if value.as_table().is_none_or(|table| !table.is_empty()) {
        return Err("example_http accepts no protocol settings".into());
    }
    Ok(Arc::new(Example))
}
#[derive(Debug)]
struct Example;
impl GatewayConfig for Example {
    fn validate(&self, _: &GatewayServiceContext, _: &mut Vec<String>) {}
    fn descriptor(&self, context: &GatewayServiceContext) -> ServiceDescriptor {
        ServiceDescriptor::new(&context.service, &context.display_name)
            .with_surface(ServiceSurface::Gateway {
                kind: "example_http".into(),
                broker_hosts: context.broker_hosts.clone(),
            })
            .with_credentials(
                CredentialDescriptor::without_execution_credential().without_verification(),
            )
            .with_actions(vec![
                ActionDescriptor::new(
                    "items.read",
                    "Read items",
                    Value::Object(
                        [("type".into(), Value::String("object".into()))]
                            .into_iter()
                            .collect(),
                    ),
                )
                .read_only()
                .credential_modes(["service"]),
            ])
    }
    fn build(
        &self,
        _: &GatewayServiceContext,
    ) -> Result<Arc<dyn GatewayProtocol>, ProviderBuildError> {
        Ok(Arc::new(Example))
    }
}
impl GatewayProtocol for Example {
    fn classify(
        &self,
        head: GatewayRequestHead<'_>,
    ) -> Result<GatewayClassification, ProviderError> {
        if head.method() != Method::GET || head.path_and_query() != "/items" {
            return Err(ProviderError::deny(
                ReasonCode::GatewayRuleNotFound,
                "route not found",
            ));
        }
        Ok(GatewayClassification::new(
            "items.read",
            ResourceScopes::new(),
            "request",
            Box::new(Example),
        ))
    }
}
#[async_trait]
impl GatewayRequest for Example {
    async fn preflight(
        self: Box<Self>,
        body: GatewayBody,
    ) -> Result<GatewayForwardPlan, ProviderError> {
        Ok(GatewayForwardPlan::new(Method::GET, "/items", body))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn linked_gateway_parses_strict_configuration_and_declares_authority() {
        let empty = toml::Value::Table(Default::default());
        let gateway = parse(empty).unwrap();
        let context = GatewayServiceContext::new("items", "Items", "https://api.example.test");
        let descriptor = gateway.descriptor(&context);
        assert_eq!(descriptor.service, "items");
        assert!(!descriptor.credentials.verification_supported);
        assert!(descriptor.action("items.read").unwrap().read_only);
        let unexpected = [("secret".into(), toml::Value::String("not accepted".into()))]
            .into_iter()
            .collect();
        assert!(parse(toml::Value::Table(unexpected)).is_err());
    }
}
