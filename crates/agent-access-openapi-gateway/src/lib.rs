//! Offline, whole-operation HTTP forwarding plans for managed OpenAPI gateways.
//!
//! This module receives no credentials or upstream clients. The host owns identity,
//! grants, credential presentation, transfer limits, dispatch fences and completion.
mod protocol;
mod request;

use agent_access_provider::{GatewayConfig, GatewayRegistration, module_metadata};
use std::sync::Arc;

static REGISTRATION: GatewayRegistration =
    GatewayRegistration::new(module_metadata!(), "openapi_gateway", reject_static_config)
        .with_managed_builder(protocol::build);

/// Select the managed OpenAPI gateway protocol in a Broker assembly.
/// The companion import adapter is selected separately.
pub const fn registration() -> &'static GatewayRegistration {
    &REGISTRATION
}

fn reject_static_config(_: toml::Value) -> Result<Arc<dyn GatewayConfig>, String> {
    Err(
        "openapi_gateway requires an accepted managed import and an operator gateway binding"
            .into(),
    )
}

#[cfg(test)]
mod tests;
