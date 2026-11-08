//! Offline, whole-operation HTTP forwarding plans for managed OpenAPI gateways.
//!
//! This module receives no credentials or upstream clients. The host owns identity,
//! grants, credential presentation, transfer limits, dispatch fences and completion.
//! The import adapter checks accepted security against the execution binding before
//! supplying this candidate; credential modes are grant modes, not a substitute for
//! that check. Every retained V1 plan is validated, including inactive plans, so a
//! corrupt or unsupported retained record cannot silently publish a partial service.
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
