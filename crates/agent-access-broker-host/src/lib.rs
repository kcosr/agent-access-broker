//! Broker host: HTTP handlers, management, MCP serving, portal serving, the
//! generic Git gateway, reload and runtime state. The linking assembly supplies
//! the backend registry and its build status.
mod build_status;
mod handlers;
mod ingress;
mod mcp;
mod observability;
mod operations;
mod reload;
mod router;
mod state;

#[cfg(test)]
mod test_composition;
#[cfg(test)]
mod tests;

pub use build_status::{BrokerBuildStatus, BuildProvenance};
pub use reload::{build_reloadable_state, validate_shutdown_timeout};
pub use router::{build_gateway_router, build_public_router, build_router};
pub use state::ReloadableState;

#[cfg(test)]
use test_composition::{backend_registry, broker_build_status};
