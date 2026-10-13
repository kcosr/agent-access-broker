//! Broker host: module composition, the broker application and its process
//! lifecycle, HTTP handlers, management, MCP serving, portal serving, the
//! generic Git gateway, reload and runtime state. The linking assembly
//! supplies its composition and identity.
mod application;
mod build_status;
mod composition;
mod handlers;
mod ingress;
mod lifecycle;
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

pub use application::{AssemblyIdentity, BrokerApplication, BrokerExit};
pub use build_status::{BrokerBuildStatus, BuildProvenance};
pub use composition::{BrokerComposition, BrokerCompositionBuilder, CompositionError};
pub use reload::{build_reloadable_state, validate_shutdown_timeout};
pub use router::{build_gateway_router, build_public_router, build_router};
pub use state::ReloadableState;

#[cfg(test)]
use test_composition::{backend_registry, broker_build_status};
