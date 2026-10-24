//! Broker host: module composition, the broker application and its process
//! lifecycle, HTTP handlers, management, MCP serving, portal serving, the
//! generic Git gateway, reload and runtime state. The linking assembly
//! supplies its composition and identity.
mod admission;
mod application;
mod build_status;
mod composition;
mod handlers;
mod http_server;
mod identity;
mod ingress;
mod lifecycle;
mod mcp;
mod membership_renewal;
mod oauth_revocations;
mod observability;
mod oidc_id_token;
mod operations;
mod reload;
mod router;
mod state;
#[cfg(any(test, feature = "test-support"))]
pub mod test_support;

#[cfg(test)]
mod test_composition;
#[cfg(test)]
mod tests;

/// The opaque import selection [`BrokerCompositionBuilder::import_adapter`]
/// takes; shipped adapter crates return one from `registration()`.
pub use agent_access_core::imports::ImportedAdapterRegistration;
pub use application::{BrokerApplication, BrokerExit};
pub use build_status::BrokerBuildStatus;
pub use composition::{BrokerComposition, BrokerCompositionBuilder, CompositionError};
pub use identity::{AssemblyIdentity, ModuleProvenance, SourceRevision};

#[cfg(test)]
use test_composition::{backend_registry, broker_build_status};
