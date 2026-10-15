//! The internal import contract: imported-service definitions, bounded
//! schemas, the protocol adapter seam, the opaque registration an assembly
//! selects, and the command-import process budgets shared across runtime
//! generations. This is Broker implementation, not a supported extension
//! interface; only the shipped import adapters implement it.
mod adapter;
mod authority;
mod command;
mod command_facts;
mod command_registry;
mod command_request;
mod definition;
mod metadata;
mod registration;
mod schema;
mod type_changes;

pub use adapter::*;
pub use authority::*;
pub use command::*;
pub use command_facts::{CommandProcessFacts, CommandProcessFactsSnapshot};
pub use command_registry::{
    CommandAcquireError, CommandPermit, CommandProcessControl, CommandRegistry,
    CommandRegistryClosed, LiveCommandProcess,
};
pub use command_request::CommandSecrets;
pub(crate) use command_request::{
    CommandCaller, CommandCallerToken, CommandCallerUsername, CommandCredential, InvokeRequest,
    RequestAuthorization, RequestBoundary, RequestCredentials, RequestGrant, RequestResource,
    wire_deadline, wire_mode,
};
pub use definition::*;
pub use metadata::*;
pub use registration::{
    ImportOAuthCompanion, ImportedAdapterRegistration, imported_adapter_registration,
};
pub use schema::*;
pub use type_changes::*;

/// The implementation an imported protocol client names itself as, such as
/// an imported MCP connection's `clientInfo`: the Broker host package and
/// its version, which core shares. It never names the linking assembly or the
/// adapter package.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HostImplementation {
    pub name: &'static str,
    pub version: &'static str,
}

pub const HOST_IMPLEMENTATION: HostImplementation = HostImplementation {
    name: "agent-access-broker-host",
    version: env!("CARGO_PKG_VERSION"),
};
