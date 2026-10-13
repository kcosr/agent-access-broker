//! The internal import contract: imported-service definitions, bounded
//! schemas, the protocol adapter seam and the opaque registration an
//! assembly selects. This is Broker implementation, not a supported
//! extension interface; only the shipped import adapters implement it.
mod adapter;
mod definition;
mod registration;
mod schema;

pub use adapter::*;
pub use definition::*;
pub use registration::{
    ImportOAuthCompanion, ImportedAdapterRegistration, imported_adapter_registration,
};
pub use schema::*;
