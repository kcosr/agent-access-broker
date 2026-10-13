//! Contract between the Agent Access Broker host and its backends.
//!
//! A backend describes its services with a [`ServiceDescriptor`], serves
//! invocations through the [`Provider`] trait, and reaches upstream systems
//! through the host services defined here: upstream clients the host
//! constructs (TLS trust and egress routing stay inside the host), upstream
//! allowlists, correlation headers, trace events, and stable token signing.
//! The broker owns identity, policy, credentials, audit, limits and network
//! construction; backends see only the narrow views in this crate. The
//! [`host`] module is the construction interface the broker host implements.

mod attribution;
mod backend;
mod capabilities;
mod config;
mod correlation;
mod delegated;
mod descriptor;
mod egress_config;
mod error;
mod finalization;
pub mod host;
mod identifiers;
mod import_schema;
mod imports;
mod imports_adapter;
mod invocation;
mod oauth_dialect;
pub mod presentation;
mod provider;
mod reason;
mod resource;
mod result;
mod signing;
#[cfg(any(test, feature = "test-support"))]
pub mod test_support;
mod trace;
mod upstream;
mod upstream_allowlist;
mod upstream_rate_limit;
mod upstream_validation;

pub use attribution::*;
pub use backend::*;
pub use capabilities::*;
pub use config::*;
pub use correlation::*;
pub use delegated::*;
pub use descriptor::*;
pub use egress_config::*;
pub use error::*;
pub use finalization::*;
pub use identifiers::*;
pub use import_schema::*;
pub use imports::*;
pub use imports_adapter::*;
pub use invocation::*;
pub use oauth_dialect::*;
pub use presentation::{
    ActionPresentation, BodyPathSegment, EmbeddedBody, EmbeddedBodyCodec, PresentationBudget,
    ReadContentFormat, RenderBudget, RenderBudgetExhausted, RenderContext, RenderError,
    RenderedBody, ResponseCapabilities, ResponseFormat, ResponseOptions, WholeResultRenderer,
};
pub use provider::*;
pub use reason::*;
pub use resource::*;
pub use result::*;
pub use signing::*;
pub use trace::*;
pub use upstream::*;
pub use upstream_allowlist::*;
pub use upstream_rate_limit::*;
pub use upstream_validation::*;
