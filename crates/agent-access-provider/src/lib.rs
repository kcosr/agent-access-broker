//! Contract between the Agent Access Broker host and its backends.
//!
//! A backend describes its services with a [`ServiceDescriptor`], serves
//! invocations through the [`Provider`] trait, and reaches upstream systems
//! through the host services defined here: egress proxy selection, outbound
//! TLS trust, upstream allowlists, correlation headers, trace events, and
//! stable token signing. The broker owns identity, policy, credentials,
//! audit, and limits; backends see only the narrow views in this crate.

mod attribution;
mod backend;
mod capabilities;
mod config;
mod correlation;
mod delegated;
mod descriptor;
mod egress_config;
mod egress_proxy;
mod error;
mod finalization;
mod identifiers;
mod import_schema;
mod imports;
mod imports_adapter;
mod invocation;
mod oauth_dialect;
mod outbound_tls;
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
pub use egress_proxy::*;
pub use error::*;
pub use finalization::*;
pub use identifiers::*;
pub use import_schema::*;
pub use imports::*;
pub use imports_adapter::*;
pub use invocation::*;
pub use oauth_dialect::*;
pub use outbound_tls::*;
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
