//! The upstream Agent Access Broker assembly. `composition()` selects the
//! modules this distribution links and `build_identity()` describes the
//! executable. The binary passes both to the host's `BrokerApplication`;
//! acceptance tests pass them to the host's test support.
mod backends;
mod build_info;

pub use backends::composition;
pub use build_info::build_identity;
