//! Third-party types and macros that the SDK's supported signatures name.
//!
//! Each submodule is named after the package that defines its items and
//! re-exports only the items supported signatures use, at the SDK's version of
//! that package (see the crate documentation's
//! [Third-party dependencies](crate#third-party-dependencies) table). A
//! provider can implement every SDK trait through these paths without naming
//! the packages in its own manifest:
//!
//! ```
//! use agent_access_provider::deps::{async_trait, serde_json::Value};
//! use agent_access_provider::{
//!     Provider, ProviderError, ProviderInvocation, ProviderResult, ReasonCode, ScopeRequest,
//!     ScopeResolution,
//! };
//!
//! struct ReadOnly;
//!
//! #[async_trait]
//! impl Provider for ReadOnly {
//!     async fn resolve_scopes(
//!         &self,
//!         _request: ScopeRequest<'_>,
//!     ) -> Result<ScopeResolution, ProviderError> {
//!         Ok(ScopeResolution::no_resources())
//!     }
//!
//!     async fn invoke(
//!         &self,
//!         request: ProviderInvocation,
//!     ) -> Result<ProviderResult, ProviderError> {
//!         let reason = match request.inputs().get("item") {
//!             Some(Value::String(_)) => ReasonCode::ServiceActionDenied,
//!             _ => ReasonCode::InputInvalid,
//!         };
//!         Err(ProviderError::deny(reason, "this example performs no action"))
//!     }
//! }
//! ```
//!
//! Re-exporting does not decouple the SDK from these packages: an
//! incompatible release of one of them is an SDK compatibility event.

/// The `async-trait` 0.1 attribute macro, for implementing the SDK's async
/// traits: [`Provider`](crate::Provider), [`OAuthDialect`](crate::OAuthDialect),
/// [`DelegatedLease`](crate::DelegatedLease) and
/// [`RedirectAuthorizer`](crate::RedirectAuthorizer).
pub use ::async_trait::async_trait;

/// `bytes` 1: the chunks of a provider result stream.
pub mod bytes {
    pub use ::bytes::Bytes;
}

/// `chrono` 0.4: upstream retry times.
pub mod chrono {
    pub use ::chrono::{DateTime, Utc};
}

/// `futures-core` 0.3: the byte streams a raw result carries.
pub mod futures_core {
    pub use ::futures_util::stream::Stream;
}

/// `http` 1, as `reqwest` 0.12 re-exports it: request methods, header maps
/// and the header names credential placements use.
pub mod http {
    pub use ::reqwest::Method;
    pub use ::reqwest::header::{HeaderMap, HeaderName};
}

/// `reqwest` 0.12: the HTTP client, requests, responses and bodies that
/// upstream clients and the host's client factory exchange.
pub mod reqwest {
    pub use ::reqwest::{Body, Client, ClientBuilder, RequestBuilder, Response};
}

/// `serde_json` 1: inputs, results, audit and schema values.
pub mod serde_json {
    pub use ::serde_json::{Map, Value};
}

/// `tokio` 1: finalization deadlines and upload progress.
pub mod tokio {
    pub mod time {
        pub use ::tokio::time::Instant;
    }

    pub mod sync {
        pub mod watch {
            pub use ::tokio::sync::watch::Receiver;
        }
    }
}

/// `toml` 0.9: the deserializer and error a backend configuration parser
/// ([`BackendConfigParser`](crate::BackendConfigParser)) takes and returns.
pub mod toml {
    pub mod de {
        pub use ::toml::de::{Error, ValueDeserializer};
    }
}

/// `url` 2: upstream URLs and hosts.
pub mod url {
    pub use ::url::{Host, Url};
}

/// `tracing` 0.1: the span and instrumented futures of scoped trace capture
/// in test support.
#[cfg(any(test, feature = "test-support"))]
pub mod tracing {
    pub use ::tracing::Span;
    pub use ::tracing::instrument::Instrumented;
}
