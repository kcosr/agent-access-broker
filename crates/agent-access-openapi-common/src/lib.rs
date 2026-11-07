//! Bounded, offline OpenAPI gateway documents and the explicitly versioned V1 wire contract.
//!
//! This helper contains no Broker policy, credentials, store, or transport dependencies.
//! Its V1 wire structs are intentionally exhaustive: changed wire semantics require a new version.
mod model;
mod profile;
mod routes;
mod schema;

pub use model::*;
pub use profile::{
    GATEWAY_COMMON_REQUEST_HEADERS, GATEWAY_COMMON_RESPONSE_HEADERS, GatewayValidatedParameters,
    validate_declared_header,
};
pub use routes::{GatewayPathMatch, canonical_path, validate_path_template};

/// Maximum bytes in a source document or durable route manifest.
pub const GATEWAY_MAX_DOCUMENT_BYTES: usize = 4 * 1024 * 1024;
/// Maximum serialized durable guard manifest size.
pub const GATEWAY_MAX_MANIFEST_BYTES: usize = 4 * 1024 * 1024;
/// Historical paths are never evicted to fit this limit.
pub const GATEWAY_MAX_PATHS: usize = 4096;
/// Maximum operations in one source document.
pub const GATEWAY_MAX_OPERATIONS: usize = 512;
/// Maximum nesting in source JSON and local references.
pub const GATEWAY_MAX_DEPTH: usize = 64;
/// Review notice required for template routes and subset acceptance.
pub const GATEWAY_TEMPLATE_COVERAGE_NOTICE: &str = "Route guards cover only paths declared in this document or retained from earlier versions. Include literal routes that shadow templates, even when those operations will not be accepted.";

pub(crate) fn bounded(value: &str, max: usize) -> bool {
    !value.is_empty() && value.len() <= max && !value.chars().any(char::is_control)
}

#[cfg(test)]
mod tests;

/// Validate the immutable approved base URL. This function performs no network access.
pub fn validate_endpoint(raw: &str) -> Result<url::Url, String> {
    let url = url::Url::parse(raw).map_err(|_| "invalid gateway endpoint")?;
    if !matches!(url.scheme(), "http" | "https")
        || url.host_str().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
        || !bounded(raw, 4096)
        || raw.contains(['*', '\\'])
    {
        return Err("gateway endpoint requires a fixed HTTP(S) URL without credentials, query, fragment or wildcards".into());
    }
    canonical_path(url.path())?;
    Ok(url)
}
