//! Preserve Actions/tools source limits while sharing duplicate-aware neutral JSON admission.
pub(crate) fn decode(bytes: &[u8]) -> Result<serde_json::Value, String> {
    agent_access_openapi_common::decode_bounded_document_json(
        bytes,
        agent_access_core::imports::IMPORT_MAX_DOCUMENT_BYTES,
        agent_access_core::imports::IMPORT_MAX_SCHEMA_DEPTH,
    )
}
