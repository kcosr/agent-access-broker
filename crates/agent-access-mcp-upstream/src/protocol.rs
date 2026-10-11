//! Private, bounded startup classification. Only sanitized successes reach rmcp.
use agent_access_provider::{ProviderError, ReasonCode};
use serde_json::{Value, json};
use std::collections::BTreeSet;

pub const PROTOCOL_VERSION: &str = "2026-07-28";
pub(crate) const LEGACY_PROTOCOL_VERSION: &str = "2025-11-25";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Lifecycle {
    Discover,
    Initialize,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum LegacyReason {
    VersionAdvertisement,
    DiscoveryUnsupported,
    HttpRejection,
}

impl LegacyReason {
    pub fn label(self) -> &'static str {
        match self {
            Self::VersionAdvertisement => "previous version advertised",
            Self::DiscoveryUnsupported => "discovery unsupported",
            Self::HttpRejection => "startup HTTP rejection",
        }
    }
}

pub(crate) enum ProbeSelection {
    Current(Value),
    Legacy(LegacyReason),
}

pub(crate) fn eligible_probe_status(status: u16) -> bool {
    matches!(status, 400 | 404 | 405 | 415 | 422)
}

fn startup_error(category: &str) -> ProviderError {
    ProviderError::error(
        ReasonCode::UpstreamProtocolFailed,
        format!("MCP {PROTOCOL_VERSION} discovery failed: {category}"),
    )
}

/// HTTP error responses may precede JSON-RPC decoding. Only those responses get
/// the transport-correlation exception; a 200 always has a strict RPC envelope.
pub(crate) fn classify_probe(
    status: u16,
    reply: Option<Value>,
    expected: &Value,
) -> Result<ProbeSelection, ProviderError> {
    if status != 200 && !eligible_probe_status(status) {
        return Err(startup_error("ineligible HTTP status"));
    }
    if status == 200 {
        let reply = reply.as_ref().ok_or_else(protocol_error)?;
        validate_envelope(reply, expected)?;
        if reply.get("error").is_none() {
            let result = validate_reply(reply.clone(), expected)?;
            let versions = version_list(result.get("supportedVersions"))?;
            let mut typed = result.clone();
            typed
                .as_object_mut()
                .ok_or_else(protocol_error)?
                .insert("resultType".into(), json!("complete"));
            let discovered: rmcp::model::DiscoverResult =
                serde_json::from_value(typed).map_err(|_| protocol_error())?;
            if discovered.capabilities.tools.is_none() {
                return Err(startup_error("tools capability unavailable"));
            }
            if versions.contains(PROTOCOL_VERSION) {
                return Ok(ProbeSelection::Current(result));
            }
            return if versions.contains(LEGACY_PROTOCOL_VERSION) {
                Ok(ProbeSelection::Legacy(LegacyReason::VersionAdvertisement))
            } else {
                Err(startup_error("no supported protocol overlap"))
            };
        }
    }
    let error = reply.as_ref().and_then(|v| v.get("error"));
    let code = error.and_then(|e| e.get("code")).and_then(Value::as_i64);
    if matches!(code, Some(-32020 | -32021)) {
        return Err(startup_error("modern protocol requirement rejected"));
    }
    let data = error.and_then(|e| e.get("data"));
    let supported = data.and_then(|v| v.get("supported"));
    if code == Some(-32022) || supported.is_some() {
        let versions = version_list(supported)?;
        if data
            .and_then(|v| v.get("requested"))
            .is_some_and(|v| v.as_str() != Some(PROTOCOL_VERSION))
        {
            return Err(startup_error("invalid requested-version advertisement"));
        }
        // A rejected current version is never probed again, even if the peer
        // contradicts itself by including it in this list.
        return if versions.contains(LEGACY_PROTOCOL_VERSION) {
            Ok(ProbeSelection::Legacy(LegacyReason::VersionAdvertisement))
        } else {
            Err(startup_error("no supported protocol overlap"))
        };
    }
    if status != 200 {
        return Ok(ProbeSelection::Legacy(LegacyReason::HttpRejection));
    }
    if matches!(code, Some(-32601 | -32600)) {
        return Ok(ProbeSelection::Legacy(LegacyReason::DiscoveryUnsupported));
    }
    Err(startup_error("discovery RPC rejection"))
}

fn version_list(value: Option<&Value>) -> Result<BTreeSet<&str>, ProviderError> {
    let values = value
        .and_then(Value::as_array)
        .filter(|v| !v.is_empty() && v.len() <= 32)
        .ok_or_else(|| startup_error("invalid supported-version advertisement"))?;
    let mut versions = BTreeSet::new();
    for value in values {
        let value = value
            .as_str()
            .filter(|v| !v.is_empty() && v.len() <= 64 && v.is_ascii())
            .ok_or_else(|| startup_error("invalid supported-version advertisement"))?;
        if !versions.insert(value) {
            return Err(startup_error("duplicate supported-version advertisement"));
        }
    }
    Ok(versions)
}

pub(crate) fn validate_initialize(result: &Value) -> Result<(), ProviderError> {
    let initialized: rmcp::model::InitializeResult =
        serde_json::from_value(result.clone()).map_err(|_| protocol_error())?;
    if initialized.protocol_version.as_str() != LEGACY_PROTOCOL_VERSION {
        return Err(ProviderError::error(
            ReasonCode::UpstreamProtocolFailed,
            "MCP 2025-11-25 initialization selected an unsupported protocol version",
        ));
    }
    if initialized.capabilities.tools.is_none() {
        return Err(ProviderError::error(
            ReasonCode::UpstreamProtocolFailed,
            "MCP 2025-11-25 initialization has no tools capability",
        ));
    }
    Ok(())
}

fn validate_envelope(reply: &Value, expected: &Value) -> Result<(), ProviderError> {
    if reply.get("jsonrpc").and_then(Value::as_str) != Some("2.0")
        || reply.get("id") != Some(expected)
        || reply.get("method").is_some()
        || reply.get("error").is_some() == reply.get("result").is_some()
    {
        return Err(protocol_error());
    }
    if let Some(error) = reply.get("error")
        && (error.get("code").and_then(Value::as_i64).is_none()
            || error.get("message").and_then(Value::as_str).is_none())
    {
        return Err(protocol_error());
    }
    Ok(())
}

pub(crate) fn validate_reply(reply: Value, expected: &Value) -> Result<Value, ProviderError> {
    validate_envelope(&reply, expected)?;
    let result = reply
        .get("result")
        .filter(|v| v.is_object())
        .ok_or_else(protocol_error)?;
    if result
        .get("resultType")
        .is_some_and(|v| v.as_str() != Some("complete"))
    {
        return Err(ProviderError::error(
            ReasonCode::UpstreamProtocolFailed,
            "upstream MCP operation requires an unsupported continuation; completion is unknown",
        ));
    }
    Ok(result.clone())
}

pub(crate) fn protocol_error() -> ProviderError {
    ProviderError::error(
        ReasonCode::UpstreamProtocolFailed,
        "upstream MCP response is invalid or unsupported",
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn error_correlation_exception_is_limited_to_eligible_http_rejections() {
        let reply = json!({"jsonrpc":"2.0", "id":"server-error", "error":{"code":-32600, "message":"opaque"}});
        assert!(matches!(
            classify_probe(400, Some(reply.clone()), &json!(1)).unwrap(),
            ProbeSelection::Legacy(LegacyReason::HttpRejection)
        ));
        assert!(classify_probe(200, Some(reply.clone()), &json!(1)).is_err());
        assert!(classify_probe(429, Some(reply), &json!(1)).is_err());
    }

    #[test]
    fn modern_requirements_and_invalid_advertisements_do_not_downgrade() {
        for code in [-32020, -32021] {
            let reply =
                json!({"error":{"code":code,"data":{"supported":[LEGACY_PROTOCOL_VERSION]}}});
            assert!(classify_probe(400, Some(reply), &json!(1)).is_err());
        }
        for supported in [
            json!([]),
            json!([LEGACY_PROTOCOL_VERSION, LEGACY_PROTOCOL_VERSION]),
            json!([42]),
            json!(["é"]),
            json!(["x".repeat(65)]),
            json!([PROTOCOL_VERSION]),
        ] {
            let reply = json!({"error":{"code":-32022,"data":{"supported":supported}}});
            assert!(classify_probe(400, Some(reply), &json!(1)).is_err());
        }
        let reply = json!({"error":{"code":-32022,"data":{"supported":[PROTOCOL_VERSION,LEGACY_PROTOCOL_VERSION],"requested":PROTOCOL_VERSION}}});
        assert!(matches!(
            classify_probe(400, Some(reply), &json!(1)).unwrap(),
            ProbeSelection::Legacy(LegacyReason::VersionAdvertisement)
        ));
    }
}
