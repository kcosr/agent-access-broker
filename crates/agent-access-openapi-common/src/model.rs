use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::BTreeMap;

/// Explicit upstream authentication selection; it never falls back at execution.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum GatewayAuthenticationSelection {
    Anonymous,
    /// An unselected draft discovers schemes and unsupported operation previews.
    Static {
        scheme: Option<String>,
    },
}

/// Source-relative servers resolve against `document_base`; uploads use the API endpoint.
#[derive(Clone, Debug)]
pub struct GatewayCompileOptions {
    pub endpoint: String,
    pub document_base: String,
    pub authentication: GatewayAuthenticationSelection,
}

/// Whole-document result. Unsupported operations remain visible and reserve their routes.
#[derive(Clone, Debug)]
pub struct GatewayCompilation {
    pub version: String,
    pub metadata: Value,
    pub operations: Vec<GatewayCompiledOperation>,
    pub routes: GatewayRouteManifestV1,
}

#[derive(Clone, Debug)]
pub struct GatewayCompiledOperation {
    pub action: String,
    pub source: Value,
    pub label: Option<String>,
    pub description: String,
    pub plan: Option<GatewayPlanV1>,
    pub unsupported_reason: Option<String>,
}

/// Exact durable operation profile. V1 is strict; unknown fields and versions fail closed.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct GatewayPlanV1 {
    pub version: u32,
    pub source: Value,
    pub method: String,
    pub path: String,
    pub security: GatewaySecurityV1,
    pub parameters: Vec<GatewayParameterV1>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub request_body: Option<GatewayRequestBodyV1>,
    pub responses: BTreeMap<String, GatewayResponseV1>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct GatewaySecurityV1 {
    pub kind: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scheme: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub header: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct GatewayParameterV1 {
    pub name: String,
    pub location: String,
    pub required: bool,
    pub style: String,
    pub explode: bool,
    /// Strict, bounded primitive profile, validated when compiling and when restoring a plan.
    pub schema: Value,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct GatewayRequestBodyV1 {
    pub required: bool,
    pub media_types: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct GatewayResponseV1 {
    pub headers: Vec<GatewayResponseHeaderV1>,
    pub content_types: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct GatewayResponseHeaderV1 {
    pub name: String,
    pub schema: Value,
}

/// The complete durable path universe; executable actions are resolved separately by the host.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct GatewayRouteManifestV1 {
    pub version: u32,
    pub paths: BTreeMap<String, GatewayPathV1>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct GatewayPathV1 {
    pub methods: BTreeMap<String, GatewayRouteV1>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct GatewayRouteV1 {
    /// Exactly `{operationId}` or `{method,path}`; never an arbitrary upstream address.
    pub source: Value,
    /// Removed operations retain a denial guard but cannot dispatch.
    pub current: bool,
    pub supported: bool,
}
