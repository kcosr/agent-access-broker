//! Wire projection of service descriptors.
use crate::ResourceType;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::BTreeMap;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct ServiceCapabilities {
    pub service: String,
    pub display_name: String,
    pub surface: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub gateway_kind: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub broker_hosts: Vec<String>,
    /// Inputs credential verification needs besides the credential.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub credential_verification_inputs: Vec<String>,
    pub scope_types: Vec<String>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub resource_scopes: BTreeMap<String, ResourceScopeCapabilities>,
    pub actions: Vec<ActionCapabilities>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct ResourceScopeCapabilities {
    pub resource_type: ResourceType,
    pub selectors: Vec<String>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum UpstreamResourceOwnership {
    ActingUser,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct ActionCapabilities {
    pub action: String,
    /// True only when the backend explicitly classifies this action as read-only.
    pub read_only: bool,
    pub description: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub documentation: Option<Value>,
    pub required_scope_types: Vec<String>,
    pub credential_modes: Vec<String>,
    #[serde(default)]
    pub lookup_required: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub upstream_resource_ownership: Option<UpstreamResourceOwnership>,
    pub input_schema: Value,
}
