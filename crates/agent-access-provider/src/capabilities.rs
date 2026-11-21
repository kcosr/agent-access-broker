//! Wire projection of service descriptors.
use crate::ResourceType;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::BTreeMap;

/// A service as capability discovery projects it from its
/// [`ServiceDescriptor`](crate::ServiceDescriptor).
#[non_exhaustive]
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
    /// Active verification capability, independent of its required inputs.
    pub credential_verification_supported: bool,
    pub scope_types: Vec<String>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub resource_scopes: BTreeMap<String, ResourceScopeCapabilities>,
    pub actions: Vec<ActionCapabilities>,
}

/// One declared matching contract. Containment is never projected as a scalar
/// type or an evidence-free exact/all approximation.
#[non_exhaustive]
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(tag = "matching", rename_all = "snake_case")]
pub enum ResourceScopeCapabilities {
    Scalar {
        #[serde(rename = "resourceType")]
        resource_type: ResourceType,
        selectors: Vec<String>,
    },
    Containment(crate::ContainmentScopeCapabilities),
}

impl ResourceScopeCapabilities {
    pub fn new(resource_type: ResourceType, selectors: Vec<String>) -> Self {
        Self::Scalar {
            resource_type,
            selectors,
        }
    }
    pub fn containment(contract: crate::ContainmentScopeCapabilities) -> Self {
        Self::Containment(contract)
    }
    pub fn as_scalar(&self) -> Option<(&ResourceType, &[String])> {
        match self {
            Self::Scalar {
                resource_type,
                selectors,
            } => Some((resource_type, selectors)),
            Self::Containment(_) => None,
        }
    }
    pub fn as_containment(&self) -> Option<&crate::ContainmentScopeCapabilities> {
        match self {
            Self::Containment(contract) => Some(contract),
            Self::Scalar { .. } => None,
        }
    }
    pub fn resource_types(&self) -> Vec<&ResourceType> {
        match self {
            Self::Scalar { resource_type, .. } => vec![resource_type],
            Self::Containment(contract) => contract.selectors_by_type.keys().collect(),
        }
    }
    pub fn accepts_resource_type(&self, resource_type: &ResourceType) -> bool {
        match self {
            Self::Scalar {
                resource_type: own, ..
            } => own == resource_type,
            Self::Containment(contract) => contract.selectors_by_type.contains_key(resource_type),
        }
    }
}

#[non_exhaustive]
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum UpstreamResourceOwnership {
    ActingUser,
}

/// An action as capability discovery projects it from its
/// [`ActionDescriptor`](crate::ActionDescriptor).
#[non_exhaustive]
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
    /// Explicit live enumeration, with authority independent of other actions.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub listing_of: Option<ResourceType>,
    /// Direct companion reads for optional content, checked at admission.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub companion_read_actions: Vec<String>,
    pub credential_modes: Vec<String>,
    #[serde(default)]
    pub lookup_required: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub upstream_resource_ownership: Option<UpstreamResourceOwnership>,
    pub input_schema: Value,
}
