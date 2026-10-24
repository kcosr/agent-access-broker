//! How an accepted imported action names resources and which credential
//! modes it supports, as its adapter reads them from the stored definition.
//!
//! Core maps the declaration onto the action's descriptor: a declared
//! resource type becomes a resource scope bound to the Broker type the
//! import's accepted metadata assigns it. For a `command:<name>` import,
//! the declaration also selects who checks the resources:
//!
//! | Declaration | Checked by | Descriptor |
//! | --- | --- | --- |
//! | type with input pointers | the Broker, before dispatch | `scope(type)` |
//! | type without input pointers | the command, from the passed grants | `scope(type)`, separately classified as command-enforced |
//! | no type | the command, from action grants | action-only |
//!
//! MCP and OpenAPI imports declare no resource authority or live listing:
//! their actions are action-only and use every bound credential mode. Every
//! imported descriptor keeps native search enforcement unset; command
//! classification reads this accepted declaration.
use super::ImportedCredentialMode;

/// The resource and credential declaration of one accepted imported action.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ImportedActionAuthority {
    /// The resources the action names; `None` for an action without a
    /// resource type.
    pub resources: Option<ImportedActionResources>,
    /// The credential modes the action supports, a subset of the import's
    /// declared modes; `None` for every mode the import binds.
    pub credential_modes: Option<Vec<ImportedCredentialMode>>,
    /// Explicit live enumeration of a declared source resource type. Core
    /// maps this to the accepted Broker type; it grants no other action access.
    pub listing_of: Option<String>,
}

/// A declared resource type and the inputs that name its resources.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ImportedActionResources {
    /// The source's type id, such as a command manifest's `resources.type`.
    /// It is the action's resource scope name; the import's accepted
    /// metadata maps it to a Broker resource type.
    pub resource_type: String,
    /// JSON pointers to the required string or string-array inputs that name
    /// the resources. Nonempty: the Broker resolves and checks them before
    /// dispatch. Empty: the import enforces containment from the grants it
    /// is passed.
    pub inputs: Vec<String>,
}

impl ImportedActionResources {
    /// Whether the Broker resolves the resources from the inputs.
    pub fn broker_enforced(&self) -> bool {
        !self.inputs.is_empty()
    }
}
