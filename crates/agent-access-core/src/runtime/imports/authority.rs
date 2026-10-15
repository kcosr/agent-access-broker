//! Imported action descriptors from the adapter's authority declaration:
//! resource scopes bound to the import's accepted Broker types, who checks
//! them, and per-action credential modes.
use super::*;
use crate::imports::{ImportedActionAuthority, ImportedAdapter, ImportedCredentialMode};

/// The selector forms imported resource types support.
const IMPORTED_SELECTORS: [&str; 2] = ["exact", "all"];

/// The scope of an action whose declaration cannot be read. Its name is
/// outside the manifest type-id grammar, so it never shares a binding with a
/// declared type.
const UNREADABLE_SCOPE: &str = "unresolved-resource";

/// One imported action's scope and credential modes.
pub(super) struct ImportedActionShape {
    /// The resource scope (the declared source type id), its Broker type,
    /// and whether the import enforces it from the passed grants.
    pub scope: Option<ImportedActionScope>,
    pub credential_modes: Vec<&'static str>,
}

pub(super) struct ImportedActionScope {
    pub name: String,
    pub resource_type: ResourceType,
    pub search_contained: bool,
}

fn command_endpoint(definition: &ImportedServiceDefinition) -> bool {
    definition
        .endpoint()
        .is_ok_and(|endpoint| endpoint.form() == ImportEndpointForm::Command)
}

/// The Broker type that `source_type` is accepted under, or the unresolved
/// type when the import accepted none: such a scope authorizes nothing.
fn broker_type(record: &ImportedServiceRecord, source_type: &str) -> ResourceType {
    record
        .accepted_metadata
        .as_ref()
        .and_then(|metadata| {
            metadata
                .resource_types
                .iter()
                .find(|declared| declared.id == source_type)
        })
        .and_then(|declared| ResourceType::new(declared.broker_type.clone()).ok())
        .unwrap_or_else(|| UNRESOLVED_RESOURCE_TYPE.id().clone())
}

/// Maps `definition`'s declaration. Credential modes are the import's
/// declared modes the action supports; acceptance requires one, so an
/// action whose modes the import does not bind keeps its own and no grant
/// can select it.
///
/// An unreadable declaration authorizes nothing, and neither does any
/// action of a command import whose adapter this Broker does not link (the
/// import is unavailable): both bind an unresolved scope, under which every
/// retained grant, with or without resources, stays valid. A command
/// import's unresolved scope is command-enforced, so retained grants mixing
/// modes stay valid too; its boundary is always empty. Other imports declare
/// no resources, so without their adapter they keep the action-only shape.
pub(super) fn action_shape(
    record: &ImportedServiceRecord,
    adapter: Option<&dyn ImportedAdapter>,
    definition: &ImportedActionDefinition,
    declared_modes: &[&'static str],
) -> ImportedActionShape {
    let unresolved = || ImportedActionShape {
        scope: Some(ImportedActionScope {
            name: UNREADABLE_SCOPE.into(),
            resource_type: UNRESOLVED_RESOURCE_TYPE.id().clone(),
            search_contained: command_endpoint(&record.definition),
        }),
        credential_modes: declared_modes.to_vec(),
    };
    let authority = match adapter.map(|adapter| adapter.action_authority(definition)) {
        Some(Ok(authority)) => authority,
        None if !command_endpoint(&record.definition) => ImportedActionAuthority::default(),
        Some(Err(_)) | None => return unresolved(),
    };
    let credential_modes = match &authority.credential_modes {
        None => declared_modes.to_vec(),
        Some(modes) => {
            let supported = modes.iter().map(|mode| mode.as_str()).collect::<Vec<_>>();
            let bound = declared_modes
                .iter()
                .copied()
                .filter(|mode| supported.contains(mode))
                .collect::<Vec<_>>();
            if bound.is_empty() {
                modes
                    .iter()
                    .map(|mode| ImportedCredentialMode::as_str(*mode))
                    .collect()
            } else {
                bound
            }
        }
    };
    ImportedActionShape {
        scope: authority.resources.map(|resources| ImportedActionScope {
            resource_type: broker_type(record, &resources.resource_type),
            search_contained: !resources.broker_enforced(),
            name: resources.resource_type,
        }),
        credential_modes,
    }
}

/// The resource scope binding of `scope`, offering the imported selectors.
pub(super) fn scope_binding(scope: &ImportedActionScope) -> ResourceScopeCapabilities {
    ResourceScopeCapabilities::new(
        scope.resource_type.clone(),
        IMPORTED_SELECTORS
            .iter()
            .map(|kind| (*kind).to_owned())
            .collect(),
    )
}
