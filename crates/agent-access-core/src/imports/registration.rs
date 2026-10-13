//! Opaque import adapter selections and their import-authentication role.
use super::ImportedAdapter;
use agent_access_provider::{ModuleMetadata, OAuthDialectRegistration, OAuthRegistrationConfig};
use std::fmt;

/// The OAuth companion that authenticates an import kind's personal
/// connections. Selecting the import selects this dialect; core derives
/// which registrations an import may bind from this association, never from
/// a dialect ID.
#[derive(Clone, Copy)]
pub struct ImportOAuthCompanion {
    /// The companion dialect, registered together with the import adapter.
    pub dialect: &'static OAuthDialectRegistration,
    /// The resource an operator registration of this dialect approves, after
    /// the dialect's own validation; `None` for a registration it rejects.
    pub approved_resource: fn(&OAuthRegistrationConfig) -> Option<String>,
}

impl fmt::Debug for ImportOAuthCompanion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ImportOAuthCompanion")
            .field("dialect", &self.dialect.id())
            .finish_non_exhaustive()
    }
}

/// A shipped import adapter as an assembly selects it, with the OAuth
/// companion, if any, that authenticates its imports. Only adapter crates
/// construct one, through [`imported_adapter_registration`].
#[derive(Clone, Copy)]
pub struct ImportedAdapterRegistration {
    module: ModuleMetadata,
    adapter: &'static dyn ImportedAdapter,
    authentication: Option<ImportOAuthCompanion>,
}

impl ImportedAdapterRegistration {
    /// The package that declares this adapter.
    pub fn module(&self) -> ModuleMetadata {
        self.module
    }

    /// The import kind, `adapterKind` in imported definitions.
    pub fn kind(&self) -> &'static str {
        self.adapter.kind()
    }

    pub(crate) fn adapter(&self) -> &'static dyn ImportedAdapter {
        self.adapter
    }

    pub(crate) fn authentication(&self) -> Option<&ImportOAuthCompanion> {
        self.authentication.as_ref()
    }
}

impl fmt::Debug for ImportedAdapterRegistration {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ImportedAdapterRegistration")
            .field("module", &self.module)
            .field("kind", &self.kind())
            .field("authentication", &self.authentication)
            .finish()
    }
}

/// Builds the selection for a shipped import adapter, declared by `module`
/// (captured with `agent_access_provider::module_metadata!()` in the adapter
/// crate), and its optional OAuth companion. A free function rather than an
/// inherent constructor, so the registration handle carries no public way to
/// assemble one.
pub fn imported_adapter_registration(
    module: ModuleMetadata,
    adapter: &'static dyn ImportedAdapter,
    authentication: Option<ImportOAuthCompanion>,
) -> ImportedAdapterRegistration {
    ImportedAdapterRegistration {
        module,
        adapter,
        authentication,
    }
}
