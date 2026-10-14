//! Module metadata: the package a registration is declared in.

/// The Cargo package that declares a native, OAuth or import registration,
/// or the SDK itself ([`SDK_PACKAGE`]).
///
/// Capture it in the declaring crate with [`module_metadata!`](crate::module_metadata),
/// which reads that package's name and version at compile time. The assembly
/// supplies source provenance separately; this records only what was linked.
/// Several registrations from one package are roles of the same module.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ModuleMetadata {
    crate_name: &'static str,
    crate_version: &'static str,
}

impl ModuleMetadata {
    #[doc(hidden)]
    pub const fn __from_package(crate_name: &'static str, crate_version: &'static str) -> Self {
        Self {
            crate_name,
            crate_version,
        }
    }

    /// The Cargo package name, such as `agent-access-cloudbees-ci`.
    pub const fn crate_name(&self) -> &'static str {
        self.crate_name
    }

    /// The Cargo package version.
    pub const fn crate_version(&self) -> &'static str {
        self.crate_version
    }
}

/// This SDK package as linked, which a host reports next to its own identity
/// and its module inventory.
pub const SDK_PACKAGE: ModuleMetadata = crate::module_metadata!();

/// The [`ModuleMetadata`] of the crate this macro is invoked in.
///
/// ```
/// use agent_access_provider::{ModuleMetadata, module_metadata};
///
/// const MODULE: ModuleMetadata = module_metadata!();
/// assert_eq!(MODULE.crate_name(), "agent-access-provider");
/// ```
#[macro_export]
macro_rules! module_metadata {
    () => {
        $crate::ModuleMetadata::__from_package(
            ::core::env!("CARGO_PKG_NAME"),
            ::core::env!("CARGO_PKG_VERSION"),
        )
    };
}

#[cfg(test)]
mod tests {
    #[test]
    fn module_metadata_names_the_invoking_package() {
        let module = crate::module_metadata!();
        assert_eq!(module.crate_name(), "agent-access-provider");
        assert_eq!(module.crate_version(), env!("CARGO_PKG_VERSION"));
        assert_eq!(super::SDK_PACKAGE, module);
    }
}
