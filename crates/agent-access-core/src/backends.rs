//! The backends a broker build links, and the `[providers]` tables that
//! configure them.
use agent_access_provider::{
    BackendConfig, BackendRegistration, GIT_REPOSITORY_RESOURCE, OAuthDialectRegistration,
    ResourceTypeDescriptor, ResourceTypeRegistry, is_service_name,
};
use serde::de::{Deserializer as _, MapAccess, Visitor};
use std::any::Any;
use std::collections::BTreeMap;
use std::fmt;
use std::sync::Arc;
use toml::de::{DeValue, ValueDeserializer};

/// Resource types the broker itself defines, independent of any backend.
fn host_resource_types() -> [&'static ResourceTypeDescriptor; 2] {
    [
        &GIT_REPOSITORY_RESOURCE,
        &crate::oauth_records::OAUTH_COLLECTION_RESOURCE,
    ]
}

/// OAuth dialects the broker itself provides.
fn host_oauth_dialects() -> [&'static OAuthDialectRegistration; 1] {
    [&crate::oauth::STUB_OAUTH_DIALECT]
}

/// The backends and OAuth dialects this build can configure, and every
/// resource type they and the broker define. Built once by the broker binary.
#[derive(Debug)]
pub struct BackendRegistry {
    registrations: Vec<&'static BackendRegistration>,
    resource_types: ResourceTypeRegistry,
    oauth_dialects: Vec<&'static OAuthDialectRegistration>,
    imported_adapters: Vec<&'static dyn agent_access_provider::ImportedAdapter>,
}

impl BackendRegistry {
    pub fn new(
        registrations: impl IntoIterator<Item = &'static BackendRegistration>,
    ) -> Result<Self, Vec<String>> {
        let registrations = registrations.into_iter().collect::<Vec<_>>();
        let mut errors = Vec::new();
        let mut kinds = BTreeMap::new();
        for registration in &registrations {
            if !is_service_name(registration.kind) {
                errors.push(format!(
                    "backend kind {} is not a valid service name",
                    registration.kind
                ));
            }
            if kinds.insert(registration.kind, ()).is_some() {
                errors.push(format!(
                    "backend kind {} is registered more than once",
                    registration.kind
                ));
            }
        }
        let [git, oauth] = host_resource_types();
        let types = std::iter::once(git)
            .chain(
                registrations
                    .iter()
                    .flat_map(|registration| registration.resource_types.iter().copied()),
            )
            .chain(std::iter::once(oauth));
        let resource_types = ResourceTypeRegistry::new(types).unwrap_or_else(|type_errors| {
            errors.extend(type_errors);
            ResourceTypeRegistry::new(host_resource_types()).expect("host resource types are valid")
        });
        if errors.is_empty() {
            Ok(Self {
                registrations,
                resource_types,
                oauth_dialects: host_oauth_dialects().to_vec(),
                imported_adapters: Vec::new(),
            })
        } else {
            Err(errors)
        }
    }

    pub fn with_imported_adapters(
        mut self,
        adapters: impl IntoIterator<Item = &'static dyn agent_access_provider::ImportedAdapter>,
    ) -> Result<Self, Vec<String>> {
        for adapter in adapters {
            if !is_service_name(adapter.kind()) || self.imported_adapter(adapter.kind()).is_some() {
                return Err(vec![
                    "import adapter kind is invalid or registered more than once".into(),
                ]);
            }
            self.imported_adapters.push(adapter);
        }
        Ok(self)
    }

    pub fn imported_adapter(
        &self,
        kind: &str,
    ) -> Option<&'static dyn agent_access_provider::ImportedAdapter> {
        self.imported_adapters
            .iter()
            .copied()
            .find(|adapter| adapter.kind() == kind)
    }

    /// Adds OAuth dialects linked outside core, selectable by a
    /// registration's `adapter`.
    pub fn with_oauth_dialects(
        mut self,
        dialects: impl IntoIterator<Item = &'static OAuthDialectRegistration>,
    ) -> Result<Self, Vec<String>> {
        let mut errors = Vec::new();
        for dialect in dialects {
            if !is_service_name(dialect.id) {
                errors.push(format!(
                    "OAuth dialect {} is not a valid identifier",
                    dialect.id
                ));
            } else if self.oauth_dialect(dialect.id).is_some() {
                errors.push(format!(
                    "OAuth dialect {} is registered more than once",
                    dialect.id
                ));
            } else {
                self.oauth_dialects.push(dialect);
            }
        }
        if errors.is_empty() {
            Ok(self)
        } else {
            Err(errors)
        }
    }

    pub fn oauth_dialect(&self, id: &str) -> Option<&'static OAuthDialectRegistration> {
        self.oauth_dialects
            .iter()
            .copied()
            .find(|dialect| dialect.id == id)
    }

    pub fn oauth_dialect_ids(&self) -> impl Iterator<Item = &'static str> + '_ {
        self.oauth_dialects.iter().map(|dialect| dialect.id)
    }

    /// A registry with no backends: only the broker's own resource types.
    pub fn empty() -> Self {
        Self::new([]).expect("the empty backend registry is valid")
    }

    pub fn get(&self, kind: &str) -> Option<&'static BackendRegistration> {
        self.registrations
            .iter()
            .copied()
            .find(|registration| registration.kind == kind)
    }

    pub fn registrations(&self) -> impl Iterator<Item = &'static BackendRegistration> + '_ {
        self.registrations.iter().copied()
    }

    pub fn resource_owner(
        &self,
        resource_type: &agent_access_provider::ResourceType,
    ) -> Option<&'static str> {
        self.registrations()
            .find(|registration| {
                registration
                    .resource_types
                    .iter()
                    .any(|descriptor| &descriptor.id == resource_type)
            })
            .map(|registration| registration.kind)
    }

    pub fn resource_types(&self) -> &ResourceTypeRegistry {
        &self.resource_types
    }

    /// Parses the document's `[providers]` table through each backend's
    /// strict parser. Errors keep the document position of the offending
    /// table or field.
    pub(crate) fn parse_providers(
        self: &Arc<Self>,
        providers: toml::Spanned<DeValue<'_>>,
        raw: &str,
    ) -> Result<ProvidersConfig, toml::de::Error> {
        let with_input = |mut error: toml::de::Error| {
            error.set_input(Some(raw));
            error
        };
        let span = providers.span();
        let tables = match providers.into_inner() {
            DeValue::Table(tables) => tables,
            other => {
                return Err(with_input(rejection(
                    toml::Spanned::new(span, other),
                    Rejection::NotATable("a table of provider configurations"),
                )));
            }
        };
        let mut configured = ProvidersConfig::new(Arc::clone(self));
        for (kind, table) in tables {
            let kind = kind.into_inner();
            let Some(registration) = self.get(&kind) else {
                let expected = self.registrations().map(|r| r.kind).collect::<Vec<_>>();
                return Err(with_input(rejection(
                    table,
                    Rejection::UnknownBackend {
                        kind: &kind,
                        expected: &expected,
                    },
                )));
            };
            if !matches!(table.get_ref(), DeValue::Table(_)) {
                return Err(with_input(rejection(
                    table,
                    Rejection::NotATable("a provider configuration table"),
                )));
            }
            let config =
                (registration.parse)(ValueDeserializer::from(table)).map_err(with_input)?;
            debug_assert_eq!(
                config.kind(),
                registration.kind,
                "a backend parser must produce its own kind"
            );
            configured
                .backends
                .insert(kind.into_owned(), Arc::from(config));
        }
        Ok(configured)
    }
}

/// Why a `[providers]` value is rejected before any backend parses it.
enum Rejection<'a> {
    NotATable(&'static str),
    UnknownBackend {
        kind: &'a str,
        expected: &'a [&'static str],
    },
}

impl Rejection<'_> {
    /// What the value should have been, for toml's invalid-type messages.
    fn expecting(&self) -> &'static str {
        match self {
            Self::NotATable(expected) => expected,
            Self::UnknownBackend { .. } => "a provider this broker supports",
        }
    }

    /// The message for a table (or a toml date-time, which also arrives as
    /// a map).
    fn map_message(&self) -> String {
        match self {
            Self::NotATable(expected) => format!("expected {expected}"),
            Self::UnknownBackend { kind, expected } => {
                let expected = expected
                    .iter()
                    .map(|kind| format!("`{kind}`"))
                    .collect::<Vec<_>>();
                if expected.is_empty() {
                    format!("unknown provider `{kind}`; this broker registers no providers")
                } else {
                    format!(
                        "unknown provider `{kind}`, expected one of {}",
                        expected.join(", ")
                    )
                }
            }
        }
    }
}

/// An error positioned at `value` in the document. Deserializing through a
/// visitor that accepts nothing lets toml attach the value's span.
fn rejection(value: toml::Spanned<DeValue<'_>>, rejection: Rejection<'_>) -> toml::de::Error {
    let visitor = RejectingVisitor {
        expecting: rejection.expecting(),
        map_message: rejection.map_message(),
    };
    let fallback = visitor.map_message.clone();
    match ValueDeserializer::from(value).deserialize_any(visitor) {
        Err(error) => error,
        Ok(()) => serde::de::Error::custom(fallback),
    }
}

struct RejectingVisitor {
    expecting: &'static str,
    map_message: String,
}

impl<'de> Visitor<'de> for RejectingVisitor {
    type Value = ();

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.expecting)
    }

    fn visit_map<A: MapAccess<'de>>(self, _map: A) -> Result<(), A::Error> {
        Err(serde::de::Error::custom(self.map_message))
    }
}

/// `[providers.<kind>]` tables resolved against the backend registry that
/// parsed them.
#[derive(Clone, Debug)]
pub struct ProvidersConfig {
    registry: Arc<BackendRegistry>,
    backends: BTreeMap<String, Arc<dyn BackendConfig>>,
}

impl Default for ProvidersConfig {
    fn default() -> Self {
        Self::new(Arc::new(BackendRegistry::empty()))
    }
}

impl ProvidersConfig {
    pub fn new(registry: Arc<BackendRegistry>) -> Self {
        Self {
            registry,
            backends: BTreeMap::new(),
        }
    }

    pub fn registry(&self) -> &Arc<BackendRegistry> {
        &self.registry
    }

    /// Adds or replaces the configuration for `config.kind()`.
    pub fn insert(&mut self, config: impl BackendConfig) {
        self.backends
            .insert(config.kind().to_string(), Arc::new(config));
    }

    pub fn with(mut self, config: impl BackendConfig) -> Self {
        self.insert(config);
        self
    }

    pub fn remove(&mut self, kind: &str) -> Option<Arc<dyn BackendConfig>> {
        self.backends.remove(kind)
    }

    pub fn get_kind(&self, kind: &str) -> Option<&dyn BackendConfig> {
        self.backends.get(kind).map(Arc::as_ref)
    }

    /// The configuration of the backend whose parsed type is `T`.
    pub fn get<T: BackendConfig>(&self) -> Option<&T> {
        self.backends
            .values()
            .find_map(|config| (config.as_ref() as &dyn Any).downcast_ref::<T>())
    }

    /// Mutable access to the configuration whose parsed type is `T`. A
    /// configuration shared with clones of this one is copied first.
    pub fn get_mut<T: BackendConfig + Clone>(&mut self) -> Option<&mut T> {
        let config = self
            .backends
            .values_mut()
            .find(|config| (config.as_ref() as &dyn Any).is::<T>())?;
        if Arc::get_mut(config).is_none() {
            let copy = (config.as_ref() as &dyn Any).downcast_ref::<T>()?.clone();
            *config = Arc::new(copy);
        }
        (Arc::get_mut(config)? as &mut dyn Any).downcast_mut::<T>()
    }

    pub fn is_empty(&self) -> bool {
        self.backends.is_empty()
    }

    /// Configured backends in registration order; kinds the registry does
    /// not know (only possible for programmatic configurations, and
    /// rejected by validation) come last.
    pub fn iter(&self) -> impl Iterator<Item = &dyn BackendConfig> + '_ {
        let registered = self
            .registry
            .registrations()
            .filter_map(|registration| self.get_kind(registration.kind));
        let unregistered = self
            .backends
            .iter()
            .filter(|(kind, _)| self.registry.get(kind).is_none())
            .map(|(_, config)| config.as_ref());
        registered.chain(unregistered)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    static SECOND_STUB: OAuthDialectRegistration = OAuthDialectRegistration {
        id: "stub",
        development_only: true,
        dialect: crate::oauth::STUB_OAUTH_DIALECT.dialect,
    };
    static INVALID: OAuthDialectRegistration = OAuthDialectRegistration {
        id: "Not A Name",
        development_only: false,
        dialect: crate::oauth::STUB_OAUTH_DIALECT.dialect,
    };

    #[test]
    fn oauth_dialects_include_the_stub_and_reject_conflicts() {
        let registry = BackendRegistry::empty();
        assert_eq!(registry.oauth_dialect_ids().collect::<Vec<_>>(), ["stub"]);
        assert!(registry.oauth_dialect("stub").is_some());
        assert!(registry.oauth_dialect("outlook").is_none());
        let errors = BackendRegistry::empty()
            .with_oauth_dialects([&SECOND_STUB, &INVALID])
            .unwrap_err();
        assert_eq!(
            errors,
            [
                "OAuth dialect stub is registered more than once",
                "OAuth dialect Not A Name is not a valid identifier",
            ]
        );
    }
}
