//! Helpers for tests in this and dependent crates.

use crate::{AuditQueryLimits, AuditStoreType};
use agent_access_provider::{
    BackendConfig, BuildContext, ProviderBuildError, ServiceDescriptor, ServiceProvider,
};
use serde_json::Value;
use std::collections::BTreeMap;
use std::fmt;
use std::path::Path;
use std::sync::Arc;

type ProviderFixtureFactory =
    Arc<dyn Fn(&ProviderFixtureContext<'_>) -> ServiceProvider + Send + Sync>;

/// Provider instances that a test fixture supplies in place of the ones that
/// selected, configured native registrations would build. A runtime asks the
/// fixture once for every generation it constructs, including reload
/// candidates; configuration parsing and validation, admission, state locks
/// and generation ownership are unchanged. Only test-support builds contain
/// this hook, and only [`crate::BrokerRuntime::new_with_provider_fixtures`]
/// installs it.
#[derive(Clone, Default)]
pub struct ProviderFixtures {
    factories: BTreeMap<String, ProviderFixtureFactory>,
}

impl ProviderFixtures {
    pub fn new() -> Self {
        Self::default()
    }

    /// Supplies the provider of the native kind `kind` for every generation
    /// that configures it. The provider must serve the service `kind`.
    /// Returns `false`, keeping the earlier factory, when `kind` already has
    /// one.
    pub fn insert(
        &mut self,
        kind: impl Into<String>,
        factory: impl Fn(&ProviderFixtureContext<'_>) -> ServiceProvider + Send + Sync + 'static,
    ) -> bool {
        match self.factories.entry(kind.into()) {
            std::collections::btree_map::Entry::Occupied(_) => false,
            std::collections::btree_map::Entry::Vacant(entry) => {
                entry.insert(Arc::new(factory));
                true
            }
        }
    }

    pub fn is_empty(&self) -> bool {
        self.factories.is_empty()
    }

    /// The native kinds this fixture supplies, in name order.
    pub fn kinds(&self) -> impl Iterator<Item = &str> + '_ {
        self.factories.keys().map(String::as_str)
    }

    pub(crate) fn build(
        &self,
        kind: &str,
        context: &ProviderFixtureContext<'_>,
    ) -> Option<ServiceProvider> {
        self.factories.get(kind).map(|factory| factory(context))
    }
}

impl fmt::Debug for ProviderFixtures {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ProviderFixtures")
            .field("kinds", &self.factories.keys().collect::<Vec<_>>())
            .finish()
    }
}

/// What a provider fixture receives while a generation is constructed: the
/// service descriptor its configuration declares and the build context the
/// registration's own provider would have been built with.
pub struct ProviderFixtureContext<'a> {
    descriptor: &'a ServiceDescriptor,
    build: &'a BuildContext<'a>,
    backend: &'a dyn BackendConfig,
}

impl<'a> ProviderFixtureContext<'a> {
    pub(crate) fn new(
        descriptor: &'a ServiceDescriptor,
        build: &'a BuildContext<'a>,
        backend: &'a dyn BackendConfig,
    ) -> Self {
        Self {
            descriptor,
            build,
            backend,
        }
    }

    /// The provider the configured registration builds itself, for fixtures
    /// that serve it in some generations or wrap it.
    pub fn registered_provider(&self) -> Result<ServiceProvider, ProviderBuildError> {
        Ok(ServiceProvider::new(
            self.descriptor.clone(),
            self.backend.build(self.build)?,
        ))
    }

    /// The descriptor of the configured service.
    pub fn descriptor(&self) -> &'a ServiceDescriptor {
        self.descriptor
    }

    /// The generation's build context: limits, upstream client factory,
    /// attribution and signing key.
    pub fn build_context(&self) -> &'a BuildContext<'a> {
        self.build
    }
}

/// Overrides the reader-pool limits (connections, waiting queries, deadline)
/// of the SQLite audit database at `path`, for runtimes built afterwards.
pub fn override_audit_query_limits(path: &Path, limits: AuditQueryLimits) {
    crate::runtime::override_audit_query_limits(path, limits);
}

/// Every record in the audit store of type `kind` at `path`, in write order.
/// A store that does not exist yet has no records. For JSONL this reads the
/// live file only, not rotated files; for SQLite it reads `record_json` in
/// insertion order.
pub fn read_audit_records(kind: AuditStoreType, path: &Path) -> Vec<Value> {
    match kind {
        AuditStoreType::Jsonl => read_jsonl_audit_records(path),
        AuditStoreType::Sqlite => read_sqlite_audit_records(path),
    }
}

/// The records in the audit store of type `kind` at `path` as JSONL text:
/// the file itself for JSONL, and each stored `record_json` (exactly the line
/// JSONL would write) followed by a newline for SQLite.
pub fn read_audit_text(kind: AuditStoreType, path: &Path) -> String {
    match kind {
        AuditStoreType::Jsonl => match std::fs::read_to_string(path) {
            Ok(contents) => contents,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => String::new(),
            Err(error) => panic!("failed to read audit file {}: {error}", path.display()),
        },
        AuditStoreType::Sqlite => read_sqlite_record_json(path)
            .into_iter()
            .map(|json| json + "\n")
            .collect(),
    }
}

fn read_jsonl_audit_records(path: &Path) -> Vec<Value> {
    let contents = match std::fs::read_to_string(path) {
        Ok(contents) => contents,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Vec::new(),
        Err(error) => panic!("failed to read audit file {}: {error}", path.display()),
    };
    contents
        .lines()
        .map(|line| {
            serde_json::from_str(line).unwrap_or_else(|error| {
                panic!("invalid audit line in {}: {error}: {line}", path.display())
            })
        })
        .collect()
}

fn read_sqlite_audit_records(path: &Path) -> Vec<Value> {
    read_sqlite_record_json(path)
        .into_iter()
        .map(|json| {
            serde_json::from_str(&json).unwrap_or_else(|error| {
                panic!(
                    "invalid audit record in {}: {error}: {json}",
                    path.display()
                )
            })
        })
        .collect()
}

fn read_sqlite_record_json(path: &Path) -> Vec<String> {
    if !path.exists() {
        return Vec::new();
    }
    let conn = rusqlite::Connection::open_with_flags(
        path,
        rusqlite::OpenFlags::SQLITE_OPEN_READ_WRITE | rusqlite::OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )
    .unwrap_or_else(|error| panic!("failed to open audit database {}: {error}", path.display()));
    conn.busy_timeout(std::time::Duration::from_secs(5))
        .unwrap();
    let mut statement = match conn.prepare("SELECT record_json FROM audit_events ORDER BY id") {
        Ok(statement) => statement,
        // A database the broker has not initialized yet has no records.
        Err(error) if error.to_string().contains("no such table") => return Vec::new(),
        Err(error) => panic!("failed to read audit database {}: {error}", path.display()),
    };
    statement
        .query_map([], |row| row.get::<_, String>(0))
        .unwrap()
        .collect::<Result<Vec<_>, _>>()
        .unwrap()
}
