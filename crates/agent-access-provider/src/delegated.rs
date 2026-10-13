//! Delegated credentials: authority a person granted the broker upstream,
//! such as an OAuth connection, lent to one invocation. The runtime acquires
//! the credential after policy admits the invocation and confirms it is still
//! current immediately before dispatch; the provider only presents it.
use crate::ProviderError;
use async_trait::async_trait;
use std::sync::Arc;

/// The access a delegated credential currently grants.
#[derive(Clone, PartialEq, Eq)]
pub struct DelegatedAccess {
    /// The bearer token to present upstream.
    pub token: String,
    /// The upstream resource the access is bound to.
    pub target: String,
    /// The API audience the token was issued for.
    pub audience: String,
    /// Identifies this access; renewed access has a new version.
    pub version: String,
    /// Unix seconds after which the token is no longer valid.
    pub expires_at: i64,
}

impl std::fmt::Debug for DelegatedAccess {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("DelegatedAccess")
            .field("target", &self.target)
            .field("audience", &self.audience)
            .field("version", &self.version)
            .field("expires_at", &self.expires_at)
            .finish_non_exhaustive()
    }
}

/// Opaque identity of the delegated binding a lease was acquired under: the
/// service, owner, OAuth registration, permission profile, configuration,
/// connection slot generation and connection. Routine refresh keeps it; new
/// consent, replacement and reconnecting change it. It supports equality and
/// a digest for binding signed tokens to the binding, not store access, and
/// never shows its value in Debug output.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct DelegatedBindingId([u8; 32]);

impl DelegatedBindingId {
    pub(crate) fn from_digest(digest: [u8; 32]) -> Self {
        Self(digest)
    }

    pub fn digest(&self) -> &[u8; 32] {
        &self.0
    }
}

impl std::fmt::Debug for DelegatedBindingId {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("DelegatedBindingId(<redacted>)")
    }
}

/// The host side of a delegated credential, lent to one invocation.
#[async_trait]
pub trait DelegatedLease: Send + Sync + 'static {
    /// The access the invocation holds now.
    fn access(&self) -> DelegatedAccess;

    /// The binding the lease was acquired under. It never changes for the
    /// lease's lifetime: access that would belong to another binding fails
    /// instead of replacing the held access.
    fn binding_identity(&self) -> DelegatedBindingId;

    /// Confirms the held access is still authorized, renewing it when it has
    /// gone stale. The runtime calls this immediately before dispatch.
    async fn revalidate(&self) -> Result<(), ProviderError>;

    /// Invalidates only the upstream-rejected access version for later calls.
    /// This never refreshes credentials or replays the current request.
    fn mark_rejected(&self, version: &str) -> Result<(), ProviderError>;

    /// Replaces access the upstream rejected as unauthorized. An invocation
    /// may recover once; later calls fail.
    async fn recover_after_unauthorized(&self) -> Result<DelegatedAccess, ProviderError>;
}

/// A delegated credential lent to one invocation. Clones share the lease.
#[derive(Clone)]
pub struct DelegatedCredential(Arc<dyn DelegatedLease>);

impl DelegatedCredential {
    pub fn new(lease: Arc<dyn DelegatedLease>) -> Self {
        Self(lease)
    }

    pub fn access(&self) -> DelegatedAccess {
        self.0.access()
    }

    pub fn binding_identity(&self) -> DelegatedBindingId {
        self.0.binding_identity()
    }

    pub async fn revalidate(&self) -> Result<(), ProviderError> {
        self.0.revalidate().await
    }

    pub fn mark_rejected(&self, version: &str) -> Result<(), ProviderError> {
        self.0.mark_rejected(version)
    }

    pub async fn recover_after_unauthorized(&self) -> Result<DelegatedAccess, ProviderError> {
        self.0.recover_after_unauthorized().await
    }
}

impl std::fmt::Debug for DelegatedCredential {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.debug_tuple("DelegatedCredential").finish()
    }
}
