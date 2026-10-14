//! Delegated credentials: authority a person granted the broker upstream,
//! such as an OAuth connection, lent to one invocation. The runtime acquires
//! the credential after policy admits the invocation and confirms it is still
//! current immediately before dispatch; the provider only presents it.
use crate::authorization::Material;
use crate::{CredentialPlacement, CredentialPlacementError, ProviderError, UpstreamAuthorization};
use async_trait::async_trait;
use std::sync::Arc;

/// The access a delegated credential currently grants. Like static
/// credential material it is read-only: a lease creates it, and providers
/// read its target, audience, version and expiry through the accessors. They
/// never read the token: they obtain an [`UpstreamAuthorization`] with
/// [`Self::authorization`] or [`Self::authorization_as`] and hand it to the
/// upstream client's send methods. The token never appears in Debug output.
/// Only with the `test-support` feature does access compare (`==`), with the
/// token compared in constant time over digests.
#[non_exhaustive]
#[derive(Clone)]
pub struct DelegatedAccess {
    token: String,
    target: String,
    audience: String,
    version: String,
    expires_at: i64,
}

impl DelegatedAccess {
    /// Access presenting the bearer `token`, bound to the upstream resource
    /// `target` and issued for the API `audience`. `version` identifies this
    /// access, so renewed access has a new one; the token is no longer valid
    /// after `expires_at` (Unix seconds).
    pub fn new(
        token: impl Into<String>,
        target: impl Into<String>,
        audience: impl Into<String>,
        version: impl Into<String>,
        expires_at: i64,
    ) -> Self {
        Self {
            token: token.into(),
            target: target.into(),
            audience: audience.into(),
            version: version.into(),
            expires_at,
        }
    }

    /// The token as `Authorization: Bearer <token>`, presented as issued,
    /// without further checks.
    pub fn authorization(&self) -> UpstreamAuthorization {
        Material::Token(&self.token).authorization()
    }

    /// The token presented in `placement`, after the placement's checks of
    /// the token. Delegated access is a token, so
    /// [`CredentialPlacement::basic`] fails with
    /// [`CredentialPlacementError::KindMismatch`].
    pub fn authorization_as(
        &self,
        placement: &CredentialPlacement,
    ) -> Result<UpstreamAuthorization, CredentialPlacementError> {
        Material::Token(&self.token).placed(placement)
    }

    /// The upstream resource the access is bound to.
    pub fn target(&self) -> &str {
        &self.target
    }

    /// The API audience the token was issued for.
    pub fn audience(&self) -> &str {
        &self.audience
    }

    /// Identifies this access; renewed access has a new version.
    pub fn version(&self) -> &str {
        &self.version
    }

    /// Unix seconds after which the token is no longer valid.
    pub fn expires_at(&self) -> i64 {
        self.expires_at
    }
}

/// Test support only: equal when every field is. The token is compared in
/// constant time over digests, and the comparison never stops early at it.
#[cfg(any(test, feature = "test-support"))]
impl PartialEq for DelegatedAccess {
    fn eq(&self, other: &Self) -> bool {
        let token = crate::authorization::digests_equal(
            &Material::Token(&self.token).digest(),
            &Material::Token(&other.token).digest(),
        );
        token
            & (self.target == other.target)
            & (self.audience == other.audience)
            & (self.version == other.version)
            & (self.expires_at == other.expires_at)
    }
}

#[cfg(any(test, feature = "test-support"))]
impl Eq for DelegatedAccess {}

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

/// Why [`DelegatedCredential::revalidated_access_for`] or
/// [`DelegatedCredential::access_for`] returned no access. A provider returns
/// a revalidation failure unchanged and reports a mismatch as its own
/// failure, usually `credential_invalid`.
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum DelegatedAccessError {
    /// The lease could not be revalidated. This is the host's failure, such
    /// as a revoked connection or a refresh already in progress; return it
    /// unchanged.
    #[error("delegated access could not be revalidated")]
    Revalidation(ProviderError),
    /// The access is bound to another upstream target or issued for another
    /// audience than the provider requires.
    #[error("delegated access is bound to another target or audience")]
    Mismatch,
}

/// A delegated credential lent to one invocation. Clones share the lease.
#[derive(Clone)]
pub struct DelegatedCredential(Arc<dyn DelegatedLease>);

impl DelegatedCredential {
    /// The host lends a lease with [`crate::host::delegated_credential`].
    pub(crate) fn new(lease: Arc<dyn DelegatedLease>) -> Self {
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

    /// Revalidates the lease, then returns its access only when that access
    /// is bound to exactly `target` and issued for exactly `audience`. Call
    /// it before each upstream request, including each page or detail call
    /// of one invocation, and present only the access it returns.
    pub async fn revalidated_access_for(
        &self,
        target: &str,
        audience: &str,
    ) -> Result<DelegatedAccess, DelegatedAccessError> {
        self.revalidate()
            .await
            .map_err(DelegatedAccessError::Revalidation)?;
        self.access_for(target, audience)
    }

    /// The access the invocation holds now, only when it is bound to
    /// exactly `target` and issued for exactly `audience`; otherwise
    /// [`DelegatedAccessError::Mismatch`]. It does not revalidate the lease,
    /// so it suits checks that send nothing upstream, such as comparing a
    /// continuation's binding with the selected lease; use
    /// [`Self::revalidated_access_for`] before an upstream request.
    pub fn access_for(
        &self,
        target: &str,
        audience: &str,
    ) -> Result<DelegatedAccess, DelegatedAccessError> {
        let access = self.access();
        if access.target() == target && access.audience() == audience {
            Ok(access)
        } else {
            Err(DelegatedAccessError::Mismatch)
        }
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ReasonCode;
    use crate::test_support::delegated_binding_id;
    use std::sync::atomic::{AtomicUsize, Ordering};

    const TARGET: &str = "https://notes.example.test/";
    const AUDIENCE: &str = "https://notes.example.test/api";

    struct Lease {
        target: &'static str,
        audience: &'static str,
        revoked: bool,
        validations: AtomicUsize,
    }

    #[async_trait]
    impl DelegatedLease for Lease {
        fn access(&self) -> DelegatedAccess {
            DelegatedAccess::new("token", self.target, self.audience, "version-1", i64::MAX)
        }
        fn binding_identity(&self) -> DelegatedBindingId {
            delegated_binding_id("notes")
        }
        async fn revalidate(&self) -> Result<(), ProviderError> {
            self.validations.fetch_add(1, Ordering::SeqCst);
            if self.revoked { Err(revoked()) } else { Ok(()) }
        }
        fn mark_rejected(&self, _: &str) -> Result<(), ProviderError> {
            Ok(())
        }
        async fn recover_after_unauthorized(&self) -> Result<DelegatedAccess, ProviderError> {
            Err(revoked())
        }
    }

    fn revoked() -> ProviderError {
        ProviderError::deny(ReasonCode::CredentialInvalid, "connection revoked")
    }

    fn credential(
        target: &'static str,
        audience: &'static str,
        revoked: bool,
    ) -> (DelegatedCredential, Arc<Lease>) {
        let lease = Arc::new(Lease {
            target,
            audience,
            revoked,
            validations: AtomicUsize::new(0),
        });
        (DelegatedCredential::new(lease.clone()), lease)
    }

    #[tokio::test]
    async fn revalidated_access_is_returned_only_for_the_exact_target_and_audience() {
        let (exact, lease) = credential(TARGET, AUDIENCE, false);
        assert_eq!(
            exact.revalidated_access_for(TARGET, AUDIENCE).await,
            Ok(exact.access())
        );
        assert_eq!(lease.validations.load(Ordering::SeqCst), 1);
        for (target, audience) in [
            ("https://other.example.test/", AUDIENCE),
            (TARGET, "https://other.example.test/api"),
            ("https://notes.example.test", AUDIENCE),
            (TARGET, "https://notes.example.test/api/"),
        ] {
            let (other, lease) = credential(target, audience, false);
            assert_eq!(
                other.revalidated_access_for(TARGET, AUDIENCE).await,
                Err(DelegatedAccessError::Mismatch),
                "{target} {audience}"
            );
            assert_eq!(lease.validations.load(Ordering::SeqCst), 1);
        }
    }

    /// A revalidation failure is returned unchanged, before the access is
    /// compared.
    #[tokio::test]
    async fn revalidation_failures_come_first_and_unchanged() {
        for target in [TARGET, "https://other.example.test/"] {
            let (credential, _) = credential(target, AUDIENCE, true);
            assert_eq!(
                credential.revalidated_access_for(TARGET, AUDIENCE).await,
                Err(DelegatedAccessError::Revalidation(revoked()))
            );
        }
    }

    #[test]
    fn delegated_access_presents_its_token_without_revealing_it() {
        let access = DelegatedAccess::new("delegated-secret", TARGET, AUDIENCE, "v1", i64::MAX);
        let header = |authorization: UpstreamAuthorization| {
            let request = crate::host::authorize_host_request(
                reqwest::Client::new().get(TARGET),
                &authorization,
            )
            .build()
            .unwrap();
            let value = request.headers()[reqwest::header::AUTHORIZATION].clone();
            assert!(value.is_sensitive());
            value
        };
        assert_eq!(header(access.authorization()), "Bearer delegated-secret");
        assert_eq!(
            header(
                access
                    .authorization_as(&CredentialPlacement::bearer())
                    .unwrap()
            ),
            "Bearer delegated-secret"
        );
        assert_eq!(
            access
                .authorization_as(&CredentialPlacement::basic())
                .unwrap_err(),
            CredentialPlacementError::KindMismatch
        );
        let rendered = format!("{access:?} {:?}", access.authorization());
        assert!(!rendered.contains("delegated-secret"), "{rendered}");
        let with_token =
            |token: &str| DelegatedAccess::new(token, TARGET, AUDIENCE, "v1", i64::MAX);
        assert_eq!(access, with_token("delegated-secret"));
        assert_ne!(access, with_token("delegated-secreT"));
        assert_ne!(
            access,
            DelegatedAccess::new("delegated-secret", TARGET, AUDIENCE, "v2", i64::MAX)
        );
    }

    #[test]
    fn access_for_compares_without_revalidating() {
        let (exact, lease) = credential(TARGET, AUDIENCE, true);
        assert_eq!(exact.access_for(TARGET, AUDIENCE), Ok(exact.access()));
        assert_eq!(
            exact.access_for(TARGET, "https://other.example.test/api"),
            Err(DelegatedAccessError::Mismatch)
        );
        assert_eq!(lease.validations.load(Ordering::SeqCst), 0);
    }
}
