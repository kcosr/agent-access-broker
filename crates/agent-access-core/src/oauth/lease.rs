//! An OAuth connection's access lent to one invocation as a delegated
//! credential.
use super::{OAuthBinding, OAuthError, OAuthLease, OAuthManager};
use agent_access_provider::host::{HostPort, delegated_credential, port_failure};
use agent_access_provider::{
    DelegatedAccess, DelegatedBindingId, DelegatedCredential, DelegatedLease, ProviderError,
    ReasonCode, UpstreamRetryAfter, upstream_retry_hint,
};
use async_trait::async_trait;
use serde_json::json;
use sha2::{Digest, Sha256};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

/// Holds the manager of the runtime generation that acquired it, so a lease
/// taken before a reload is judged by the configuration it was issued under.
pub(crate) struct ManagedOAuthLease {
    manager: OAuthManager,
    /// The invoked service, named when its connection's refresh is throttled.
    service: String,
    current: Mutex<OAuthLease>,
    /// Fixed at acquisition; replacement access must belong to it.
    binding: DelegatedBindingId,
    recovered: AtomicBool,
}

impl ManagedOAuthLease {
    /// Acquires the owner's access to `service` through `binding`,
    /// refreshing it when due.
    pub(crate) async fn acquire(
        manager: OAuthManager,
        service: String,
        owner: String,
        binding: OAuthBinding,
    ) -> Result<DelegatedCredential, ProviderError> {
        let lease = manager
            .acquire(&owner, &binding)
            .await
            .map_err(|error| oauth_provider_error(&service, error))?;
        manager
            .validate_lease(&lease)
            .map_err(|error| oauth_provider_error(&service, error))?;
        Ok(delegated_credential(Arc::new(Self {
            manager,
            binding: delegated_binding_identity(&service, &lease),
            service,
            current: Mutex::new(lease),
            recovered: AtomicBool::new(false),
        })))
    }

    fn current(&self) -> OAuthLease {
        self.current
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clone()
    }

    fn replace(&self, lease: OAuthLease) -> Result<(), ProviderError> {
        if delegated_binding_identity(&self.service, &lease) != self.binding {
            return Err(self.error(OAuthError::Stale));
        }
        *self
            .current
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) = lease;
        Ok(())
    }

    fn error(&self, error: OAuthError) -> ProviderError {
        oauth_provider_error(&self.service, error)
    }
}

/// Domain-separated SHA-256 over the length-delimited binding fields of a
/// lease: service, owner, registration, permission profile, configuration
/// fingerprint, slot generation and connection. Token contents, access
/// version and expiry, refresh material and the account subject are excluded,
/// so routine refresh keeps the identity while new consent, replacement and
/// reconnecting change it.
pub(crate) fn delegated_binding_identity(service: &str, lease: &OAuthLease) -> DelegatedBindingId {
    const DOMAIN: &[u8] = b"agent-access-broker/delegated-binding/v1";
    let mut digest = Sha256::new();
    for field in [
        DOMAIN,
        service.as_bytes(),
        lease.owner.as_bytes(),
        lease.binding.registration.as_bytes(),
        lease.binding.permission_profile.as_bytes(),
        lease.config_fingerprint.as_bytes(),
        lease.generation.as_bytes(),
        lease.connection_id.as_bytes(),
    ] {
        digest.update((field.len() as u64).to_be_bytes());
        digest.update(field);
    }
    agent_access_provider::host::delegated_binding_id(digest.finalize().into())
}

#[async_trait]
impl DelegatedLease for ManagedOAuthLease {
    fn binding_identity(&self) -> DelegatedBindingId {
        self.binding
    }

    fn mark_rejected(&self, version: &str) -> Result<(), ProviderError> {
        let lease = self.current();
        if lease.access_version() != version {
            return Ok(());
        }
        self.manager
            .mark_access_rejected(&lease)
            .map_err(|error| self.error(error))
    }
    fn access(&self) -> DelegatedAccess {
        let lease = self.current();
        DelegatedAccess::new(
            lease.token().to_owned(),
            lease.target().to_owned(),
            lease.audience().to_owned(),
            lease.access_version().to_owned(),
            lease.expires_at(),
        )
    }

    /// A stale lease (expired, superseded, or its connection changed) is
    /// acquired once more; the manager decides whether the connection can
    /// still issue access.
    async fn revalidate(&self) -> Result<(), ProviderError> {
        match self.manager.validate_lease(&self.current()) {
            Ok(()) => Ok(()),
            Err(OAuthError::Stale) => {
                let lease = self
                    .manager
                    .reacquire_pinned(&self.current(), false)
                    .await
                    .map_err(|error| self.error(error))?;
                self.manager
                    .validate_lease(&lease)
                    .map_err(|error| self.error(error))?;
                self.replace(lease)?;
                Ok(())
            }
            Err(error) => Err(self.error(error)),
        }
    }

    async fn recover_after_unauthorized(&self) -> Result<DelegatedAccess, ProviderError> {
        if self.recovered.swap(true, Ordering::SeqCst) {
            return Err(port_failure(
                HostPort::DelegatedLease,
                ProviderError::deny(
                    ReasonCode::CredentialInvalid,
                    "delegated credential was already recovered for this invocation",
                ),
            ));
        }
        let rejected = self.current();
        let lease = self
            .manager
            .reacquire_pinned(&rejected, true)
            .await
            .map_err(|error| self.error(error))?;
        self.manager
            .validate_lease(&lease)
            .map_err(|error| self.error(error))?;
        self.replace(lease)?;
        Ok(self.access())
    }
}

impl OAuthManager {
    /// A late 401 must not revoke a newer connection, family, or access entry.
    pub(super) fn mark_access_rejected(&self, lease: &OAuthLease) -> Result<(), OAuthError> {
        self.active()?;
        self.update(&lease.owner, &lease.binding.registration, |_, current| {
            let mut slot = current.ok_or(OAuthError::Stale)?;
            let connection = slot.connection.as_mut().ok_or(OAuthError::Stale)?;
            if slot.generation != lease.generation
                || slot.config_fingerprint != lease.config_fingerprint
                || connection.id != lease.connection_id
            {
                return Err(OAuthError::Stale);
            }
            let entries = &mut connection.family.access;
            if entries
                .get(&lease.binding.permission_profile)
                .is_some_and(|entry| entry.version == lease.access_version)
            {
                entries.remove(&lease.binding.permission_profile);
                if connection.family.refresh_token.is_none() && entries.is_empty() {
                    connection.status = super::OAuthConnectionStatus::ReconnectRequired;
                }
            }
            Ok((slot, ()))
        })
    }
}

/// The delegated-lease port's failure for `error`: providers pass it on with
/// its decision and reason unchanged.
fn oauth_provider_error(service: &str, error: OAuthError) -> ProviderError {
    port_failure(HostPort::DelegatedLease, oauth_failure(service, error))
}

fn oauth_failure(service: &str, error: OAuthError) -> ProviderError {
    match error {
        OAuthError::BeforeSend | OAuthError::Provider => {
            ProviderError::error(ReasonCode::UpstreamConnectionFailed, error.code())
        }
        OAuthError::RequestRejected | OAuthError::InvalidResponse => {
            ProviderError::error(ReasonCode::UpstreamProtocolFailed, error.code())
        }
        // Only the authorization server throttling refresh is a rate limit.
        OAuthError::RetryLater(seconds) => {
            oauth_refresh_rate_limited(service, Some(UpstreamRetryAfter::after_seconds(seconds)))
        }
        OAuthError::Throttled => oauth_refresh_rate_limited(service, None),
        // A cooldown after any other failure reports that failure's class,
        // with the time refresh resumes.
        OAuthError::RefreshPaused { seconds, failure } => oauth_refresh_paused(
            service,
            UpstreamRetryAfter::after_seconds(seconds),
            *failure,
        ),
        OAuthError::RefreshBusy => {
            ProviderError::error(ReasonCode::ConcurrencyLimited, error.code())
        }
        OAuthError::ConsentPending => {
            ProviderError::deny(ReasonCode::VersionConflict, error.code())
        }
        _ => ProviderError::deny(ReasonCode::CredentialInvalid, error.code()),
    }
}

fn oauth_refresh_paused(
    service: &str,
    retry_after: UpstreamRetryAfter,
    failure: OAuthError,
) -> ProviderError {
    let code = failure.code();
    let mut error = oauth_provider_error(service, failure);
    error.message = format!(
        "{service} OAuth token refresh is paused after a failed attempt ({code}). {}",
        upstream_retry_hint(Some(&retry_after))
    );
    error.with_result(json!({
        "retryAfterSeconds": retry_after.seconds(),
        "retryAt": retry_after.retry_at(),
    }))
}

fn oauth_refresh_rate_limited(
    service: &str,
    retry_after: Option<UpstreamRetryAfter>,
) -> ProviderError {
    ProviderError::error(
        ReasonCode::UpstreamRateLimited,
        format!(
            "{service} OAuth token refresh is rate limited. {}",
            upstream_retry_hint(retry_after.as_ref())
        ),
    )
    .with_upstream_rate_limit(service, retry_after)
}

#[cfg(test)]
mod tests {
    use super::*;
    use agent_access_provider::Decision;

    /// Lease failures pass through providers as the port's own, fixed
    /// outcome, within the port's allowlist.
    fn assert_delegated_lease_failure(error: &ProviderError) {
        let reason = error.reason_code();
        assert_eq!(
            reason.host_port(),
            Some(HostPort::DelegatedLease),
            "{error:?}"
        );
        assert_eq!(reason.fixed_decision(), Some(error.decision()), "{error:?}");
        assert!(
            HostPort::DelegatedLease.permits(&error.decision(), reason.standard().unwrap()),
            "{error:?}"
        );
    }

    #[test]
    fn refresh_busy_stays_a_host_concurrency_limit() {
        let busy = oauth_provider_error("gmail", OAuthError::RefreshBusy);
        assert_eq!(busy.decision(), Decision::Error);
        assert_eq!(busy.reason_code(), ReasonCode::ConcurrencyLimited);
        assert_eq!(busy.reason_code().http_status(), 429);
        assert!(!ReasonCode::ConcurrencyLimited.is_provider_emittable());
        assert_delegated_lease_failure(&busy);
    }

    #[test]
    fn oauth_recovery_states_have_distinct_invocation_errors() {
        for (error, decision, reason) in [
            (
                OAuthError::BeforeSend,
                Decision::Error,
                ReasonCode::UpstreamConnectionFailed,
            ),
            (
                OAuthError::RequestRejected,
                Decision::Error,
                ReasonCode::UpstreamProtocolFailed,
            ),
            (
                OAuthError::RefreshBusy,
                Decision::Error,
                ReasonCode::ConcurrencyLimited,
            ),
            (
                OAuthError::ConsentPending,
                Decision::Deny,
                ReasonCode::VersionConflict,
            ),
            (
                OAuthError::ReconnectRequired,
                Decision::Deny,
                ReasonCode::CredentialInvalid,
            ),
            (
                OAuthError::RefreshUncertain,
                Decision::Deny,
                ReasonCode::CredentialInvalid,
            ),
        ] {
            let code = error.code();
            let mapped = oauth_provider_error("gmail", error);
            assert_eq!(mapped.decision(), decision);
            assert_eq!(mapped.reason_code(), reason);
            assert_eq!(mapped.message, code);
            assert_delegated_lease_failure(&mapped);
        }
    }

    #[test]
    fn refresh_paused_after_a_failure_reports_the_failure_class_and_the_wait() {
        for (failure, decision, reason) in [
            (
                OAuthError::Provider,
                Decision::Error,
                ReasonCode::UpstreamConnectionFailed,
            ),
            (
                OAuthError::BeforeSend,
                Decision::Error,
                ReasonCode::UpstreamConnectionFailed,
            ),
            (
                OAuthError::InvalidResponse,
                Decision::Error,
                ReasonCode::UpstreamProtocolFailed,
            ),
            (
                OAuthError::RequestRejected,
                Decision::Error,
                ReasonCode::UpstreamProtocolFailed,
            ),
            (
                OAuthError::Permission,
                Decision::Deny,
                ReasonCode::CredentialInvalid,
            ),
        ] {
            let code = failure.code();
            let paused = OAuthError::RefreshPaused {
                seconds: 12,
                failure: Box::new(failure),
            };
            assert_eq!(paused.code(), code);
            let mapped = oauth_provider_error("gmail", paused);
            assert_eq!(mapped.decision(), decision);
            assert_eq!(mapped.reason_code(), reason);
            assert_delegated_lease_failure(&mapped);
            assert_ne!(mapped.reason_code(), ReasonCode::UpstreamRateLimited);
            let result = mapped.result.as_deref().unwrap();
            assert_eq!(result["retryAfterSeconds"], 12);
            let retry_at = result["retryAt"].as_str().unwrap();
            assert_eq!(
                result,
                &serde_json::json!({"retryAfterSeconds": 12, "retryAt": retry_at})
            );
            assert_eq!(
                mapped.message,
                format!(
                    "gmail OAuth token refresh is paused after a failed attempt ({code}). Retry after 12s (at {retry_at})."
                )
            );
        }
    }

    #[test]
    fn throttled_refresh_is_an_upstream_rate_limit_with_the_known_wait() {
        let before = chrono::Utc::now();
        let mapped = oauth_provider_error("gmail", OAuthError::RetryLater(30));
        assert_eq!(mapped.decision(), Decision::Error);
        assert_eq!(mapped.reason_code(), ReasonCode::UpstreamRateLimited);
        assert_delegated_lease_failure(&mapped);
        let result = mapped.result.as_deref().unwrap();
        assert_eq!(result["limitScope"], "upstream");
        assert_eq!(result["service"], "gmail");
        assert_eq!(result["retryAfterSeconds"], 30);
        let retry_at = chrono::DateTime::parse_from_rfc3339(result["retryAt"].as_str().unwrap())
            .unwrap()
            .with_timezone(&chrono::Utc);
        assert!(retry_at >= before + chrono::TimeDelta::seconds(30));
        assert!(retry_at <= chrono::Utc::now() + chrono::TimeDelta::seconds(31));
        assert!(result.get("retrySafe").is_none());
        assert!(result.get("executionState").is_none());
        assert_eq!(
            mapped.message,
            format!(
                "gmail OAuth token refresh is rate limited. Retry after 30s (at {}).",
                result["retryAt"].as_str().unwrap()
            )
        );

        let throttled = oauth_provider_error("gmail", OAuthError::Throttled);
        assert_eq!(throttled.reason_code(), ReasonCode::UpstreamRateLimited);
        assert_eq!(
            throttled.message,
            "gmail OAuth token refresh is rate limited. Retry later."
        );
        assert_eq!(
            throttled.result.as_deref(),
            Some(&serde_json::json!({"limitScope": "upstream", "service": "gmail"}))
        );
    }
}
