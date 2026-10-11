//! An OAuth connection's access lent to one invocation as a delegated
//! credential.
use super::{OAuthBinding, OAuthError, OAuthLease, OAuthManager};
use crate::{
    DelegatedAccess, DelegatedCredential, DelegatedLease, ProviderError, ReasonCode,
    UpstreamRetryAfter, upstream_retry_hint,
};
use async_trait::async_trait;
use serde_json::json;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

/// Holds the manager of the runtime generation that acquired it, so a lease
/// taken before a reload is judged by the configuration it was issued under.
pub(crate) struct ManagedOAuthLease {
    manager: OAuthManager,
    /// The invoked service, named when its connection's refresh is throttled.
    service: String,
    current: Mutex<OAuthLease>,
    connection_id: String,
    generation: String,
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
        Ok(DelegatedCredential::new(Arc::new(Self {
            manager,
            service,
            connection_id: lease.connection_id.clone(),
            generation: lease.generation.clone(),
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
        if lease.connection_id != self.connection_id || lease.generation != self.generation {
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

#[async_trait]
impl DelegatedLease for ManagedOAuthLease {
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
        DelegatedAccess {
            token: lease.token().to_owned(),
            target: lease.target().to_owned(),
            audience: lease.audience().to_owned(),
            version: lease.access_version().to_owned(),
            expires_at: lease.expires_at(),
        }
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
            return Err(ProviderError::deny(
                ReasonCode::CredentialInvalid,
                "delegated credential was already recovered for this invocation",
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

fn oauth_provider_error(service: &str, error: OAuthError) -> ProviderError {
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
    use crate::Decision;

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
            assert_eq!(mapped.decision, decision);
            assert_eq!(mapped.reason_code, reason);
            assert_eq!(mapped.message, code);
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
            assert_eq!(mapped.decision, decision);
            assert_eq!(mapped.reason_code, reason);
            assert_ne!(mapped.reason_code, ReasonCode::UpstreamRateLimited);
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
        assert_eq!(mapped.decision, Decision::Error);
        assert_eq!(mapped.reason_code, ReasonCode::UpstreamRateLimited);
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
        assert_eq!(throttled.reason_code, ReasonCode::UpstreamRateLimited);
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
