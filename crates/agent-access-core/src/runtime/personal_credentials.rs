//! The caller's personal (`per_user`) credential through a credential
//! connection: [`crate::select`] picks the method for the caller's principal
//! kind from configuration, and a token method reads the connection's
//! stored row `(connection, default)`. There is no fallback between methods.
use super::*;
use crate::{CONNECTION_CREDENTIAL_NAME, PersonalConnection, Selection};

impl BrokerRuntime {
    /// The connection `service` consumes and the method `identity` selects
    /// for it; `None` when the service's per-user entry is not a
    /// connection.
    pub(crate) fn personal_selection(
        &self,
        service: &str,
        identity: &IdentityContext,
    ) -> Option<(PersonalConnection<'_>, Selection<'_>)> {
        let connection = self.effective_credentials.personal_connection(service)?;
        Some((connection, connection.select(identity.principal_kind)))
    }

    /// The token profile of `service`'s credential connection and the
    /// credential kind its consumers declare for it; `None` without a
    /// connection or a token profile. A Git gateway consumer can store a
    /// profile another consumer of its connection declares.
    pub fn personal_token_profile(&self, service: &str) -> Option<(&str, &'static str)> {
        let connection = self.effective_credentials.personal_connection(service)?;
        let profile = connection.config.token_profile.as_deref()?;
        let kind = crate::connections::connection_token_kind(
            &self.effective_credentials,
            &self.services,
            connection.id,
        )?;
        Some((profile, kind))
    }

    /// The `service` column of `service`'s personal token rows: the ID of
    /// the credential connection it consumes, if any.
    pub fn personal_credential_key(&self, service: &str) -> Option<&str> {
        self.effective_credentials
            .personal_connection(service)
            .map(|connection| connection.id)
    }

    /// The caller's token for `service`'s connection, which execution,
    /// both lookup phases and the gateway use. An OAuth selection cannot
    /// supply a static credential, and an unavailable selection never falls
    /// back to another method.
    pub(super) async fn resolve_connection_token(
        &self,
        service: &str,
        identity: &IdentityContext,
    ) -> Result<ExecutionCredential, ProviderError> {
        let (connection, selection) = self
            .personal_selection(service, identity)
            .ok_or_else(personal_credential_unconfigured)?;
        let profile = match selection {
            Selection::Token(profile) => profile,
            Selection::OAuth(_) => {
                return Err(ProviderError::deny(
                    ReasonCode::CredentialNotProvisioned,
                    "selected credential kind cannot be resolved for execution",
                ));
            }
            Selection::Unavailable => return Err(personal_method_unavailable()),
        };
        self.resolve_stored_connection_token(connection.id, profile, identity)
            .await
    }

    /// Reads and records the use of `identity`'s token row for
    /// `connection`, which must have `profile`.
    async fn resolve_stored_connection_token(
        &self,
        connection: &str,
        profile: &str,
        identity: &IdentityContext,
    ) -> Result<ExecutionCredential, ProviderError> {
        let identity = identity.authenticated.then_some(identity).ok_or_else(|| {
            ProviderError::deny(
                ReasonCode::CredentialNotProvisioned,
                "managed per_user credential requires authenticated identity",
            )
        })?;
        let store = self.managed_store.clone().ok_or_else(|| {
            ProviderError::deny(
                ReasonCode::CredentialNotProvisioned,
                "managed credential store is not configured",
            )
        })?;
        let key_ring = self.credential_key_ring.clone().ok_or_else(|| {
            ProviderError::error(
                ReasonCode::EncryptionKeyMissing,
                "credential encryption key ring is not configured",
            )
        })?;
        let (principal, connection, profile) = (
            identity.principal.clone(),
            connection.to_owned(),
            profile.to_owned(),
        );
        managed_store_blocking(move || {
            store.resolve_user_credential(
                &key_ring,
                &principal,
                &connection,
                CONNECTION_CREDENTIAL_NAME,
                &profile,
            )
        })
        .await
        .map_err(provider_error_from_managed_store)
    }

    /// Readiness of a connection entry: the connection exists and, with
    /// OAuth, names a configured registration and profile for a service that
    /// accepts delegated credentials. It never depends on any principal's
    /// stored token or consent.
    pub(super) fn check_connection_ready(
        &self,
        label: &str,
        service: &str,
    ) -> Result<(), RuntimeError> {
        let connection = self
            .effective_credentials
            .personal_connection(service)
            .ok_or_else(|| RuntimeError::Credential {
                label: label.to_string(),
                message: "credential connection is not configured".into(),
            })?;
        if let Some(oauth) = &connection.config.oauth {
            let profile = self
                .config
                .oauth
                .registrations
                .get(&oauth.registration)
                .and_then(|registration| registration.permission_profiles.get(&oauth.profile));
            if profile.is_none() || !self.accepts_delegated_credentials(service) {
                return Err(RuntimeError::Credential {
                    label: label.to_string(),
                    message: "OAuth requires a configured per_user registration/profile binding"
                        .into(),
                });
            }
        }
        Ok(())
    }
}

/// The service has no credential connection.
fn personal_credential_unconfigured() -> ProviderError {
    ProviderError::deny(
        ReasonCode::CredentialNotProvisioned,
        "selected credential mode is not provisioned",
    )
}

/// The connection selects no method for the caller's principal kind, which
/// only configuration can change; distinct from a missing stored token.
pub(super) fn personal_method_unavailable() -> ProviderError {
    ProviderError::deny(
        ReasonCode::CredentialNotProvisioned,
        "the credential connection offers no personal credential method for this principal",
    )
}
