//! The caller's personal (`per_user`) credential through a credential
//! connection: [`crate::select`] picks the method for the caller's principal
//! kind from configuration, and a token method reads the connection's
//! stored row `(connection, default)` when its stored profile is one the
//! selected list accepts. There is no fallback between methods.
use super::*;
use crate::{CONNECTION_CREDENTIAL_NAME, PersonalConnection, PrincipalKind, Selection};

/// One token profile a credential connection accepts from a principal, as
/// management offers it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConnectionTokenProfile {
    pub profile: String,
    /// The label a consumer declares for it; management falls back to the
    /// profile name.
    pub label: Option<String>,
    /// The credential kind its consumers agree on.
    pub credential_kind: &'static str,
}

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

    /// The token profiles the effective credential connection `connection`
    /// accepts from a principal of `kind`, in configuration order, each
    /// with the credential kind its consumers declare and its label; `None`
    /// for an unknown connection or one that selects no token method for
    /// `kind`. A listed profile whose kind the consumers do not settle,
    /// which validation rejects, is left out.
    pub fn connection_token_profiles(
        &self,
        connection: &str,
        kind: Option<PrincipalKind>,
    ) -> Option<Vec<ConnectionTokenProfile>> {
        let config = self.effective_credentials.connections.get(connection)?;
        let Selection::Token(profiles) = crate::select(config, kind) else {
            return None;
        };
        let accepted = profiles
            .iter()
            .filter_map(|profile| {
                Some(ConnectionTokenProfile {
                    credential_kind: crate::connections::connection_profile_kind(
                        &self.effective_credentials,
                        &self.services,
                        connection,
                        profile,
                    )?,
                    label: self.connection_profile_label(connection, profile),
                    profile: profile.clone(),
                })
            })
            .collect::<Vec<_>>();
        (!accepted.is_empty()).then_some(accepted)
    }

    /// The label the consumers of `connection` declare for `profile`, for a
    /// stored row of that profile; `None` when none declares one.
    pub fn connection_profile_label(&self, connection: &str, profile: &str) -> Option<String> {
        crate::connections::connection_profile_label(
            &self.effective_credentials,
            &self.services,
            connection,
            profile,
        )
    }

    /// The credential connection a call's audit record names: the one a
    /// personal lookup before policy used (`personal_lookup`), even when the
    /// call then ends before a credential mode is selected or is rejected for
    /// planning drift; otherwise the one `service` consumes, when the call's
    /// selected mode is `per_user` or a command call passes a `per_user`
    /// grant (its `credentialMode` is then null when it also passes service
    /// grants). `None` when only service credentials are used.
    pub(super) fn audit_credential_connection(
        &self,
        service: &str,
        credential_mode: Option<&str>,
        command: Option<&super::command_dispatch::AdmittedCommand>,
        personal_lookup: Option<String>,
    ) -> Option<String> {
        if personal_lookup.is_some() {
            return personal_lookup;
        }
        let personal = credential_mode == Some("per_user")
            || command.is_some_and(|command| {
                command
                    .authorization()
                    .credential_modes()
                    .contains("per_user")
            });
        personal
            .then(|| self.effective_credentials.personal_connection(service))
            .flatten()
            .map(|connection| connection.id.to_owned())
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
        let profiles = match selection {
            Selection::Token(profiles) => profiles,
            Selection::OAuth(_) => {
                return Err(ProviderError::deny(
                    ReasonCode::CredentialNotProvisioned,
                    "selected credential kind cannot be resolved for execution",
                ));
            }
            Selection::Unavailable => return Err(personal_method_unavailable()),
        };
        self.resolve_stored_connection_token(connection.id, profiles, identity)
            .await
    }

    /// Reads and records the use of `identity`'s token row for
    /// `connection`, whose stored profile must be one of `profiles`.
    async fn resolve_stored_connection_token(
        &self,
        connection: &str,
        profiles: &[String],
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
        let requirement = self
            .imported_connection_requirement(connection)
            .map_err(provider_error_from_managed_store)?;
        let (principal, connection, profiles) = (
            identity.principal.clone(),
            connection.to_owned(),
            profiles.to_vec(),
        );
        managed_store_blocking(move || {
            store.resolve_user_credential_with_imported_contract(
                &key_ring,
                &principal,
                &connection,
                CONNECTION_CREDENTIAL_NAME,
                &profiles,
                requirement.as_ref(),
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
