//! Action credential eligibility: whether an action may run with the method
//! a grant region's selected credential mode uses for the caller.
//!
//! A token-only action ([`ActionDescriptor::token_only`]) needs static
//! (token) material. It is ineligible exactly where the winning grant's mode
//! is `per_user` and the caller's credential connection selects OAuth. A
//! `service` region with its static credential, and a `per_user` region whose
//! connection selects a stored token, keep it usable. The check is part of
//! the per-action credential-mode checks every selection already applies,
//! after grant precedence, so an ineligible winning grant still suppresses
//! the grants below it: the Broker never falls back to another region or
//! credential. It reads configuration only, never stored material.
use super::*;

impl BrokerRuntime {
    /// Whether `action` of `service` may run with credential `mode` for
    /// `identity`: false only for a token-only action under `per_user` when
    /// the caller's connection selects OAuth.
    pub(super) fn action_credential_eligible(
        &self,
        service: &str,
        action: &str,
        mode: &str,
        identity: &IdentityContext,
    ) -> bool {
        mode != "per_user"
            || !self
                .action_descriptor(service, action)
                .is_some_and(|descriptor| descriptor.token_only)
            || !matches!(
                self.personal_selection(service, identity),
                Some((_, crate::Selection::OAuth(_)))
            )
    }

    /// [`Self::action_credential_eligible`] as the denial a selection
    /// reports.
    pub(super) fn check_action_credential_eligibility(
        &self,
        service: &str,
        action: &str,
        mode: &str,
        identity: &IdentityContext,
    ) -> Result<(), ProviderError> {
        if self.action_credential_eligible(service, action, mode, identity) {
            Ok(())
        } else {
            Err(token_only_denial())
        }
    }
}

/// The denial for a token-only action whose winning `per_user` grant would
/// use the caller's OAuth connection.
pub(super) fn token_only_denial() -> ProviderError {
    ProviderError::deny(
        ReasonCode::CredentialNotProvisioned,
        "this action requires a token credential, and the caller's credential connection uses OAuth",
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    const SERVICE: &str = "fake";
    const ACTION: &str = "echo";

    /// The development fake service, consuming a connection with the given
    /// methods, with `echo` marked token-only when `token_only` is set.
    fn runtime(token_profile: bool, oauth: bool, token_only: bool) -> BrokerRuntime {
        let mut runtime = BrokerRuntime::new(super::super::tests::base_fake_config()).unwrap();
        let mut services = (*runtime.services).clone();
        let mut descriptor = (*services[SERVICE]).clone();
        for action in &mut descriptor.actions {
            action.token_only = token_only && action.action == ACTION;
        }
        services.insert(SERVICE.into(), Arc::new(descriptor));
        runtime.services = Arc::new(services);
        let mut credentials = (*runtime.effective_credentials).clone();
        credentials.connections.insert(
            SERVICE.into(),
            crate::ConnectionConfig {
                display_name: None,
                token_profile: token_profile.then(|| "fake-token".into()),
                oauth: oauth.then(|| crate::ConnectionOAuthConfig {
                    registration: "stub".into(),
                    profile: "read".into(),
                }),
            },
        );
        credentials.per_user.insert(
            SERVICE.into(),
            CredentialConfig {
                kind: "connection".into(),
                provider: None,
                connection: Some(SERVICE.into()),
                profile: None,
                username_ref: None,
                token_ref: None,
                path: None,
                read_only: None,
            },
        );
        runtime.effective_credentials = Arc::new(credentials);
        runtime
    }

    fn caller(principal_kind: Option<crate::PrincipalKind>) -> IdentityContext {
        IdentityContext {
            caller_id: None,
            principal: "avery".into(),
            principal_kind,
            principal_subject: Some("avery".into()),
            groups: Vec::new(),
            policy_groups: Vec::new(),
            authenticated: true,
            source: None,
        }
    }

    /// Only `per_user` with an OAuth selection is ineligible, and only for a
    /// token-only action; every other mode, selection and action is unchanged.
    #[test]
    fn only_a_per_user_oauth_selection_excludes_a_token_only_action() {
        use crate::PrincipalKind::{ServiceAccount, System, User};
        let token_and_oauth = runtime(true, true, true);
        let user = caller(Some(User));
        assert!(!token_and_oauth.action_credential_eligible(SERVICE, ACTION, "per_user", &user));
        let denied = token_and_oauth
            .check_action_credential_eligibility(SERVICE, ACTION, "per_user", &user)
            .unwrap_err();
        assert_eq!(denied.decision(), Decision::Deny);
        assert_eq!(denied.reason_code(), ReasonCode::CredentialNotProvisioned);
        assert_eq!(denied.message, token_only_denial().message);
        // A service region is eligible for the same OAuth-selecting caller.
        assert!(token_and_oauth.action_credential_eligible(SERVICE, ACTION, "service", &user));
        // Principals that select the stored token, or nothing, are not
        // excluded by eligibility (availability reports an empty selection).
        for kind in [Some(ServiceAccount), Some(System), None] {
            assert!(
                token_and_oauth.action_credential_eligible(
                    SERVICE,
                    ACTION,
                    "per_user",
                    &caller(kind)
                ),
                "{kind:?}"
            );
        }
        // A user selects the token of a connection without OAuth.
        assert!(
            runtime(true, false, true)
                .action_credential_eligible(SERVICE, ACTION, "per_user", &user)
        );
        // Unmarked actions accept OAuth.
        assert!(
            runtime(true, true, false)
                .action_credential_eligible(SERVICE, ACTION, "per_user", &user)
        );
        // A per-user entry that is not a connection selects nothing to check.
        let mut static_entry = runtime(true, true, true);
        let mut credentials = (*static_entry.effective_credentials).clone();
        credentials.per_user.remove(SERVICE);
        static_entry.effective_credentials = Arc::new(credentials);
        assert!(static_entry.action_credential_eligible(SERVICE, ACTION, "per_user", &user));
    }
}
