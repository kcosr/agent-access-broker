//! Lookup access: the material an action's upstream metadata lookups use
//! before policy (scope resolution) and at execution.
//!
//! A service-mode lookup uses the service's shared static lookup credential.
//! A personal (`per_user`) lookup uses the caller's own credential connection:
//! its token, or the delegated OAuth lease the operation's execution then
//! shares, with one recovery budget. A personal lookup never falls back to the
//! shared credential, and planning drift from a personal lookup to a `service`
//! grant is rejected. Delegated lookup access is not yet lent: every path that
//! would need it fails closed with [`delegated_lookup_unsupported`].
use super::*;

/// The lookup access scope resolution used, which execution must agree with.
#[derive(Debug, Clone)]
pub(super) enum PreScopeLookup {
    None,
    /// The caller's personal lookup access.
    PerUser(LookupAccess),
    /// The service's shared static lookup credential.
    Shared(LookupAccess),
}

impl PreScopeLookup {
    pub(super) fn access(&self) -> Option<&LookupAccess> {
        match self {
            Self::None => None,
            Self::PerUser(access) | Self::Shared(access) => Some(access),
        }
    }

    /// The execution material a personal pre-scope lookup fixes for a
    /// `per_user` operation: the same token. `None` when scope resolution
    /// used no personal lookup.
    pub(super) fn personal_execution(&self) -> Option<Result<ExecutionAccess, ProviderError>> {
        match self {
            Self::PerUser(LookupAccess::Static(credential)) => {
                Some(Ok(ExecutionAccess::Static(credential.clone())))
            }
            Self::PerUser(_) => Some(Err(delegated_lookup_unsupported())),
            Self::None | Self::Shared(_) => None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum PreScopeLookupPlan {
    UsePerUserCredential,
    UseSharedLookupCredential,
    NoCandidateGrant,
}

/// A path that needs delegated lookup access, which the host does not yet
/// lend. It fails closed: never a static or shared credential instead.
fn delegated_lookup_unsupported() -> ProviderError {
    ProviderError::deny(
        ReasonCode::CredentialNotProvisioned,
        "delegated lookup access is not supported",
    )
}

/// The lookup access a `per_user` operation derives from its execution
/// material when scope resolution used no personal lookup.
fn personal_lookup_from_execution(
    execution: &ExecutionAccess,
) -> Result<LookupAccess, ProviderError> {
    match execution {
        ExecutionAccess::Static(credential) => Ok(LookupAccess::Static(credential.clone())),
        ExecutionAccess::Delegated(_) => Err(delegated_lookup_unsupported()),
        _ => Err(ProviderError::deny(
            ReasonCode::CredentialNotProvisioned,
            "selected credential mode is not provisioned",
        )),
    }
}

impl BrokerRuntime {
    /// The lookup access execution receives after final policy, consistent
    /// with the access scope resolution used.
    pub(super) async fn resolve_lookup_access_if_required(
        &self,
        lookup: LookupRequirement,
        service: &str,
        policy: &PolicyDecision,
        execution: &ExecutionAccess,
        pre_scope_lookup: &PreScopeLookup,
    ) -> Result<Option<LookupAccess>, ProviderError> {
        if !lookup.credential_required() {
            return Ok(None);
        }
        match (policy.credential_mode.as_str(), pre_scope_lookup) {
            ("per_user", PreScopeLookup::PerUser(access)) => Ok(Some(access.clone())),
            ("per_user", _) => personal_lookup_from_execution(execution).map(Some),
            ("service", PreScopeLookup::Shared(access)) => Ok(Some(access.clone())),
            ("service", PreScopeLookup::PerUser(_)) => Err(policy_planning_drift_error()),
            ("service", PreScopeLookup::None) => self
                .resolve_lookup_credential(service)
                .map(|credential| Some(LookupAccess::Static(credential))),
            _ => Err(ProviderError::deny(
                ReasonCode::CredentialNotProvisioned,
                "selected credential mode is not provisioned",
            )),
        }
    }

    pub(super) async fn resolve_pre_scope_lookup_if_required(
        &self,
        policy_snapshot: &PolicySnapshot,
        lookup: LookupRequirement,
        identity: &IdentityContext,
        execution_context: &ExecutionContext,
        service: &str,
        action: &str,
    ) -> Result<PreScopeLookup, ProviderError> {
        if !lookup.before_policy() {
            return Ok(PreScopeLookup::None);
        }
        match self.plan_pre_scope_lookup(
            policy_snapshot,
            identity,
            execution_context,
            service,
            action,
        ) {
            PreScopeLookupPlan::NoCandidateGrant => Err(lookup_scope_denial()),
            PreScopeLookupPlan::UsePerUserCredential => self
                .personal_pre_scope_lookup(service, identity)
                .await
                .map(PreScopeLookup::PerUser),
            PreScopeLookupPlan::UseSharedLookupCredential => self
                .resolve_lookup_credential(service)
                .map(|credential| PreScopeLookup::Shared(LookupAccess::Static(credential))),
        }
    }

    /// The caller's personal lookup access before policy: the token their
    /// connection selects. An OAuth selection would need delegated lookup
    /// access and fails closed before any acquisition.
    async fn personal_pre_scope_lookup(
        &self,
        service: &str,
        identity: &IdentityContext,
    ) -> Result<LookupAccess, ProviderError> {
        if let Some((_, crate::Selection::OAuth(_))) = self.personal_selection(service, identity) {
            return Err(delegated_lookup_unsupported());
        }
        self.resolve_execution_credential(service, "per_user", identity)
            .await
            .map(LookupAccess::Static)
    }

    pub(super) fn plan_pre_scope_lookup(
        &self,
        policy_snapshot: &PolicySnapshot,
        identity: &IdentityContext,
        execution_context: &ExecutionContext,
        service: &str,
        action: &str,
    ) -> PreScopeLookupPlan {
        let candidates = self.policy_candidates_for_action(
            policy_snapshot,
            identity,
            execution_context,
            service,
            action,
        );
        if candidates.is_empty() {
            return PreScopeLookupPlan::NoCandidateGrant;
        }
        if !candidates
            .iter()
            .any(|candidate| candidate.credential_mode == "service")
        {
            return PreScopeLookupPlan::UsePerUserCredential;
        }
        let top_band = top_policy_band(candidates.clone());
        let top_band_has_per_user_wildcard = top_band.iter().any(|candidate| {
            candidate.credential_mode == "per_user" && candidate.boundary.is_universe()
        });
        let top_band_has_service = top_band
            .iter()
            .any(|candidate| candidate.credential_mode == "service");
        if top_band_has_per_user_wildcard && !top_band_has_service {
            return PreScopeLookupPlan::UsePerUserCredential;
        }
        PreScopeLookupPlan::UseSharedLookupCredential
    }

    /// The service's shared static lookup credential.
    pub(super) fn resolve_lookup_credential(
        &self,
        service: &str,
    ) -> Result<ExecutionCredential, ProviderError> {
        let credential = self
            .effective_credentials
            .lookup
            .get(service)
            .ok_or_else(|| {
                ProviderError::deny(
                    ReasonCode::CredentialNotProvisioned,
                    "lookup credential is not provisioned",
                )
            })?;
        load_execution_credential(service, "lookup", credential, None)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use agent_access_provider::test_support::{bearer_credential, delegated_binding_id};
    use async_trait::async_trait;

    /// A delegated lease no path in this module may use.
    struct UnusedLease;

    #[async_trait]
    impl DelegatedLease for UnusedLease {
        fn access(&self) -> DelegatedAccess {
            DelegatedAccess::new("unused", "target", "audience", "v1", i64::MAX)
        }
        fn binding_identity(&self) -> DelegatedBindingId {
            delegated_binding_id("unused")
        }
        async fn revalidate(&self) -> Result<(), ProviderError> {
            panic!("an unsupported delegated lookup must not revalidate");
        }
        fn mark_rejected(&self, _: &str) -> Result<(), ProviderError> {
            panic!("an unsupported delegated lookup must not mark access rejected");
        }
        async fn recover_after_unauthorized(&self) -> Result<DelegatedAccess, ProviderError> {
            panic!("an unsupported delegated lookup must not recover");
        }
    }

    fn delegated() -> DelegatedCredential {
        agent_access_provider::host::delegated_credential(Arc::new(UnusedLease))
    }

    fn assert_unsupported(error: ProviderError) {
        assert_eq!(error.decision(), Decision::Deny);
        assert_eq!(error.reason_code(), ReasonCode::CredentialNotProvisioned);
        assert_eq!(error.message, "delegated lookup access is not supported");
    }

    #[test]
    fn a_personal_static_pre_scope_lookup_fixes_the_same_execution_token() {
        let token = bearer_credential("personal-token");
        let lookup = PreScopeLookup::PerUser(LookupAccess::Static(token.clone()));
        let execution = lookup.personal_execution().unwrap().unwrap();
        assert_eq!(execution.static_credential(), Some(&token));
        assert!(
            PreScopeLookup::Shared(LookupAccess::Static(token))
                .personal_execution()
                .is_none()
        );
        assert!(PreScopeLookup::None.personal_execution().is_none());
    }

    /// Paths that would need delegated lookup access fail closed instead of
    /// substituting static or shared material.
    #[test]
    fn delegated_lookup_paths_fail_closed() {
        let personal = PreScopeLookup::PerUser(LookupAccess::Delegated(delegated()));
        assert_unsupported(personal.personal_execution().unwrap().unwrap_err());
        assert_unsupported(
            personal_lookup_from_execution(&ExecutionAccess::Delegated(delegated())).unwrap_err(),
        );
        let missing = personal_lookup_from_execution(&ExecutionAccess::None).unwrap_err();
        assert_eq!(missing.reason_code(), ReasonCode::CredentialNotProvisioned);
        assert_eq!(
            missing.message,
            "selected credential mode is not provisioned"
        );
        let token = bearer_credential("personal-token");
        let derived = personal_lookup_from_execution(&ExecutionAccess::Static(token.clone()));
        assert_eq!(derived.unwrap().static_credential(), Some(&token));
    }
}
