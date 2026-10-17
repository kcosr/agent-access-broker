//! Lookup access: the material an action's upstream metadata lookups use
//! before policy (scope resolution) and at execution.
//!
//! A service-mode lookup uses the service's shared static lookup credential.
//! A personal (`per_user`) lookup uses what the caller's credential connection
//! selects: their token, or a lease on their OAuth connection. One operation
//! holds at most one lease: a lease acquired for scope resolution is the one
//! execution and its lookups use, and otherwise execution's lease serves its
//! lookups, so the operation has one 401-recovery budget. A lease is acquired
//! only once a candidate grant exists. A personal lookup never falls back to
//! the shared credential, and planning drift from a personal lookup to a
//! `service` grant is rejected.
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
    /// `per_user` operation: the same token, or the same delegated lease.
    /// `None` when scope resolution used no personal lookup.
    pub(super) fn personal_execution(&self) -> Option<Result<ExecutionAccess, ProviderError>> {
        match self {
            Self::PerUser(LookupAccess::Static(credential)) => {
                Some(Ok(ExecutionAccess::Static(credential.clone())))
            }
            Self::PerUser(LookupAccess::Delegated(credential)) => {
                Some(Ok(ExecutionAccess::Delegated(credential.clone())))
            }
            Self::PerUser(_) => Some(Err(unsupported_lookup_access())),
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

/// Lookup access of a kind this host does not lend.
fn unsupported_lookup_access() -> ProviderError {
    ProviderError::deny(
        ReasonCode::CredentialNotProvisioned,
        "selected lookup access is not supported",
    )
}

/// The lookup access a `per_user` operation derives from its execution
/// material when scope resolution used no personal lookup: the same token,
/// or the same delegated lease.
fn personal_lookup_from_execution(
    execution: &ExecutionAccess,
) -> Result<LookupAccess, ProviderError> {
    match execution {
        ExecutionAccess::Static(credential) => Ok(LookupAccess::Static(credential.clone())),
        ExecutionAccess::Delegated(credential) => Ok(LookupAccess::Delegated(credential.clone())),
        _ => Err(ProviderError::deny(
            ReasonCode::CredentialNotProvisioned,
            "selected credential mode is not provisioned",
        )),
    }
}

/// Whether `error` is a delegated lease's failure that lookup concealment
/// passes on, because it describes the caller's OAuth connection rather than
/// the resource a lookup named: consent pending (`version_conflict`), a
/// refresh in progress (`concurrency_limited`) or a throttled refresh
/// (`upstream_rate_limited`, with its retry metadata). A reconnect
/// requirement (`credential_invalid`) passes for every origin. A provider's
/// own failure with one of these reasons stays concealed.
pub(super) fn is_public_lease_failure(error: &ProviderError) -> bool {
    error.reason_code().host_port() == Some(agent_access_provider::host::HostPort::DelegatedLease)
        && matches!(
            error.reason_code().standard(),
            Some(
                ReasonCode::VersionConflict
                    | ReasonCode::ConcurrencyLimited
                    | ReasonCode::UpstreamRateLimited
            )
        )
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

    #[allow(clippy::too_many_arguments)]
    pub(super) async fn resolve_pre_scope_lookup_if_required(
        &self,
        policy_snapshot: &PolicySnapshot,
        lookup: LookupRequirement,
        identity: &IdentityContext,
        execution_context: &ExecutionContext,
        service: &str,
        action: &str,
        correlation: &CorrelationContext,
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
            PreScopeLookupPlan::UsePerUserCredential => {
                // Final policy can only select `per_user` under this plan,
                // so an ineligible action is denied before the lease below
                // is acquired.
                self.check_action_credential_eligibility(service, action, "per_user", identity)?;
                self.personal_pre_scope_lookup(service, action, identity, correlation)
                    .await
                    .map(PreScopeLookup::PerUser)
            }
            PreScopeLookupPlan::UseSharedLookupCredential => self
                .resolve_lookup_credential(service)
                .map(|credential| PreScopeLookup::Shared(LookupAccess::Static(credential))),
        }
    }

    /// The credential connection whose material `lookup` used, when scope
    /// resolution looked up with the caller's personal token or lease: the
    /// connection `service` consumes. `None` for a shared or absent lookup,
    /// or a personal credential that is not a connection.
    pub(super) fn personal_lookup_connection(
        &self,
        service: &str,
        lookup: &PreScopeLookup,
    ) -> Option<String> {
        matches!(lookup, PreScopeLookup::PerUser(_))
            .then(|| self.effective_credentials.personal_connection(service))
            .flatten()
            .map(|connection| connection.id.to_owned())
    }

    /// The caller's personal lookup access before policy, planned only once
    /// a candidate grant exists: the token their connection selects, or a
    /// lease on their OAuth connection, which execution then reuses.
    async fn personal_pre_scope_lookup(
        &self,
        service: &str,
        action: &str,
        identity: &IdentityContext,
        correlation: &CorrelationContext,
    ) -> Result<LookupAccess, ProviderError> {
        if let Some((_, crate::Selection::OAuth(oauth))) =
            self.personal_selection(service, identity)
        {
            return with_provider_context(
                correlation.clone(),
                service.to_owned(),
                action.to_owned(),
                self.acquire_delegated_credential(
                    service,
                    self.accepts_delegated_credentials(service),
                    oauth.binding(),
                    identity,
                ),
            )
            .await
            .map(LookupAccess::Delegated);
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
            candidate.credential_mode == "per_user"
                && candidate
                    .scopes
                    .values()
                    .all(|scope| scope.boundary.is_universe())
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
    use agent_access_provider::host::{HostPort, delegated_credential, port_failure};
    use agent_access_provider::test_support::{bearer_credential, delegated_binding_id};
    use async_trait::async_trait;
    use std::sync::atomic::{AtomicBool, Ordering};

    /// A lease with the host's one recovery per operation. It must not be
    /// revalidated by the paths under test.
    #[derive(Default)]
    struct BudgetLease {
        recovered: AtomicBool,
    }

    #[async_trait]
    impl DelegatedLease for BudgetLease {
        fn access(&self) -> DelegatedAccess {
            DelegatedAccess::new("lease-token", "target", "audience", "v1", i64::MAX)
        }
        fn binding_identity(&self) -> DelegatedBindingId {
            delegated_binding_id("lease")
        }
        async fn revalidate(&self) -> Result<(), ProviderError> {
            panic!("lookup selection must not revalidate the lease");
        }
        fn mark_rejected(&self, _: &str) -> Result<(), ProviderError> {
            panic!("lookup selection must not mark access rejected");
        }
        async fn recover_after_unauthorized(&self) -> Result<DelegatedAccess, ProviderError> {
            if self.recovered.swap(true, Ordering::SeqCst) {
                return Err(ProviderError::deny(
                    ReasonCode::CredentialInvalid,
                    "already recovered",
                ));
            }
            Ok(self.access())
        }
    }

    fn lease() -> DelegatedCredential {
        delegated_credential(Arc::new(BudgetLease::default()))
    }

    /// `first` and `second` hold one lease: the operation's single recovery,
    /// spent through `first`, is gone for `second`.
    async fn assert_one_lease(first: &DelegatedCredential, second: &DelegatedCredential) {
        first.recover_after_unauthorized().await.unwrap();
        let error = second.recover_after_unauthorized().await.unwrap_err();
        assert_eq!(error.reason_code(), ReasonCode::CredentialInvalid);
    }

    #[tokio::test]
    async fn a_personal_pre_scope_lookup_fixes_the_same_execution_material() {
        let token = bearer_credential("personal-token");
        let execution = PreScopeLookup::PerUser(LookupAccess::Static(token.clone()))
            .personal_execution()
            .unwrap()
            .unwrap();
        assert_eq!(execution.static_credential(), Some(&token));

        let lookup = PreScopeLookup::PerUser(LookupAccess::Delegated(lease()));
        let execution = lookup.personal_execution().unwrap().unwrap();
        assert_one_lease(
            lookup.access().unwrap().delegated().unwrap(),
            execution.delegated().unwrap(),
        )
        .await;

        assert!(
            PreScopeLookup::Shared(LookupAccess::Static(token))
                .personal_execution()
                .is_none()
        );
        assert!(PreScopeLookup::None.personal_execution().is_none());
    }

    #[tokio::test]
    async fn per_user_lookups_derive_from_the_execution_material() {
        let token = bearer_credential("personal-token");
        let derived = personal_lookup_from_execution(&ExecutionAccess::Static(token.clone()));
        assert_eq!(derived.unwrap().static_credential(), Some(&token));

        let execution = ExecutionAccess::Delegated(lease());
        let derived = personal_lookup_from_execution(&execution).unwrap();
        assert_one_lease(derived.delegated().unwrap(), execution.delegated().unwrap()).await;

        let missing = personal_lookup_from_execution(&ExecutionAccess::None).unwrap_err();
        assert_eq!(missing.reason_code(), ReasonCode::CredentialNotProvisioned);
        assert_eq!(
            missing.message,
            "selected credential mode is not provisioned"
        );
    }

    /// A personal lookup, static or delegated, never continues under a
    /// `service` grant: both execution selection and execution-phase lookup
    /// reject the drift without touching the lease or the shared credential.
    #[tokio::test]
    async fn planning_drift_from_a_personal_lookup_to_service_is_rejected() {
        let runtime = BrokerRuntime::new(super::super::tests::base_fake_config()).unwrap();
        let service_policy = PolicyDecision {
            credential_mode: "service".into(),
            matched_grant: MatchedGrantAudit {
                config_index: None,
                grant_id: None,
                grant_version: None,
                policy_generation: None,
                subject: "user:agent-one".into(),
                priority: None,
                resources: ResourceSelection::default(),
                execution_contexts: Vec::new(),
            },
        };
        let identity = IdentityContext::anonymous();
        let correlation = CorrelationContext::for_tests();
        for personal in [
            LookupAccess::Static(bearer_credential("personal-token")),
            LookupAccess::Delegated(lease()),
        ] {
            let lookup = PreScopeLookup::PerUser(personal);
            let execution = runtime
                .resolve_execution_credential_after_policy(
                    None,
                    "fake",
                    "echo",
                    "service",
                    &identity,
                    &correlation,
                    &lookup,
                )
                .await
                .unwrap_err();
            let execution_lookup = runtime
                .resolve_lookup_access_if_required(
                    LookupRequirement::ScopeResolution,
                    "fake",
                    &service_policy,
                    &ExecutionAccess::Static(bearer_credential("service-token")),
                    &lookup,
                )
                .await
                .unwrap_err();
            for error in [execution, execution_lookup] {
                assert_eq!(error.reason_code(), ReasonCode::ServiceActionDenied);
                assert_eq!(
                    error.message,
                    "policy lookup planner drifted from final policy selection"
                );
            }
        }
    }

    /// Lookup concealment passes on the caller's OAuth connection state from
    /// the delegated lease port, with its retry metadata, but conceals the
    /// same reasons from a provider and every other lease failure.
    #[test]
    fn delegated_lease_failures_pass_lookup_concealment() {
        let throttled = || {
            ProviderError::error(
                ReasonCode::UpstreamRateLimited,
                "records OAuth token refresh is rate limited",
            )
            .with_result(serde_json::json!({"retryAfterSeconds": 30}))
        };
        let lease_failures = [
            ProviderError::deny(ReasonCode::VersionConflict, "oauth_consent_pending"),
            ProviderError::error(ReasonCode::ConcurrencyLimited, "oauth_refresh_busy"),
            throttled(),
        ];
        for failure in lease_failures.clone() {
            let failure = port_failure(HostPort::DelegatedLease, failure);
            assert!(is_public_lease_failure(&failure));
            assert_eq!(public_lookup_scope_error(failure.clone()), failure);
        }
        let concealed = |error: ProviderError| {
            let public = public_lookup_scope_error(error);
            assert_eq!(public.reason_code(), ReasonCode::ScopeUnresolved);
            assert_eq!(
                public.message,
                "resource scope is not authorized or unavailable"
            );
            assert!(public.result.is_none());
        };
        for failure in lease_failures {
            assert!(!is_public_lease_failure(&failure));
            concealed(failure);
        }
        concealed(port_failure(
            HostPort::DelegatedLease,
            ProviderError::error(ReasonCode::UpstreamConnectionFailed, "oauth_provider"),
        ));
        // A reconnect requirement passes from any origin, as before.
        let reconnect = port_failure(
            HostPort::DelegatedLease,
            ProviderError::deny(ReasonCode::CredentialInvalid, "oauth_reconnect_required"),
        );
        assert_eq!(public_lookup_scope_error(reconnect.clone()), reconnect);
    }
}
