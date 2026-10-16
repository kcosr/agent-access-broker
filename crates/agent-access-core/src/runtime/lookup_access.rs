//! Lookup planning and selection: the material an action's upstream
//! metadata lookups use before policy (scope resolution) and at execution.
use super::*;

#[derive(Debug, Clone)]
pub(super) enum PreScopeLookup {
    None,
    PerUser(ExecutionCredential),
    Shared(ExecutionCredential),
}

impl PreScopeLookup {
    pub(super) fn as_ref(&self) -> Option<&ExecutionCredential> {
        match self {
            Self::None => None,
            Self::PerUser(credential) | Self::Shared(credential) => Some(credential),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum PreScopeLookupPlan {
    UsePerUserCredential,
    UseSharedLookupCredential,
    NoCandidateGrant,
}

impl BrokerRuntime {
    pub(super) async fn resolve_lookup_credential_if_required(
        &self,
        lookup: LookupRequirement,
        service: &str,
        policy: &PolicyDecision,
        execution_credential: Option<&ExecutionCredential>,
        pre_scope_lookup: &PreScopeLookup,
    ) -> Result<Option<ExecutionCredential>, ProviderError> {
        if !lookup.credential_required() {
            return Ok(None);
        }
        match (policy.credential_mode.as_str(), pre_scope_lookup) {
            ("per_user", PreScopeLookup::PerUser(credential)) => Ok(Some(credential.clone())),
            ("per_user", _) => execution_credential.cloned().map(Some).ok_or_else(|| {
                ProviderError::deny(
                    ReasonCode::CredentialNotProvisioned,
                    "selected credential mode is not provisioned",
                )
            }),
            ("service", PreScopeLookup::Shared(credential)) => Ok(Some(credential.clone())),
            ("service", PreScopeLookup::PerUser(_)) => Err(policy_planning_drift_error()),
            ("service", PreScopeLookup::None) => self.resolve_lookup_credential(service).map(Some),
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
                .resolve_execution_credential(service, "per_user", identity)
                .await
                .map(PreScopeLookup::PerUser),
            PreScopeLookupPlan::UseSharedLookupCredential => self
                .resolve_lookup_credential(service)
                .map(PreScopeLookup::Shared),
        }
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
