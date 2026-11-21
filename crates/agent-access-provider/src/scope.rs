//! Scope resolution: the one hook through which a provider names the
//! canonical resources an action operates on, before the host authorizes it.
use crate::{
    ContainmentError, ContainmentEvidence, ContainmentEvidenceLevel, CorrelationContext,
    InvocationIdentity, LookupAccess, ProviderState, ResourceScopes, TypedResourceSelector,
};
use serde_json::Value;

/// What a provider may use to resolve an action's resources. It carries no
/// admitted execution authority and no execution credential. The lookup
/// access, when present, is the one the host selected for this request; a
/// provider never chooses another or falls back to a shared credential.
#[derive(Debug, Clone, Copy)]
pub struct ScopeRequest<'a> {
    pub(crate) service: &'a str,
    pub(crate) action: &'a str,
    pub(crate) inputs: &'a Value,
    pub(crate) execution_context: &'a str,
    pub(crate) identity: &'a InvocationIdentity,
    pub(crate) correlation: &'a CorrelationContext,
    pub(crate) lookup_access: Option<&'a LookupAccess>,
    pub(crate) containment_evidence_level: ContainmentEvidenceLevel,
    pub(crate) containment_roots: &'a [TypedResourceSelector],
    pub(crate) locator_state: Option<&'a ProviderState>,
}

impl<'a> ScopeRequest<'a> {
    pub fn service(&self) -> &'a str {
        self.service
    }

    pub fn action(&self) -> &'a str {
        self.action
    }

    /// Caller-supplied inputs for the provider to validate.
    pub fn inputs(&self) -> &'a Value {
        self.inputs
    }

    /// The execution context the host selected, never a tool input.
    pub fn execution_context(&self) -> &'a str {
        self.execution_context
    }

    pub fn identity(&self) -> &'a InvocationIdentity {
        self.identity
    }

    pub fn correlation(&self) -> &'a CorrelationContext {
        self.correlation
    }

    /// Minimum evidence selected by the host from every viable policy predicate.
    pub fn containment_evidence_level(&self) -> ContainmentEvidenceLevel {
        self.containment_evidence_level
    }
    /// Policy-owned selector roots whose relationships a region proof requires.
    pub fn containment_roots(&self) -> &'a [TypedResourceSelector] {
        self.containment_roots
    }
    /// Opaque state returned by this operation's synchronous local locator hook.
    pub fn locator_state(&self) -> Option<&'a ProviderState> {
        self.locator_state
    }

    /// The host-selected lookup access, present only for actions whose
    /// descriptor requires lookup before policy and when a viable grant path
    /// exists. Delegated lookup access holds the operation's lease, which
    /// the same operation's execution reuses.
    pub fn lookup_access(&self) -> Option<&'a LookupAccess> {
        self.lookup_access
    }
}

/// A credential-free local phase. Configuration and signing material belong to
/// the provider instance; this request has no network or execution capability.
#[derive(Debug, Clone, Copy)]
pub struct LocalScopeRequest<'a> {
    pub(crate) service: &'a str,
    pub(crate) action: &'a str,
    pub(crate) inputs: &'a Value,
    pub(crate) execution_context: &'a str,
    pub(crate) identity: &'a InvocationIdentity,
    pub(crate) correlation: &'a CorrelationContext,
}
impl<'a> LocalScopeRequest<'a> {
    pub fn service(&self) -> &'a str {
        self.service
    }
    pub fn action(&self) -> &'a str {
        self.action
    }
    pub fn inputs(&self) -> &'a Value {
        self.inputs
    }
    pub fn execution_context(&self) -> &'a str {
        self.execution_context
    }
    pub fn identity(&self) -> &'a InvocationIdentity {
        self.identity
    }
    pub fn correlation(&self) -> &'a CorrelationContext {
        self.correlation
    }
}

/// The provider's explicit scalar or containment scope result. Containment
/// evidence cannot be mistaken for an empty scalar scope map.
#[non_exhaustive]
#[derive(Debug, Clone)]
pub enum ScopeEvidence {
    Scalar(ResourceScopes),
    Containment(ContainmentEvidence),
}

#[derive(Debug, Clone)]
pub struct ScopeResolution {
    evidence: ScopeEvidence,
    state: Option<ProviderState>,
}
impl ScopeResolution {
    pub fn resources(scopes: ResourceScopes) -> Self {
        Self {
            evidence: ScopeEvidence::Scalar(scopes),
            state: None,
        }
    }
    pub fn no_resources() -> Self {
        Self::resources(ResourceScopes::new())
    }
    pub fn containment(evidence: ContainmentEvidence) -> Self {
        Self {
            evidence: ScopeEvidence::Containment(evidence),
            state: None,
        }
    }
    pub fn with_state(mut self, state: ProviderState) -> Self {
        self.state = Some(state);
        self
    }
    pub fn evidence(&self) -> &ScopeEvidence {
        &self.evidence
    }
    pub fn scopes(&self) -> Result<&ResourceScopes, ContainmentError> {
        match &self.evidence {
            ScopeEvidence::Scalar(scopes) => Ok(scopes),
            ScopeEvidence::Containment(_) => Err(ContainmentError::InvalidEvidence),
        }
    }
    pub fn state(&self) -> Option<&ProviderState> {
        self.state.as_ref()
    }
    pub fn into_scopes(self) -> Result<ResourceScopes, ContainmentError> {
        match self.evidence {
            ScopeEvidence::Scalar(scopes) => Ok(scopes),
            ScopeEvidence::Containment(_) => Err(ContainmentError::InvalidEvidence),
        }
    }
    pub fn into_parts(self) -> (ScopeEvidence, Option<ProviderState>) {
        (self.evidence, self.state)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::{InvocationBuilder, ScopeRequestFixture, test_signing_key};
    use crate::{
        ContinuationFamily, ContinuationLifetime, ContinuationSigner, CredentialMode, Decision,
        HookPhase, ProviderError, ReasonCode,
    };
    use serde_json::json;

    #[test]
    fn local_scope_binding_checks_owner_route_and_context_without_lookup_material() {
        let family =
            ContinuationFamily::new("docs", "draft", 5, ContinuationLifetime::Durable, 256)
                .opened_during_scope_resolution();
        let signer = ContinuationSigner::new(Some(test_signing_key(17)));
        let identity = InvocationIdentity::new("alice", true);
        let admitted = InvocationBuilder::new("docs", "draft.view")
            .identity(identity.clone())
            .credential_mode(CredentialMode::PerUser)
            .build();
        let token = signer
            .seal(
                &family.bind(admitted.context(), "route-a"),
                b"verified draft facts",
            )
            .unwrap();
        let fixture = ScopeRequestFixture::new("docs", "draft.view", json!({})).identity(identity);
        assert!(fixture.request().lookup_access().is_none());
        let local = fixture.local_request();
        assert_eq!(
            signer
                .open_during_scope_resolution(&family.bind_local_scope(&local, "route-a"), &token)
                .unwrap(),
            b"verified draft facts"
        );
        assert!(
            signer
                .open_during_scope_resolution(&family.bind_local_scope(&local, "route-b"), &token)
                .is_err()
        );
        for changed in [
            fixture
                .clone()
                .identity(InvocationIdentity::new("bob", true)),
            fixture.clone().execution_context("another"),
        ] {
            assert!(
                signer
                    .open_during_scope_resolution(
                        &family.bind_local_scope(&changed.local_request(), "route-a"),
                        &token
                    )
                    .is_err()
            );
        }
        let with_state = fixture.locator_state(ProviderState::new(23_u64));
        assert_eq!(
            with_state
                .request()
                .locator_state()
                .unwrap()
                .downcast_ref::<u64>(),
            Ok(&23)
        );
    }

    #[test]
    fn local_reason_contract_is_narrow_and_never_admits_upstream_traces() {
        let hook =
            crate::host::hook_context("docs", "draft.view", HookPhase::ScopeLocatorValidation, &[]);
        for reason in ReasonCode::all() {
            for decision in [Decision::Deny, Decision::Error, Decision::Allow] {
                let expected = matches!(
                    (reason, &decision),
                    (ReasonCode::InputInvalid, Decision::Deny | Decision::Error)
                        | (ReasonCode::InvalidDraftHandle, Decision::Deny)
                        | (
                            ReasonCode::CursorSigningUnavailable
                                | ReasonCode::UpstreamProtocolFailed,
                            Decision::Error
                        )
                );
                let error = match decision {
                    Decision::Deny => ProviderError::deny(*reason, "fixed local failure"),
                    Decision::Error => ProviderError::error(*reason, "fixed local failure"),
                    Decision::Allow => ProviderError::allow(*reason, "fixed local failure"),
                };
                assert_eq!(
                    hook.check_failure(&error).is_ok(),
                    expected,
                    "{reason:?} {:?}",
                    error.decision()
                );
            }
            assert!(!reason.permits_provider_trace(HookPhase::ScopeLocatorValidation));
        }
        let error = ProviderError::deny(ReasonCode::InvalidDraftHandle, "invalid draft handle")
            .with_result(json!({"secret":"body"}))
            .with_audit(json!({"ancestor":"secret"}))
            .with_object_ids(json!({"id":"secret"}))
            .with_upstream(Some(404), Some(12));
        let clean = crate::host::strip_scope_locator_details(error);
        assert_eq!(clean.reason_code(), ReasonCode::InvalidDraftHandle);
        assert!(
            clean.result.is_none()
                && clean.audit.is_none()
                && clean.object_ids.is_none()
                && clean.upstream_status.is_none()
                && clean.upstream_duration_ms.is_none()
        );
        assert_eq!(clean.message, "invalid draft handle");
    }
}
