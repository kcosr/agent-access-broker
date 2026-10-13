//! What a provider hook may report. The host checks each outcome a provider
//! returns at the hook boundary: hook failures, late result-stream failures
//! and upstream trace classifications.
use crate::{
    Decision, HookPhase, ProviderError, ProviderReason, ProviderReasonDefinition, ReasonCode,
    UPSTREAM_RETRY_AFTER_MAX_SECONDS,
};
use serde_json::Value;

/// The provider hook a task runs, as the host supplies it: the service and
/// action, the hook phase, and the domain reasons the service's backend
/// registered (none for an imported service). The host constructs it with
/// [`crate::host::hook_context`] for every hook it runs; the phase is never
/// inferred from a reason.
#[derive(Debug, Clone)]
pub struct HookContext {
    service: String,
    action: String,
    phase: HookPhase,
    domain_reasons: &'static [&'static ProviderReasonDefinition],
}

/// Why the host rejected an outcome a provider reported. The host replaces
/// the outcome with its own `broker_provider_contract_failed` and records
/// this diagnostic internally, never the provider's code or message.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ContractViolation {
    /// A standard reason only the Broker host reports.
    HostOnlyReason,
    /// A provider-reportable standard reason with a decision or in a hook
    /// its contract does not allow.
    ReasonNotPermitted,
    /// An allow outcome other than an invocation's `verification_mismatch`
    /// with its verification result.
    AllowNotPermitted,
    /// A domain reason the service's backend did not register with this
    /// outcome, such as another module's or a modified definition.
    UnregisteredDomainReason,
    /// A host port's failure outside that port's allowlist.
    HostPortNotPermitted,
    /// An `upstream_rate_limited` failure without the upstream rate-limit
    /// result for the invoked service.
    RateLimitResultInvalid,
    /// A late result-stream failure classified outside the code-only stream
    /// subset and the backend's domain reasons, including any host-origin
    /// reason.
    StreamReasonNotPermitted,
    /// An upstream trace classified outside any provider hook.
    MissingHookContext,
    /// An upstream trace attributed to another service than its hook's.
    InconsistentHookContext,
}

impl ContractViolation {
    /// The bounded diagnostic the host records with its contract failure.
    pub fn diagnostic_code(self) -> &'static str {
        match self {
            Self::HostOnlyReason => "provider_reason_host_only",
            Self::ReasonNotPermitted => "provider_reason_not_permitted",
            Self::AllowNotPermitted => "provider_allow_not_permitted",
            Self::UnregisteredDomainReason => "provider_domain_reason_unregistered",
            Self::HostPortNotPermitted => "provider_host_port_not_permitted",
            Self::RateLimitResultInvalid => "provider_rate_limit_result_invalid",
            Self::StreamReasonNotPermitted => "provider_stream_reason_not_permitted",
            Self::MissingHookContext => "provider_hook_context_missing",
            Self::InconsistentHookContext => "provider_hook_context_inconsistent",
        }
    }
}

impl HookContext {
    pub(crate) fn new(
        service: String,
        action: String,
        phase: HookPhase,
        domain_reasons: &'static [&'static ProviderReasonDefinition],
    ) -> Self {
        Self {
            service,
            action,
            phase,
            domain_reasons,
        }
    }

    pub fn service(&self) -> &str {
        &self.service
    }

    pub fn action(&self) -> &str {
        &self.action
    }

    pub fn phase(&self) -> HookPhase {
        self.phase
    }

    /// The domain reasons the service's backend registered.
    pub fn domain_reasons(&self) -> &'static [&'static ProviderReasonDefinition] {
        self.domain_reasons
    }

    /// Whether the service's backend registered `definition`, compared by
    /// value: a same-spelled definition with another outcome is foreign.
    pub fn declares(&self, definition: &ProviderReasonDefinition) -> bool {
        self.domain_reasons
            .iter()
            .any(|declared| **declared == *definition)
    }

    /// Checks a failure this hook returned:
    /// - a host port's failure against the port's allowlist;
    /// - a domain reason against the backend's registration;
    /// - a standard reason against the provider-reportable subset for this
    ///   hook and decision, with `upstream_rate_limited` carrying the
    ///   upstream rate-limit result for this service;
    /// - an allow outcome only as an invocation's `verification_mismatch`
    ///   with its verification result.
    pub fn check_failure(&self, error: &ProviderError) -> Result<(), ContractViolation> {
        let reason = error.reason_code();
        let decision = error.decision();
        if let (Some(port), Some(code)) = (reason.host_port(), reason.standard()) {
            return port
                .permits(&decision, code)
                .then_some(())
                .ok_or(ContractViolation::HostPortNotPermitted);
        }
        if let Some(definition) = reason.domain() {
            return self
                .declares(definition)
                .then_some(())
                .ok_or(ContractViolation::UnregisteredDomainReason);
        }
        let Some(code) = reason.standard() else {
            return Err(ContractViolation::HostOnlyReason);
        };
        if decision == Decision::Allow {
            return code
                .permits_provider_allow(self.phase, error.result.is_some())
                .then_some(())
                .ok_or(ContractViolation::AllowNotPermitted);
        }
        if !code.is_provider_emittable() {
            return Err(ContractViolation::HostOnlyReason);
        }
        if !code.permits_provider_failure(&decision, self.phase) {
            return Err(ContractViolation::ReasonNotPermitted);
        }
        if code == ReasonCode::UpstreamRateLimited
            && !upstream_rate_limit_result(error.result.as_deref(), &self.service)
        {
            return Err(ContractViolation::RateLimitResultInvalid);
        }
        Ok(())
    }

    /// Checks a late result-stream failure's code. Only the code-only stream
    /// subset and the backend's domain reasons classify one; a host port's
    /// reason never does. The host keeps its own late-failure decision.
    pub fn check_late_stream(&self, reason: ProviderReason) -> Result<(), ContractViolation> {
        if reason.host_port().is_some() {
            return Err(ContractViolation::StreamReasonNotPermitted);
        }
        if let Some(definition) = reason.domain() {
            return self
                .declares(definition)
                .then_some(())
                .ok_or(ContractViolation::UnregisteredDomainReason);
        }
        reason
            .standard()
            .is_some_and(ReasonCode::permits_late_stream)
            .then_some(())
            .ok_or(ContractViolation::StreamReasonNotPermitted)
    }

    /// Checks an upstream trace classification. A trace confers no decision:
    /// any reason this hook may report qualifies, and a host port's reason
    /// within the port's allowlist.
    pub fn check_trace(&self, reason: ProviderReason) -> Result<(), ContractViolation> {
        if let (Some(port), Some(code), Some(decision)) = (
            reason.host_port(),
            reason.standard(),
            reason.fixed_decision(),
        ) {
            return port
                .permits(&decision, code)
                .then_some(())
                .ok_or(ContractViolation::HostPortNotPermitted);
        }
        if let Some(definition) = reason.domain() {
            return self
                .declares(definition)
                .then_some(())
                .ok_or(ContractViolation::UnregisteredDomainReason);
        }
        match reason.standard() {
            Some(code) if !code.is_provider_emittable() => Err(ContractViolation::HostOnlyReason),
            Some(code) if code.permits_provider_trace(self.phase) => Ok(()),
            _ => Err(ContractViolation::ReasonNotPermitted),
        }
    }
}

/// Whether `result` is the upstream rate-limit result for `service`, as
/// [`ProviderError::with_upstream_rate_limit`] writes it: `limitScope`
/// `upstream`, the invoked service, and a bounded wait with its time or
/// neither.
fn upstream_rate_limit_result(result: Option<&Value>, service: &str) -> bool {
    let Some(Value::Object(result)) = result else {
        return false;
    };
    if result.get("limitScope").and_then(Value::as_str) != Some("upstream")
        || result.get("service").and_then(Value::as_str) != Some(service)
    {
        return false;
    }
    match (result.get("retryAfterSeconds"), result.get("retryAt")) {
        (None, None) => true,
        (Some(seconds), Some(Value::String(_))) => seconds
            .as_u64()
            .is_some_and(|seconds| (1..=UPSTREAM_RETRY_AFTER_MAX_SECONDS).contains(&seconds)),
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::host::{HostPort, hook_context, port_failure};
    use crate::{
        AuthorityMismatch, ProviderFailureStatus, ProviderStateError, UpstreamRetryAfter,
        upstream_rate_limited,
    };
    use serde_json::json;

    static LOG_TOO_LARGE: ProviderReasonDefinition = ProviderReasonDefinition::deny(
        "example_log_too_large",
        ProviderFailureStatus::ContentTooLarge,
    );
    static QUEUE_FROZEN: ProviderReasonDefinition = ProviderReasonDefinition::error(
        "example_queue_frozen",
        ProviderFailureStatus::ServiceUnavailable,
    );
    static FOREIGN: ProviderReasonDefinition = ProviderReasonDefinition::deny(
        "other_log_too_large",
        ProviderFailureStatus::ContentTooLarge,
    );
    static MODIFIED: ProviderReasonDefinition = ProviderReasonDefinition::error(
        "example_log_too_large",
        ProviderFailureStatus::ContentTooLarge,
    );
    static REASONS: [&ProviderReasonDefinition; 2] = [&LOG_TOO_LARGE, &QUEUE_FROZEN];

    const PHASES: [HookPhase; 4] = [
        HookPhase::ScopeResolution,
        HookPhase::BodyAdmission,
        HookPhase::Invocation,
        HookPhase::CredentialVerification,
    ];

    fn hook(phase: HookPhase) -> HookContext {
        hook_context("example", "item.view", phase, &REASONS)
    }

    fn failure(decision: &Decision, code: ReasonCode) -> ProviderError {
        match decision {
            Decision::Deny => ProviderError::deny(code, "provider text"),
            Decision::Error => ProviderError::error(code, "provider text"),
            Decision::Allow => ProviderError::allow(code, "provider text"),
        }
    }

    /// The design's provider-reportable table: decisions and hook phases.
    #[test]
    fn standard_failures_follow_the_provider_table_in_every_phase() {
        use Decision::{Deny, Error};
        let s = HookPhase::ScopeResolution;
        let a = HookPhase::BodyAdmission;
        let i = HookPhase::Invocation;
        let v = HookPhase::CredentialVerification;
        let saiv: &[HookPhase] = &[s, a, i, v];
        let sai: &[HookPhase] = &[s, a, i];
        let table: &[(ReasonCode, &[Decision], &[HookPhase])] = &[
            (ReasonCode::InputInvalid, &[Deny, Error], saiv),
            (ReasonCode::BodyMalformed, &[Deny, Error], saiv),
            (ReasonCode::InvalidDraftHandle, &[Deny], sai),
            (ReasonCode::ServiceActionDenied, &[Deny], saiv),
            (ReasonCode::ScopeUnresolved, &[Deny], saiv),
            (ReasonCode::LocatorInvalid, &[Deny], saiv),
            (ReasonCode::CredentialNotProvisioned, &[Deny], saiv),
            (ReasonCode::GitRefDenied, &[Deny], saiv),
            (ReasonCode::WebhookDestinationDenied, &[Deny], saiv),
            (ReasonCode::CredentialInvalid, &[Deny, Error], saiv),
            (ReasonCode::ResourceNotFound, &[Deny, Error], saiv),
            (ReasonCode::VerificationMismatch, &[Deny], saiv),
            (ReasonCode::VersionConflict, &[Deny, Error], saiv),
            (ReasonCode::MutationVerificationFailed, &[Error], &[i]),
            (ReasonCode::BodySizeDenied, &[Deny], saiv),
            (ReasonCode::AttachmentSizeDenied, &[Deny], saiv),
            (ReasonCode::AttachmentIntegrityMismatch, &[Deny], saiv),
            (ReasonCode::BodyFormatUnsupported, &[Deny], saiv),
            (ReasonCode::ResponseFormatUnsupported, &[Deny], saiv),
            (ReasonCode::AttachmentMediaTypeDenied, &[Deny], saiv),
            (ReasonCode::UpstreamUnauthorized, &[Deny, Error], saiv),
            (ReasonCode::UpstreamForbidden, &[Deny, Error], saiv),
            (ReasonCode::UpstreamFailed, &[Error], saiv),
            (ReasonCode::UpstreamConnectionFailed, &[Error], saiv),
            (ReasonCode::UpstreamProtocolFailed, &[Deny, Error], saiv),
            (ReasonCode::CursorSigningUnavailable, &[Error], sai),
            (ReasonCode::UpstreamTimeout, &[Error], saiv),
            (ReasonCode::OperationFailed, &[Error], saiv),
            (ReasonCode::OperationCancelled, &[Error], saiv),
        ];
        for (code, decisions, phases) in table {
            assert!(code.is_provider_emittable(), "{code:?}");
            for phase in PHASES {
                for decision in [Deny, Error] {
                    let expected = if !phases.contains(&phase) || !decisions.contains(&decision) {
                        Err(ContractViolation::ReasonNotPermitted)
                    } else {
                        Ok(())
                    };
                    assert_eq!(
                        hook(phase).check_failure(&failure(&decision, *code)),
                        expected,
                        "{code:?} {decision:?} {phase:?}"
                    );
                }
            }
        }
        // `upstream_rate_limited` is reportable only through its helper.
        for phase in PHASES {
            assert_eq!(
                hook(phase).check_failure(&upstream_rate_limited("example", None)),
                Ok(())
            );
        }
        let reportable = table.iter().map(|(code, _, _)| *code).collect::<Vec<_>>();
        for code in ReasonCode::all() {
            if !reportable.contains(code) && *code != ReasonCode::UpstreamRateLimited {
                assert!(!code.is_provider_emittable(), "{code:?}");
                for phase in PHASES {
                    for decision in [Deny, Error] {
                        assert_eq!(
                            hook(phase).check_failure(&failure(&decision, *code)),
                            Err(ContractViolation::HostOnlyReason),
                            "{code:?} {decision:?} {phase:?}"
                        );
                    }
                }
            }
        }
    }

    #[test]
    fn only_an_invocations_verification_mismatch_with_its_result_reports_allow() {
        let mismatch = ProviderError::allow_with_result(
            ReasonCode::VerificationMismatch,
            "mismatch",
            json!({"verified": false}),
        );
        for phase in PHASES {
            let expected = if phase == HookPhase::Invocation {
                Ok(())
            } else {
                Err(ContractViolation::AllowNotPermitted)
            };
            assert_eq!(hook(phase).check_failure(&mismatch), expected, "{phase:?}");
        }
        let invocation = hook(HookPhase::Invocation);
        assert_eq!(
            invocation.check_failure(&ProviderError::allow(
                ReasonCode::VerificationMismatch,
                "no result"
            )),
            Err(ContractViolation::AllowNotPermitted)
        );
        assert_eq!(
            invocation.check_failure(&ProviderError::allow_with_result(
                ReasonCode::InputInvalid,
                "allowed",
                json!({}),
            )),
            Err(ContractViolation::AllowNotPermitted)
        );
    }

    #[test]
    fn domain_reasons_are_the_backends_own_registered_definitions() {
        for phase in PHASES {
            for definition in REASONS {
                assert_eq!(
                    hook(phase).check_failure(&ProviderError::domain(definition, "domain")),
                    Ok(()),
                    "{phase:?}"
                );
            }
            for definition in [&FOREIGN, &MODIFIED] {
                assert_eq!(
                    hook(phase).check_failure(&ProviderError::domain(definition, "domain")),
                    Err(ContractViolation::UnregisteredDomainReason),
                    "{phase:?}"
                );
            }
            let imported = hook_context("imported", "act", phase, &[]);
            assert_eq!(
                imported.check_failure(&ProviderError::domain(&LOG_TOO_LARGE, "domain")),
                Err(ContractViolation::UnregisteredDomainReason)
            );
        }
    }

    #[test]
    fn host_port_failures_pass_within_their_port_allowlist() {
        let busy = port_failure(
            HostPort::DelegatedLease,
            ProviderError::error(ReasonCode::ConcurrencyLimited, "refresh busy"),
        );
        let state = ProviderError::from(ProviderStateError::Missing);
        let authority = ProviderError::from(AuthorityMismatch::NotSearch);
        for phase in PHASES {
            for error in [&busy, &state, &authority] {
                assert_eq!(hook(phase).check_failure(error), Ok(()), "{error:?}");
            }
        }
        // The same reasons without the port are host-only.
        assert_eq!(
            hook(HookPhase::Invocation).check_failure(&ProviderError::error(
                ReasonCode::ConcurrencyLimited,
                "refresh busy"
            )),
            Err(ContractViolation::HostOnlyReason)
        );
        assert_eq!(
            hook(HookPhase::Invocation).check_failure(&ProviderError::error(
                ReasonCode::BrokerProviderContractFailed,
                "contract"
            )),
            Err(ContractViolation::HostOnlyReason)
        );
        // A port failure outside the port's allowlist.
        for (port, error) in [
            (
                HostPort::DelegatedLease,
                ProviderError::error(ReasonCode::AuditUnavailable, "audit"),
            ),
            (
                HostPort::AdmittedOperation,
                ProviderError::error(ReasonCode::OperationFailed, "failed"),
            ),
        ] {
            assert_eq!(
                hook(HookPhase::Invocation).check_failure(&port_failure(port, error)),
                Err(ContractViolation::HostPortNotPermitted)
            );
        }
    }

    #[test]
    fn sdk_contract_failures_keep_their_reason_and_diagnostic_code() {
        for (error, code) in [
            (
                ProviderError::from(ProviderStateError::TypeMismatch),
                "provider_state_type_mismatch",
            ),
            (
                ProviderError::from(AuthorityMismatch::NotResources),
                "provider_authority_not_resources",
            ),
        ] {
            assert_eq!(
                error.reason_code().host_port(),
                Some(HostPort::AdmittedOperation)
            );
            assert_eq!(error.decision(), Decision::Error);
            assert_eq!(
                error.reason_code(),
                ReasonCode::BrokerProviderContractFailed
            );
            assert_eq!(error.internal_diagnostic_code, Some(code));
        }
    }

    #[test]
    fn upstream_rate_limits_carry_the_helpers_result_for_the_invoked_service() {
        let invocation = hook(HookPhase::Invocation);
        let waiting = upstream_rate_limited("example", Some(UpstreamRetryAfter::after_seconds(30)));
        assert_eq!(invocation.check_failure(&waiting), Ok(()));
        for result in [
            None,
            Some(json!({"limitScope": "upstream", "service": "other"})),
            Some(json!({"limitScope": "broker", "service": "example"})),
            Some(
                json!({"limitScope": "upstream", "service": "example", "retryAfterSeconds": 0, "retryAt": "2026-10-13T00:00:00Z"}),
            ),
            Some(
                json!({"limitScope": "upstream", "service": "example", "retryAfterSeconds": 86_401, "retryAt": "2026-10-13T00:00:00Z"}),
            ),
            Some(json!({"limitScope": "upstream", "service": "example", "retryAfterSeconds": 30})),
        ] {
            let mut error = ProviderError::error(ReasonCode::UpstreamRateLimited, "throttled");
            error.result = result.map(Box::new);
            assert_eq!(
                invocation.check_failure(&error),
                Err(ContractViolation::RateLimitResultInvalid),
                "{error:?}"
            );
        }
    }

    #[test]
    fn late_streams_carry_only_the_code_only_subset_or_registered_domain_codes() {
        let invocation = hook(HookPhase::Invocation);
        for code in ReasonCode::all() {
            let expected = if code.permits_late_stream() {
                Ok(())
            } else {
                Err(ContractViolation::StreamReasonNotPermitted)
            };
            assert_eq!(
                invocation.check_late_stream((*code).into()),
                expected,
                "{code:?}"
            );
        }
        assert_eq!(
            invocation.check_late_stream((&LOG_TOO_LARGE).into()),
            Ok(())
        );
        assert_eq!(
            invocation.check_late_stream((&FOREIGN).into()),
            Err(ContractViolation::UnregisteredDomainReason)
        );
        let lease = port_failure(
            HostPort::DelegatedLease,
            ProviderError::error(ReasonCode::UpstreamConnectionFailed, "lease"),
        );
        assert_eq!(
            invocation.check_late_stream(lease.reason_code()),
            Err(ContractViolation::StreamReasonNotPermitted)
        );
    }

    #[test]
    fn traces_use_reasons_admitted_for_their_hook() {
        for phase in PHASES {
            let hook = hook(phase);
            assert_eq!(hook.check_trace(ReasonCode::UpstreamTimeout.into()), Ok(()));
            assert_eq!(hook.check_trace((&QUEUE_FROZEN).into()), Ok(()));
            assert_eq!(
                hook.check_trace((&MODIFIED).into()),
                Err(ContractViolation::UnregisteredDomainReason)
            );
            assert_eq!(
                hook.check_trace(ReasonCode::RateLimited.into()),
                Err(ContractViolation::HostOnlyReason)
            );
            let expected = if phase == HookPhase::Invocation {
                Ok(())
            } else {
                Err(ContractViolation::ReasonNotPermitted)
            };
            assert_eq!(
                hook.check_trace(ReasonCode::MutationVerificationFailed.into()),
                expected
            );
            let lease = port_failure(
                HostPort::DelegatedLease,
                ProviderError::error(ReasonCode::ConcurrencyLimited, "busy"),
            );
            assert_eq!(hook.check_trace(lease.reason_code()), Ok(()));
        }
    }
}
