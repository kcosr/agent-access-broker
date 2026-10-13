//! Provider-owned domain reasons and the reason handles provider failures,
//! streams and traces carry.
use crate::host::HostPort;
use crate::{Decision, ReasonCode, ReasonCodeId, is_reason_code_id};
use std::borrow::Cow;
use std::fmt;

/// The HTTP status a domain reason fixes. This closed set preserves the CLI
/// exit mapping: 400 and 404 exit 3; 403, 409, 413 and 415 exit 2; 424, 502
/// and 504 exit 4; 500 and 503 exit 5.
///
/// It has no success, redirect, authentication challenge, rate-limit,
/// cancellation or method outcome: upstream throttling uses the standard
/// `upstream_rate_limited` reason, and a domain status never creates a
/// challenge, `Retry-After` header, admission decision or retry promise.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ProviderFailureStatus {
    /// 400
    BadRequest,
    /// 403
    Forbidden,
    /// 404
    NotFound,
    /// 409
    Conflict,
    /// 413
    ContentTooLarge,
    /// 415
    UnsupportedMediaType,
    /// 424
    FailedDependency,
    /// 500
    InternalServerError,
    /// 502
    BadGateway,
    /// 503
    ServiceUnavailable,
    /// 504
    GatewayTimeout,
}

impl ProviderFailureStatus {
    pub const fn as_u16(self) -> u16 {
        match self {
            Self::BadRequest => 400,
            Self::Forbidden => 403,
            Self::NotFound => 404,
            Self::Conflict => 409,
            Self::ContentTooLarge => 413,
            Self::UnsupportedMediaType => 415,
            Self::FailedDependency => 424,
            Self::InternalServerError => 500,
            Self::BadGateway => 502,
            Self::ServiceUnavailable => 503,
            Self::GatewayTimeout => 504,
        }
    }

    /// Every status, in ascending order.
    pub const fn all() -> &'static [Self] {
        &[
            Self::BadRequest,
            Self::Forbidden,
            Self::NotFound,
            Self::Conflict,
            Self::ContentTooLarge,
            Self::UnsupportedMediaType,
            Self::FailedDependency,
            Self::InternalServerError,
            Self::BadGateway,
            Self::ServiceUnavailable,
            Self::GatewayTimeout,
        ]
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
enum FixedDecision {
    Deny,
    Error,
}

impl FixedDecision {
    fn decision(self) -> Decision {
        match self {
            Self::Deny => Decision::Deny,
            Self::Error => Decision::Error,
        }
    }
}

/// A failure reason one native backend defines for its own domain, with a
/// fixed decision and HTTP status.
///
/// Declare each as a `static` and list it in the backend's registration with
/// [`BackendRegistration::with_domain_reasons`](crate::BackendRegistration::with_domain_reasons).
/// The code starts with the backend kind (hyphens written as underscores)
/// and `_`, followed by a nonempty name; the Broker checks this, and that no
/// other selected module or standard reason uses the same code, before it
/// serves. Adding, removing or renaming a domain reason, or changing its
/// outcome, is an incompatible module change.
///
/// ```
/// use agent_access_provider::{ProviderFailureStatus, ProviderReasonDefinition};
///
/// pub static EXPORT_TOO_LARGE: ProviderReasonDefinition = ProviderReasonDefinition::deny(
///     "example_export_too_large",
///     ProviderFailureStatus::ContentTooLarge,
/// );
/// assert_eq!(EXPORT_TOO_LARGE.status().as_u16(), 413);
/// ```
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ProviderReasonDefinition {
    code: &'static str,
    decision: FixedDecision,
    status: ProviderFailureStatus,
}

impl ProviderReasonDefinition {
    /// A reason whose failures are always `decision = deny`.
    ///
    /// # Panics
    ///
    /// If `code` is not a reason identifier (`^[a-z][a-z0-9_]{0,63}$`). In a
    /// `static` or `const` this is a compile error.
    pub const fn deny(code: &'static str, status: ProviderFailureStatus) -> Self {
        Self::new(code, FixedDecision::Deny, status)
    }

    /// A reason whose failures are always `decision = error`.
    ///
    /// # Panics
    ///
    /// If `code` is not a reason identifier (`^[a-z][a-z0-9_]{0,63}$`). In a
    /// `static` or `const` this is a compile error.
    pub const fn error(code: &'static str, status: ProviderFailureStatus) -> Self {
        Self::new(code, FixedDecision::Error, status)
    }

    const fn new(
        code: &'static str,
        decision: FixedDecision,
        status: ProviderFailureStatus,
    ) -> Self {
        assert!(
            is_reason_code_id(code),
            "a domain reason code must be 1 to 64 lowercase ASCII letters, digits or \
             underscores, starting with a letter"
        );
        Self {
            code,
            decision,
            status,
        }
    }

    pub const fn code(&self) -> &'static str {
        self.code
    }

    /// The wire identifier responses and audit records carry.
    pub fn id(&self) -> ReasonCodeId {
        ReasonCodeId::from_valid(Cow::Borrowed(self.code))
    }

    /// Deny or error, never allow.
    pub fn decision(&self) -> Decision {
        self.decision.decision()
    }

    pub const fn status(&self) -> ProviderFailureStatus {
        self.status
    }
}

/// A reason as a provider failure, result stream or upstream trace carries
/// it: a standard [`ReasonCode`], one of the backend's registered
/// [`ProviderReasonDefinition`]s, or a failure a host port produced.
///
/// Handles compare by value. The host checks a domain handle against the
/// definitions its backend registered, so a same-spelled definition the
/// backend did not register, or one with a different outcome, is a contract
/// failure. A host-origin handle keeps the decision the host port chose; the
/// provider can pass it on but not change it.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct ProviderReason(Origin);

#[derive(Clone, Copy, PartialEq, Eq, Hash)]
enum Origin {
    Standard(ReasonCode),
    Domain(&'static ProviderReasonDefinition),
    Host {
        port: HostPort,
        decision: FixedDecision,
        code: ReasonCode,
    },
}

impl ProviderReason {
    /// The standard reason, including one a host port passed on.
    pub fn standard(&self) -> Option<ReasonCode> {
        match self.0 {
            Origin::Standard(code) | Origin::Host { code, .. } => Some(code),
            Origin::Domain(_) => None,
        }
    }

    /// The backend's domain definition, if this is a domain reason.
    pub fn domain(&self) -> Option<&'static ProviderReasonDefinition> {
        match self.0 {
            Origin::Domain(definition) => Some(definition),
            Origin::Standard(_) | Origin::Host { .. } => None,
        }
    }

    /// The host port that produced this failure, if it came from one.
    pub fn host_port(&self) -> Option<HostPort> {
        match self.0 {
            Origin::Host { port, .. } => Some(port),
            Origin::Standard(_) | Origin::Domain(_) => None,
        }
    }

    /// The decision this reason fixes: a domain definition's, or the host
    /// port's. A standard reason leaves the decision to its failure.
    pub fn fixed_decision(&self) -> Option<Decision> {
        match self.0 {
            Origin::Standard(_) => None,
            Origin::Domain(definition) => Some(definition.decision()),
            Origin::Host { decision, .. } => Some(decision.decision()),
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self.0 {
            Origin::Standard(code) | Origin::Host { code, .. } => code.as_str(),
            Origin::Domain(definition) => definition.code(),
        }
    }

    /// The wire identifier responses and audit records carry.
    pub fn id(&self) -> ReasonCodeId {
        match self.0 {
            Origin::Standard(code) | Origin::Host { code, .. } => code.into(),
            Origin::Domain(definition) => definition.id(),
        }
    }

    pub fn http_status(&self) -> u16 {
        match self.0 {
            Origin::Standard(code) | Origin::Host { code, .. } => code.http_status(),
            Origin::Domain(definition) => definition.status().as_u16(),
        }
    }

    /// A host-origin handle for a failure `port` produced. Only
    /// [`crate::host::port_failure`] creates one.
    pub(crate) fn host(port: HostPort, decision: &Decision, code: ReasonCode) -> Option<Self> {
        let decision = match decision {
            Decision::Deny => FixedDecision::Deny,
            Decision::Error => FixedDecision::Error,
            Decision::Allow => return None,
        };
        Some(Self(Origin::Host {
            port,
            decision,
            code,
        }))
    }
}

impl From<ReasonCode> for ProviderReason {
    fn from(code: ReasonCode) -> Self {
        Self(Origin::Standard(code))
    }
}

impl From<&'static ProviderReasonDefinition> for ProviderReason {
    fn from(definition: &'static ProviderReasonDefinition) -> Self {
        Self(Origin::Domain(definition))
    }
}

impl From<ProviderReason> for ReasonCodeId {
    fn from(reason: ProviderReason) -> Self {
        reason.id()
    }
}

/// Equal when this is that standard reason, including one a host port
/// passed on. A domain reason never equals a standard one.
impl PartialEq<ReasonCode> for ProviderReason {
    fn eq(&self, other: &ReasonCode) -> bool {
        self.standard() == Some(*other)
    }
}

impl PartialEq<ProviderReason> for ReasonCode {
    fn eq(&self, other: &ProviderReason) -> bool {
        other == self
    }
}

impl fmt::Debug for ProviderReason {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.0 {
            Origin::Standard(code) => fmt::Debug::fmt(&code, formatter),
            Origin::Domain(definition) => formatter
                .debug_tuple("Domain")
                .field(&definition.code())
                .finish(),
            Origin::Host {
                port,
                decision,
                code,
            } => formatter
                .debug_struct("Host")
                .field("port", &port)
                .field("decision", &decision)
                .field("code", &code)
                .finish(),
        }
    }
}

impl fmt::Display for ProviderReason {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// The prefix a native backend's domain reason codes start with: its kind
/// with hyphens written as underscores, then `_`.
pub fn domain_reason_prefix(kind: &str) -> String {
    format!("{}_", kind.replace('-', "_"))
}

#[cfg(test)]
mod tests {
    use super::*;

    static QUOTA: ProviderReasonDefinition = ProviderReasonDefinition::error(
        "example_quota_exhausted",
        ProviderFailureStatus::ServiceUnavailable,
    );
    static TOO_LARGE: ProviderReasonDefinition = ProviderReasonDefinition::deny(
        "example_export_too_large",
        ProviderFailureStatus::ContentTooLarge,
    );
    static TOO_LARGE_COPY: ProviderReasonDefinition = ProviderReasonDefinition::deny(
        "example_export_too_large",
        ProviderFailureStatus::ContentTooLarge,
    );
    static TOO_LARGE_ERROR: ProviderReasonDefinition = ProviderReasonDefinition::error(
        "example_export_too_large",
        ProviderFailureStatus::ContentTooLarge,
    );

    #[test]
    fn statuses_are_the_closed_failure_set() {
        assert_eq!(
            ProviderFailureStatus::all()
                .iter()
                .map(|status| status.as_u16())
                .collect::<Vec<_>>(),
            [400, 403, 404, 409, 413, 415, 424, 500, 502, 503, 504]
        );
    }

    #[test]
    fn definitions_fix_their_outcome() {
        assert_eq!(QUOTA.code(), "example_quota_exhausted");
        assert_eq!(QUOTA.decision(), Decision::Error);
        assert_eq!(QUOTA.status(), ProviderFailureStatus::ServiceUnavailable);
        assert_eq!(TOO_LARGE.decision(), Decision::Deny);
        assert_eq!(TOO_LARGE.id().as_str(), "example_export_too_large");
        let reason = ProviderReason::from(&TOO_LARGE);
        assert_eq!(reason.domain(), Some(&TOO_LARGE));
        assert_eq!(reason.standard(), None);
        assert_eq!(reason.fixed_decision(), Some(Decision::Deny));
        assert_eq!(reason.http_status(), 413);
        assert_eq!(
            ReasonCodeId::from(reason).as_str(),
            "example_export_too_large"
        );
    }

    #[test]
    #[should_panic(expected = "a domain reason code must be")]
    fn definitions_reject_invalid_codes() {
        let code: &'static str = Box::leak("Example-Reason".to_owned().into_boxed_str());
        let _ = ProviderReasonDefinition::deny(code, ProviderFailureStatus::BadRequest);
    }

    #[test]
    fn handles_compare_by_value() {
        assert_eq!(
            ProviderReason::from(&TOO_LARGE),
            ProviderReason::from(&TOO_LARGE_COPY)
        );
        assert_ne!(
            ProviderReason::from(&TOO_LARGE),
            ProviderReason::from(&TOO_LARGE_ERROR)
        );
        assert_ne!(
            ProviderReason::from(&TOO_LARGE),
            ProviderReason::from(&QUOTA)
        );
        let standard = ProviderReason::from(ReasonCode::BodySizeDenied);
        assert_eq!(standard, ReasonCode::BodySizeDenied);
        assert_eq!(standard.fixed_decision(), None);
        assert_ne!(ProviderReason::from(&TOO_LARGE), ReasonCode::BodySizeDenied);
    }

    #[test]
    fn host_handles_keep_their_port_and_decision() {
        let host = ProviderReason::host(
            HostPort::DelegatedLease,
            &Decision::Error,
            ReasonCode::ConcurrencyLimited,
        )
        .unwrap();
        assert_eq!(host, ReasonCode::ConcurrencyLimited);
        assert_ne!(host, ProviderReason::from(ReasonCode::ConcurrencyLimited));
        assert_eq!(host.host_port(), Some(HostPort::DelegatedLease));
        assert_eq!(host.fixed_decision(), Some(Decision::Error));
        assert_eq!(host.http_status(), 429);
        assert!(
            ProviderReason::host(
                HostPort::DelegatedLease,
                &Decision::Allow,
                ReasonCode::InputInvalid
            )
            .is_none()
        );
    }

    #[test]
    fn prefixes_normalize_hyphens() {
        assert_eq!(domain_reason_prefix("cloudbees_ci"), "cloudbees_ci_");
        assert_eq!(
            domain_reason_prefix("gitlab-dedicated"),
            "gitlab_dedicated_"
        );
    }
}
