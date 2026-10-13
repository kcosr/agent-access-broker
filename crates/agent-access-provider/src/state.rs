//! Provider-owned state carried within one prepared operation: from scope
//! resolution, through multipart body admission, to dispatch. The host
//! carries it without inspecting, mutating, serializing or merging it.
use crate::{BrokerBodyPartSpec, ProviderError, ReasonCode};
use std::any::Any;
use std::sync::Arc;
use thiserror::Error;

/// Opaque in-process state a provider hands to its own later hooks within
/// one prepared operation. The prepared operation pins the provider instance,
/// so state never reaches another runtime generation's provider.
///
/// Contents are owned and `'static`; references into configuration or a
/// temporary request cannot escape through it. Cloning shares the same value
/// rather than copying it. Prefer immutable snapshots: interior mutation is
/// the provider's responsibility, including under cancellation and
/// concurrent use. Debug output never shows the contents.
#[derive(Clone)]
pub struct ProviderState(Arc<dyn Any + Send + Sync>);

impl ProviderState {
    pub fn new<T: Any + Send + Sync>(value: T) -> Self {
        Self(Arc::new(value))
    }

    /// The state as `T`, or [`ProviderStateError::TypeMismatch`] when it
    /// holds another type.
    pub fn downcast_ref<T: Any + Send + Sync>(&self) -> Result<&T, ProviderStateError> {
        self.0
            .downcast_ref::<T>()
            .ok_or(ProviderStateError::TypeMismatch)
    }

    /// Required state of type `T`: missing state and a different type both
    /// fail closed.
    pub fn require<T: Any + Send + Sync>(
        state: Option<&ProviderState>,
    ) -> Result<&T, ProviderStateError> {
        state
            .ok_or(ProviderStateError::Missing)?
            .downcast_ref::<T>()
    }

    /// Optional state of type `T`: no state is `None`, but state of a
    /// different type still fails closed.
    pub fn optional<T: Any + Send + Sync>(
        state: Option<&ProviderState>,
    ) -> Result<Option<&T>, ProviderStateError> {
        state.map(ProviderState::downcast_ref::<T>).transpose()
    }

    /// Whether both handles share one value.
    pub fn same(&self, other: &ProviderState) -> bool {
        Arc::ptr_eq(&self.0, &other.0)
    }
}

impl std::fmt::Debug for ProviderState {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("ProviderState(<redacted>)")
    }
}

/// A provider hook found its own required state missing or of another type.
/// This is an SDK invariant failure, not an upstream or caller error; the
/// host reports it as a provider contract failure without the state contents.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum ProviderStateError {
    #[error("required provider state is missing")]
    Missing,
    #[error("provider state has an unexpected type")]
    TypeMismatch,
}

impl ProviderStateError {
    pub fn diagnostic_code(self) -> &'static str {
        match self {
            Self::Missing => "provider_state_missing",
            Self::TypeMismatch => "provider_state_type_mismatch",
        }
    }
}

impl From<ProviderStateError> for ProviderError {
    fn from(error: ProviderStateError) -> Self {
        ProviderError::error(
            ReasonCode::OperationFailed,
            "provider operation state is unavailable",
        )
        .with_internal_diagnostic_code(error.diagnostic_code())
    }
}

/// What multipart body admission does with the operation's provider state.
/// There is no default: a provider states whether it keeps, replaces or
/// clears the state it received.
#[derive(Debug, Clone)]
pub enum StateDisposition {
    Keep,
    /// Replaces the whole state; a provider needing both its scope and
    /// admission metadata composes them into one value.
    Replace(ProviderState),
    Clear,
}

/// The outcome of multipart body admission: the parts the host may accept,
/// and the provider state handed to the same operation's invocation.
#[derive(Debug, Clone)]
pub struct BodyAdmission {
    part_specs: Vec<BrokerBodyPartSpec>,
    state: StateDisposition,
}

impl BodyAdmission {
    pub fn new(part_specs: Vec<BrokerBodyPartSpec>, state: StateDisposition) -> Self {
        Self { part_specs, state }
    }

    pub fn part_specs(&self) -> &[BrokerBodyPartSpec] {
        &self.part_specs
    }

    pub fn state(&self) -> &StateDisposition {
        &self.state
    }

    pub fn into_parts(self) -> (Vec<BrokerBodyPartSpec>, StateDisposition) {
        (self.part_specs, self.state)
    }
}

impl StateDisposition {
    /// The state after this disposition is applied to `current`.
    pub fn apply(self, current: Option<ProviderState>) -> Option<ProviderState> {
        match self {
            Self::Keep => current,
            Self::Replace(state) => Some(state),
            Self::Clear => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Debug, PartialEq)]
    struct Scope(u64);

    #[derive(Debug, PartialEq)]
    struct Admission(&'static str);

    #[test]
    fn state_downcasts_to_its_own_type_and_fails_closed_otherwise() {
        let state = ProviderState::new(Scope(7));
        assert_eq!(state.downcast_ref::<Scope>(), Ok(&Scope(7)));
        assert_eq!(
            state.downcast_ref::<Admission>(),
            Err(ProviderStateError::TypeMismatch)
        );
        assert_eq!(ProviderState::require::<Scope>(Some(&state)), Ok(&Scope(7)));
        assert_eq!(
            ProviderState::require::<Scope>(None),
            Err(ProviderStateError::Missing)
        );
        assert_eq!(
            ProviderState::require::<Admission>(Some(&state)),
            Err(ProviderStateError::TypeMismatch)
        );
        assert_eq!(ProviderState::optional::<Scope>(None), Ok(None));
        assert_eq!(
            ProviderState::optional::<Admission>(Some(&state)),
            Err(ProviderStateError::TypeMismatch)
        );
    }

    #[test]
    fn clones_share_identity_and_debug_is_redacted() {
        let state = ProviderState::new(Admission("secret-admission-detail"));
        let clone = state.clone();
        assert!(clone.same(&state));
        assert!(!ProviderState::new(Admission("secret-admission-detail")).same(&state));
        assert_eq!(format!("{state:?}"), "ProviderState(<redacted>)");
        let admission = BodyAdmission::new(Vec::new(), StateDisposition::Replace(state));
        assert!(!format!("{admission:?}").contains("secret-admission-detail"));
    }

    #[test]
    fn dispositions_keep_replace_or_clear_the_whole_state() {
        let scope = ProviderState::new(Scope(1));
        let admission = ProviderState::new(Admission("metadata"));
        let kept = StateDisposition::Keep.apply(Some(scope.clone())).unwrap();
        assert!(kept.same(&scope));
        assert!(StateDisposition::Keep.apply(None).is_none());
        let replaced = StateDisposition::Replace(admission.clone())
            .apply(Some(scope.clone()))
            .unwrap();
        assert!(replaced.same(&admission));
        assert_eq!(
            replaced.downcast_ref::<Scope>(),
            Err(ProviderStateError::TypeMismatch)
        );
        assert!(StateDisposition::Clear.apply(Some(scope)).is_none());
    }

    #[test]
    fn invariant_failures_map_to_a_provider_contract_error_without_contents() {
        for (error, code) in [
            (ProviderStateError::Missing, "provider_state_missing"),
            (
                ProviderStateError::TypeMismatch,
                "provider_state_type_mismatch",
            ),
        ] {
            let mapped = ProviderError::from(error);
            assert_eq!(mapped.decision, crate::Decision::Error);
            assert_eq!(mapped.reason_code, ReasonCode::OperationFailed);
            assert_eq!(mapped.internal_diagnostic_code, Some(code));
            assert!(mapped.result.is_none() && mapped.audit.is_none());
        }
    }
}
