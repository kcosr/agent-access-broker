//! Scope resolution: the one hook through which a provider names the
//! canonical resources an action operates on, before the host authorizes it.
use crate::{CorrelationContext, InvocationIdentity, LookupAccess, ProviderState, ResourceScopes};
use serde_json::Value;

/// What a provider may use to resolve an action's resources. It carries no
/// admitted execution authority and no execution credential. The lookup
/// access, when present, is the one the host selected for this request; a
/// provider never chooses another or falls back to a shared credential.
#[derive(Clone, Copy)]
pub struct ScopeRequest<'a> {
    pub(crate) service: &'a str,
    pub(crate) action: &'a str,
    pub(crate) inputs: &'a Value,
    pub(crate) execution_context: &'a str,
    pub(crate) identity: &'a InvocationIdentity,
    pub(crate) correlation: &'a CorrelationContext,
    pub(crate) lookup_access: Option<&'a LookupAccess>,
}

impl std::fmt::Debug for ScopeRequest<'_> {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ScopeRequest")
            .field("service", &self.service)
            .field("action", &self.action)
            .field("inputs", &"[REDACTED]")
            .field("execution_context", &self.execution_context)
            .field("identity", &self.identity)
            .field("correlation", &self.correlation)
            .field("lookup_access", &self.lookup_access)
            .finish()
    }
}

impl<'a> ScopeRequest<'a> {
    pub fn service(&self) -> &'a str {
        self.service
    }

    pub fn action(&self) -> &'a str {
        self.action
    }

    /// Inputs at scope resolution. Declared secret payload fields can still
    /// contain opaque references; validate them with the action's
    /// `reference_input_schema` and do not use their values to resolve scope.
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

    /// The host-selected lookup access, present only for actions whose
    /// descriptor requires lookup before policy and when a viable grant path
    /// exists. Delegated lookup access holds the operation's lease, which
    /// the same operation's execution reuses.
    pub fn lookup_access(&self) -> Option<&'a LookupAccess> {
        self.lookup_access
    }
}

/// The canonical resource scopes an action names, plus optional provider
/// state for the same prepared operation's later hooks.
#[derive(Debug, Clone)]
pub struct ScopeResolution {
    scopes: ResourceScopes,
    state: Option<ProviderState>,
}

impl ScopeResolution {
    /// Canonical resource scopes resolved for the action.
    pub fn resources(scopes: ResourceScopes) -> Self {
        Self {
            scopes,
            state: None,
        }
    }

    /// An action-only provider names no resources.
    pub fn no_resources() -> Self {
        Self::resources(ResourceScopes::new())
    }

    pub fn with_state(mut self, state: ProviderState) -> Self {
        self.state = Some(state);
        self
    }

    pub fn scopes(&self) -> &ResourceScopes {
        &self.scopes
    }

    pub fn state(&self) -> Option<&ProviderState> {
        self.state.as_ref()
    }

    pub fn into_scopes(self) -> ResourceScopes {
        self.scopes
    }

    pub fn into_parts(self) -> (ResourceScopes, Option<ProviderState>) {
        (self.scopes, self.state)
    }
}
