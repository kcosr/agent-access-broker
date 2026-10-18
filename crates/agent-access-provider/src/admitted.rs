//! What the host admitted for one operation: the read-only context shared by
//! multipart admission and invocation, and the invocation built from it.
use crate::{
    BrokerBodyPart, CorrelationContext, CredentialMode, ExecutionAccess, InvocationIdentity,
    LookupAccess, ProviderError, ProviderState, ReasonCode, ResourceAttributes, ResourceScopes,
    SearchAuthorization,
};
use serde_json::Value;
use std::sync::Arc;
use thiserror::Error;

/// The exact authority the host admitted, chosen from the action's validated
/// contract: an ordinary scoped action never receives empty resource
/// authority, an action-only action never inherits resources, and a search
/// action receives its complete normalized clause boundary.
#[non_exhaustive]
#[derive(Debug, Clone)]
pub enum InvocationAuthority {
    /// An action without a resource scope.
    ActionOnly,
    /// The canonical resources one admitted grant covers.
    Resources(ResourceScopes),
    /// The search boundary a search action must enforce.
    Search(SearchAuthorization),
}

impl InvocationAuthority {
    pub fn resources(&self) -> Option<&ResourceScopes> {
        match self {
            Self::Resources(scopes) => Some(scopes),
            Self::ActionOnly | Self::Search(_) => None,
        }
    }

    pub fn search(&self) -> Option<&SearchAuthorization> {
        match self {
            Self::Search(search) => Some(search),
            Self::ActionOnly | Self::Resources(_) => None,
        }
    }
}

/// A provider asked for authority its action was not admitted with. This is
/// an SDK invariant failure: the host reports it as a provider contract
/// failure.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum AuthorityMismatch {
    #[error("the operation was not admitted with resource authority")]
    NotResources,
    #[error("the operation was not admitted with a search boundary")]
    NotSearch,
}

impl AuthorityMismatch {
    pub fn diagnostic_code(self) -> &'static str {
        match self {
            Self::NotResources => "provider_authority_not_resources",
            Self::NotSearch => "provider_authority_not_search",
        }
    }
}

impl From<AuthorityMismatch> for ProviderError {
    fn from(error: AuthorityMismatch) -> Self {
        crate::host::port_failure(
            crate::host::HostPort::AdmittedOperation,
            ProviderError::error(
                ReasonCode::BrokerProviderContractFailed,
                "provider operation authority is unavailable",
            )
            .with_internal_diagnostic_code(error.diagnostic_code()),
        )
    }
}

/// Read-only admitted authority: service and action, the host-selected
/// execution context, minimal caller identity, correlation, the selected
/// credential mode and the exact authority. Clones share one value.
#[derive(Clone)]
pub struct AdmittedContext(Arc<ContextInner>);

#[derive(Debug)]
struct ContextInner {
    service: String,
    action: String,
    execution_context: String,
    identity: InvocationIdentity,
    correlation: CorrelationContext,
    credential_mode: CredentialMode,
    authority: InvocationAuthority,
}

impl AdmittedContext {
    pub fn service(&self) -> &str {
        &self.0.service
    }

    pub fn action(&self) -> &str {
        &self.0.action
    }

    /// The execution context the host authorized, never a tool input.
    pub fn execution_context(&self) -> &str {
        &self.0.execution_context
    }

    pub fn identity(&self) -> &InvocationIdentity {
        &self.0.identity
    }

    pub fn correlation(&self) -> &CorrelationContext {
        &self.0.correlation
    }

    pub fn credential_mode(&self) -> CredentialMode {
        self.0.credential_mode
    }

    pub fn authority(&self) -> &InvocationAuthority {
        &self.0.authority
    }

    /// The admitted resources; any other authority fails closed.
    pub fn resource_scopes(&self) -> Result<&ResourceScopes, AuthorityMismatch> {
        self.authority()
            .resources()
            .ok_or(AuthorityMismatch::NotResources)
    }

    /// The admitted search boundary; any other authority fails closed.
    pub fn search_authorization(&self) -> Result<&SearchAuthorization, AuthorityMismatch> {
        self.authority()
            .search()
            .ok_or(AuthorityMismatch::NotSearch)
    }
}

impl std::fmt::Debug for AdmittedContext {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.fmt(formatter)
    }
}

/// The view multipart admission receives: the admitted context, validated
/// inputs and the selected execution and lookup material. It has neither
/// consumed body data nor decrypted private resource attributes.
#[derive(Debug, Clone)]
pub struct AdmittedRequest {
    context: AdmittedContext,
    inputs: Value,
    execution: ExecutionAccess,
    lookup_access: Option<LookupAccess>,
}

/// One admitted invocation: the admitted request plus what the host staged
/// after admission (consumed body parts, then the admitted resource's
/// decrypted private attributes) and the operation's provider state. It is
/// built once, immediately before dispatch, and never serializes.
#[derive(Debug, Clone)]
pub struct ProviderInvocation {
    request: AdmittedRequest,
    body_parts: Vec<BrokerBodyPart>,
    resource_attributes: ResourceAttributes,
    state: Option<ProviderState>,
}

/// Read accessors shared by [`AdmittedRequest`] and [`ProviderInvocation`].
macro_rules! admitted_accessors {
    ($request:ident) => {
        pub fn context(&self) -> &AdmittedContext {
            &self.$request().context
        }

        pub fn service(&self) -> &str {
            self.context().service()
        }

        pub fn action(&self) -> &str {
            self.context().action()
        }

        /// The execution context the host authorized, never a tool input.
        pub fn execution_context(&self) -> &str {
            self.context().execution_context()
        }

        pub fn identity(&self) -> &InvocationIdentity {
            self.context().identity()
        }

        pub fn correlation(&self) -> &CorrelationContext {
            self.context().correlation()
        }

        pub fn credential_mode(&self) -> CredentialMode {
            self.context().credential_mode()
        }

        pub fn authority(&self) -> &InvocationAuthority {
            self.context().authority()
        }

        /// The admitted resources; any other authority fails closed.
        pub fn resource_scopes(&self) -> Result<&ResourceScopes, AuthorityMismatch> {
            self.context().resource_scopes()
        }

        /// The admitted search boundary; any other authority fails closed.
        pub fn search_authorization(&self) -> Result<&SearchAuthorization, AuthorityMismatch> {
            self.context().search_authorization()
        }

        /// Inputs validated against the action's schema.
        pub fn inputs(&self) -> &Value {
            &self.$request().inputs
        }

        /// Execution material the host selected for the credential mode.
        pub fn execution(&self) -> &ExecutionAccess {
            &self.$request().execution
        }

        /// Lookup material the host selected, never a stand-in for
        /// execution material. Delegated lookup access shares the
        /// operation's lease and recovery budget with delegated execution
        /// material.
        pub fn lookup_access(&self) -> Option<&LookupAccess> {
            self.$request().lookup_access.as_ref()
        }
    };
}

impl AdmittedRequest {
    pub(crate) fn new(
        context: AdmittedContext,
        inputs: Value,
        execution: ExecutionAccess,
        lookup_access: Option<LookupAccess>,
    ) -> Self {
        Self {
            context,
            inputs,
            execution,
            lookup_access,
        }
    }

    /// The request itself, so the shared accessors read the same fields as
    /// [`ProviderInvocation`]'s.
    fn request(&self) -> &Self {
        self
    }

    admitted_accessors!(request);
}

impl ProviderInvocation {
    pub(crate) fn new(
        request: AdmittedRequest,
        body_parts: Vec<BrokerBodyPart>,
        resource_attributes: ResourceAttributes,
        state: Option<ProviderState>,
    ) -> Self {
        Self {
            request,
            body_parts,
            resource_attributes,
            state,
        }
    }

    /// The admitted request this invocation was built from.
    pub fn admitted(&self) -> &AdmittedRequest {
        &self.request
    }

    admitted_accessors!(admitted);

    /// Body parts the host consumed and validated after admission.
    pub fn body_parts(&self) -> &[BrokerBodyPart] {
        &self.body_parts
    }

    /// Only the admitted exact resource's private attributes, decrypted by
    /// the host after its revision fence.
    pub fn resource_attributes(&self) -> &ResourceAttributes {
        &self.resource_attributes
    }

    /// Provider state from scope resolution or body admission.
    pub fn state(&self) -> Option<&ProviderState> {
        self.state.as_ref()
    }
}

impl AdmittedContext {
    pub(crate) fn new(
        service: String,
        action: String,
        execution_context: String,
        identity: InvocationIdentity,
        correlation: CorrelationContext,
        credential_mode: CredentialMode,
        authority: InvocationAuthority,
    ) -> Self {
        Self(Arc::new(ContextInner {
            service,
            action,
            execution_context,
            identity,
            correlation,
            credential_mode,
            authority,
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::SearchAuthorizationScope;
    use crate::test_support::{InvocationBuilder, bearer_credential, delegated_binding_id};
    use serde_json::json;
    use std::collections::BTreeMap;

    fn scopes() -> ResourceScopes {
        BTreeMap::from([("project".to_string(), vec!["ENG".to_string()])])
    }

    #[test]
    fn authority_accessors_fail_closed_for_another_authority() {
        let resources = InvocationBuilder::new("svc", "act")
            .resources(scopes())
            .build();
        assert_eq!(resources.resource_scopes(), Ok(&scopes()));
        assert_eq!(
            resources.search_authorization().unwrap_err(),
            AuthorityMismatch::NotSearch
        );

        let search = SearchAuthorization::new(
            "project".to_string(),
            SearchAuthorizationScope::excluding_exact_values(vec!["SECRET".to_string()]),
        );
        let searching = InvocationBuilder::new("svc", "search")
            .search(search.clone())
            .build();
        assert_eq!(searching.search_authorization(), Ok(&search));
        assert_eq!(
            searching.resource_scopes().unwrap_err(),
            AuthorityMismatch::NotResources
        );

        let action_only = InvocationBuilder::new("svc", "act").build();
        assert!(matches!(
            action_only.authority(),
            InvocationAuthority::ActionOnly
        ));
        let error = ProviderError::from(action_only.resource_scopes().unwrap_err());
        assert_eq!(error.decision(), crate::Decision::Error);
        assert_eq!(
            error.reason_code(),
            ReasonCode::BrokerProviderContractFailed
        );
        assert_eq!(
            error.internal_diagnostic_code,
            Some("provider_authority_not_resources")
        );
    }

    #[test]
    fn admission_and_invocation_share_one_read_only_context() {
        let builder = InvocationBuilder::new("svc", "act")
            .inputs(json!({"key": "value"}))
            .credential_mode(CredentialMode::PerUser)
            .resources(scopes())
            .credential(bearer_credential("execution-secret"))
            .lookup_credential(bearer_credential("lookup-secret"));
        let admitted = builder.admitted();
        let shared = admitted.context().clone();
        assert!(Arc::ptr_eq(&admitted.context().0, &shared.0));
        let invocation = crate::host::invocation(
            admitted,
            Vec::new(),
            ResourceAttributes::from(BTreeMap::from([(
                "endpoint".to_string(),
                "private-endpoint".to_string(),
            )])),
            Some(ProviderState::new(7_u8)),
        );
        assert!(Arc::ptr_eq(&invocation.context().0, &shared.0));
        assert_eq!(invocation.service(), "svc");
        assert_eq!(invocation.action(), "act");
        assert_eq!(invocation.execution_context(), "internal");
        assert_eq!(invocation.credential_mode(), CredentialMode::PerUser);
        assert_eq!(invocation.inputs(), &json!({"key": "value"}));
        assert!(invocation.execution().static_credential().is_some());
        assert!(
            invocation
                .lookup_access()
                .and_then(LookupAccess::static_credential)
                .is_some()
        );
        assert_eq!(invocation.state().unwrap().downcast_ref::<u8>(), Ok(&7));
        let debug = format!("{invocation:?}");
        for secret in ["execution-secret", "lookup-secret", "private-endpoint"] {
            assert!(!debug.contains(secret), "{debug}");
        }
    }

    #[test]
    fn reopened_invocations_keep_every_admitted_value() {
        let original = InvocationBuilder::new("svc", "act")
            .resources(scopes())
            .principal("alice")
            .state(ProviderState::new("state"))
            .build();
        let state = original.state().unwrap().clone();
        let changed = InvocationBuilder::from(original)
            .credential_mode(CredentialMode::PerUser)
            .build();
        assert_eq!(changed.resource_scopes(), Ok(&scopes()));
        assert_eq!(changed.identity().principal, "alice");
        assert!(changed.state().unwrap().same(&state));
        assert_eq!(changed.credential_mode(), CredentialMode::PerUser);
    }

    #[test]
    fn delegated_binding_identities_compare_without_revealing_their_digest() {
        let first = delegated_binding_id("binding-one");
        assert_eq!(first, delegated_binding_id("binding-one"));
        assert_ne!(first, delegated_binding_id("binding-two"));
        assert_eq!(first.digest().len(), 32);
        assert_eq!(format!("{first:?}"), "DelegatedBindingId(<redacted>)");
    }
}
