//! Admitted requests and provider invocations for provider tests, built the
//! way the host admits them: an anonymous caller in the `internal` execution
//! context, service credential mode, action-only authority, and no
//! credentials unless supplied.
use crate::host::{AdmittedRequestParts, admitted_request, invocation};
use crate::{
    AdmittedRequest, BrokerBodyPart, CorrelationContext, CredentialMode, DelegatedCredential,
    ExecutionAccess, ExecutionCredential, InvocationAuthority, InvocationIdentity, LookupAccess,
    ProviderInvocation, ProviderState, ResourceAttributes, ResourceScopes, SearchAuthorization,
};
use serde_json::{Value, json};

#[derive(Debug, Clone)]
pub struct InvocationBuilder {
    service: String,
    action: String,
    inputs: Value,
    execution_context: String,
    identity: InvocationIdentity,
    correlation: CorrelationContext,
    credential_mode: CredentialMode,
    authority: InvocationAuthority,
    universal_reach: bool,
    execution: ExecutionAccess,
    lookup_access: Option<LookupAccess>,
    body_parts: Vec<BrokerBodyPart>,
    resource_attributes: ResourceAttributes,
    state: Option<ProviderState>,
}

impl InvocationBuilder {
    pub fn new(service: &str, action: &str) -> Self {
        Self {
            service: service.to_owned(),
            action: action.to_owned(),
            inputs: json!({}),
            execution_context: "internal".to_owned(),
            identity: InvocationIdentity::anonymous(),
            correlation: CorrelationContext::for_tests(),
            credential_mode: CredentialMode::Service,
            authority: InvocationAuthority::ActionOnly,
            universal_reach: false,
            execution: ExecutionAccess::None,
            lookup_access: None,
            body_parts: Vec::new(),
            resource_attributes: ResourceAttributes::default(),
            state: None,
        }
    }

    pub fn service(mut self, service: &str) -> Self {
        self.service = service.to_owned();
        self
    }

    pub fn action(mut self, action: &str) -> Self {
        self.action = action.to_owned();
        self
    }

    pub fn inputs(mut self, inputs: Value) -> Self {
        self.inputs = inputs;
        self
    }

    /// Sets one top-level input.
    pub fn input(mut self, name: &str, value: Value) -> Self {
        if !self.inputs.is_object() {
            self.inputs = json!({});
        }
        self.inputs[name] = value;
        self
    }

    pub fn execution_context(mut self, execution_context: &str) -> Self {
        self.execution_context = execution_context.to_owned();
        self
    }

    pub fn identity(mut self, identity: InvocationIdentity) -> Self {
        self.identity = identity;
        self
    }

    /// Keeps whether the caller authenticated and changes only the principal.
    pub fn principal(mut self, principal: &str) -> Self {
        self.identity.principal = principal.to_owned();
        self
    }

    pub fn correlation(mut self, correlation: CorrelationContext) -> Self {
        self.correlation = correlation;
        self
    }

    pub fn credential_mode(mut self, credential_mode: CredentialMode) -> Self {
        self.credential_mode = credential_mode;
        self
    }

    /// Resource authority for an ordinary scoped action.
    pub fn resources(mut self, resources: ResourceScopes) -> Self {
        self.authority = InvocationAuthority::Resources(resources);
        self
    }

    /// The search boundary of a search action.
    pub fn search(mut self, search: SearchAuthorization) -> Self {
        self.authority = InvocationAuthority::Search(search);
        self
    }

    pub fn authority(mut self, authority: InvocationAuthority) -> Self {
        self.authority = authority;
        self
    }

    /// Supply the host's same-response disclosure proof for a provider test.
    /// Defaults to false; does not change exact resource authority.
    pub fn universal_reach(mut self, universal_reach: bool) -> Self {
        self.universal_reach = universal_reach;
        self
    }

    /// Static execution credential, replacing any delegated credential:
    /// static and delegated material never coexist.
    pub fn credential(mut self, credential: ExecutionCredential) -> Self {
        self.execution = ExecutionAccess::Static(credential);
        self
    }

    /// Delegated execution credential, replacing any static credential.
    pub fn delegated(mut self, delegated: DelegatedCredential) -> Self {
        self.execution = ExecutionAccess::Delegated(delegated);
        self
    }

    pub fn execution(mut self, execution: ExecutionAccess) -> Self {
        self.execution = execution;
        self
    }

    /// Static lookup access, replacing any other lookup access.
    pub fn lookup_credential(self, credential: ExecutionCredential) -> Self {
        self.lookup_access(Some(LookupAccess::Static(credential)))
    }

    /// Delegated lookup access, replacing any other lookup access. Pass a
    /// clone of the delegated execution credential to share its lease, as
    /// the host does.
    pub fn delegated_lookup(self, credential: DelegatedCredential) -> Self {
        self.lookup_access(Some(LookupAccess::Delegated(credential)))
    }

    pub fn lookup_access(mut self, lookup_access: Option<LookupAccess>) -> Self {
        self.lookup_access = lookup_access;
        self
    }

    pub fn body_parts(mut self, body_parts: Vec<BrokerBodyPart>) -> Self {
        self.body_parts = body_parts;
        self
    }

    pub fn body_part(mut self, body_part: BrokerBodyPart) -> Self {
        self.body_parts.push(body_part);
        self
    }

    pub fn resource_attributes(mut self, resource_attributes: ResourceAttributes) -> Self {
        self.resource_attributes = resource_attributes;
        self
    }

    pub fn state(mut self, state: ProviderState) -> Self {
        self.state = Some(state);
        self
    }

    pub fn without_state(mut self) -> Self {
        self.state = None;
        self
    }

    /// The admission view of this request, without body parts, private
    /// attributes or provider state.
    pub fn admitted(&self) -> AdmittedRequest {
        admitted_request(AdmittedRequestParts {
            service: self.service.clone(),
            action: self.action.clone(),
            execution_context: self.execution_context.clone(),
            identity: self.identity.clone(),
            correlation: self.correlation.clone(),
            credential_mode: self.credential_mode,
            authority: self.authority.clone(),
            universal_reach: self.universal_reach,
            inputs: self.inputs.clone(),
            execution: self.execution.clone(),
            lookup_access: self.lookup_access.clone(),
        })
    }

    pub fn build(self) -> ProviderInvocation {
        let request = self.admitted();
        invocation(
            request,
            self.body_parts,
            self.resource_attributes,
            self.state,
        )
    }
}

/// Reopens an invocation to build a variant of it.
impl From<ProviderInvocation> for InvocationBuilder {
    fn from(invocation: ProviderInvocation) -> Self {
        let context = invocation.context();
        Self {
            service: context.service().to_owned(),
            action: context.action().to_owned(),
            inputs: invocation.inputs().clone(),
            execution_context: context.execution_context().to_owned(),
            identity: context.identity().clone(),
            correlation: context.correlation().clone(),
            credential_mode: context.credential_mode(),
            authority: context.authority().clone(),
            universal_reach: context.universal_reach(),
            execution: invocation.execution().clone(),
            lookup_access: invocation.lookup_access().cloned(),
            body_parts: invocation.body_parts().to_vec(),
            resource_attributes: invocation.resource_attributes().clone(),
            state: invocation.state().cloned(),
        }
    }
}
