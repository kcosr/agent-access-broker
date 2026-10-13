//! Provider invocations for provider tests, built the way the host admits
//! them: an anonymous caller in the `internal` execution context, service
//! credential mode, no resources or credentials unless supplied.
use crate::{
    BrokerBodyPart, CorrelationContext, DelegatedCredential, ExecutionCredential,
    InvocationIdentity, ProviderInvocation, ProviderState, ResourceAttributes, ResourceScopes,
    SearchAuthorization,
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
    credential_mode: String,
    resources: ResourceScopes,
    search: Option<SearchAuthorization>,
    credential: Option<ExecutionCredential>,
    delegated: Option<DelegatedCredential>,
    lookup_credential: Option<ExecutionCredential>,
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
            credential_mode: "service".to_owned(),
            resources: ResourceScopes::new(),
            search: None,
            credential: None,
            delegated: None,
            lookup_credential: None,
            body_parts: Vec::new(),
            resource_attributes: ResourceAttributes::default(),
            state: None,
        }
    }

    pub fn inputs(mut self, inputs: Value) -> Self {
        self.inputs = inputs;
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

    pub fn correlation(mut self, correlation: CorrelationContext) -> Self {
        self.correlation = correlation;
        self
    }

    pub fn credential_mode(mut self, credential_mode: &str) -> Self {
        self.credential_mode = credential_mode.to_owned();
        self
    }

    /// Admitted resource authority for an ordinary scoped action.
    pub fn resources(mut self, resources: ResourceScopes) -> Self {
        self.resources = resources;
        self
    }

    /// Admitted search boundary for a search-contained action.
    pub fn search(mut self, search: SearchAuthorization) -> Self {
        self.search = Some(search);
        self
    }

    /// Static execution credential.
    pub fn credential(mut self, credential: ExecutionCredential) -> Self {
        self.credential = Some(credential);
        self
    }

    /// Delegated execution credential.
    pub fn delegated(mut self, delegated: DelegatedCredential) -> Self {
        self.delegated = Some(delegated);
        self
    }

    pub fn lookup_credential(mut self, credential: ExecutionCredential) -> Self {
        self.lookup_credential = Some(credential);
        self
    }

    pub fn body_parts(mut self, body_parts: Vec<BrokerBodyPart>) -> Self {
        self.body_parts = body_parts;
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

    pub fn build(self) -> ProviderInvocation {
        ProviderInvocation {
            execution_context: self.execution_context,
            identity: self.identity,
            service: self.service,
            action: self.action,
            correlation: self.correlation,
            inputs: self.inputs,
            body_parts: self.body_parts,
            resource_scopes: self.resources,
            resource_attributes: self.resource_attributes,
            credential_mode: self.credential_mode,
            credential: self.credential,
            lookup_credential: self.lookup_credential,
            delegated_credential: self.delegated,
            state: self.state,
            search_authorization: self.search,
        }
    }
}
