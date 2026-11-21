//! Content location policy. The SDK owns relation proofs; core owns candidate
//! eligibility, precedence, token conjunction and disclosure.
use super::*;

#[cfg(test)]
mod tests;

#[derive(Debug, Clone)]
pub(super) struct ActionContainmentScope {
    pub scope: String,
    pub contract: ContainmentScopeCapabilities,
    pub site_origin: String,
}

pub(super) struct ContainmentAdmission {
    pub scopes: ResourceScopes,
    pub policy: PolicyDecision,
    pub authority: InvocationAuthority,
    pub audit: Value,
    pub search_audit: Option<SearchAuthorizationAudit>,
}

pub(super) fn containment_contract_error() -> ProviderError {
    ProviderError::error(
        ReasonCode::OperationFailed,
        "provider content location evidence does not match the action contract",
    )
}

fn containment_matching_error(error: ContainmentError) -> ProviderError {
    match error {
        ContainmentError::UnresolvedRelation
        | ContainmentError::ChangedLocation
        | ContainmentError::BudgetExceeded => ProviderError::deny(
            ReasonCode::ScopeUnresolved,
            "content location could not be verified",
        ),
        _ => containment_contract_error(),
    }
}

impl BrokerRuntime {
    pub(super) fn action_containment_scope(
        &self,
        service: &str,
        action: &str,
    ) -> Option<ActionContainmentScope> {
        let descriptor = self.services.get(service)?;
        let (scope, binding) = descriptor.action_resource_scope(action)?;
        let contract = binding.as_containment()?;
        Some(ActionContainmentScope {
            scope: scope.to_owned(),
            contract: contract.clone(),
            site_origin: descriptor.upstream_authority.as_ref()?.origin().to_owned(),
        })
    }

    pub(super) fn resolve_containment_boundary(
        &self,
        snapshot: &PolicySnapshot,
        context: &ExecutionContext,
        scope: &ActionContainmentScope,
        selection: &ResourceSelection,
    ) -> ContainmentBoundary {
        snapshot
            .resources
            .resolve_containment(
                selection,
                &scope.contract,
                &scope.site_origin,
                self.resource_types.registry(),
                context.as_str(),
            )
            .expect("published containment selectors remain valid")
    }

    pub(super) fn token_containment_boundary(
        &self,
        snapshot: &PolicySnapshot,
        context: &ExecutionContext,
        scope: &ActionContainmentScope,
        token: Option<&ParsedAgentInvokeTokenCaveats<'_>>,
        service: &str,
    ) -> Option<ContainmentBoundary> {
        let selection = token?
            .caveats
            .service_restrictions
            .as_ref()?
            .get(service)?
            .resources
            .as_ref()?;
        Some(self.resolve_containment_boundary(snapshot, context, scope, selection))
    }

    /// The required proof level is selected before lookup from all viable
    /// candidates and the independent token ceiling, never from the eventual
    /// winning credential or the caller's guessed target.
    pub(super) fn containment_lookup_requirements(
        &self,
        snapshot: &PolicySnapshot,
        identity: &IdentityContext,
        context: &ExecutionContext,
        service: &str,
        action: &str,
        token: Option<&ParsedAgentInvokeTokenCaveats<'_>>,
    ) -> (ContainmentEvidenceLevel, Vec<TypedResourceSelector>) {
        let Some(scope) = self.action_containment_scope(service, action) else {
            return (ContainmentEvidenceLevel::ContainerOnly, Vec::new());
        };
        let candidates =
            self.policy_candidates_for_action(snapshot, identity, context, service, action);
        let token = self.token_containment_boundary(snapshot, context, &scope, token, service);
        let boundaries = candidates
            .iter()
            .filter_map(|candidate| candidate.containment.as_ref())
            .chain(token.iter());
        let mut roots = Vec::new();
        let mut lineage = scope
            .contract
            .effects
            .contains(&ContainmentEffect::SubtreeImpact);
        for boundary in boundaries {
            for selector in boundary.included().iter().chain(boundary.excluded()) {
                if matches!(selector.selector(), ResourceSelector::Subtree { .. }) {
                    lineage = true;
                }
            }
            // Region disjointness needs the exclusion root's authenticated
            // lineage, including exact exclusions below a moved subtree.
            if scope
                .contract
                .effects
                .contains(&ContainmentEffect::SubtreeImpact)
            {
                for selector in boundary.excluded() {
                    if selector.projection().is_some() && !roots.contains(selector) {
                        roots.push(selector.clone());
                    }
                }
            }
        }
        (
            if lineage {
                ContainmentEvidenceLevel::CompleteLineage
            } else {
                ContainmentEvidenceLevel::ContainerOnly
            },
            roots,
        )
    }

    /// Resolve only policy-authored provenance for the roots the provider must
    /// observe. No upstream identity or URL enters this bounded diagnostic.
    #[allow(clippy::too_many_arguments)]
    pub(super) fn containment_root_provenance(
        &self,
        snapshot: &PolicySnapshot,
        identity: &IdentityContext,
        context: &ExecutionContext,
        service: &str,
        action: &str,
        token: Option<&ParsedAgentInvokeTokenCaveats<'_>>,
        roots: &[TypedResourceSelector],
    ) -> Option<Value> {
        if roots.is_empty() {
            return None;
        }
        let candidates =
            self.policy_candidates_for_action(snapshot, identity, context, service, action);
        let token_selection = token
            .and_then(|token| token.caveats.service_restrictions.as_ref())
            .and_then(|restrictions| restrictions.get(service))
            .and_then(|restriction| restriction.resources.as_ref());
        let mut resources = BTreeSet::new();
        let mut groups = BTreeSet::new();
        for selection in candidates
            .iter()
            .map(|candidate| &candidate.resources)
            .chain(token_selection)
        {
            for group_id in &selection.resource_group_ids {
                let Some(group) = snapshot.resources.resource_groups.get(group_id) else {
                    continue;
                };
                for resource_id in &group.excluded_resource_ids {
                    let Some(resource) = snapshot.resources.resources.get(resource_id) else {
                        continue;
                    };
                    let Ok(selector) = self
                        .resource_types
                        .registry()
                        .typed_selector(&resource.resource_type, &resource.selector)
                    else {
                        continue;
                    };
                    if roots.contains(&selector) {
                        resources.insert(resource_id);
                        groups.insert(group_id);
                    }
                }
            }
        }
        let resource_ids: Vec<_> = resources.iter().take(16).collect();
        let group_ids: Vec<_> = groups.iter().take(16).collect();
        Some(json!({
            "resourceIds": resource_ids, "resourceGroupIds": group_ids,
            "additionalProvenanceCount": resources.len() + groups.len() - resource_ids.len() - group_ids.len(),
        }))
    }

    #[allow(clippy::too_many_arguments)]
    pub(super) fn admit_containment_evidence(
        &self,
        snapshot: &PolicySnapshot,
        identity: &IdentityContext,
        context: &ExecutionContext,
        service: &str,
        action: &str,
        token: Option<&ParsedAgentInvokeTokenCaveats<'_>>,
        evidence: ContainmentEvidence,
        required_level: ContainmentEvidenceLevel,
    ) -> Result<ContainmentAdmission, ProviderError> {
        let scope = self
            .action_containment_scope(service, action)
            .ok_or_else(containment_contract_error)?;
        if evidence.site_origin() != scope.site_origin {
            return Err(containment_contract_error());
        }
        evidence
            .validate(
                &scope.contract,
                self.resource_types.registry(),
                required_level,
            )
            .map_err(|_| containment_contract_error())?;
        let token_boundary =
            self.token_containment_boundary(snapshot, context, &scope, token, service);
        if let Some(boundary) = &token_boundary
            && !boundary
                .matches_evidence(&evidence)
                .map_err(containment_matching_error)?
        {
            return Err(token_caveat_denial(
                token.and_then(|token| token.token_id),
                service,
                action,
                "broker token is not allowed to invoke the resolved content location",
            ));
        }
        let mut matches = Vec::new();
        for candidate in
            self.policy_candidates_for_action(snapshot, identity, context, service, action)
        {
            let boundary = candidate
                .containment
                .as_ref()
                .ok_or_else(containment_contract_error)?;
            if boundary
                .matches_evidence(&evidence)
                .map_err(containment_matching_error)?
            {
                matches.push(candidate);
            }
        }
        if matches.is_empty() {
            return Err(ProviderError::deny(
                ReasonCode::ServiceActionDenied,
                "policy denied service action for resolved content location",
            ));
        }
        let band = top_policy_band(matches);
        let policy =
            self.containment_policy_decision(snapshot, identity, service, action, &band)?;
        let digest = containment_digest(
            identity,
            context,
            service,
            action,
            &policy.credential_mode,
            &band,
            token_boundary.as_ref(),
            Some(&evidence),
        );
        let scopes = evidence.projection(&scope.scope);
        let audit = point_authorization_audit(
            &scope.contract,
            &evidence,
            required_level,
            &policy.matched_grant,
        );
        let authority = agent_access_provider::host::containment_authorization(
            &scope.site_origin,
            scope.contract,
            evidence,
            self.resource_types.registry(),
            required_level,
            digest,
        )
        .map_err(|_| containment_contract_error())?;
        Ok(ContainmentAdmission {
            scopes,
            policy,
            authority: InvocationAuthority::Containment(authority),
            audit,
            search_audit: None,
        })
    }

    #[allow(clippy::too_many_arguments)]
    pub(super) fn admit_containment_collection(
        &self,
        snapshot: &PolicySnapshot,
        identity: &IdentityContext,
        context: &ExecutionContext,
        service: &str,
        action: &str,
        token: Option<&ParsedAgentInvokeTokenCaveats<'_>>,
    ) -> Result<ContainmentAdmission, ProviderError> {
        let scope = self
            .action_containment_scope(service, action)
            .ok_or_else(containment_contract_error)?;
        let candidates =
            self.policy_candidates_for_action(snapshot, identity, context, service, action);
        if candidates.is_empty() {
            return Err(ProviderError::deny(
                ReasonCode::ServiceActionDenied,
                "policy denied content collection",
            ));
        }
        // Native collections select the global winning band before the token
        // conjunction, with no per-target fallback to a lower grant.
        let band = top_policy_band(candidates);
        let policy =
            self.containment_policy_decision(snapshot, identity, service, action, &band)?;
        let token_boundary =
            self.token_containment_boundary(snapshot, context, &scope, token, service);
        if let Some(boundary) = &token_boundary
            && (boundary.prove_nonempty(&scope.contract, &scope.site_origin)
                == OfflineContainmentProof::Empty
                || band.iter().all(|candidate| {
                    candidate
                        .containment
                        .as_ref()
                        .expect("containment candidate")
                        .prove_intersection(boundary, &scope.contract, &scope.site_origin)
                        == OfflineContainmentProof::Empty
                }))
        {
            return Err(token_caveat_denial(
                token.and_then(|token| token.token_id),
                service,
                action,
                "broker token content boundary has no currently authorized resources",
            ));
        }
        let boundaries: Vec<_> = band
            .iter()
            .map(|candidate| {
                candidate
                    .containment
                    .clone()
                    .expect("containment candidate")
            })
            .collect();
        let required_level = if boundaries
            .iter()
            .chain(token_boundary.iter())
            .any(|boundary| {
                boundary
                    .included()
                    .iter()
                    .chain(boundary.excluded())
                    .any(|selector| matches!(selector.selector(), ResourceSelector::Subtree { .. }))
            }) {
            ContainmentEvidenceLevel::CompleteLineage
        } else {
            ContainmentEvidenceLevel::ContainerOnly
        };
        let digest = containment_digest(
            identity,
            context,
            service,
            action,
            &policy.credential_mode,
            &band,
            token_boundary.as_ref(),
            None,
        );
        let audit = json!({ "kind": "collection", "domain": scope.contract.domain, "evidenceLevel": required_level, "finalCheck": "not_run" });
        let search_audit = Some(SearchAuthorizationAudit::Location(
            LocationSearchAuthorizationPlan {
                scope: LocationSearchScope::Location,
                scope_type: scope.scope.clone(),
                resource_types: scope.contract.selectors_by_type.keys().cloned().collect(),
                domain: scope.contract.domain.clone(),
                evidence_level: required_level,
                grant_boundaries: boundaries.iter().map(LocationBoundary::from).collect(),
                token_boundary: token_boundary.as_ref().map(LocationBoundary::from),
                authority_digest: digest.clone(),
                credential_mode: policy.credential_mode.clone(),
                matched_grants: band
                    .iter()
                    .map(|candidate| matched_grant_audit(snapshot, candidate))
                    .collect(),
            },
        ));
        let mut summary = BTreeMap::<String, BTreeSet<String>>::new();
        for boundary in &boundaries {
            for selector in boundary.included() {
                let only = ContainmentBoundary::new(vec![selector.clone()], Vec::new());
                if only.prove_intersection(boundary, &scope.contract, &scope.site_origin)
                    == OfflineContainmentProof::Empty
                    || token_boundary.as_ref().is_some_and(|token| {
                        token.prove_intersection(&only, &scope.contract, &scope.site_origin)
                            == OfflineContainmentProof::Empty
                    })
                {
                    continue;
                }
                if selector.projection().is_some() {
                    if let Some(value) = selector.selector().value() {
                        summary
                            .entry(scope.scope.clone())
                            .or_default()
                            .insert(value.to_owned());
                    }
                } else if scope
                    .contract
                    .container_types
                    .contains(selector.resource_type())
                {
                    // Scalar containers keep their provider-declared summary key;
                    // canonical content URLs remain under the location scope key.
                    for (name, binding) in &self.services[service].resource_scopes {
                        if binding.as_scalar().is_some_and(|(resource_type, _)| {
                            resource_type == selector.resource_type()
                        }) {
                            let value = match selector.selector() {
                                ResourceSelector::Exact { value } => value.clone(),
                                ResourceSelector::All | ResourceSelector::Namespace { .. } => {
                                    "*".into()
                                }
                                _ => continue,
                            };
                            summary.entry(name.clone()).or_default().insert(value);
                        }
                    }
                }
            }
        }
        let scopes = summary
            .into_iter()
            .map(|(scope, values)| {
                let values = if values.contains("*") {
                    vec!["*".into()]
                } else {
                    values.into_iter().collect()
                };
                (scope, values)
            })
            .collect();
        let authority = agent_access_provider::host::containment_collection_authorization(
            &scope.site_origin,
            scope.contract,
            boundaries,
            token_boundary,
            self.resource_types.registry(),
            required_level,
            digest,
        )
        .map_err(|_| containment_contract_error())?;
        Ok(ContainmentAdmission {
            scopes,
            policy,
            authority: InvocationAuthority::ContainmentCollection(authority),
            audit,
            search_audit,
        })
    }

    fn containment_policy_decision(
        &self,
        snapshot: &PolicySnapshot,
        identity: &IdentityContext,
        service: &str,
        action: &str,
        band: &[PolicyCandidate],
    ) -> Result<PolicyDecision, ProviderError> {
        let credential_mode = single_policy_credential_mode(band)?;
        if !self.action_supports_mode(service, action, &credential_mode) {
            return Err(ProviderError::deny(
                ReasonCode::CredentialNotProvisioned,
                "selected credential mode is not supported by this action",
            ));
        }
        self.check_action_credential_eligibility(service, action, &credential_mode, identity)?;
        if !credential_mode_available(
            &self.effective_credentials,
            service,
            &credential_mode,
            self.services
                .get(service)
                .map(|descriptor| &descriptor.credentials),
        ) {
            return Err(ProviderError::deny(
                ReasonCode::CredentialNotProvisioned,
                "selected credential mode is not provisioned",
            ));
        }
        Ok(PolicyDecision {
            credential_mode,
            matched_grant: matched_grant_audit(snapshot, &band[0]),
        })
    }
}

fn point_authorization_audit(
    contract: &ContainmentScopeCapabilities,
    evidence: &ContainmentEvidence,
    level: ContainmentEvidenceLevel,
    grant: &MatchedGrantAudit,
) -> Value {
    let resources: Vec<_> = grant.resources.resource_ids.iter().take(32).collect();
    let groups: Vec<_> = grant
        .resources
        .resource_group_ids
        .iter()
        .take(32 - resources.len())
        .collect();
    let omitted = grant.resources.resource_ids.len() + grant.resources.resource_group_ids.len()
        - resources.len()
        - groups.len();
    let mut nodes = BTreeSet::new();
    for obligation in evidence.obligations() {
        let locations: Vec<_> = match obligation {
            ContainmentObligation::Content(location)
            | ContainmentObligation::ChildPlacement(location) => vec![location],
            ContainmentObligation::SubtreeImpact { current, proposed } => vec![current, proposed],
            _ => Vec::new(),
        };
        for location in locations {
            nodes.extend(std::iter::once(&location.target).chain(&location.ancestors));
        }
    }
    json!({
        "kind": "point", "domain": contract.domain, "evidenceLevel": level,
        "publicNodeCount": nodes.len(), "resourceIds": resources, "resourceGroupIds": groups,
        "additionalProvenanceCount": omitted, "finalCheck": "not_run",
    })
}

/// The temporary provenance stays in the host finalization context, never in
/// a provider request or a caller response. Only an unresolved-root marker
/// releases these configured IDs into the protected audit.
pub(super) fn with_root_provenance(mut summary: Value, provenance: Option<&Value>) -> Value {
    if let Some(provenance) = provenance {
        summary["_rootVisibilityProvenance"] = provenance.clone();
    }
    summary
}

pub(super) fn root_visibility_diagnostic(
    provider: Option<&Value>,
    provenance: Option<&Value>,
) -> Option<Value> {
    let proof = provider?.get("locationProof")?;
    if proof.get("finalCheck")?.as_str()? != "unresolved"
        || proof.get("diagnostic")?.as_str()? != "confluence_move_relation_unresolved"
    {
        return None;
    }
    let category = proof.get("category")?.as_str()?;
    if !matches!(category, "not_visible_or_absent" | "unconfirmed") {
        return None;
    }
    let mut diagnostic = provenance?.clone();
    diagnostic["diagnostic"] = json!("confluence_move_relation_unresolved");
    diagnostic["category"] = json!(category);
    Some(diagnostic)
}

pub(super) fn attach_containment_audit(
    provider: Option<Value>,
    summary: Option<Value>,
) -> Option<Value> {
    let Some(mut summary) = summary else {
        return provider;
    };
    let mut provider = provider.unwrap_or_else(|| json!({}));
    let provenance = summary
        .as_object_mut()
        .and_then(|summary| summary.remove("_rootVisibilityProvenance"));
    if let Some(diagnostic) = root_visibility_diagnostic(Some(&provider), provenance.as_ref()) {
        summary["rootVisibility"] = diagnostic;
    }
    let final_check = provider
        .pointer("/locationProof/finalCheck")
        .and_then(Value::as_str)
        .filter(|value| matches!(*value, "not_run" | "matched" | "changed" | "unresolved"))
        .unwrap_or("not_run");
    summary["finalCheck"] = json!(final_check);
    if !provider.is_object() {
        provider = json!({"providerAudit": provider});
    }
    provider
        .as_object_mut()
        .expect("audit object")
        .insert("locationAuthorization".into(), summary);
    Some(provider)
}

#[allow(clippy::too_many_arguments)]
fn containment_digest(
    identity: &IdentityContext,
    context: &ExecutionContext,
    service: &str,
    action: &str,
    mode: &str,
    candidates: &[PolicyCandidate],
    token: Option<&ContainmentBoundary>,
    evidence: Option<&ContainmentEvidence>,
) -> String {
    let mut boundaries: Vec<_> = candidates
        .iter()
        .filter_map(|candidate| candidate.containment.as_ref())
        .collect();
    // The union is independent of policy publication, grant order and duplicate
    // same-mode grants. The actual selected boundaries and token are the fence.
    boundaries.sort_by(|left, right| {
        left.included()
            .cmp(right.included())
            .then_with(|| left.excluded().cmp(right.excluded()))
    });
    boundaries.dedup();
    let binding = serde_json::to_vec(&json!({
        "principal": identity.principal,
        "context": context, "service": service, "action": action,
        "credentialMode": mode, "boundaries": boundaries, "token": token,
        "evidence": evidence.map(evidence_digest_value),
    }))
    .expect("validated containment authority serialization");
    format!("{:x}", Sha256::digest(binding))
}

fn evidence_digest_value(evidence: &ContainmentEvidence) -> Value {
    let location = |location: &ContentLocation| {
        json!({
            "target": location.target, "containers": location.containers,
            "ancestors": location.ancestors, "level": location.evidence_level,
            "provenance": format!("{:?}", location.provenance),
        })
    };
    let obligations: Vec<_> = evidence
        .obligations()
        .iter()
        .map(|obligation| match obligation {
            ContainmentObligation::Content(value) => json!({"content": location(value)}),
            ContainmentObligation::ChildPlacement(value) => {
                json!({"childPlacement": location(value)})
            }
            ContainmentObligation::SubtreeImpact { current, proposed } => {
                json!({"subtreeImpact": [location(current), location(proposed)]})
            }
            _ => Value::Null,
        })
        .collect();
    json!({"domain": evidence.domain(), "site": evidence.site_origin(), "obligations": obligations})
}

pub(super) fn candidate_is_universe(
    candidate: &PolicyCandidate,
    scope: Option<&ActionContainmentScope>,
) -> bool {
    match (&candidate.containment, scope) {
        (Some(boundary), Some(scope)) => boundary.is_universe(&scope.contract, &scope.site_origin),
        (None, None) => candidate.boundary.is_universe(),
        _ => false,
    }
}

/// Management projection of an authored selector. The projection contains no
/// provider evidence and never becomes invocation authority on deserialization.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct LocationSelector {
    pub resource_type: ResourceType,
    pub selector: ResourceSelector,
}

impl From<&TypedResourceSelector> for LocationSelector {
    fn from(selector: &TypedResourceSelector) -> Self {
        Self {
            resource_type: selector.resource_type().clone(),
            selector: selector.selector().clone(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct LocationBoundary {
    pub included: Vec<LocationSelector>,
    pub excluded: Vec<LocationSelector>,
}

impl From<&ContainmentBoundary> for LocationBoundary {
    fn from(boundary: &ContainmentBoundary) -> Self {
        Self {
            included: boundary
                .included()
                .iter()
                .map(LocationSelector::from)
                .collect(),
            excluded: boundary
                .excluded()
                .iter()
                .map(LocationSelector::from)
                .collect(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct LocationAccessClause {
    pub required: Vec<usize>,
    pub excluded_requests: Vec<usize>,
    pub credential_mode: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(
    tag = "projectionStatus",
    rename_all = "snake_case",
    deny_unknown_fields
)]
pub enum LocationProjection {
    Complete {
        boundaries: Vec<LocationBoundary>,
        clauses: Vec<LocationAccessClause>,
    },
    TooComplex {
        #[serde(rename = "reasonCode")]
        reason_code: LocationProjectionFailure,
    },
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum LocationProjectionFailure {
    ResourceAccessTooComplex,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ContainmentVerification {
    AtInvocation,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct LocationAccess {
    pub resource_types: Vec<ResourceType>,
    pub domain: String,
    pub enforcement: ResourceAccessEnforcement,
    pub containment_verification: ContainmentVerification,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub requires_runtime_root_visibility: bool,
    #[serde(flatten)]
    pub projection: LocationProjection,
}

impl LocationAccess {
    pub(super) fn is_empty(&self) -> bool {
        matches!(&self.projection, LocationProjection::Complete { clauses, .. } if clauses.is_empty())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct LocationCoverage {
    pub resource_type: ResourceType,
    pub selector: ResourceSelector,
    pub restricted: bool,
    pub conditional: bool,
}

struct ContainmentPlan {
    scope: ActionContainmentScope,
    candidates: Vec<PolicyCandidate>,
    token: Option<ContainmentBoundary>,
    collection: bool,
}

impl ContainmentPlan {
    fn requires_runtime_root_visibility(&self) -> bool {
        self.scope
            .contract
            .effects
            .contains(&ContainmentEffect::SubtreeImpact)
            && self
                .candidates
                .iter()
                .filter_map(|candidate| candidate.containment.as_ref())
                .chain(self.token.iter())
                .any(|boundary| {
                    boundary
                        .excluded()
                        .iter()
                        .any(|selector| selector.projection().is_some())
                })
    }

    fn boundary(&self, index: usize) -> &ContainmentBoundary {
        self.candidates[index]
            .containment
            .as_ref()
            .expect("containment candidate")
    }

    fn competing(&self, index: usize, other: usize) -> bool {
        if self.collection {
            return false;
        }
        let candidate = &self.candidates[index];
        let other = &self.candidates[other];
        let band = (candidate.subject_rank, candidate.priority);
        let other_band = (other.subject_rank, other.priority);
        other_band > band
            || other_band == band && other.credential_mode != candidate.credential_mode
    }

    fn possible(&self, index: usize) -> bool {
        let boundary = self.boundary(index);
        if self.token.as_ref().is_some_and(|token| {
            boundary.prove_intersection(token, &self.scope.contract, &self.scope.site_origin)
                == OfflineContainmentProof::Empty
        }) {
            return false;
        }
        // Keep conditional relationships. Proven whole-boundary shadowing is
        // sufficient to reject a candidate without enumerating locations.
        !(0..self.candidates.len()).any(|other| {
            self.competing(index, other)
                && self.boundary(other).prove_covers(
                    boundary,
                    &self.scope.contract,
                    &self.scope.site_origin,
                ) == OfflineContainmentProof::Covered
        })
    }
}

impl BrokerRuntime {
    #[allow(clippy::too_many_arguments)]
    fn containment_plan(
        &self,
        snapshot: &PolicySnapshot,
        identity: &IdentityContext,
        context: &ExecutionContext,
        service: &str,
        action: &str,
        token: Option<&ParsedAgentInvokeTokenCaveats<'_>>,
    ) -> Option<ContainmentPlan> {
        let scope = self.action_containment_scope(service, action)?;
        let collection = self
            .action_descriptor(service, action)?
            .native_search
            .is_some();
        let mut candidates = if token
            .is_some_and(|token| !self.agent_invoke_permits_action(token, context, service, action))
        {
            Vec::new()
        } else {
            self.policy_candidates_for_action(snapshot, identity, context, service, action)
        };
        if collection && !candidates.is_empty() {
            candidates = top_policy_band(candidates);
            if single_policy_credential_mode(&candidates).is_err() {
                candidates.clear();
            }
        }
        let token = self.token_containment_boundary(snapshot, context, &scope, token, service);
        Some(ContainmentPlan {
            scope,
            candidates,
            token,
            collection,
        })
    }

    fn containment_mode_available(
        &self,
        identity: &IdentityContext,
        service: &str,
        action: &str,
        mode: &str,
    ) -> bool {
        self.action_supports_mode(service, action, mode)
            && self.action_credential_eligible(service, action, mode, identity)
            && credential_mode_available(
                &self.effective_credentials,
                service,
                mode,
                self.services
                    .get(service)
                    .map(|descriptor| &descriptor.credentials),
            )
    }

    /// Availability walks candidate conditions directly. It is independent of
    /// the detailed expression's serialization budget.
    #[allow(clippy::too_many_arguments)]
    pub(super) fn containment_has_access(
        &self,
        snapshot: &PolicySnapshot,
        identity: &IdentityContext,
        context: &ExecutionContext,
        service: &str,
        action: &str,
        token: Option<&ParsedAgentInvokeTokenCaveats<'_>>,
        mode_available: impl Fn(&str) -> bool,
    ) -> bool {
        let Some(plan) = self.containment_plan(snapshot, identity, context, service, action, token)
        else {
            return false;
        };
        plan.candidates
            .iter()
            .enumerate()
            .any(|(index, candidate)| {
                mode_available(&candidate.credential_mode)
                    && self.containment_mode_available(
                        identity,
                        service,
                        action,
                        &candidate.credential_mode,
                    )
                    && plan.possible(index)
            })
    }

    #[allow(clippy::too_many_arguments)]
    pub(super) fn containment_access_projection(
        &self,
        snapshot: &PolicySnapshot,
        identity: &IdentityContext,
        context: &ExecutionContext,
        service: &str,
        action: &str,
        token: Option<&ParsedAgentInvokeTokenCaveats<'_>>,
    ) -> Option<LocationAccess> {
        let plan = self.containment_plan(snapshot, identity, context, service, action, token)?;
        let projection = project_location_plan(
            &plan,
            |mode| self.containment_mode_available(identity, service, action, mode),
            crate::RESOURCE_ACCESS_MAX_RESPONSE_BYTES as u64,
        );
        Some(bound_location_access(location_access(
            &plan.scope,
            plan.collection,
            projection,
            plan.requires_runtime_root_visibility(),
        )))
    }

    pub(super) fn containment_selection_projection(
        &self,
        snapshot: &PolicySnapshot,
        context: &ExecutionContext,
        scope: &ActionContainmentScope,
        resources: &ResourceSelection,
        credential_mode: &str,
        collection: bool,
    ) -> LocationAccess {
        let boundary = self.resolve_containment_boundary(snapshot, context, scope, resources);
        let requires_runtime_root_visibility = scope
            .contract
            .effects
            .contains(&ContainmentEffect::SubtreeImpact)
            && boundary
                .excluded()
                .iter()
                .any(|selector| selector.projection().is_some());
        let projection = if boundary
            .included()
            .len()
            .checked_add(boundary.excluded().len())
            .is_none_or(|count| count > 4096)
        {
            projection_too_complex()
        } else if boundary.prove_nonempty(&scope.contract, &scope.site_origin)
            == OfflineContainmentProof::Empty
        {
            LocationProjection::Complete {
                boundaries: Vec::new(),
                clauses: Vec::new(),
            }
        } else {
            let clauses = vec![LocationAccessClause {
                required: vec![0],
                excluded_requests: Vec::new(),
                credential_mode: credential_mode.into(),
            }];
            if location_projection_fits_bytes(
                scope,
                collection,
                requires_runtime_root_visibility,
                &[&boundary],
                &clauses,
                crate::RESOURCE_ACCESS_MAX_RESPONSE_BYTES as u64,
            ) {
                LocationProjection::Complete {
                    boundaries: vec![LocationBoundary::from(&boundary)],
                    clauses,
                }
            } else {
                projection_too_complex()
            }
        };
        bound_location_access(location_access(
            scope,
            collection,
            projection,
            requires_runtime_root_visibility,
        ))
    }

    /// Redacted positive coverage is derived from the same candidate conditions
    /// without constructing a withheld management expression.
    #[allow(clippy::too_many_arguments)]
    pub(super) fn containment_coverage(
        &self,
        snapshot: &PolicySnapshot,
        identity: &IdentityContext,
        context: &ExecutionContext,
        service: &str,
        action: &str,
        token: Option<&ParsedAgentInvokeTokenCaveats<'_>>,
        mode_available: impl Fn(&str) -> bool,
    ) -> Vec<LocationCoverage> {
        let Some(plan) = self.containment_plan(snapshot, identity, context, service, action, token)
        else {
            return Vec::new();
        };
        let mut result = Vec::new();
        for (index, candidate) in plan.candidates.iter().enumerate() {
            if !mode_available(&candidate.credential_mode)
                || !self.containment_mode_available(
                    identity,
                    service,
                    action,
                    &candidate.credential_mode,
                )
                || !plan.possible(index)
            {
                continue;
            }
            let boundary = plan.boundary(index);
            let competitors = (0..plan.candidates.len()).any(|other| plan.competing(index, other));
            for selector in boundary.included() {
                let singleton = ContainmentBoundary::new(vec![selector.clone()], Vec::new());
                if singleton.prove_intersection(
                    boundary,
                    &plan.scope.contract,
                    &plan.scope.site_origin,
                ) == OfflineContainmentProof::Empty
                {
                    continue;
                }
                if plan.token.as_ref().is_some_and(|token| {
                    singleton.prove_intersection(
                        token,
                        &plan.scope.contract,
                        &plan.scope.site_origin,
                    ) == OfflineContainmentProof::Empty
                }) {
                    continue;
                }
                let restricted = !boundary.excluded().is_empty()
                    || competitors
                    || plan.token.as_ref().is_some_and(|token| {
                        token.prove_covers(
                            &singleton,
                            &plan.scope.contract,
                            &plan.scope.site_origin,
                        ) != OfflineContainmentProof::Covered
                    });
                let conditional =
                    restricted || matches!(selector.selector(), ResourceSelector::Subtree { .. });
                let coverage = LocationCoverage {
                    resource_type: selector.resource_type().clone(),
                    selector: selector.selector().clone(),
                    restricted,
                    conditional,
                };
                if !result.contains(&coverage) {
                    result.push(coverage);
                }
            }
        }
        if let Some(token) = &plan.token {
            for selector in token.included() {
                if result.iter().any(|coverage| {
                    coverage.resource_type == *selector.resource_type()
                        && coverage.selector == *selector.selector()
                }) {
                    continue;
                }
                let singleton = ContainmentBoundary::new(vec![selector.clone()], Vec::new());
                if singleton.prove_intersection(
                    token,
                    &plan.scope.contract,
                    &plan.scope.site_origin,
                ) == OfflineContainmentProof::Empty
                {
                    continue;
                }
                let covered = plan
                    .candidates
                    .iter()
                    .enumerate()
                    .any(|(index, candidate)| {
                        mode_available(&candidate.credential_mode)
                            && self.containment_mode_available(
                                identity,
                                service,
                                action,
                                &candidate.credential_mode,
                            )
                            && plan.possible(index)
                            && plan.boundary(index).prove_covers(
                                &singleton,
                                &plan.scope.contract,
                                &plan.scope.site_origin,
                            ) == OfflineContainmentProof::Covered
                    });
                if covered {
                    result.push(LocationCoverage {
                        resource_type: selector.resource_type().clone(),
                        selector: selector.selector().clone(),
                        restricted: true,
                        conditional: true,
                    });
                }
            }
        }
        result
    }

    /// A registered reference is disclosed only with an authored-coordinate
    /// proof. Unknown hierarchy is sufficient for conditional availability,
    /// but cannot disclose unrelated catalog identities.
    #[allow(clippy::too_many_arguments)]
    pub(super) fn containment_reference_visible(
        &self,
        snapshot: &PolicySnapshot,
        identity: &IdentityContext,
        context: &ExecutionContext,
        service: &str,
        action: &str,
        token: Option<&ParsedAgentInvokeTokenCaveats<'_>>,
        resource_type: &ResourceType,
        selector: &ResourceSelector,
        mode_available: impl Fn(&str) -> bool,
    ) -> bool {
        let Some(plan) = self.containment_plan(snapshot, identity, context, service, action, token)
        else {
            return false;
        };
        let Ok(selector) = self
            .resource_types
            .registry()
            .typed_selector(resource_type, selector)
        else {
            return false;
        };
        if !plan
            .scope
            .contract
            .selector_applicable(&selector, &plan.scope.site_origin)
        {
            return false;
        }
        let reference = ContainmentBoundary::new(vec![selector], Vec::new());
        if plan.token.as_ref().is_some_and(|token| {
            token.prove_covers(&reference, &plan.scope.contract, &plan.scope.site_origin)
                != OfflineContainmentProof::Covered
        }) {
            return false;
        }
        plan.candidates
            .iter()
            .enumerate()
            .any(|(index, candidate)| {
                mode_available(&candidate.credential_mode)
                    && self.containment_mode_available(
                        identity,
                        service,
                        action,
                        &candidate.credential_mode,
                    )
                    && plan.boundary(index).prove_covers(
                        &reference,
                        &plan.scope.contract,
                        &plan.scope.site_origin,
                    ) == OfflineContainmentProof::Covered
                    && (0..plan.candidates.len()).all(|other| {
                        !plan.competing(index, other)
                            || plan.boundary(other).prove_intersection(
                                &reference,
                                &plan.scope.contract,
                                &plan.scope.site_origin,
                            ) == OfflineContainmentProof::Empty
                    })
            })
    }

    #[allow(clippy::too_many_arguments)]
    pub(super) fn containment_universal_reach(
        &self,
        snapshot: &PolicySnapshot,
        identity: &IdentityContext,
        context: &ExecutionContext,
        service: &str,
        action: &str,
        token: Option<&ParsedAgentInvokeTokenCaveats<'_>>,
        selected_mode: &str,
    ) -> bool {
        let Some(plan) = self.containment_plan(snapshot, identity, context, service, action, token)
        else {
            return false;
        };
        if plan.collection
            || plan.token.as_ref().is_some_and(|token| {
                !token.is_universe(&plan.scope.contract, &plan.scope.site_origin)
            })
        {
            return false;
        }
        plan.candidates
            .iter()
            .enumerate()
            .any(|(index, candidate)| {
                candidate.credential_mode == selected_mode
                    && self.containment_mode_available(identity, service, action, selected_mode)
                    && plan
                        .boundary(index)
                        .is_universe(&plan.scope.contract, &plan.scope.site_origin)
                    && plan.candidates.iter().all(|other| {
                        other.credential_mode == selected_mode
                            || (other.subject_rank, other.priority)
                                < (candidate.subject_rank, candidate.priority)
                    })
            })
    }

    #[allow(clippy::too_many_arguments)]
    pub(super) fn admitted_containment_companion_reads(
        &self,
        snapshot: &PolicySnapshot,
        identity: &IdentityContext,
        context: &ExecutionContext,
        service: &str,
        action: &ActionDescriptor,
        source: &ContainmentAuthorization,
        token: Option<&ParsedAgentInvokeTokenCaveats<'_>>,
        selected_mode: &str,
    ) -> bool {
        if action.companion_read_actions.is_empty()
            || !action.read_only
            || action.native_search.is_some()
            || action.requires_resource_attributes
            || !matches!(action.io, ActionIo::Json)
            || !matches!(
                action.scoped_mcp_name_source,
                ScopedMcpNameSource::CanonicalAction
            )
        {
            return false;
        }
        action.companion_read_actions.iter().all(|name| {
            let Some(companion) = self.served_action_descriptor(service, name) else {
                return false;
            };
            if name == &action.action
                || !companion.read_only
                || companion.native_search.is_some()
                || companion.requires_resource_attributes
                || !matches!(companion.io, ActionIo::Json)
                || !matches!(
                    companion.scoped_mcp_name_source,
                    ScopedMcpNameSource::CanonicalAction
                )
                || self
                    .enforce_agent_invoke_token_caveats_with(token, service, name, context)
                    .is_err()
            {
                return false;
            }
            let (level, _) = self
                .containment_lookup_requirements(snapshot, identity, context, service, name, token);
            self.admit_containment_evidence(
                snapshot,
                identity,
                context,
                service,
                name,
                token,
                source.evidence().clone(),
                level,
            )
            .is_ok_and(|admission| admission.policy.credential_mode == selected_mode)
        })
    }
}

fn location_access(
    scope: &ActionContainmentScope,
    collection: bool,
    projection: LocationProjection,
    requires_runtime_root_visibility: bool,
) -> LocationAccess {
    LocationAccess {
        resource_types: scope.contract.selectors_by_type.keys().cloned().collect(),
        domain: scope.contract.domain.clone(),
        enforcement: if collection {
            ResourceAccessEnforcement::Results
        } else {
            ResourceAccessEnforcement::Request
        },
        containment_verification: ContainmentVerification::AtInvocation,
        requires_runtime_root_visibility,
        projection,
    }
}

fn bound_location_access(mut access: LocationAccess) -> LocationAccess {
    let mut writer = ProjectionByteCounter {
        remaining: crate::RESOURCE_ACCESS_MAX_RESPONSE_BYTES as u64,
    };
    if serde_json::to_writer(&mut writer, &access).is_err() {
        access.projection = projection_too_complex();
    }
    access
}

fn projection_too_complex() -> LocationProjection {
    LocationProjection::TooComplex {
        reason_code: LocationProjectionFailure::ResourceAccessTooComplex,
    }
}

/// Preflight references and selector occurrences before cloning any boundary.
/// This keeps stored selectors linear and caps the quadratic precedence links.
fn project_location_plan<'a>(
    plan: &'a ContainmentPlan,
    available: impl Fn(&str) -> bool,
    byte_limit: u64,
) -> LocationProjection {
    let mut boundaries: Vec<&ContainmentBoundary> = Vec::new();
    let mut clauses = Vec::new();
    let mut selector_count = 0usize;
    let mut reference_count = 0usize;
    for (index, candidate) in plan.candidates.iter().enumerate() {
        if !available(&candidate.credential_mode) || !plan.possible(index) {
            continue;
        }
        if clauses.len() == 512 {
            return projection_too_complex();
        }
        let mut insert = |boundary: &'a ContainmentBoundary| -> Option<usize> {
            reference_count = reference_count.checked_add(1)?;
            if reference_count > 16_384 {
                return None;
            }
            if let Some(index) = boundaries.iter().position(|stored| *stored == boundary) {
                return Some(index);
            }
            selector_count = selector_count
                .checked_add(boundary.included().len())?
                .checked_add(boundary.excluded().len())?;
            if selector_count > 4096 {
                return None;
            }
            let index = boundaries.len();
            boundaries.push(boundary);
            Some(index)
        };
        let Some(grant) = insert(plan.boundary(index)) else {
            return projection_too_complex();
        };
        let mut required = vec![grant];
        if let Some(token) = &plan.token {
            let Some(token) = insert(token) else {
                return projection_too_complex();
            };
            if !required.contains(&token) {
                required.push(token);
            }
        }
        let mut excluded_requests = Vec::new();
        for other in 0..plan.candidates.len() {
            if !plan.competing(index, other) {
                continue;
            }
            let Some(other) = insert(plan.boundary(other)) else {
                return projection_too_complex();
            };
            if !excluded_requests.contains(&other) {
                excluded_requests.push(other);
            }
        }
        clauses.push(LocationAccessClause {
            required,
            excluded_requests,
            credential_mode: candidate.credential_mode.clone(),
        });
    }
    if !location_projection_fits_bytes(
        &plan.scope,
        plan.collection,
        plan.requires_runtime_root_visibility(),
        &boundaries,
        &clauses,
        byte_limit,
    ) {
        return projection_too_complex();
    }
    LocationProjection::Complete {
        boundaries: boundaries.into_iter().map(LocationBoundary::from).collect(),
        clauses,
    }
}

/// SDK boundaries serialize exactly the authored selector fields used by the
/// management projection. Borrow them for the byte preflight so an over-budget
/// expression never clones its URL/selector strings into an owned result.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct BorrowedLocationProjection<'a> {
    projection_status: &'static str,
    boundaries: &'a [&'a ContainmentBoundary],
    clauses: &'a [LocationAccessClause],
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct BorrowedLocationAccess<'a> {
    resource_types: Vec<&'a ResourceType>,
    domain: &'a str,
    enforcement: ResourceAccessEnforcement,
    containment_verification: ContainmentVerification,
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    requires_runtime_root_visibility: bool,
    #[serde(flatten)]
    projection: BorrowedLocationProjection<'a>,
}

fn location_projection_fits_bytes(
    scope: &ActionContainmentScope,
    collection: bool,
    requires_runtime_root_visibility: bool,
    boundaries: &[&ContainmentBoundary],
    clauses: &[LocationAccessClause],
    byte_limit: u64,
) -> bool {
    let access = BorrowedLocationAccess {
        resource_types: scope.contract.selectors_by_type.keys().collect(),
        domain: &scope.contract.domain,
        enforcement: if collection {
            ResourceAccessEnforcement::Results
        } else {
            ResourceAccessEnforcement::Request
        },
        containment_verification: ContainmentVerification::AtInvocation,
        requires_runtime_root_visibility,
        projection: BorrowedLocationProjection {
            projection_status: "complete",
            boundaries,
            clauses,
        },
    };
    serialized_fits_bytes(&access, byte_limit)
}

fn serialized_fits_bytes(value: &impl Serialize, byte_limit: u64) -> bool {
    let mut writer = ProjectionByteCounter {
        remaining: byte_limit,
    };
    serde_json::to_writer(&mut writer, value).is_ok()
}

struct ProjectionByteCounter {
    remaining: u64,
}
impl std::io::Write for ProjectionByteCounter {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.remaining = self
            .remaining
            .checked_sub(bytes.len() as u64)
            .ok_or_else(|| std::io::Error::other("resource access projection byte limit"))?;
        Ok(bytes.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}
