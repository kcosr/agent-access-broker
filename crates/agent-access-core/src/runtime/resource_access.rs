//! Resource selection discovery and previews share the runtime's compiled boundaries.
use super::*;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ResourceGroupOption {
    pub id: String,
    pub name: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct EffectiveAccessPreview {
    pub policy_generation: u64,
    pub access: Vec<EffectiveAccessEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct EffectiveAccessEntry {
    pub service: String,
    pub action: String,
    pub execution_context: ExecutionContext,
    pub clauses: Vec<EffectiveAccessClause>,
}

/// One typed dimension of an effective request boundary.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct EffectiveAccessScope {
    pub resource_type: ResourceType,
    pub included: Vec<ResourceSelector>,
    pub excluded: Vec<ResourceSelector>,
}

impl EffectiveAccessScope {
    fn new(resource_type: ResourceType, boundary: ResourceBoundary) -> Self {
        Self {
            resource_type,
            included: boundary.included,
            excluded: boundary.excluded,
        }
    }
    fn boundary(&self) -> ResourceBoundary {
        ResourceBoundary {
            included: self.included.clone(),
            excluded: self.excluded.clone(),
        }
    }
}

/// A precedence exclusion applies to one complete request, retaining all
/// scope dimensions together rather than denying their independent projections.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct EffectiveRequestBoundary {
    pub scopes: BTreeMap<String, EffectiveAccessScope>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct EffectiveAccessClause {
    pub scopes: BTreeMap<String, EffectiveAccessScope>,
    pub excluded_requests: Vec<EffectiveRequestBoundary>,
}

fn scope_boundaries_match(
    scopes: &BTreeMap<String, EffectiveAccessScope>,
    targets: &ResourceScopes,
) -> bool {
    scopes.len() == targets.len()
        && scopes.iter().all(|(name, scope)| {
            targets.get(name).is_some_and(|values| {
                !values.is_empty() && values.iter().all(|value| scope.boundary().matches(value))
            })
        })
}

impl EffectiveAccessClause {
    pub(super) fn from_boundary(
        name: String,
        resource_type: ResourceType,
        boundary: ResourceBoundary,
    ) -> Self {
        Self {
            scopes: BTreeMap::from([(name, EffectiveAccessScope::new(resource_type, boundary))]),
            excluded_requests: Vec::new(),
        }
    }

    fn from_candidate(candidate: &PolicyCandidate) -> Self {
        Self {
            scopes: candidate
                .scopes
                .iter()
                .map(|(name, scope)| {
                    (
                        name.clone(),
                        EffectiveAccessScope::new(
                            scope.resource_type.id().clone(),
                            scope.boundary.clone(),
                        ),
                    )
                })
                .collect(),
            excluded_requests: Vec::new(),
        }
    }

    pub(super) fn action_only() -> Self {
        Self {
            scopes: BTreeMap::new(),
            excluded_requests: Vec::new(),
        }
    }

    pub fn matches_request(&self, targets: &ResourceScopes) -> bool {
        scope_boundaries_match(&self.scopes, targets)
            && !self
                .excluded_requests
                .iter()
                .any(|request| scope_boundaries_match(&request.scopes, targets))
    }

    fn is_empty(&self) -> bool {
        self.scopes
            .values()
            .any(|scope| scope.boundary().is_empty())
            || self.excluded_requests.iter().any(|request| {
                request.scopes.len() == self.scopes.len()
                    && self.scopes.iter().all(|(name, allowed)| {
                        request.scopes.get(name).is_some_and(|forbidden| {
                            forbidden.resource_type == allowed.resource_type
                                && subtract_boundary(&allowed.boundary(), &forbidden.boundary())
                                    .is_empty()
                        })
                    })
            })
    }

    fn intersection(&self, restriction: &BTreeMap<String, ResourceBoundary>) -> Self {
        let mut result = self.clone();
        for (name, scope) in &mut result.scopes {
            *scope = EffectiveAccessScope::new(
                scope.resource_type.clone(),
                scope
                    .boundary()
                    .intersection(&restriction.get(name).cloned().unwrap_or_default()),
            );
        }
        result
    }

    fn intersects_scope(&self, name: &str, boundary: &ResourceBoundary) -> bool {
        let Some(scope) = self.scopes.get(name) else {
            return false;
        };
        let mut narrowed = self.clone();
        narrowed.scopes.insert(
            name.to_owned(),
            EffectiveAccessScope::new(
                scope.resource_type.clone(),
                scope.boundary().intersection(boundary),
            ),
        );
        !narrowed.is_empty()
    }

    /// Existential projection of a complete clause to one named scope. Each
    /// other scope must retain a viable partner request in this same clause.
    pub(super) fn single_target_reach(&self, name: &str) -> Vec<ResourceBoundary> {
        if self.is_empty() {
            return Vec::new();
        }
        let Some(scope) = self.scopes.get(name) else {
            return Vec::new();
        };
        self.excluded_requests
            .iter()
            .filter(|request| {
                self.scopes
                    .iter()
                    .filter(|(other, _)| other.as_str() != name)
                    .all(|(other, allowed)| {
                        request.scopes.get(other).is_some_and(|forbidden| {
                            forbidden.resource_type == allowed.resource_type
                                && subtract_boundary(&allowed.boundary(), &forbidden.boundary())
                                    .is_empty()
                        })
                    })
            })
            .fold(
                deduplicate_boundaries(vec![scope.boundary()]),
                |parts, request| {
                    let Some(forbidden) = request.scopes.get(name) else {
                        return parts;
                    };
                    deduplicate_boundaries(
                        parts
                            .iter()
                            .flat_map(|part| subtract_boundary(part, &forbidden.boundary()))
                            .collect(),
                    )
                },
            )
    }

    pub(super) fn matches_partial_target(&self, name: &str, target: &str) -> bool {
        self.single_target_reach(name)
            .iter()
            .any(|boundary| boundary.matches(target))
    }
}

/// Whether the union of `parts` contains every target `selector` matches.
pub(super) fn boundaries_cover(parts: &[ResourceBoundary], selector: &ResourceSelector) -> bool {
    let whole = ResourceBoundary {
        included: vec![selector.clone()],
        excluded: Vec::new(),
    };
    parts
        .iter()
        .fold(deduplicate_boundaries(vec![whole]), |remaining, part| {
            deduplicate_boundaries(
                remaining
                    .iter()
                    .flat_map(|rest| subtract_boundary(rest, part))
                    .collect(),
            )
        })
        .is_empty()
}

impl BrokerRuntime {
    /// Catalog management views are filtered by the caller's delegated service authority.
    /// A mixed group is projected to visible resource IDs, never leaking foreign IDs.
    pub fn policy_resource_catalog_for_scope(
        &self,
        scope: &PolicyReadScope,
    ) -> ManagedResourceCatalog {
        let snapshot = self.policy_snapshot();
        if matches!(scope, PolicyReadScope::Global) {
            return snapshot.resource_catalog.clone();
        }
        let types = self
            .services
            .values()
            .filter(|service| scope.authorizes_service(&service.service))
            .flat_map(|service| {
                service
                    .resource_scopes
                    .values()
                    .map(|scope| scope.resource_type.clone())
            })
            .collect::<BTreeSet<_>>();
        let resources = snapshot
            .resource_catalog
            .resources
            .iter()
            .filter(|resource| types.contains(&resource.resource_type))
            .cloned()
            .collect::<Vec<_>>();
        let visible = resources
            .iter()
            .map(|resource| resource.id.as_str())
            .collect::<BTreeSet<_>>();
        let referenced_groups = snapshot
            .grants
            .iter()
            .filter(|grant| scope.authorizes_service(&grant.service))
            .flat_map(|grant| grant.resources.resource_group_ids.iter())
            .collect::<BTreeSet<_>>();
        let resource_groups = snapshot
            .resource_catalog
            .resource_groups
            .iter()
            .filter_map(|group| {
                let included_resource_ids = group
                    .included_resource_ids
                    .iter()
                    .filter(|id| visible.contains(id.as_str()))
                    .cloned()
                    .collect::<Vec<_>>();
                let excluded_resource_ids = group
                    .excluded_resource_ids
                    .iter()
                    .filter(|id| visible.contains(id.as_str()))
                    .cloned()
                    .collect::<Vec<_>>();
                (!included_resource_ids.is_empty()
                    || !excluded_resource_ids.is_empty()
                    || referenced_groups.contains(&group.id)
                    || (group.included_resource_ids.is_empty()
                        && group.excluded_resource_ids.is_empty()))
                .then(|| ResourceGroupDefinition {
                    id: group.id.clone(),
                    name: group.name.clone(),
                    included_resource_ids,
                    excluded_resource_ids,
                })
            })
            .collect();
        ManagedResourceCatalog {
            attribute_bindings: Vec::new(),
            resource_fences: Default::default(),
            resources,
            resource_groups,
        }
    }

    pub fn preview_policy_resources(
        &self,
        service: &str,
        actions: &[String],
        execution_contexts: &[ExecutionContext],
        resources: &ResourceSelection,
    ) -> Result<EffectiveAccessPreview, ManagedStoreError> {
        let snapshot = self.policy_snapshot();
        resources
            .validate_structure()
            .map_err(resource_preview_validation_error)?;
        // Use execution semantics, including mixed types and currently hidden
        // references. Unknown IDs resolve fail closed without catalog lookup errors.
        self.validate_preview_contexts(execution_contexts)?;
        let mut access = Vec::new();
        for action in actions {
            if self.action_descriptor(service, action).is_none() {
                return Err(ManagedStoreError::PolicyValidationFailed(
                    "preview service/action is not supported".into(),
                ));
            }
            let required = self
                .action_resource_scopes(service, action)
                .unwrap_or_default();
            if required.is_empty() && !resources.is_empty() {
                return Err(ManagedStoreError::PolicyValidationFailed(
                    "resource selections are unsupported for this action".into(),
                ));
            }
            for context in execution_contexts {
                let clause = EffectiveAccessClause {
                    scopes: required
                        .iter()
                        .map(|scope| {
                            (
                                scope.scope.clone(),
                                EffectiveAccessScope::new(
                                    scope.resource_type.id().clone(),
                                    normalize_boundary(snapshot.resources.resolve(
                                        resources,
                                        scope.resource_type.id(),
                                        context.as_str(),
                                    )),
                                ),
                            )
                        })
                        .collect(),
                    excluded_requests: Vec::new(),
                };
                if !clause.is_empty() {
                    access.push(EffectiveAccessEntry {
                        service: service.into(),
                        action: action.clone(),
                        execution_context: context.clone(),
                        clauses: vec![clause],
                    });
                }
            }
        }
        Ok(EffectiveAccessPreview {
            policy_generation: snapshot.generation(),
            access,
        })
    }

    pub fn preview_agent_token_access(
        &self,
        identity: &IdentityContext,
        caveats: &AgentInvokeTokenCaveats,
    ) -> Result<EffectiveAccessPreview, ManagedStoreError> {
        let snapshot = self.policy_snapshot();
        if let Some(restrictions) = &caveats.service_restrictions {
            for restriction in restrictions.values() {
                if let Some(selection) = &restriction.resources {
                    selection
                        .validate_structure()
                        .map_err(resource_preview_validation_error)?;
                }
            }
        }
        let configured_contexts = self.configured_execution_contexts();
        if let Some(contexts) = &caveats.allowed_execution_contexts {
            self.validate_preview_contexts(contexts)?;
        }
        let mut access = Vec::new();
        for service in self.services.values() {
            for action in &service.actions {
                for context in &configured_contexts {
                    let clauses = self.effective_resource_clauses(
                        &snapshot,
                        identity,
                        context,
                        &service.service,
                        &action.action,
                        Some(caveats),
                    );
                    if !clauses.is_empty() {
                        access.push(EffectiveAccessEntry {
                            service: service.service.clone(),
                            action: action.action.clone(),
                            execution_context: context.clone(),
                            clauses,
                        });
                    }
                }
            }
        }
        Ok(EffectiveAccessPreview {
            policy_generation: snapshot.generation(),
            access,
        })
    }

    pub fn validate_agent_token_resources(
        &self,
        caveats: &AgentInvokeTokenCaveats,
    ) -> Result<(), ManagedStoreError> {
        self.validate_token_resource_references(&self.policy_snapshot(), caveats)
    }

    fn validate_token_resource_references(
        &self,
        snapshot: &PolicySnapshot,
        caveats: &AgentInvokeTokenCaveats,
    ) -> Result<(), ManagedStoreError> {
        if let Some(restrictions) = &caveats.service_restrictions {
            for restriction in restrictions.values() {
                if let Some(selection) = &restriction.resources {
                    snapshot
                        .resources
                        .validate_selection(selection)
                        .map_err(resource_preview_validation_error)?;
                }
            }
        }
        Ok(())
    }

    fn validate_preview_contexts(
        &self,
        contexts: &[ExecutionContext],
    ) -> Result<(), ManagedStoreError> {
        let configured = self.configured_execution_contexts();
        if contexts.iter().any(|context| !configured.contains(context)) {
            return Err(ManagedStoreError::PolicyValidationFailed(
                "preview references an unknown execution context".to_string(),
            ));
        }
        Ok(())
    }

    pub(super) fn effective_resource_clauses(
        &self,
        snapshot: &PolicySnapshot,
        identity: &IdentityContext,
        context: &ExecutionContext,
        service: &str,
        action: &str,
        token: Option<&AgentInvokeTokenCaveats>,
    ) -> Vec<EffectiveAccessClause> {
        self.effective_resource_clauses_for_modes(
            snapshot,
            identity,
            context,
            service,
            action,
            token,
            |_| true,
        )
    }

    /// Filter selected authority without removing competing grants: unavailable
    /// credentials must never expose a lower-precedence credential's authority.
    #[allow(clippy::too_many_arguments)]
    pub(super) fn effective_resource_clauses_for_modes(
        &self,
        snapshot: &PolicySnapshot,
        identity: &IdentityContext,
        context: &ExecutionContext,
        service: &str,
        action: &str,
        token: Option<&AgentInvokeTokenCaveats>,
        mode_available: impl Fn(&str) -> bool,
    ) -> Vec<EffectiveAccessClause> {
        if token.is_some_and(|caveats| !caveats_permit_action(caveats, context, service, action)) {
            return Vec::new();
        }
        if self.command_enforced(service, action) {
            return deduplicate_clauses(self.command_effective_clauses(
                snapshot,
                identity,
                context,
                service,
                action,
                token,
                mode_available,
            ));
        }
        let native_search = self
            .action_descriptor(service, action)
            .is_some_and(|descriptor| descriptor.native_search.is_some());
        let mut clauses = if native_search {
            match self.plan_search_authorization(snapshot, identity, context, service, action) {
                Ok(search) if mode_available(&search.credential_mode) => self
                    .action_resource_type(service, action)
                    .map(|resource_type| {
                        search
                            .scope
                            .clauses()
                            .iter()
                            .map(|clause| {
                                EffectiveAccessClause::from_boundary(
                                    search.scope_type.clone(),
                                    resource_type.clone(),
                                    search_clause_boundary(clause),
                                )
                            })
                            .collect()
                    })
                    .unwrap_or_default(),
                _ => Vec::new(),
            }
        } else {
            let candidates =
                self.policy_candidates_for_action(snapshot, identity, context, service, action);
            candidate_clauses_for_modes(&candidates, |mode| {
                mode_available(mode)
                    && self.action_supports_mode(service, action, mode)
                    && self.action_credential_eligible(service, action, mode, identity)
                    && credential_mode_available(
                        &self.effective_credentials,
                        service,
                        mode,
                        self.services
                            .get(service)
                            .map(|descriptor| &descriptor.credentials),
                    )
            })
        };
        if let Some(boundary) = token.and_then(|caveats| {
            self.token_resource_boundary(snapshot, context, caveats, service, action)
        }) {
            if boundary.is_empty() {
                return Vec::new();
            }
            clauses = clauses
                .into_iter()
                .filter(|clause| clause.scopes.keys().eq(boundary.keys()))
                .map(|clause| normalize_clause(clause.intersection(&boundary)))
                .filter(|clause| !clause.is_empty())
                .collect();
        }
        deduplicate_clauses(clauses)
    }

    pub(super) fn token_resource_picker_options(
        &self,
        snapshot: &PolicySnapshot,
        identity: &IdentityContext,
        services: &[AgentTokenServiceOption],
    ) -> (Vec<ResourceDefinition>, Vec<ResourceGroupOption>) {
        // Authored references remain selectable even when their current boundary is empty.
        // This permits deliberate preparation without exposing unrelated catalog entries.
        let mut authored_resources = BTreeSet::new();
        let mut authored_groups = BTreeSet::new();
        for grant in &snapshot.grants {
            if subject_rank(&grant.subject, identity).is_none() {
                continue;
            }
            let Some(service) = services
                .iter()
                .find(|service| service.service == grant.service)
            else {
                continue;
            };
            for action in service
                .actions
                .iter()
                .filter(|action| grant.actions.contains(&action.action))
            {
                if !grant
                    .execution_contexts
                    .iter()
                    .any(|context| action.execution_contexts.contains(context))
                {
                    continue;
                }
                let mut selected = grant.resources.resource_ids.clone();
                for group_id in &grant.resources.resource_group_ids {
                    authored_groups.insert(group_id.clone());
                    if let Some(group) = snapshot.resources.resource_groups.get(group_id) {
                        selected.extend(group.included_resource_ids.iter().cloned());
                        selected.extend(group.excluded_resource_ids.iter().cloned());
                    }
                }
                for id in selected {
                    if snapshot
                        .resources
                        .resources
                        .get(&id)
                        .is_some_and(|resource| {
                            action
                                .required_scopes
                                .values()
                                .any(|scope| scope.resource_type == resource.resource_type)
                        })
                    {
                        authored_resources.insert(id);
                    }
                }
            }
        }
        let resources = snapshot
            .resource_catalog
            .resources
            .iter()
            .filter(|resource| {
                if authored_resources.contains(&resource.id) {
                    return true;
                }
                if !resource.enabled {
                    return false;
                }
                let entry = ResourceBoundary {
                    included: vec![resource.selector.clone()],
                    excluded: Vec::new(),
                };
                services
                    .iter()
                    .flat_map(|service| &service.actions)
                    .filter(|action| {
                        action
                            .required_scopes
                            .values()
                            .any(|scope| scope.resource_type == resource.resource_type)
                    })
                    .any(|action| {
                        action.effective_access_by_execution_context.iter().any(
                            |(context, clauses)| {
                                resource
                                    .allowed_execution_contexts
                                    .iter()
                                    .any(|allowed| allowed == context.as_str())
                                    && clauses.iter().any(|clause| {
                                        clause.scopes.iter().any(|(name, scope)| {
                                            scope.resource_type == resource.resource_type
                                                && clause.intersects_scope(name, &entry)
                                        })
                                    })
                            },
                        )
                    })
            })
            .cloned()
            .collect::<Vec<_>>();
        let groups = snapshot
            .resource_catalog
            .resource_groups
            .iter()
            .filter_map(|group| {
                let selection = ResourceSelection {
                    resource_ids: Vec::new(),
                    resource_group_ids: vec![group.id.clone()],
                };
                let visible = authored_groups.contains(&group.id)
                    || services
                        .iter()
                        .flat_map(|service| &service.actions)
                        .any(|action| {
                            action.effective_access_by_execution_context.iter().any(
                                |(context, clauses)| {
                                    action.required_scopes.iter().any(|(name, scope)| {
                                        let boundary = snapshot.resources.resolve(
                                            &selection,
                                            &scope.resource_type,
                                            context.as_str(),
                                        );
                                        clauses
                                            .iter()
                                            .any(|clause| clause.intersects_scope(name, &boundary))
                                    })
                                },
                            )
                        });
                visible.then(|| ResourceGroupOption {
                    id: group.id.clone(),
                    name: group.name.clone(),
                })
            })
            .collect();
        (resources, groups)
    }
}

fn caveats_permit_action(
    caveats: &AgentInvokeTokenCaveats,
    context: &ExecutionContext,
    service: &str,
    action: &str,
) -> bool {
    caveats
        .allowed_execution_contexts
        .as_ref()
        .is_none_or(|contexts| contexts.contains(context))
        && caveats
            .allowed_services
            .as_ref()
            .is_none_or(|services| services.iter().any(|value| value == service))
        && caveats
            .service_restrictions
            .as_ref()
            .and_then(|restrictions| restrictions.get(service))
            .is_none_or(|restriction| restriction.actions.iter().any(|value| value == action))
}

fn resource_preview_validation_error(errors: Vec<String>) -> ManagedStoreError {
    ManagedStoreError::PolicyValidationFailed(errors.join("; "))
}

fn normalize_boundary(boundary: ResourceBoundary) -> ResourceBoundary {
    search_clause_boundary(&SearchAuthorizationClause::new(
        boundary.included,
        boundary.excluded,
    ))
}

fn deduplicate_boundaries(boundaries: Vec<ResourceBoundary>) -> Vec<ResourceBoundary> {
    let mut result = Vec::new();
    for boundary in boundaries {
        let boundary = normalize_boundary(boundary);
        if !boundary.is_empty() && !result.contains(&boundary) {
            result.push(boundary);
        }
    }
    result
}

/// C \\ (I \\ E) = (C \\ I) union (C intersect E). Preserve branches:
/// exclusions on an unrelated grant never become a global deny.
fn subtract_boundary(left: &ResourceBoundary, right: &ResourceBoundary) -> Vec<ResourceBoundary> {
    let left = SearchAuthorizationClause::new(left.included.clone(), left.excluded.clone());
    let right = SearchAuthorizationClause::new(right.included.clone(), right.excluded.clone());
    left.subtract(&right)
        .iter()
        .map(search_clause_boundary)
        .collect()
}

fn normalize_clause(mut clause: EffectiveAccessClause) -> EffectiveAccessClause {
    for scope in clause.scopes.values_mut() {
        *scope = EffectiveAccessScope::new(
            scope.resource_type.clone(),
            normalize_boundary(scope.boundary()),
        );
    }
    let mut exclusions = Vec::new();
    for request in clause.excluded_requests {
        if !request.scopes.keys().eq(clause.scopes.keys()) {
            continue;
        }
        let mut scopes = BTreeMap::new();
        for (name, forbidden) in request.scopes {
            let allowed = &clause.scopes[&name];
            if forbidden.resource_type != allowed.resource_type {
                break;
            }
            let boundary =
                normalize_boundary(forbidden.boundary().intersection(&allowed.boundary()));
            if boundary.is_empty() {
                break;
            }
            scopes.insert(
                name,
                EffectiveAccessScope::new(forbidden.resource_type, boundary),
            );
        }
        let request = EffectiveRequestBoundary { scopes };
        if request.scopes.len() == clause.scopes.len() && !exclusions.contains(&request) {
            exclusions.push(request);
        }
    }
    clause.excluded_requests = exclusions;
    clause
}

fn deduplicate_clauses(clauses: Vec<EffectiveAccessClause>) -> Vec<EffectiveAccessClause> {
    let mut result = Vec::new();
    for clause in clauses {
        let clause = normalize_clause(clause);
        if !clause.is_empty() && !result.contains(&clause) {
            result.push(clause);
        }
    }
    result
}

/// Candidate selection checks every target before choosing a precedence band.
/// Preserve that order in the preview: a competing grant suppresses a clause
/// only when that competing grant can cover the entire requested target tuple.
#[cfg(test)]
fn usable_candidate_clauses(
    candidates: &[PolicyCandidate],
    credentials: &crate::CredentialsConfig,
    service: &str,
    descriptor: Option<&CredentialDescriptor>,
) -> Vec<EffectiveAccessClause> {
    candidate_clauses_for_modes(candidates, |mode| {
        credential_mode_available(credentials, service, mode, descriptor)
    })
}

fn candidate_clauses_for_modes(
    candidates: &[PolicyCandidate],
    mode_available: impl Fn(&str) -> bool,
) -> Vec<EffectiveAccessClause> {
    let mut result = Vec::new();
    for candidate in candidates {
        if !mode_available(&candidate.credential_mode) {
            continue;
        }
        let candidate_band = (candidate.subject_rank, candidate.priority);
        let mut clause = EffectiveAccessClause::from_candidate(candidate);
        for other in candidates {
            let other_band = (other.subject_rank, other.priority);
            if other_band > candidate_band
                || other_band == candidate_band
                    && other.credential_mode != candidate.credential_mode
            {
                clause.excluded_requests.push(EffectiveRequestBoundary {
                    scopes: EffectiveAccessClause::from_candidate(other).scopes,
                });
            }
        }
        result.push(clause);
    }
    deduplicate_clauses(result)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn exact(value: &str) -> ResourceSelector {
        ResourceSelector::Exact {
            value: value.into(),
        }
    }
    fn namespace(value: &str) -> ResourceSelector {
        ResourceSelector::Namespace {
            value: value.into(),
        }
    }
    fn boundary(
        included: Vec<ResourceSelector>,
        excluded: Vec<ResourceSelector>,
    ) -> ResourceBoundary {
        ResourceBoundary { included, excluded }
    }
    fn candidate(
        mode: &str,
        rank: u8,
        priority: i32,
        boundary: ResourceBoundary,
    ) -> PolicyCandidate {
        PolicyCandidate {
            subject: "group:agents".into(),
            credential_mode: mode.into(),
            explicit_priority: Some(priority),
            priority,
            subject_rank: rank,
            order: 0,
            subject_order: 0,
            config_index: Some(0),
            grant_id: None,
            grant_version: None,
            resources: ResourceSelection::default(),
            execution_contexts: vec![ExecutionContext::new("default").unwrap()],
            scopes: BTreeMap::from([(
                "repository".into(),
                PolicyCandidateScope {
                    resource_type: Arc::new(agent_access_provider::GIT_REPOSITORY_RESOURCE.clone()),
                    boundary,
                },
            )]),
        }
    }

    #[test]
    fn finite_cofinite_search_algebra_preserves_separate_grants_and_token_exclusions() {
        let all_except_private =
            SearchAuthorizationScope::excluding_exact_values(vec!["PRIVATE".into()]);
        let private_grant = SearchAuthorizationScope::from_exact_values(vec!["PRIVATE".into()]);
        assert!(
            all_except_private.union(&private_grant).is_universe(),
            "a separate grant can restore an excluded project"
        );
        let token = SearchAuthorizationScope::excluding_exact_values(vec!["SECRET".into()]);
        let restricted = all_except_private.intersection(&token);
        assert!(!restricted.matches("PRIVATE"));
        assert!(!restricted.matches("SECRET"));
        assert!(
            restricted.matches("NEWPROJECT"),
            "new upstream projects remain covered"
        );
        assert!(restricted.intersection(&private_grant).is_empty());
        assert!(
            SearchAuthorizationScope::from_exact_values(vec![])
                .intersection(&token)
                .is_empty()
        );
    }

    #[test]
    fn effective_access_matches_concrete_credential_precedence_with_nested_exceptions() {
        let mut credentials = crate::CredentialsConfig::default();
        credentials
            .service
            .insert("gitlab".into(), fake_service_credential("env:SERVICE"));
        credentials
            .per_user
            .insert("gitlab".into(), fake_service_credential("env:USER"));
        let candidates = vec![
            candidate(
                "service",
                1,
                0,
                boundary(vec![ResourceSelector::All], vec![]),
            ),
            candidate(
                "per_user",
                2,
                0,
                boundary(
                    vec![namespace("engineering")],
                    vec![namespace("engineering/private")],
                ),
            ),
            candidate(
                "service",
                2,
                0,
                boundary(
                    vec![namespace("engineering/platform")],
                    vec![exact("engineering/platform/open")],
                ),
            ),
            candidate(
                "missing",
                2,
                1,
                boundary(vec![exact("engineering/blocked")], vec![]),
            ),
        ];
        let preview = usable_candidate_clauses(&candidates, &credentials, "gitlab", None);
        for path in [
            "other/repo",
            "engineering/api",
            "engineering/private/repo",
            "engineering/platform/api",
            "engineering/platform/open",
            "engineering/blocked",
            "engineering/platform-tools/api",
        ] {
            let matches = candidates
                .iter()
                .filter(|candidate| candidate.scopes["repository"].boundary.matches(path))
                .cloned()
                .collect::<Vec<_>>();
            let expected = single_policy_credential_mode(&top_policy_band(matches))
                .is_ok_and(|mode| crate::credential_mode_configured(&credentials, "gitlab", &mode));
            assert_eq!(
                preview
                    .iter()
                    .any(|clause| clause.matches_partial_target("repository", path)),
                expected,
                "preview diverged at {path}"
            );
        }
        assert!(
            !preview
                .iter()
                .any(|clause| clause
                    .matches_partial_target("repository", "engineering/platform/api")),
            "same winning band conflicts must be hidden"
        );
        assert!(
            preview
                .iter()
                .any(|clause| clause
                    .matches_partial_target("repository", "engineering/private/repo")),
            "higher grant exclusion does not suppress an eligible lower grant"
        );
    }

    #[test]
    fn whole_request_preview_preserves_coherent_multi_resource_fallback() {
        let mut credentials = crate::CredentialsConfig::default();
        credentials
            .service
            .insert("test".into(), fake_service_credential("env:SERVICE"));
        credentials
            .per_user
            .insert("test".into(), fake_service_credential("env:USER"));
        for (resource_type, scope, first, second) in [
            (
                &agent_access_provider::GIT_REPOSITORY_RESOURCE,
                "repository",
                "engineering/first",
                "engineering/second",
            ),
            (
                &agent_access_jira::JIRA_PROJECT_RESOURCE,
                "project",
                "FIRST",
                "SECOND",
            ),
        ] {
            let mut candidates = vec![
                candidate(
                    "service",
                    1,
                    0,
                    boundary(vec![ResourceSelector::All], vec![]),
                ),
                candidate("service", 1, 1, boundary(vec![exact(first)], vec![])),
                candidate("per_user", 1, 1, boundary(vec![exact(first)], vec![])),
                candidate("service", 1, 1, boundary(vec![exact(second)], vec![])),
                candidate("per_user", 1, 1, boundary(vec![exact(second)], vec![])),
            ];
            for (index, candidate) in candidates.iter_mut().enumerate() {
                let boundary = candidate.scopes.remove("repository").unwrap().boundary;
                candidate.scopes.insert(
                    scope.into(),
                    PolicyCandidateScope {
                        resource_type: Arc::new(resource_type.clone()),
                        boundary,
                    },
                );
                candidate.subject = format!("group:group-{index}");
            }
            let clauses = usable_candidate_clauses(&candidates, &credentials, "test", None);
            for targets in [vec![first], vec![second], vec![first, second]] {
                let scopes = ResourceScopes::from([(
                    scope.into(),
                    targets.iter().map(|value| value.to_string()).collect(),
                )]);
                let matching = candidates
                    .iter()
                    .filter(|candidate| candidate_authorizes_scopes(candidate, &scopes))
                    .cloned()
                    .collect::<Vec<_>>();
                let expected = single_policy_credential_mode(&top_policy_band(matching)).is_ok();
                assert_eq!(
                    clauses.iter().any(|clause| clause.matches_request(&scopes)),
                    expected,
                    "whole-request preview diverged for {} {targets:?}",
                    resource_type.id()
                );
            }
            assert!(
                !clauses
                    .iter()
                    .any(|clause| clause.matches_partial_target(scope, first))
            );
            assert!(
                clauses
                    .iter()
                    .any(|clause| clause.matches_request(&ResourceScopes::from([(
                        scope.into(),
                        vec![first.into(), second.into()]
                    )]))),
                "narrow high grants do not match a cross-resource request"
            );
            assert!(
                clauses
                    .iter()
                    .any(|clause| !clause.excluded_requests.is_empty())
            );
            let token = boundary(vec![exact(first)], vec![]);
            assert!(
                deduplicate_clauses(
                    clauses
                        .iter()
                        .map(|clause| clause
                            .intersection(&BTreeMap::from([(scope.into(), token.clone())])))
                        .collect()
                )
                .is_empty(),
                "token narrowing retains the whole-request precedence condition"
            );
        }
    }

    #[test]
    fn plural_precedence_exclusions_retain_the_whole_request_conjunction() {
        let make = |mode: &str, priority, repos: &[&str], spaces: &[&str]| {
            let mut grant = candidate(
                mode,
                1,
                priority,
                boundary(repos.iter().map(|value| exact(value)).collect(), vec![]),
            );
            grant.scopes.insert(
                "space".into(),
                PolicyCandidateScope {
                    resource_type: Arc::new(
                        agent_access_confluence::CONFLUENCE_SPACE_RESOURCE.clone(),
                    ),
                    boundary: boundary(spaces.iter().map(|value| exact(value)).collect(), vec![]),
                },
            );
            grant
        };
        let candidates = vec![
            make("service", 0, &["team/a", "team/b"], &["ENG", "OPS"]),
            make("service", 1, &["team/a"], &["ENG"]),
            make("per_user", 1, &["team/a"], &["ENG"]),
            make("per_user", 1, &["team/b"], &["ENG"]),
            make("unavailable", 1, &["team/b"], &["OPS"]),
        ];
        let clauses = candidate_clauses_for_modes(&candidates, |mode| mode != "unavailable");
        for repositories in [vec!["team/a"], vec!["team/b"], vec!["team/a", "team/b"]] {
            for spaces in [vec!["ENG"], vec!["OPS"], vec!["ENG", "OPS"]] {
                let request = ResourceScopes::from([
                    (
                        "repository".into(),
                        repositories.iter().map(|value| (*value).into()).collect(),
                    ),
                    (
                        "space".into(),
                        spaces.iter().map(|value| (*value).into()).collect(),
                    ),
                ]);
                let matching = candidates
                    .iter()
                    .filter(|grant| candidate_authorizes_scopes(grant, &request))
                    .cloned()
                    .collect();
                let expected = single_policy_credential_mode(&top_policy_band(matching))
                    .is_ok_and(|mode| mode != "unavailable");
                assert_eq!(
                    clauses
                        .iter()
                        .any(|clause| clause.matches_request(&request)),
                    expected,
                    "{request:?}"
                );
            }
        }
        let lower = clauses
            .iter()
            .find(|clause| !clause.excluded_requests.is_empty())
            .unwrap();
        assert!(
            lower.matches_partial_target("repository", "team/a"),
            "OPS remains a partner even though (a,ENG) is excluded"
        );
        assert!(
            lower.matches_partial_target("space", "OPS"),
            "a remains a partner even though (b,OPS) is excluded"
        );
        assert!(
            lower.matches_partial_target("repository", "team/b"),
            "a multi-target partner spanning both narrow higher grants still reaches the lower grant"
        );
        let wire = serde_json::to_value(lower).unwrap();
        assert_eq!(
            wire["excludedRequests"][0]["scopes"]
                .as_object()
                .unwrap()
                .len(),
            2
        );
        let restriction = BTreeMap::from([
            ("repository".into(), boundary(vec![exact("team/a")], vec![])),
            ("space".into(), boundary(vec![exact("ENG")], vec![])),
        ]);
        assert!(
            deduplicate_clauses(
                clauses
                    .iter()
                    .map(|clause| clause.intersection(&restriction))
                    .collect()
            )
            .is_empty()
        );
    }

    #[test]
    fn action_only_clauses_are_explicit_and_reject_extra_dimensions() {
        let clause = EffectiveAccessClause::action_only();
        assert!(clause.matches_request(&ResourceScopes::new()));
        assert!(!clause.matches_request(&ResourceScopes::from([(
            "project".into(),
            vec!["ENG".into()]
        )])));
        assert_eq!(
            serde_json::to_value(&clause).unwrap(),
            json!({"scopes":{},"excludedRequests":[]})
        );
        assert_eq!(deduplicate_clauses(vec![clause]).len(), 1);
    }

    #[test]
    fn wildcard_grants_and_exclusions_do_not_authorize_malformed_resolved_targets() {
        let grant = candidate(
            "service",
            1,
            0,
            boundary(vec![ResourceSelector::All], vec![namespace("private")]),
        );
        for path in [
            "",
            "/private/repo",
            "private//repo",
            "private/../public",
            "private%2frepo",
            "private",
        ] {
            let scopes = ResourceScopes::from([("repository".into(), vec![path.into()])]);
            assert!(
                !candidate_authorizes_scopes(&grant, &scopes),
                "invalid resolved path was authorized: {path:?}"
            );
        }
        assert!(candidate_authorizes_scopes(
            &grant,
            &ResourceScopes::from([("repository".into(), vec!["public/repo".into()])])
        ));
    }

    #[test]
    fn single_target_reach_withholds_targets_inside_any_precedence_condition() {
        let mut clause = EffectiveAccessClause::from_boundary(
            "repository".into(),
            agent_access_provider::GIT_REPOSITORY_RESOURCE.id().clone(),
            boundary(vec![ResourceSelector::All], vec![]),
        );
        clause.excluded_requests = vec![
            boundary(vec![namespace("team")], vec![namespace("team/open")]),
            boundary(vec![namespace("team/open")], vec![]),
        ]
        .into_iter()
        .map(|boundary| EffectiveRequestBoundary {
            scopes: EffectiveAccessClause::from_boundary(
                "repository".into(),
                agent_access_provider::GIT_REPOSITORY_RESOURCE.id().clone(),
                boundary,
            )
            .scopes,
        })
        .collect();
        let team = boundary(vec![namespace("team")], vec![]);
        assert!(
            clause.intersects_scope("repository", &team)
                && clause.matches_request(&ResourceScopes::from([(
                    "repository".into(),
                    vec!["team/open/a".into(), "team/b".into()]
                )])),
            "a request spanning both conditions remains admitted"
        );
        let reach = clause.single_target_reach("repository");
        for target in ["team/open/a", "team/b"] {
            assert!(!clause.matches_partial_target("repository", target));
            assert!(!reach.iter().any(|part| part.matches(target)));
        }
        assert!(!reach.iter().any(|part| part.intersects(&team)));
        assert!(boundaries_cover(&reach, &namespace("other")));
        assert!(!boundaries_cover(&reach, &ResourceSelector::All));
        assert!(boundaries_cover(
            &[
                boundary(vec![ResourceSelector::All], vec![namespace("team")]),
                boundary(vec![namespace("team")], vec![exact("team/x")]),
                boundary(vec![exact("team/x")], vec![]),
            ],
            &ResourceSelector::All
        ));
    }

    #[test]
    fn symbolic_subtraction_keeps_holes_local_to_the_subtracted_boundary() {
        let left = boundary(vec![ResourceSelector::All], vec![exact("already/denied")]);
        let right = boundary(
            vec![namespace("engineering")],
            vec![namespace("engineering/public")],
        );
        let remainder = subtract_boundary(&left, &right);
        for path in [
            "other/repo",
            "engineering/api",
            "engineering/public/api",
            "already/denied",
            "engineering/public-tools/api",
        ] {
            assert_eq!(
                remainder.iter().any(|part| part.matches(path)),
                left.matches(path) && !right.matches(path)
            );
        }
    }
}
