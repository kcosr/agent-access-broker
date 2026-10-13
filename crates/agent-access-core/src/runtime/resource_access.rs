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
    pub resource_type: Option<ResourceType>,
    pub clauses: Vec<EffectiveAccessClause>,
}

/// A complete request must fit one clause. `excluded_requests` are precedence
/// conditions on the whole request, distinct from per-resource exclusions.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct EffectiveAccessClause {
    pub included: Vec<ResourceSelector>,
    pub excluded: Vec<ResourceSelector>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub excluded_requests: Vec<ResourceBoundary>,
}

impl EffectiveAccessClause {
    fn from_boundary(boundary: ResourceBoundary) -> Self {
        Self {
            included: boundary.included,
            excluded: boundary.excluded,
            excluded_requests: Vec::new(),
        }
    }

    fn boundary(&self) -> ResourceBoundary {
        ResourceBoundary {
            included: self.included.clone(),
            excluded: self.excluded.clone(),
        }
    }

    pub fn matches_request(&self, targets: &[&str]) -> bool {
        !targets.is_empty()
            && targets.iter().all(|target| self.boundary().matches(target))
            && !self
                .excluded_requests
                .iter()
                .any(|boundary| targets.iter().all(|target| boundary.matches(target)))
    }

    pub fn matches(&self, target: &str) -> bool {
        self.matches_request(&[target])
    }

    fn is_empty(&self) -> bool {
        let allowed = self.boundary();
        allowed.is_empty()
            || self
                .excluded_requests
                .iter()
                .any(|forbidden| subtract_boundary(&allowed, forbidden).is_empty())
    }

    fn intersection(&self, restriction: &ResourceBoundary) -> Self {
        let allowed = self.boundary().intersection(restriction);
        Self {
            included: allowed.included,
            excluded: allowed.excluded,
            excluded_requests: self.excluded_requests.clone(),
        }
    }

    fn intersects(&self, boundary: &ResourceBoundary) -> bool {
        !self.intersection(boundary).is_empty()
    }

    /// The targets a single-resource request reaches under this clause: the
    /// allowed boundary minus every precedence condition. Unlike
    /// [`Self::intersects`], which admits a request spanning several
    /// conditions, one target is withheld by any condition that contains it.
    pub(super) fn single_target_reach(&self) -> Vec<ResourceBoundary> {
        self.excluded_requests.iter().fold(
            deduplicate_boundaries(vec![self.boundary()]),
            |parts, forbidden| {
                deduplicate_boundaries(
                    parts
                        .iter()
                        .flat_map(|part| subtract_boundary(part, forbidden))
                        .collect(),
                )
            },
        )
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
            let Some(resource_type) = self.action_resource_type(service, action) else {
                if !resources.is_empty() {
                    return Err(ManagedStoreError::PolicyValidationFailed(
                        "resource selections are unsupported for this action".into(),
                    ));
                }
                access.extend(
                    execution_contexts
                        .iter()
                        .map(|context| EffectiveAccessEntry {
                            service: service.into(),
                            action: action.clone(),
                            execution_context: context.clone(),
                            resource_type: None,
                            clauses: Vec::new(),
                        }),
                );
                continue;
            };
            for context in execution_contexts {
                let boundary = normalize_boundary(snapshot.resources.resolve(
                    resources,
                    &resource_type,
                    context.as_str(),
                ));
                if !boundary.is_empty() {
                    access.push(EffectiveAccessEntry {
                        service: service.to_string(),
                        action: action.clone(),
                        execution_context: context.clone(),
                        resource_type: Some(resource_type.clone()),
                        clauses: vec![EffectiveAccessClause::from_boundary(boundary)],
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
                let Some(resource_type) =
                    self.action_resource_type(&service.service, &action.action)
                else {
                    for context in &configured_contexts {
                        if caveats_permit_action(caveats, context, &service.service, &action.action)
                            && self.action_has_effective_access(
                                &snapshot,
                                identity,
                                context,
                                &service.service,
                                &action.action,
                                Some(caveats),
                            )
                        {
                            access.push(EffectiveAccessEntry {
                                service: service.service.clone(),
                                action: action.action.clone(),
                                execution_context: context.clone(),
                                resource_type: None,
                                clauses: Vec::new(),
                            });
                        }
                    }
                    continue;
                };
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
                            resource_type: Some(resource_type.clone()),
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
        let search_contained = self
            .action_descriptor(service, action)
            .is_some_and(|descriptor| descriptor.search_contained);
        let mut clauses = if search_contained {
            match self.plan_search_authorization(snapshot, identity, context, service, action) {
                Ok(search) if mode_available(&search.credential_mode) => {
                    vec![EffectiveAccessClause::from_boundary(
                        super::search_scope_boundary(&search.scope),
                    )]
                }
                _ => Vec::new(),
            }
        } else {
            let candidates =
                self.policy_candidates_for_action(snapshot, identity, context, service, action);
            candidate_clauses_for_modes(&candidates, |mode| {
                mode_available(mode)
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
            clauses = clauses
                .into_iter()
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
                            action.resource_type.as_ref() == Some(&resource.resource_type)
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
                    .filter(|action| action.resource_type.as_ref() == Some(&resource.resource_type))
                    .any(|action| {
                        action.effective_access_by_execution_context.iter().any(
                            |(context, clauses)| {
                                resource
                                    .allowed_execution_contexts
                                    .iter()
                                    .any(|allowed| allowed == context.as_str())
                                    && clauses.iter().any(|clause| clause.intersects(&entry))
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
                                    let Some(resource_type) = action.resource_type.as_ref() else {
                                        return false;
                                    };
                                    let boundary = snapshot.resources.resolve(
                                        &selection,
                                        resource_type,
                                        context.as_str(),
                                    );
                                    clauses.iter().any(|clause| clause.intersects(&boundary))
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

fn normalize_boundary(mut boundary: ResourceBoundary) -> ResourceBoundary {
    boundary.included.sort();
    boundary.included.dedup();
    boundary.excluded.sort();
    boundary.excluded.dedup();
    let included = boundary
        .included
        .iter()
        .enumerate()
        .filter(|(index, selector)| {
            !boundary
                .excluded
                .iter()
                .any(|excluded| excluded.contains(selector))
                && !boundary
                    .included
                    .iter()
                    .enumerate()
                    .any(|(other, broad)| other != *index && broad.contains(selector))
        })
        .map(|(_, selector)| selector.clone())
        .collect::<Vec<_>>();
    let excluded = boundary
        .excluded
        .iter()
        .enumerate()
        .filter(|(index, selector)| {
            included
                .iter()
                .any(|positive| positive.intersection(selector).is_some())
                && !boundary
                    .excluded
                    .iter()
                    .enumerate()
                    .any(|(other, broad)| other != *index && broad.contains(selector))
        })
        .map(|(_, selector)| selector.clone())
        .collect();
    ResourceBoundary { included, excluded }
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
    let mut outside = left.clone();
    outside.excluded.extend(right.included.iter().cloned());
    let mut parts = vec![outside];
    if !right.excluded.is_empty() {
        parts.push(left.intersection(&ResourceBoundary {
            included: right.excluded.clone(),
            excluded: Vec::new(),
        }));
    }
    deduplicate_boundaries(parts)
}

fn normalize_clause(mut clause: EffectiveAccessClause) -> EffectiveAccessClause {
    let allowed = normalize_boundary(clause.boundary());
    clause.included = allowed.included.clone();
    clause.excluded = allowed.excluded.clone();
    clause.excluded_requests = deduplicate_boundaries(
        clause
            .excluded_requests
            .iter()
            .map(|boundary| boundary.intersection(&allowed))
            .collect(),
    );
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
        let mut clause = EffectiveAccessClause::from_boundary(candidate.boundary.clone());
        for other in candidates {
            let other_band = (other.subject_rank, other.priority);
            if other_band > candidate_band
                || other_band == candidate_band
                    && other.credential_mode != candidate.credential_mode
            {
                clause.excluded_requests.push(other.boundary.clone());
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
            resource_scope: Some(ActionResourceScope {
                scope: "repository".to_string(),
                resource_type: &agent_access_provider::GIT_REPOSITORY_RESOURCE,
            }),
            boundary,
        }
    }

    #[test]
    fn finite_cofinite_search_algebra_preserves_separate_grants_and_token_exclusions() {
        let all_except_private = SearchAuthorizationScope::AllExcept {
            excluded_values: vec!["PRIVATE".into()],
        };
        let private_grant = SearchAuthorizationScope::Finite {
            values: vec!["PRIVATE".into()],
        };
        assert!(
            all_except_private.union(&private_grant).is_universe(),
            "a separate grant can restore an excluded project"
        );
        let token = SearchAuthorizationScope::AllExcept {
            excluded_values: vec!["SECRET".into()],
        };
        let restricted = all_except_private.intersection(&token);
        assert!(!restricted.matches("PRIVATE"));
        assert!(!restricted.matches("SECRET"));
        assert!(
            restricted.matches("NEWPROJECT"),
            "new upstream projects remain covered"
        );
        assert!(restricted.intersection(&private_grant).is_empty());
        assert!(
            SearchAuthorizationScope::Finite { values: vec![] }
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
                .filter(|candidate| candidate.boundary.matches(path))
                .cloned()
                .collect::<Vec<_>>();
            let expected = single_policy_credential_mode(&top_policy_band(matches))
                .is_ok_and(|mode| crate::credential_mode_configured(&credentials, "gitlab", &mode));
            assert_eq!(
                preview.iter().any(|clause| clause.matches(path)),
                expected,
                "preview diverged at {path}"
            );
        }
        assert!(
            !preview
                .iter()
                .any(|clause| clause.matches("engineering/platform/api")),
            "same winning band conflicts must be hidden"
        );
        assert!(
            preview
                .iter()
                .any(|clause| clause.matches("engineering/private/repo")),
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
                candidate.resource_scope = Some(ActionResourceScope {
                    scope: scope.into(),
                    resource_type,
                });
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
                    clauses
                        .iter()
                        .any(|clause| clause.matches_request(&targets)),
                    expected,
                    "whole-request preview diverged for {} {targets:?}",
                    resource_type.id
                );
            }
            assert!(!clauses.iter().any(|clause| clause.matches(first)));
            assert!(
                clauses
                    .iter()
                    .any(|clause| clause.matches_request(&[first, second])),
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
                        .map(|clause| clause.intersection(&token))
                        .collect()
                )
                .is_empty(),
                "token narrowing retains the whole-request precedence condition"
            );
        }
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
        let clause = EffectiveAccessClause {
            included: vec![ResourceSelector::All],
            excluded: vec![],
            excluded_requests: vec![
                boundary(vec![namespace("team")], vec![namespace("team/open")]),
                boundary(vec![namespace("team/open")], vec![]),
            ],
        };
        let team = boundary(vec![namespace("team")], vec![]);
        assert!(
            clause.intersects(&team) && clause.matches_request(&["team/open/a", "team/b"]),
            "a request spanning both conditions remains admitted"
        );
        let reach = clause.single_target_reach();
        for target in ["team/open/a", "team/b"] {
            assert!(!clause.matches(target));
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
