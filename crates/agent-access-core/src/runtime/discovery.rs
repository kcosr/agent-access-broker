//! Caller discovery uses a single policy snapshot, never the administrative picker.
use super::resource_access::boundaries_cover;
use super::*;
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use hmac::{Hmac, Mac};
use rand::{RngCore, rngs::OsRng};

/// Private, per-runtime cursor authentication material. It deliberately has no
/// Debug or serialization implementation, and clones of the runtime share it.
pub(super) struct DiscoveryCursorKey([u8; 32]);

impl DiscoveryCursorKey {
    pub(super) fn new() -> Self {
        let mut key = [0; 32];
        OsRng.fill_bytes(&mut key);
        Self(key)
    }

    fn authenticate(&self, binding: &[u8], position: usize) -> Hmac<Sha256> {
        let mut mac = Hmac::<Sha256>::new_from_slice(&self.0).expect("fixed HMAC key length");
        mac.update(b"agent-access-resource-discovery-v1\0");
        mac.update(binding);
        mac.update(&(position as u64).to_be_bytes());
        mac
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DiscoveredResource {
    pub id: String,
    #[serde(rename = "type")]
    pub resource_type: ResourceType,
    pub value: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub display_name: Option<String>,
    /// Action inputs that address this resource, from its type's projection.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub inputs: Option<serde_json::Map<String, Value>>,
}

/// A positive selector reached by one action's single-target authority.
/// `restricted` reports withheld targets without disclosing their identities.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ResourceCoverage {
    pub selector: ResourceSelector,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub inputs: Option<serde_json::Map<String, Value>>,
    pub restricted: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "scope", rename_all = "snake_case", deny_unknown_fields)]
pub enum ActionResourceAccess {
    Resource {
        action: String,
        #[serde(rename = "resourceType")]
        resource_type: ResourceType,
        enforcement: ResourceAccessEnforcement,
        coverage: Vec<ResourceCoverage>,
    },
    Unscoped {
        action: String,
    },
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ResourceAccessEnforcement {
    Request,
    Results,
    Command,
}

impl ActionResourceAccess {
    pub fn action(&self) -> &str {
        match self {
            Self::Resource { action, .. } | Self::Unscoped { action } => action,
        }
    }

    pub fn resource_type(&self) -> Option<&ResourceType> {
        match self {
            Self::Resource { resource_type, .. } => Some(resource_type),
            Self::Unscoped { .. } => None,
        }
    }

    pub fn coverage(&self) -> Option<&[ResourceCoverage]> {
        match self {
            Self::Resource { coverage, .. } => Some(coverage),
            Self::Unscoped { .. } => None,
        }
    }
}

/// Discovery summarizes independent single-target requests. The complete
/// target tuple of a multi-resource request is reauthorized at invocation.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ResourceCoverageSemantics {
    SingleTarget,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum RegisteredResourceSource {
    BrokerConfiguration,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RegisteredResourcePage {
    pub source: RegisteredResourceSource,
    pub items: Vec<DiscoveredResource>,
    pub next_cursor: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct LiveResourceListing {
    pub service: String,
    pub action: String,
    pub resource_type: ResourceType,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ResourceAccessDescription {
    pub service: String,
    pub execution_context: ExecutionContext,
    pub availability: ServiceAvailability,
    pub coverage_semantics: ResourceCoverageSemantics,
    pub access: Vec<ActionResourceAccess>,
    pub registered_resources: RegisteredResourcePage,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub live_listings: Vec<LiveResourceListing>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ActionList {
    pub service: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub resource: Option<String>,
    pub actions: Vec<String>,
}

#[derive(Debug, Clone, Default)]
pub struct ResourceAccessQuery {
    /// Describe only this exact, caller-visible action.
    pub action: Option<String>,
    /// Describe only actions bound to this resource type.
    pub resource_type: Option<ResourceType>,
    /// Filters registered references only, never action coverage.
    pub prefix: Option<String>,
    pub limit: Option<usize>,
    pub cursor: Option<String>,
}

/// A visible service and its pinned policy. Establish this before interpreting
/// resource-specific query fields, so hidden services reveal no scope metadata.
pub struct ServiceDiscovery<'a> {
    runtime: &'a BrokerRuntime,
    identity: &'a IdentityContext,
    context: &'a ExecutionContext,
    snapshot: Arc<PolicySnapshot>,
    capabilities: ServiceDescriptor,
    availability: ServiceAvailability,
    clauses: BTreeMap<String, Vec<EffectiveAccessClause>>,
}

impl BrokerRuntime {
    pub fn service_discovery<'a>(
        &'a self,
        identity: &'a IdentityContext,
        context: &'a ExecutionContext,
        service: &str,
    ) -> Option<ServiceDiscovery<'a>> {
        let snapshot = self.policy_snapshot();
        let service = self
            .available_service_descriptors(identity, context, &snapshot, Some(service))
            .into_iter()
            .next()?;
        Some(ServiceDiscovery {
            runtime: self,
            identity,
            context,
            snapshot,
            capabilities: service.descriptor,
            availability: service.availability,
            clauses: service.clauses,
        })
    }
}

impl ServiceDiscovery<'_> {
    /// The resource type discovery works over: the requested one, or the
    /// service's only type. A service with several types needs an explicit
    /// choice so results and locators are never mixed across types.
    fn resource_type(
        &self,
        requested: Option<&ResourceType>,
    ) -> Result<Option<&ResourceTypeDescriptor>, &'static str> {
        if self.capabilities.actions.is_empty() {
            return Ok(None);
        }
        let types = self
            .capabilities
            .resource_scopes
            .values()
            .map(|scope| scope.resource_type.clone())
            .collect::<BTreeSet<_>>();
        let chosen = match requested {
            Some(requested) if types.contains(requested) => Some(requested.clone()),
            Some(_) => return Err("resourceType is not used by this service"),
            None if types.len() > 1 => {
                return Err("resourceType is required for a service with several resource types");
            }
            None => types.into_iter().next(),
        };
        chosen
            .map(|resource_type| {
                self.runtime
                    .resource_types
                    .get(&resource_type)
                    .map(Arc::as_ref)
                    .ok_or("resource type is not registered")
            })
            .transpose()
    }

    fn action_resource_type(&self, action: &str) -> Option<&ResourceType> {
        self.capabilities
            .action_resource_scope(action)
            .map(|(_, binding)| &binding.resource_type)
    }

    fn clauses(&self, action: &str) -> Vec<EffectiveAccessClause> {
        self.clauses.get(action).cloned().unwrap_or_default()
    }

    pub fn actions(
        &self,
        resource: Option<&str>,
        resource_type: Option<&ResourceType>,
        prefix: Option<&str>,
    ) -> Result<ActionList, &'static str> {
        nonempty(prefix, "prefix must be nonempty")?;
        nonempty(resource, "resource must be nonempty")?;
        if resource.is_none() && resource_type.is_some() {
            return Err("resourceType requires resource");
        }
        if self.capabilities.actions.is_empty() {
            return Ok(ActionList {
                service: self.capabilities.service.clone(),
                resource: resource.map(str::to_owned),
                actions: Vec::new(),
            });
        }
        let kind = match resource {
            Some(resource) => {
                let kind = self
                    .resource_type(resource_type)?
                    .ok_or("service does not support resource filtering")?;
                if !kind.is_canonical_target(resource) {
                    return Err("resource must be a canonical locator for this service");
                }
                Some(kind)
            }
            None => None,
        };
        let mut actions = self
            .capabilities
            .actions
            .iter()
            .filter(|action| prefix.is_none_or(|prefix| action.action.starts_with(prefix)))
            .filter(|action| {
                resource.is_none_or(|resource| {
                    kind.is_some_and(|kind| {
                        self.action_resource_type(&action.action) == Some(kind.id())
                    }) && self
                        .clauses(&action.action)
                        .iter()
                        .any(|clause| clause.matches_request(&[resource]))
                })
            })
            .map(|action| action.action.clone())
            .collect::<Vec<_>>();
        actions.sort();
        Ok(ActionList {
            service: self.capabilities.service.clone(),
            resource: resource.map(str::to_owned),
            actions,
        })
    }

    pub fn resource_access(
        &self,
        query: &ResourceAccessQuery,
    ) -> Result<ResourceAccessDescription, &'static str> {
        if query
            .action
            .as_deref()
            .is_some_and(|action| !agent_access_provider::is_action_name(action))
        {
            return Err("action name is invalid");
        }
        nonempty(query.prefix.as_deref(), "prefix must be nonempty")?;
        nonempty(query.cursor.as_deref(), CURSOR_ERROR)?;
        let limit = query.limit.unwrap_or(50);
        if !(1..=100).contains(&limit) {
            return Err("limit must be an integer between 1 and 100");
        }
        let mut actions = self
            .capabilities
            .actions
            .iter()
            .filter(|action| {
                query
                    .action
                    .as_deref()
                    .is_none_or(|selected| action.action == selected)
            })
            .collect::<Vec<_>>();
        if query.action.is_some() && actions.is_empty() {
            return Err("action is not available");
        }
        if let (Some(action), Some(resource_type)) =
            (query.action.as_deref(), query.resource_type.as_ref())
            && self.action_resource_type(action) != Some(resource_type)
        {
            return Err("action does not use this resourceType");
        }
        // A credential-unavailable service retains no action scope metadata.
        if !actions.is_empty()
            && query.resource_type.as_ref().is_some_and(|requested| {
                !self
                    .capabilities
                    .resource_scopes
                    .values()
                    .any(|scope| &scope.resource_type == requested)
            })
        {
            return Err("resourceType is not used by this service");
        }
        actions.retain(|action| {
            query.resource_type.as_ref().is_none_or(|requested| {
                self.action_resource_type(&action.action) == Some(requested)
            })
        });
        actions.sort_by(|left, right| left.action.cmp(&right.action));
        let mut access = Vec::new();
        let mut action_clauses = BTreeMap::new();
        for action in &actions {
            if action.resource_scope.is_none() {
                access.push(ActionResourceAccess::Unscoped {
                    action: action.action.clone(),
                });
                continue;
            }
            let resource_type = self
                .action_resource_type(&action.action)
                .ok_or("action resource scope is not registered")?;
            let descriptor = self
                .runtime
                .resource_types
                .get(resource_type)
                .ok_or("resource type is not registered")?;
            let clauses = self.clauses(&action.action);
            access.push(ActionResourceAccess::Resource {
                action: action.action.clone(),
                resource_type: resource_type.clone(),
                enforcement: if self
                    .runtime
                    .command_enforced(&self.capabilities.service, &action.action)
                {
                    ResourceAccessEnforcement::Command
                } else if action.native_search.is_some() {
                    ResourceAccessEnforcement::Results
                } else {
                    ResourceAccessEnforcement::Request
                },
                coverage: self.coverage(descriptor, &clauses),
            });
            action_clauses.insert(action.action.as_str(), clauses);
        }
        let types = access
            .iter()
            .filter_map(ActionResourceAccess::resource_type)
            .collect::<BTreeSet<_>>();
        // Listing links have their own action permission and local credential
        // checks. Their scope is never claimed to equal the described action's.
        let mut live_listings = self
            .capabilities
            .actions
            .iter()
            .filter_map(|action| {
                let resource_type = action.listing_of.as_ref()?;
                types.contains(resource_type).then(|| LiveResourceListing {
                    service: self.capabilities.service.clone(),
                    action: action.action.clone(),
                    resource_type: resource_type.clone(),
                })
            })
            .collect::<Vec<_>>();
        live_listings.sort_by(|left, right| {
            (&left.action, &left.resource_type).cmp(&(&right.action, &right.resource_type))
        });
        let mut rows = self
            .snapshot
            .resource_catalog
            .resources
            .iter()
            .filter_map(|entry| {
                if !types.contains(&entry.resource_type)
                    || !entry.enabled
                    || !entry
                        .allowed_execution_contexts
                        .iter()
                        .any(|context| context == self.context.as_str())
                {
                    return None;
                }
                let ResourceSelector::Exact { value } = &entry.selector else {
                    return None;
                };
                if query
                    .prefix
                    .as_deref()
                    .is_some_and(|prefix| !value.starts_with(prefix))
                    || !action_clauses.iter().any(|(action, clauses)| {
                        self.action_resource_type(action) == Some(&entry.resource_type)
                            && clauses
                                .iter()
                                .any(|clause| clause.matches_request(&[value.as_str()]))
                    })
                {
                    return None;
                }
                Some(DiscoveredResource {
                    id: entry.id.clone(),
                    resource_type: entry.resource_type.clone(),
                    value: value.clone(),
                    display_name: entry.display_name.clone(),
                    inputs: self
                        .runtime
                        .resource_types
                        .get(&entry.resource_type)
                        .and_then(|kind| action_inputs(kind, &entry.selector)),
                })
            })
            .collect::<Vec<_>>();
        rows.sort_by(|left, right| {
            (left.resource_type.as_str(), &left.value, &left.id).cmp(&(
                right.resource_type.as_str(),
                &right.value,
                &right.id,
            ))
        });
        // token_scopes is intentionally skipped by IdentitySourceAudit's ordinary
        // serialization, but it is essential to cursor binding. Bind complete
        // authority metadata too, even though only reference rows are paginated.
        let binding = json!({
            "identity": self.identity,
            "restrictions": self.identity.source.as_ref().and_then(|source| source.token_scopes.as_ref()),
            "context": self.context,
            "capabilities": self.capabilities.capabilities(),
            "availability": self.availability,
            "action": query.action,
            "resourceType": query.resource_type,
            "prefix": query.prefix,
            "limit": limit,
            "configGeneration": self.runtime.config_generation,
            "importCatalogRevision": self.runtime.import_catalog_revision(),
            "policyGeneration": self.snapshot.generation(),
            "clauses": action_clauses,
            "access": access,
            "liveListings": live_listings,
            "resources": rows,
        });
        let binding = serde_json::to_vec(&binding).expect("cursor binding serialization");
        let position = match query.cursor.as_deref() {
            None => 0,
            Some(cursor) => {
                if cursor.len() > 512 {
                    return Err(CURSOR_ERROR);
                }
                let bytes = URL_SAFE_NO_PAD.decode(cursor).map_err(|_| CURSOR_ERROR)?;
                let cursor: ResourceCursor =
                    serde_json::from_slice(&bytes).map_err(|_| CURSOR_ERROR)?;
                let signature = URL_SAFE_NO_PAD
                    .decode(&cursor.mac)
                    .map_err(|_| CURSOR_ERROR)?;
                if cursor.position == 0
                    || cursor.position >= rows.len()
                    || !cursor.position.is_multiple_of(limit)
                    || self
                        .runtime
                        .resource_cursor_key
                        .authenticate(&binding, cursor.position)
                        .verify_slice(&signature)
                        .is_err()
                {
                    return Err(CURSOR_ERROR);
                }
                cursor.position
            }
        };
        let end = (position + limit).min(rows.len());
        let next_cursor = (end < rows.len()).then(|| {
            URL_SAFE_NO_PAD.encode(
                serde_json::to_vec(&ResourceCursor {
                    position: end,
                    mac: URL_SAFE_NO_PAD.encode(
                        self.runtime
                            .resource_cursor_key
                            .authenticate(&binding, end)
                            .finalize()
                            .into_bytes(),
                    ),
                })
                .expect("cursor serialization"),
            )
        });
        Ok(ResourceAccessDescription {
            service: self.capabilities.service.clone(),
            execution_context: self.context.clone(),
            availability: self.availability.clone(),
            coverage_semantics: ResourceCoverageSemantics::SingleTarget,
            access,
            registered_resources: RegisteredResourcePage {
                source: RegisteredResourceSource::BrokerConfiguration,
                items: rows[position..end].to_vec(),
                next_cursor,
            },
            live_listings,
        })
    }

    /// Positive selectors reached by independent single-target requests for one
    /// action. Exclusions and whole-request precedence conditions stay private.
    /// Selector identities come only from included authority or declared roots,
    /// never from the subtraction used to prove reach and complete coverage.
    fn coverage(
        &self,
        kind: &ResourceTypeDescriptor,
        clauses: &[EffectiveAccessClause],
    ) -> Vec<ResourceCoverage> {
        let mut roots = self
            .runtime
            .providers
            .get(&self.capabilities.service)
            .map(|provider| provider.resource_roots(kind.id()))
            .unwrap_or_default()
            .into_iter()
            .map(|value| ResourceSelector::Namespace { value })
            .filter(|root| kind.accepts(root))
            .collect::<Vec<_>>();
        roots.sort();
        roots.dedup();
        // An entry is listed only when its own clause reaches a singleton
        // inside it, so a narrow grant cannot surface an excluded broad root.
        let reached = clauses
            .iter()
            .flat_map(|clause| {
                let reach = clause.single_target_reach();
                clause
                    .included
                    .iter()
                    .flat_map(|selector| match selector {
                        ResourceSelector::All if !roots.is_empty() => roots.clone(),
                        ResourceSelector::All
                        | ResourceSelector::Namespace { .. }
                        | ResourceSelector::Exact { .. } => vec![selector.clone()],
                        // A selector form this build does not know is never reported.
                        _ => Vec::new(),
                    })
                    .filter(|entry| {
                        let only = ResourceBoundary {
                            included: vec![entry.clone()],
                            excluded: Vec::new(),
                        };
                        reach.iter().any(|part| part.intersects(&only))
                    })
                    .collect::<Vec<_>>()
            })
            .collect::<BTreeSet<_>>();
        let reach = clauses
            .iter()
            .flat_map(EffectiveAccessClause::single_target_reach)
            .collect::<Vec<_>>();
        let coverage = reached
            .iter()
            .filter(|entry| {
                !matches!(entry, ResourceSelector::Namespace { .. })
                    || roots.is_empty()
                    || roots.iter().any(|root| root.contains(entry))
            })
            .map(|entry| ResourceCoverage {
                selector: entry.clone(),
                inputs: action_inputs(kind, entry),
                // A reached exact selector names one admitted singleton. A
                // symbolic coverage proof would repeat quadratic normalization
                // of the complete authority for every exact entry.
                restricted: !matches!(entry, ResourceSelector::Exact { .. })
                    && !boundaries_cover(&reach, entry),
            })
            .collect::<Vec<_>>();
        let unrestricted_broad = coverage
            .iter()
            .filter(|entry| {
                !entry.restricted && !matches!(entry.selector, ResourceSelector::Exact { .. })
            })
            .map(|entry| &entry.selector)
            .collect::<Vec<_>>();
        coverage
            .iter()
            .filter(|entry| {
                !unrestricted_broad
                    .iter()
                    .any(|other| *other != &entry.selector && other.contains(&entry.selector))
            })
            .cloned()
            .collect()
    }
}

fn action_inputs(
    kind: &ResourceTypeDescriptor,
    selector: &ResourceSelector,
) -> Option<serde_json::Map<String, Value>> {
    kind.action_inputs(selector)
        .filter(|inputs| !inputs.is_empty())
}

fn nonempty(value: Option<&str>, message: &'static str) -> Result<(), &'static str> {
    if value.is_some_and(str::is_empty) {
        Err(message)
    } else {
        Ok(())
    }
}
const CURSOR_ERROR: &str = "resource cursor is invalid or stale; restart without the cursor";
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ResourceCursor {
    position: usize,
    mac: String,
}

#[cfg(test)]
mod tests {
    use super::*;
    use async_trait::async_trait;

    fn config() -> BrokerConfig {
        let mut config = super::super::tests::base_fake_config();
        config.policy.grants[0].resources.resource_ids = vec!["fake-project-all".into()];
        config
    }
    fn context() -> ExecutionContext {
        ExecutionContext::new("default").unwrap()
    }
    fn token(resources: ResourceSelection) -> IdentityContext {
        let mut identity = IdentityContext::anonymous();
        identity.source = Some(IdentitySourceAudit {
            read_only_access: None,
            namespace: None,
            binding_id: None,
            name: "test".into(),
            kind: "broker_tokens".into(),
            token_header: "Authorization".into(),
            token_scheme: "Bearer".into(),
            token_class: Some(BrokerTokenClass::AgentInvoke),
            token_id: Some("one".into()),
            token_scopes: Some(
                AgentInvokeTokenCaveats {
                    allowed_services: Some(vec!["fake".into()]),
                    allowed_execution_contexts: Some(vec![context()]),
                    service_restrictions: Some(BTreeMap::from([(
                        "fake".into(),
                        crate::AgentTokenServiceRestriction {
                            actions: vec!["echo".into()],
                            resources: Some(resources),
                        },
                    )])),
                }
                .to_scopes_value(),
            ),
        });
        identity
    }

    /// The fake service plus a second scope bound to Confluence spaces, so one
    /// service authorizes two resource types that share the value `ENG`.
    struct TwoTypeProvider;

    impl agent_access_provider::test_support::DescribedProvider for TwoTypeProvider {
        fn descriptor(&self) -> ServiceDescriptor {
            let mut descriptor = agent_access_fake::fake_descriptor();
            descriptor.resource_scopes.insert(
                "space".into(),
                ResourceScopeCapabilities::new(
                    agent_access_confluence::CONFLUENCE_SPACE_RESOURCE
                        .id()
                        .clone(),
                    vec!["exact".into(), "all".into()],
                ),
            );
            descriptor.actions.push(
                ActionDescriptor::new("note", "Note on a space", json!({"type": "object"}))
                    .scope("space")
                    .credential_modes(["service"]),
            );
            descriptor
        }
    }

    #[async_trait]
    impl Provider for TwoTypeProvider {
        async fn resolve_scopes(
            &self,
            request: ScopeRequest<'_>,
        ) -> Result<ScopeResolution, ProviderError> {
            agent_access_fake::FakeProvider
                .echo_scopes(request.action(), request.inputs())
                .map(ScopeResolution::resources)
        }

        async fn invoke(
            &self,
            request: ProviderInvocation,
        ) -> Result<ProviderResult, ProviderError> {
            agent_access_fake::FakeProvider.invoke(request).await
        }
    }

    #[test]
    fn discovery_describes_all_resource_types_and_can_filter_one() {
        // The shared fixtures already register `space-ENG` as a Confluence space.
        let mut config = config();
        let runtime =
            BrokerRuntime::with_providers(config.clone(), vec![Arc::new(TwoTypeProvider)]).unwrap();
        // Configuration validation describes `fake` from its own configuration,
        // which has no `note` action; install the grant for the injected
        // provider directly.
        let mut note = config.policy.grants[0].clone();
        note.actions = vec!["note".into()];
        note.resources.resource_ids = vec!["space-ENG".into()];
        config.policy.grants.push(note);
        runtime
            .policy_snapshot
            .store(Arc::new(PolicySnapshot::from_config(&config, 0)));
        let identity = IdentityContext::anonymous();
        let context = context();
        let view = runtime
            .service_discovery(&identity, &context, "fake")
            .unwrap();
        let fake_project = agent_access_fake::FAKE_PROJECT_RESOURCE.id().clone();
        let space = agent_access_confluence::CONFLUENCE_SPACE_RESOURCE
            .id()
            .clone();

        let all = view
            .resource_access(&ResourceAccessQuery::default())
            .unwrap();
        assert_eq!(all.access.len(), 2);
        assert!(
            all.registered_resources
                .items
                .iter()
                .any(|row| row.resource_type == space)
        );
        assert!(
            all.registered_resources
                .items
                .iter()
                .any(|row| row.resource_type == fake_project)
        );
        assert_eq!(
            view.actions(Some("ENG"), None, None).unwrap_err(),
            "resourceType is required for a service with several resource types"
        );
        // An unqualified action list still covers every type.
        assert_eq!(
            view.actions(None, None, None).unwrap().actions,
            ["echo", "note"]
        );

        let spaces = view
            .resource_access(&ResourceAccessQuery {
                resource_type: Some(space.clone()),
                ..ResourceAccessQuery::default()
            })
            .unwrap();
        assert_eq!(
            view.resource_access(&ResourceAccessQuery {
                action: Some("echo".into()),
                resource_type: Some(space.clone()),
                ..Default::default()
            })
            .unwrap_err(),
            "action does not use this resourceType"
        );
        assert_eq!(
            spaces
                .registered_resources
                .items
                .iter()
                .map(|row| (row.id.as_str(), row.resource_type.as_str()))
                .collect::<Vec<_>>(),
            [("space-ENG", "confluence_space")]
        );
        let projects = view
            .resource_access(&ResourceAccessQuery {
                resource_type: Some(fake_project.clone()),
                limit: Some(1),
                ..ResourceAccessQuery::default()
            })
            .unwrap();
        assert!(
            projects
                .registered_resources
                .items
                .iter()
                .all(|row| row.resource_type == fake_project)
        );

        // The same value names different resources per type; each type only
        // reports the actions bound to it.
        assert_eq!(
            view.actions(Some("ENG"), Some(&space), None)
                .unwrap()
                .actions,
            ["note"]
        );
        assert_eq!(
            view.actions(Some("ENG"), Some(&fake_project), None)
                .unwrap()
                .actions,
            ["echo"]
        );

        // A cursor is bound to the resource type it was issued for.
        let cursor = projects
            .registered_resources
            .next_cursor
            .expect("more than one fake project");
        assert!(
            view.resource_access(&ResourceAccessQuery {
                resource_type: Some(space),
                limit: Some(1),
                cursor: Some(cursor),
                ..ResourceAccessQuery::default()
            })
            .is_err()
        );
    }

    #[test]
    fn discovery_broad_access_lists_exact_metadata_and_accepts_unregistered_locators() {
        let mut config = config();
        config.execution_context = Some(crate::ExecutionContextConfig {
            allowed_values: vec!["default".into(), "external".into()],
            default_context: None,
        });
        config.policy.grants[0].execution_contexts = Some(vec!["default".into()]);
        for entry in &mut config.policy.resources {
            if entry.id == "fake-project-TEST" {
                entry.display_name = Some("Test project".into());
            }
            if entry.id == "fake-project-OPS" {
                entry.enabled = false;
            }
            if entry.id == "fake-project-ENG" {
                entry.allowed_execution_contexts = vec!["external".into()];
            }
        }
        let runtime = BrokerRuntime::new(config).unwrap();
        let identity = IdentityContext::anonymous();
        let context = context();
        let view = runtime
            .service_discovery(&identity, &context, "fake")
            .unwrap();
        let resources = view
            .resource_access(&ResourceAccessQuery::default())
            .unwrap();
        assert_eq!(
            resources
                .registered_resources
                .items
                .iter()
                .map(|row| row.value.as_str())
                .collect::<Vec<_>>(),
            ["OTHER", "PROJ", "RESEARCH", "TEST"]
        );
        assert_eq!(
            resources
                .registered_resources
                .items
                .last()
                .unwrap()
                .display_name
                .as_deref(),
            Some("Test project")
        );
        assert!(resources.registered_resources.next_cursor.is_none());
        for resource in ["UNREGISTERED", "OPS", "ENG"] {
            assert_eq!(
                view.actions(Some(resource), None, None).unwrap().actions,
                ["echo"]
            );
        }
        assert!(view.actions(Some("fake-project-TEST"), None, None).is_err());
        assert!(
            view.actions(Some("TEST"), None, Some("z"))
                .unwrap()
                .actions
                .is_empty()
        );
        assert!(view.actions(None, None, Some("")).is_err());
    }

    #[test]
    fn discovery_group_exclusions_alternate_grants_and_token_intersections() {
        let mut config = config();
        config.execution_context = Some(crate::ExecutionContextConfig {
            allowed_values: vec!["default".into(), "external".into()],
            default_context: None,
        });
        config.policy.grants[0].execution_contexts = Some(vec!["default".into()]);
        for entry in &mut config.policy.resources {
            if entry.id == "fake-project-OPS" {
                entry.enabled = false;
            }
            if entry.id == "fake-project-ENG" {
                entry.allowed_execution_contexts = vec!["external".into()];
            }
        }
        config.policy.resource_groups = vec![ResourceGroupDefinition {
            id: "public".into(),
            name: "Public projects".into(),
            included_resource_ids: vec!["fake-project-all".into()],
            excluded_resource_ids: vec![
                "fake-project-TEST".into(),
                "fake-project-OPS".into(),
                "fake-project-ENG".into(),
            ],
        }];
        let selection = ResourceSelection {
            resource_ids: vec![],
            resource_group_ids: vec!["public".into()],
        };
        config.policy.grants[0].resources = selection.clone();
        let context = context();
        let identity = IdentityContext::anonymous();
        let runtime = BrokerRuntime::new(config.clone()).unwrap();
        let view = runtime
            .service_discovery(&identity, &context, "fake")
            .unwrap();
        for resource in ["TEST", "OPS", "ENG"] {
            assert!(
                view.actions(Some(resource), None, None)
                    .unwrap()
                    .actions
                    .is_empty()
            );
        }
        let mut alternate = config.policy.grants[0].clone();
        alternate.resources = ResourceSelection {
            resource_ids: vec!["fake-project-TEST".into()],
            resource_group_ids: vec![],
        };
        config.policy.grants.push(alternate);
        let runtime = BrokerRuntime::new(config).unwrap();
        let view = runtime
            .service_discovery(&identity, &context, "fake")
            .unwrap();
        assert_eq!(
            view.actions(Some("TEST"), None, None).unwrap().actions,
            ["echo"]
        );
        let identity = token(selection);
        let view = runtime
            .service_discovery(&identity, &context, "fake")
            .unwrap();
        assert!(
            view.actions(Some("TEST"), None, None)
                .unwrap()
                .actions
                .is_empty()
        );
        assert!(
            !view
                .resource_access(&ResourceAccessQuery::default())
                .unwrap()
                .registered_resources
                .items
                .iter()
                .any(|row| row.value == "TEST")
        );
        assert!(
            runtime
                .service_discovery(&token(ResourceSelection::default()), &context, "fake")
                .is_none()
        );
        assert!(
            runtime
                .service_discovery(
                    &identity,
                    &ExecutionContext::new("external").unwrap(),
                    "fake"
                )
                .is_none()
        );
    }

    #[test]
    fn discovery_pagination_is_sorted_filtered_bound_and_stale_safe() {
        let mut config = config();
        let mut second_project = config
            .policy
            .resources
            .iter()
            .find(|entry| entry.id == "fake-project-TEST")
            .unwrap()
            .clone();
        second_project.id = "fake-project-TWO".into();
        second_project.selector = ResourceSelector::Exact {
            value: "TWO".into(),
        };
        config.policy.resources.push(second_project);
        let runtime = BrokerRuntime::new(config.clone())
            .unwrap()
            .with_config_generation(1);
        let identity = IdentityContext::anonymous();
        let context = context();
        let view = runtime
            .service_discovery(&identity, &context, "fake")
            .unwrap();
        let query = ResourceAccessQuery {
            action: None,
            resource_type: None,
            prefix: Some("T".into()),
            limit: Some(1),
            cursor: None,
        };
        let first = view.resource_access(&query).unwrap();
        assert_eq!(first.registered_resources.items[0].id, "fake-project-TEST");
        let cursor = first.registered_resources.next_cursor.unwrap();
        let continuation = ResourceAccessQuery {
            cursor: Some(cursor.clone()),
            ..query.clone()
        };
        let second = view.resource_access(&continuation).unwrap();
        assert_eq!(second.registered_resources.items[0].id, "fake-project-TWO");
        assert!(second.registered_resources.next_cursor.is_none());
        assert_eq!(first.access, second.access);
        for bad in [
            ResourceAccessQuery {
                prefix: None,
                ..continuation.clone()
            },
            ResourceAccessQuery {
                limit: Some(2),
                ..continuation.clone()
            },
            ResourceAccessQuery {
                cursor: Some("malformed".into()),
                ..continuation.clone()
            },
            ResourceAccessQuery {
                limit: Some(0),
                ..query.clone()
            },
            ResourceAccessQuery {
                limit: Some(101),
                ..query.clone()
            },
        ] {
            assert!(view.resource_access(&bad).is_err());
        }
        let foreign = token(ResourceSelection {
            resource_ids: vec!["fake-project-all".into()],
            resource_group_ids: vec![],
        });
        assert!(
            runtime
                .service_discovery(&foreign, &context, "fake")
                .unwrap()
                .resource_access(&continuation)
                .is_err()
        );
        // A different token restriction with the same visible rows is still bound.
        let mut restricted = foreign.clone();
        restricted.source.as_mut().unwrap().token_scopes = Some(
            AgentInvokeTokenCaveats {
                allowed_services: None,
                allowed_execution_contexts: Some(vec![context.clone()]),
                service_restrictions: None,
            }
            .to_scopes_value(),
        );
        let token_cursor = runtime
            .service_discovery(&foreign, &context, "fake")
            .unwrap()
            .resource_access(&query)
            .unwrap()
            .registered_resources
            .next_cursor;
        assert!(
            runtime
                .service_discovery(&restricted, &context, "fake")
                .unwrap()
                .resource_access(&ResourceAccessQuery {
                    cursor: token_cursor,
                    ..query.clone()
                })
                .is_err()
        );
        config
            .policy
            .resources
            .iter_mut()
            .find(|entry| entry.id == "fake-project-TEST")
            .unwrap()
            .display_name = Some("Renamed".into());
        // Equal generations across a restart do not accept changed row metadata.
        let restarted = BrokerRuntime::new(config)
            .unwrap()
            .with_config_generation(1);
        assert!(
            restarted
                .service_discovery(&identity, &context, "fake")
                .unwrap()
                .resource_access(&continuation)
                .is_err()
        );
        let changed_generation = runtime.clone().with_config_generation(2);
        assert!(
            changed_generation
                .service_discovery(&identity, &context, "fake")
                .unwrap()
                .resource_access(&continuation)
                .is_err()
        );
        assert!(
            view.resource_access(&ResourceAccessQuery {
                prefix: Some("ZZ".into()),
                ..Default::default()
            })
            .unwrap()
            .registered_resources
            .items
            .is_empty()
        );
    }

    #[test]
    fn discovery_cursors_authenticate_position_metadata_and_runtime_without_public_digest() {
        let config = config();
        let runtime = BrokerRuntime::new(config.clone()).unwrap();
        let identity = IdentityContext::anonymous();
        let context = context();
        let view = runtime
            .service_discovery(&identity, &context, "fake")
            .unwrap();
        let query = ResourceAccessQuery {
            limit: Some(1),
            ..Default::default()
        };
        let first = view.resource_access(&query).unwrap();
        let encoded = first.registered_resources.next_cursor.unwrap();
        let continuation = ResourceAccessQuery {
            cursor: Some(encoded.clone()),
            ..query.clone()
        };
        assert!(view.resource_access(&continuation).is_ok());
        assert_eq!(
            view.resource_access(&query)
                .unwrap()
                .registered_resources
                .next_cursor
                .as_deref(),
            Some(encoded.as_str())
        );
        let raw: Value =
            serde_json::from_slice(&URL_SAFE_NO_PAD.decode(&encoded).unwrap()).unwrap();
        assert_eq!(
            raw.as_object()
                .unwrap()
                .keys()
                .cloned()
                .collect::<BTreeSet<_>>(),
            BTreeSet::from(["mac".into(), "position".into()])
        );
        let mut tampered: ResourceCursor = serde_json::from_value(raw).unwrap();
        // Position two is otherwise a valid page boundary with the same limit.
        tampered.position = 2;
        assert_eq!(
            view.resource_access(&ResourceAccessQuery {
                cursor: Some(URL_SAFE_NO_PAD.encode(serde_json::to_vec(&tampered).unwrap())),
                ..query.clone()
            })
            .unwrap_err(),
            CURSOR_ERROR
        );
        tampered.position = 1;
        let mut signature = URL_SAFE_NO_PAD.decode(&tampered.mac).unwrap();
        signature[0] ^= 1;
        tampered.mac = URL_SAFE_NO_PAD.encode(signature);
        assert_eq!(
            view.resource_access(&ResourceAccessQuery {
                cursor: Some(URL_SAFE_NO_PAD.encode(serde_json::to_vec(&tampered).unwrap())),
                ..query
            })
            .unwrap_err(),
            CURSOR_ERROR
        );

        // Runtime clones share the key, while a fresh runtime and a reload do not.
        assert!(
            runtime
                .clone()
                .service_discovery(&identity, &context, "fake")
                .unwrap()
                .resource_access(&continuation)
                .is_ok()
        );
        for foreign in [
            BrokerRuntime::new(config.clone()).unwrap(),
            BrokerRuntime::new_for_reload(config.clone(), &runtime).unwrap(),
        ] {
            assert_eq!(
                foreign
                    .service_discovery(&identity, &context, "fake")
                    .unwrap()
                    .resource_access(&continuation)
                    .unwrap_err(),
                CURSOR_ERROR
            );
        }

        // Keep the key and generation unchanged to isolate metadata binding.
        let mut changed = runtime.clone();
        let mut changed_config = config;
        changed_config
            .policy
            .resources
            .iter_mut()
            .find(|entry| entry.id == "fake-project-TEST")
            .unwrap()
            .display_name = Some("Updated reference".into());
        changed.policy_snapshot = Arc::new(ArcSwap::from_pointee(PolicySnapshot::from_config(
            &changed_config,
            runtime.policy_snapshot().generation(),
        )));
        assert_eq!(
            changed
                .service_discovery(&identity, &context, "fake")
                .unwrap()
                .resource_access(&continuation)
                .unwrap_err(),
            CURSOR_ERROR
        );
    }

    #[test]
    fn discovery_scope_applicability_and_pinned_snapshot() {
        let runtime = BrokerRuntime::new(config()).unwrap();
        let identity = IdentityContext::anonymous();
        let context = context();
        let mut view = runtime
            .service_discovery(&identity, &context, "fake")
            .unwrap();
        runtime
            .policy_snapshot
            .store(Arc::new(PolicySnapshot::from_config(
                &super::super::tests::base_fake_config(),
                2,
            )));
        assert_eq!(
            view.actions(Some("UNREGISTERED"), None, None)
                .unwrap()
                .actions,
            ["echo"]
        );
        assert!(
            runtime
                .service_discovery(&identity, &context, "fake")
                .unwrap()
                .actions(Some("UNREGISTERED"), None, None)
                .unwrap()
                .actions
                .is_empty()
        );
        let same_type = view
            .capabilities
            .resource_scopes
            .values()
            .next()
            .unwrap()
            .clone();
        view.capabilities
            .resource_scopes
            .insert("alias".into(), same_type);
        assert!(
            view.resource_access(&ResourceAccessQuery::default())
                .is_ok()
        );
        view.capabilities.resource_scopes.insert(
            "space".into(),
            ResourceScopeCapabilities::new(
                agent_access_confluence::CONFLUENCE_SPACE_RESOURCE
                    .id()
                    .clone(),
                vec!["exact".into()],
            ),
        );
        assert!(
            view.resource_access(&ResourceAccessQuery::default())
                .is_ok()
        );
        assert!(view.actions(Some("TEST"), None, None).is_err());
        assert_eq!(view.actions(None, None, None).unwrap().actions, ["echo"]);
        view.capabilities.resource_scopes.clear();
        assert!(
            view.resource_access(&ResourceAccessQuery::default())
                .is_err()
        );
        assert!(view.actions(Some("TEST"), None, None).is_err());
    }

    #[test]
    fn discovery_singleton_credential_conflicts_do_not_union_authority() {
        let mut config = config();
        let directory = tempfile::tempdir().unwrap();
        let store = directory.path().join("credentials.json");
        fs::write(&store, r#"{"credentials":[]}"#).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&store, fs::Permissions::from_mode(0o600)).unwrap();
        }
        config.credentials.per_user.insert(
            "fake".into(),
            CredentialConfig {
                kind: "secret_store".into(),
                provider: Some("local_file".into()),
                path: Some(store.display().to_string()),
                username_ref: None,
                token_ref: None,
                read_only: None,
                connection: None,
                profile: None,
            },
        );
        let runtime = BrokerRuntime::new(config.clone()).unwrap();
        let mut conflict = config.policy.grants[0].clone();
        conflict.resources.resource_ids = vec!["fake-project-TEST".into()];
        conflict.credential_mode = "per_user".into();
        config.policy.grants.push(conflict);
        // Configuration validation rejects this same-band credential-mode
        // overlap; install it directly to exercise the runtime guard.
        runtime
            .policy_snapshot
            .store(Arc::new(PolicySnapshot::from_config(&config, 0)));
        let identity = IdentityContext::anonymous();
        let context = context();
        let view = runtime
            .service_discovery(&identity, &context, "fake")
            .unwrap();
        assert!(
            view.actions(Some("TEST"), None, None)
                .unwrap()
                .actions
                .is_empty()
        );
        assert_eq!(
            view.actions(Some("OTHER"), None, None).unwrap().actions,
            ["echo"]
        );
        assert!(
            !view
                .resource_access(&ResourceAccessQuery::default())
                .unwrap()
                .registered_resources
                .items
                .iter()
                .any(|row| row.value == "TEST")
        );
        // The conflict applies to the singleton request, not every compound request.
        assert!(
            view.clauses("echo")
                .iter()
                .any(|clause| clause.matches_request(&["TEST", "OTHER"]))
        );
    }
}
