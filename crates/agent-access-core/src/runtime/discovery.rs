//! Caller discovery uses a single policy snapshot, never the administrative picker.
use super::resource_access::boundaries_cover;
use super::*;
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};

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

/// Broad access the caller holds without a registered exact resource: a
/// namespace, or every resource of the type. `restricted` reports that some
/// resources inside are withheld, without naming them.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ResourceCoverage {
    #[serde(rename = "type")]
    pub resource_type: ResourceType,
    pub selector: ResourceSelector,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub inputs: Option<serde_json::Map<String, Value>>,
    pub restricted: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ResourceList {
    pub service: String,
    pub resources: Vec<DiscoveredResource>,
    /// First page only; omitted when the caller has no broad access.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub coverage: Vec<ResourceCoverage>,
    pub next_cursor: Option<String>,
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
pub struct ResourceListQuery {
    /// Required when the service authorizes more than one resource type.
    pub resource_type: Option<ResourceType>,
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
    ) -> Result<Option<&'static ResourceTypeDescriptor>, &'static str> {
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

    pub fn resources(&self, query: &ResourceListQuery) -> Result<ResourceList, &'static str> {
        nonempty(query.prefix.as_deref(), "prefix must be nonempty")?;
        nonempty(query.cursor.as_deref(), CURSOR_ERROR)?;
        let limit = query.limit.unwrap_or(50);
        if !(1..=100).contains(&limit) {
            return Err("limit must be an integer between 1 and 100");
        }
        let descriptor = self.resource_type(query.resource_type.as_ref())?;
        let kind = descriptor.map(|kind| kind.id().clone());
        let action_clauses = self
            .capabilities
            .actions
            .iter()
            .filter(|action| self.action_resource_type(&action.action) == kind.as_ref())
            .map(|action| self.clauses(&action.action))
            .collect::<Vec<_>>();
        let clauses = action_clauses.concat();
        let mut rows = self
            .snapshot
            .resource_catalog
            .resources
            .iter()
            .filter_map(|entry| {
                if Some(&entry.resource_type) != kind.as_ref()
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
                    || !clauses
                        .iter()
                        .any(|clause| clause.matches_request(&[value.as_str()]))
                {
                    return None;
                }
                Some(DiscoveredResource {
                    id: entry.id.clone(),
                    resource_type: entry.resource_type.clone(),
                    value: value.clone(),
                    display_name: entry.display_name.clone(),
                    inputs: descriptor.and_then(|kind| action_inputs(kind, &entry.selector)),
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
        // serialization, but it is essential to cursor binding.
        let binding = json!({
            "identity": self.identity,
            "restrictions": self.identity.source.as_ref().and_then(|source| source.token_scopes.as_ref()),
            "context": self.context,
            "capabilities": self.capabilities.capabilities(),
            "resourceType": kind,
            "prefix": query.prefix,
            "limit": limit,
            "configGeneration": self.runtime.config_generation,
            "importCatalogRevision": self.runtime.import_catalog_revision(),
            "policyGeneration": self.snapshot.generation(),
            "clauses": clauses,
            "resources": rows,
        });
        let fingerprint = format!("{:x}", Sha256::digest(binding.to_string().as_bytes()));
        let position = match query.cursor.as_deref() {
            None => 0,
            Some(cursor) => {
                if cursor.len() > 512 {
                    return Err(CURSOR_ERROR);
                }
                let bytes = URL_SAFE_NO_PAD.decode(cursor).map_err(|_| CURSOR_ERROR)?;
                let cursor: ResourceCursor =
                    serde_json::from_slice(&bytes).map_err(|_| CURSOR_ERROR)?;
                if cursor.fingerprint != fingerprint
                    || cursor.position == 0
                    || cursor.position >= rows.len()
                    || !cursor.position.is_multiple_of(limit)
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
                    fingerprint,
                    position: end,
                })
                .expect("cursor serialization"),
            )
        });
        let coverage = match descriptor {
            Some(kind) if query.cursor.is_none() => {
                self.coverage(kind, &action_clauses, query.prefix.as_deref())
            }
            _ => Vec::new(),
        };
        Ok(ResourceList {
            service: self.capabilities.service.clone(),
            resources: rows[position..end].to_vec(),
            coverage,
            next_cursor,
        })
    }

    /// The caller's namespace and all-resource access of one type, from the
    /// same effective clauses as the resource rows. Entries come only from
    /// the caller's own included selectors (or the provider's roots for an
    /// all selector), never from exclusions, and are listed when that clause
    /// reaches a resource inside them. An entry is `restricted` when an
    /// action whose clause includes all of it reaches only part of it, after
    /// exclusions, token restrictions and precedence conditions.
    fn coverage(
        &self,
        kind: &ResourceTypeDescriptor,
        action_clauses: &[Vec<EffectiveAccessClause>],
        prefix: Option<&str>,
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
        // An entry is listed when its own clause reaches a resource inside it,
        // so a narrower grant never surfaces a root another clause excludes.
        let reached = action_clauses
            .iter()
            .flatten()
            .flat_map(|clause| {
                let reach = clause.single_target_reach();
                clause
                    .included
                    .iter()
                    .flat_map(|selector| match selector {
                        ResourceSelector::Exact { .. } => Vec::new(),
                        // Roots enumerate the type's top-level namespaces.
                        ResourceSelector::All if !roots.is_empty() => roots.clone(),
                        _ => vec![selector.clone()],
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
        // Precedence conditions withhold a target only when no other clause of
        // the same action serves it, so restriction uses each action's reach.
        let actions = action_clauses
            .iter()
            .map(|clauses| {
                let reach = clauses
                    .iter()
                    .flat_map(EffectiveAccessClause::single_target_reach)
                    .collect::<Vec<_>>();
                (clauses, reach)
            })
            .collect::<Vec<_>>();
        reached
            .iter()
            .filter(|entry| {
                !reached
                    .iter()
                    .any(|other| other != *entry && other.contains(entry))
            })
            .filter(|entry| {
                let ResourceSelector::Namespace { value } = entry else {
                    return true;
                };
                (roots.is_empty() || roots.iter().any(|root| root.contains(entry)))
                    && prefix.is_none_or(|prefix| {
                        value.starts_with(prefix)
                            || prefix
                                .strip_prefix(value.as_str())
                                .is_some_and(|rest| rest.starts_with('/'))
                    })
            })
            .map(|entry| ResourceCoverage {
                resource_type: kind.id().clone(),
                selector: entry.clone(),
                inputs: action_inputs(kind, entry),
                restricted: actions.iter().any(|(clauses, reach)| {
                    clauses
                        .iter()
                        .flat_map(|clause| &clause.included)
                        .any(|selector| selector.contains(entry))
                        && !boundaries_cover(reach, entry)
                }),
            })
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
    fingerprint: String,
    position: usize,
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
    fn discovery_selects_one_resource_type_for_services_with_several() {
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

        assert_eq!(
            view.resources(&ResourceListQuery::default()).unwrap_err(),
            "resourceType is required for a service with several resource types"
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
            .resources(&ResourceListQuery {
                resource_type: Some(space.clone()),
                ..ResourceListQuery::default()
            })
            .unwrap();
        assert_eq!(
            spaces
                .resources
                .iter()
                .map(|row| (row.id.as_str(), row.resource_type.as_str()))
                .collect::<Vec<_>>(),
            [("space-ENG", "confluence_space")]
        );
        let projects = view
            .resources(&ResourceListQuery {
                resource_type: Some(fake_project.clone()),
                limit: Some(1),
                ..ResourceListQuery::default()
            })
            .unwrap();
        assert!(
            projects
                .resources
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
        let cursor = projects.next_cursor.expect("more than one fake project");
        assert!(
            view.resources(&ResourceListQuery {
                resource_type: Some(space),
                limit: Some(1),
                cursor: Some(cursor),
                ..ResourceListQuery::default()
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
        let resources = view.resources(&ResourceListQuery::default()).unwrap();
        assert_eq!(
            resources
                .resources
                .iter()
                .map(|row| row.value.as_str())
                .collect::<Vec<_>>(),
            ["OTHER", "PROJ", "RESEARCH", "TEST"]
        );
        assert_eq!(
            resources.resources.last().unwrap().display_name.as_deref(),
            Some("Test project")
        );
        assert!(resources.next_cursor.is_none());
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
                .resources(&ResourceListQuery::default())
                .unwrap()
                .resources
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
        let query = ResourceListQuery {
            resource_type: None,
            prefix: Some("T".into()),
            limit: Some(1),
            cursor: None,
        };
        let first = view.resources(&query).unwrap();
        assert_eq!(first.resources[0].id, "fake-project-TEST");
        let cursor = first.next_cursor.unwrap();
        let continuation = ResourceListQuery {
            cursor: Some(cursor.clone()),
            ..query.clone()
        };
        let second = view.resources(&continuation).unwrap();
        assert_eq!(second.resources[0].id, "fake-project-TWO");
        assert!(second.next_cursor.is_none());
        for bad in [
            ResourceListQuery {
                prefix: None,
                ..continuation.clone()
            },
            ResourceListQuery {
                limit: Some(2),
                ..continuation.clone()
            },
            ResourceListQuery {
                cursor: Some("malformed".into()),
                ..continuation.clone()
            },
            ResourceListQuery {
                limit: Some(0),
                ..query.clone()
            },
            ResourceListQuery {
                limit: Some(101),
                ..query.clone()
            },
        ] {
            assert!(view.resources(&bad).is_err());
        }
        let foreign = token(ResourceSelection {
            resource_ids: vec!["fake-project-all".into()],
            resource_group_ids: vec![],
        });
        assert!(
            runtime
                .service_discovery(&foreign, &context, "fake")
                .unwrap()
                .resources(&continuation)
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
            .resources(&query)
            .unwrap()
            .next_cursor;
        assert!(
            runtime
                .service_discovery(&restricted, &context, "fake")
                .unwrap()
                .resources(&ResourceListQuery {
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
                .resources(&continuation)
                .is_err()
        );
        let changed_generation = runtime.clone().with_config_generation(2);
        assert!(
            changed_generation
                .service_discovery(&identity, &context, "fake")
                .unwrap()
                .resources(&continuation)
                .is_err()
        );
        assert!(
            view.resources(&ResourceListQuery {
                prefix: Some("ZZ".into()),
                ..Default::default()
            })
            .unwrap()
            .resources
            .is_empty()
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
        assert!(view.resources(&ResourceListQuery::default()).is_ok());
        view.capabilities.resource_scopes.insert(
            "space".into(),
            ResourceScopeCapabilities::new(
                agent_access_confluence::CONFLUENCE_SPACE_RESOURCE
                    .id()
                    .clone(),
                vec!["exact".into()],
            ),
        );
        assert!(view.resources(&ResourceListQuery::default()).is_err());
        assert!(view.actions(Some("TEST"), None, None).is_err());
        assert_eq!(view.actions(None, None, None).unwrap().actions, ["echo"]);
        view.capabilities.resource_scopes.clear();
        assert!(
            view.resources(&ResourceListQuery::default())
                .unwrap()
                .resources
                .is_empty()
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
                credential_name: None,
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
                .resources(&ResourceListQuery::default())
                .unwrap()
                .resources
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
