//! Shared catalog selectors and live resource-group authorization boundaries.
use agent_access_provider::{
    ResourceSelector, ResourceType, ResourceTypeRegistry, ScalarResourceSelector,
};
use serde::{Deserialize, Deserializer, Serialize};
use std::collections::{BTreeMap, BTreeSet};

fn enabled_default() -> bool {
    true
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ResourceDefinition {
    pub id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub display_name: Option<String>,
    /// Optional browser navigation metadata. Authority comes only from `selector`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub browser_url: Option<String>,
    pub resource_type: ResourceType,
    pub selector: ResourceSelector,
    pub allowed_execution_contexts: Vec<String>,
    #[serde(default = "enabled_default")]
    pub enabled: bool,
}
impl ResourceDefinition {
    /// Type-specific checks: the resource's type is registered and its
    /// selector form and value are valid for that type.
    pub fn validate_type(&self, registry: &ResourceTypeRegistry) -> Result<(), String> {
        registry.validate_selector(&self.id, &self.resource_type, &self.selector)?;
        let Some(browser_url) = &self.browser_url else {
            return Ok(());
        };
        self.validate_browser_url_text()?;
        let invalid = || {
            format!(
                "resource {} browser URL must identify its saved location",
                self.id
            )
        };
        let descriptor = registry.get(&self.resource_type).ok_or_else(invalid)?;
        if !descriptor.has_location_normalizer() {
            return Err(invalid());
        }
        let projection = descriptor
            .project_selector(&self.selector)
            .map_err(|_| invalid())?
            .ok_or_else(invalid)?;
        let coverage = match &self.selector {
            ResourceSelector::Exact { .. } => "exact",
            ResourceSelector::Subtree { .. } => "subtree",
            _ => return Err(invalid()),
        };
        let normalized = registry
            .normalize_location(
                &self.resource_type,
                &agent_access_provider::LocationNormalizationRequest::new(
                    &projection.site_origin,
                    browser_url,
                    coverage,
                ),
            )
            .map_err(|_| invalid())?;
        if normalized.resource_type != self.resource_type || normalized.selector != self.selector {
            return Err(invalid());
        }
        Ok(())
    }

    fn validate_browser_url_text(&self) -> Result<(), String> {
        if self.browser_url.as_ref().is_some_and(|value| {
            value.is_empty()
                || value.len() > 4096
                || value.trim() != value
                || value.chars().any(char::is_control)
        }) {
            return Err(format!("resource {} browser URL is invalid", self.id));
        }
        Ok(())
    }
}

pub fn validate_resource_definition_types(
    registry: &ResourceTypeRegistry,
    resources: &[ResourceDefinition],
) -> Vec<String> {
    resources
        .iter()
        .filter_map(|resource| resource.validate_type(registry).err())
        .collect()
}

/// Validates type contracts for the entire catalog, including unused groups.
/// Exclusion support is a property of the type, independent of a resource's
/// selector, enabled state, execution contexts, or current grant/token use.
pub(crate) fn validate_resource_catalog_types(
    registry: &ResourceTypeRegistry,
    resources: &[ResourceDefinition],
    groups: &[ResourceGroupDefinition],
) -> Vec<String> {
    let mut errors = validate_resource_definition_types(registry, resources);
    let resources: BTreeMap<_, _> = resources
        .iter()
        .map(|resource| (resource.id.as_str(), resource))
        .collect();
    for group in groups {
        for id in &group.excluded_resource_ids {
            // Structural catalog validation reports unknown references; type
            // validation above reports unregistered resource types.
            let Some(resource) = resources.get(id.as_str()) else {
                continue;
            };
            if registry
                .get(&resource.resource_type)
                .is_some_and(|descriptor| !descriptor.supports_exclusions())
            {
                errors.push(format!(
                    "resource group {} cannot exclude resource {}: resource type {} does not support exclusions",
                    group.id, resource.id, resource.resource_type
                ));
            }
        }
    }
    errors
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ResourceGroupDefinition {
    pub id: String,
    pub name: String,
    #[serde(default)]
    pub included_resource_ids: Vec<String>,
    #[serde(default)]
    pub excluded_resource_ids: Vec<String>,
}
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ResourceSelection {
    #[serde(default)]
    pub resource_ids: Vec<String>,
    #[serde(default)]
    pub resource_group_ids: Vec<String>,
}
impl ResourceSelection {
    pub fn is_empty(&self) -> bool {
        self.resource_ids.is_empty() && self.resource_group_ids.is_empty()
    }

    pub fn validate_structure(&self) -> Result<(), Vec<String>> {
        let mut errors = vec![];
        validate_ids("resourceIds", &self.resource_ids, &mut errors);
        validate_ids("resourceGroupIds", &self.resource_group_ids, &mut errors);
        if errors.is_empty() {
            Ok(())
        } else {
            Err(errors)
        }
    }
}
fn validate_ids(label: &str, ids: &[String], errors: &mut Vec<String>) {
    let mut seen = BTreeSet::new();
    for id in ids {
        if !super::is_safe_identifier(id) || matches!(id.as_str(), "." | "..") {
            errors.push(format!("{label} contains invalid id {id}"));
        }
        if !seen.insert(id) {
            errors.push(format!("{label} contains duplicate id {id}"));
        }
    }
}

#[derive(Debug, Clone, Default)]
pub struct ResourceCatalog {
    pub resources: BTreeMap<String, ResourceDefinition>,
    pub resource_groups: BTreeMap<String, ResourceGroupDefinition>,
}
impl ResourceCatalog {
    pub fn new(
        resources: &[ResourceDefinition],
        groups: &[ResourceGroupDefinition],
    ) -> Result<Self, Vec<String>> {
        let mut catalog = Self::default();
        let mut errors = vec![];
        let mut selectors = BTreeSet::new();
        for resource in resources {
            validate_ids("resources", std::slice::from_ref(&resource.id), &mut errors);
            if let Err(error) = resource.validate_browser_url_text() {
                errors.push(error);
            }
            if catalog
                .resources
                .insert(resource.id.clone(), resource.clone())
                .is_some()
            {
                errors.push(format!("duplicate resource id {}", resource.id));
            }
            if !selectors.insert((resource.resource_type.clone(), resource.selector.clone())) {
                errors.push(format!(
                    "resource {} duplicates a type and selector",
                    resource.id
                ));
            }
            if resource
                .display_name
                .as_ref()
                .is_some_and(|v| v.trim().is_empty() || v.chars().any(char::is_control))
            {
                errors.push(format!("resource {} display name is invalid", resource.id));
            }
            // Storage and every resource type require a non-empty value
            // without control characters (SQLite measures text up to NUL).
            if matches!(
                &resource.selector,
                ResourceSelector::Exact { value } | ResourceSelector::Namespace { value } | ResourceSelector::Subtree { value }
                    if value.is_empty() || value.chars().any(char::is_control)
            ) {
                errors.push(format!(
                    "resource {} selector value must be non-empty without control characters",
                    resource.id
                ));
            }
            let mut contexts = BTreeSet::new();
            if resource.allowed_execution_contexts.is_empty()
                || resource.allowed_execution_contexts.len() > super::EXECUTION_CONTEXT_MAX_VALUES
            {
                errors.push(format!(
                    "resource {} requires 1..={} allowed execution contexts",
                    resource.id,
                    super::EXECUTION_CONTEXT_MAX_VALUES
                ));
            }
            for context in &resource.allowed_execution_contexts {
                if !super::is_valid_execution_context_value(context) || !contexts.insert(context) {
                    errors.push(format!(
                        "resource {} has invalid or duplicate execution context {context}",
                        resource.id
                    ));
                }
            }
        }
        for group in groups {
            validate_ids(
                "resource groups",
                std::slice::from_ref(&group.id),
                &mut errors,
            );
            if catalog
                .resource_groups
                .insert(group.id.clone(), group.clone())
                .is_some()
            {
                errors.push(format!("duplicate resource group id {}", group.id));
            }
            if group.name.trim().is_empty() || group.name.chars().any(char::is_control) {
                errors.push(format!("resource group {} name is invalid", group.id));
            }
            for (label, ids) in [
                ("includedResourceIds", &group.included_resource_ids),
                ("excludedResourceIds", &group.excluded_resource_ids),
            ] {
                validate_ids(label, ids, &mut errors);
                for id in ids {
                    if !catalog.resources.contains_key(id) {
                        errors.push(format!(
                            "resource group {} references unknown resource {id}",
                            group.id
                        ));
                    }
                }
            }
        }
        if errors.is_empty() {
            Ok(catalog)
        } else {
            Err(errors)
        }
    }
    pub fn validate_contexts(&self, configured: &[String]) -> Result<(), Vec<String>> {
        let errors: Vec<_> = self
            .resources
            .values()
            .flat_map(|r| {
                r.allowed_execution_contexts
                    .iter()
                    .filter(|c| !configured.contains(c))
                    .map(|c| format!("resource {} execution context {c} is not configured", r.id))
            })
            .collect();
        if errors.is_empty() {
            Ok(())
        } else {
            Err(errors)
        }
    }
    pub fn validate_selection(&self, selection: &ResourceSelection) -> Result<(), Vec<String>> {
        let mut errors = selection.validate_structure().err().unwrap_or_default();
        for id in &selection.resource_ids {
            if !self.resources.contains_key(id) {
                errors.push(format!("unknown resource id {id}"));
            }
        }
        for id in &selection.resource_group_ids {
            if !self.resource_groups.contains_key(id) {
                errors.push(format!("unknown resource group id {id}"));
            }
        }
        if errors.is_empty() {
            Ok(())
        } else {
            Err(errors)
        }
    }
    /// Compile one selection across all types admitted by a containment contract.
    /// Exclusions are collected across the complete selection before any matching;
    /// disabled or context-ineligible negative entries retain their effect.
    pub fn resolve_containment(
        &self,
        selection: &ResourceSelection,
        contract: &agent_access_provider::ContainmentScopeCapabilities,
        site_origin: &str,
        registry: &ResourceTypeRegistry,
        context: &str,
    ) -> Result<agent_access_provider::ContainmentBoundary, String> {
        use agent_access_provider::ContainmentBoundary;
        if self.validate_selection(selection).is_err() {
            return Ok(ContainmentBoundary::new(Vec::new(), Vec::new()));
        }
        let mut included: BTreeSet<&String> = selection.resource_ids.iter().collect();
        let mut excluded = BTreeSet::new();
        for id in &selection.resource_group_ids {
            if let Some(group) = self.resource_groups.get(id) {
                included.extend(group.included_resource_ids.iter());
                excluded.extend(group.excluded_resource_ids.iter());
            }
        }
        let selectors = |ids: BTreeSet<&String>, positive: bool| {
            let mut values = Vec::new();
            for id in ids {
                let Some(resource) = self.resources.get(id) else {
                    continue;
                };
                if !contract
                    .selectors_by_type
                    .contains_key(&resource.resource_type)
                    || positive
                        && (!resource.enabled
                            || !resource
                                .allowed_execution_contexts
                                .iter()
                                .any(|value| value == context))
                {
                    continue;
                }
                let selector = registry
                    .typed_selector(&resource.resource_type, &resource.selector)
                    .map_err(|_| {
                        "resource selector cannot be compiled for containment".to_string()
                    })?;
                if contract.selector_applicable(&selector, site_origin) {
                    values.push(selector);
                }
            }
            Ok::<_, String>(values)
        };
        Ok(ContainmentBoundary::new(
            selectors(included, true)?,
            selectors(excluded, false)?,
        ))
    }

    pub fn resolve(
        &self,
        selection: &ResourceSelection,
        resource_type: &ResourceType,
        context: &str,
    ) -> Result<ResourceBoundary, String> {
        // Invalid references never accidentally turn a restriction into broad access.
        if self.validate_selection(selection).is_err() {
            return Ok(ResourceBoundary::default());
        }
        let mut included: BTreeSet<&String> = selection.resource_ids.iter().collect();
        let mut excluded = BTreeSet::new();
        for id in &selection.resource_group_ids {
            if let Some(group) = self.resource_groups.get(id) {
                included.extend(group.included_resource_ids.iter());
                excluded.extend(group.excluded_resource_ids.iter());
            }
        }
        let selectors = |ids: BTreeSet<&String>,
                         positive: bool|
         -> Result<Vec<ScalarResourceSelector>, String> {
            ids.into_iter()
                .filter_map(|id| self.resources.get(id))
                .filter(|r| {
                    r.resource_type == *resource_type
                        && (!positive
                            || r.enabled
                                && r.allowed_execution_contexts.iter().any(|c| c == context))
                })
                .map(|r| {
                    ScalarResourceSelector::try_from(&r.selector).map_err(|_| {
                        "containment selector cannot enter a scalar resource boundary".to_string()
                    })
                })
                .collect::<Result<BTreeSet<_>, _>>()
                .map(|selectors| selectors.into_iter().collect())
        };
        Ok(ResourceBoundary {
            included: selectors(included, true)?,
            excluded: selectors(excluded, false)?,
        })
    }
}
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ResourceBoundary {
    pub included: Vec<ScalarResourceSelector>,
    pub excluded: Vec<ScalarResourceSelector>,
}
impl ResourceBoundary {
    pub fn matches(&self, target: &str) -> bool {
        self.included.iter().any(|s| s.matches(target))
            && !self.excluded.iter().any(|s| s.matches(target))
    }
    pub fn is_empty(&self) -> bool {
        self.included
            .iter()
            .all(|s| self.excluded.iter().any(|e| e.contains(s)))
    }
    pub fn is_universe(&self) -> bool {
        self.included.contains(&ScalarResourceSelector::All) && self.excluded.is_empty()
    }
    pub fn intersection(&self, other: &Self) -> Self {
        Self {
            included: self
                .included
                .iter()
                .flat_map(|a| other.included.iter().filter_map(|b| a.intersection(b)))
                .collect::<BTreeSet<_>>()
                .into_iter()
                .collect(),
            excluded: self
                .excluded
                .iter()
                .chain(&other.excluded)
                .cloned()
                .collect::<BTreeSet<_>>()
                .into_iter()
                .collect(),
        }
    }
    pub fn intersects(&self, other: &Self) -> bool {
        self.included.iter().any(|left| {
            other
                .included
                .iter()
                .filter_map(|right| left.intersection(right))
                .any(|intersection| {
                    !self
                        .excluded
                        .iter()
                        .chain(&other.excluded)
                        .any(|e| e.contains(&intersection))
                })
        })
    }
}

// Config input remains snake_case. Public management and token JSON stays camelCase.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ResourceConfig {
    id: String,
    display_name: Option<String>,
    browser_url: Option<String>,
    resource_type: ResourceType,
    selector: ResourceSelector,
    allowed_execution_contexts: Vec<String>,
    #[serde(default = "enabled_default")]
    enabled: bool,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ResourceGroupConfig {
    id: String,
    name: String,
    #[serde(default)]
    included_resource_ids: Vec<String>,
    #[serde(default)]
    excluded_resource_ids: Vec<String>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ResourceSelectionConfig {
    #[serde(default)]
    resource_ids: Vec<String>,
    #[serde(default)]
    resource_group_ids: Vec<String>,
}
pub(crate) fn deserialize_resources<'de, D: Deserializer<'de>>(
    d: D,
) -> Result<Vec<ResourceDefinition>, D::Error> {
    Ok(Vec::<ResourceConfig>::deserialize(d)?
        .into_iter()
        .map(|r| ResourceDefinition {
            id: r.id,
            display_name: r.display_name,
            browser_url: r.browser_url,
            resource_type: r.resource_type,
            selector: r.selector,
            allowed_execution_contexts: r.allowed_execution_contexts,
            enabled: r.enabled,
        })
        .collect())
}
pub(crate) fn deserialize_groups<'de, D: Deserializer<'de>>(
    d: D,
) -> Result<Vec<ResourceGroupDefinition>, D::Error> {
    Ok(Vec::<ResourceGroupConfig>::deserialize(d)?
        .into_iter()
        .map(|r| ResourceGroupDefinition {
            id: r.id,
            name: r.name,
            included_resource_ids: r.included_resource_ids,
            excluded_resource_ids: r.excluded_resource_ids,
        })
        .collect())
}
pub(crate) fn deserialize_selection<'de, D: Deserializer<'de>>(
    d: D,
) -> Result<ResourceSelection, D::Error> {
    let r = ResourceSelectionConfig::deserialize(d)?;
    Ok(ResourceSelection {
        resource_ids: r.resource_ids,
        resource_group_ids: r.resource_group_ids,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn browser_url_registry() -> ResourceTypeRegistry {
        ResourceTypeRegistry::new([
            &agent_access_confluence::CONFLUENCE_CONTENT_RESOURCE,
            &agent_access_confluence::CONFLUENCE_SPACE_RESOURCE,
            &agent_access_provider::GIT_REPOSITORY_RESOURCE,
        ])
        .unwrap()
    }

    #[test]
    fn browser_urls_match_stable_identity_without_becoming_authority() {
        let registry = browser_url_registry();
        for (kind, path, coverage) in [
            ("page", "pages", "exact"),
            ("page", "pages", "subtree"),
            ("folder", "folder", "subtree"),
            ("blog", "blog", "exact"),
        ] {
            let identity = format!("https://example.atlassian.net/wiki/content/{kind}/123");
            let selector = if coverage == "subtree" {
                ResourceSelector::Subtree { value: identity }
            } else {
                ResourceSelector::Exact { value: identity }
            };
            let mut resource = resource("content", selector, &["internal"], true);
            resource.resource_type = agent_access_confluence::CONFLUENCE_CONTENT_RESOURCE
                .id()
                .clone();
            assert!(resource.validate_type(&registry).is_ok());
            let identity = resource.selector.clone();
            for space in ["ENG", "OLD", "NEW"] {
                resource.browser_url = Some(format!(
                    "https://example.atlassian.net/wiki/spaces/{space}/{path}/123/Operations+日本語"
                ));
                assert!(resource.validate_type(&registry).is_ok());
                assert_eq!(resource.selector, identity);
            }
        }
    }

    #[test]
    fn browser_urls_reject_mismatched_unsafe_and_unsupported_locations_without_echoing_values() {
        let registry = browser_url_registry();
        let mut content = resource(
            "content",
            ResourceSelector::Subtree {
                value: "https://example.atlassian.net/wiki/content/folder/123".into(),
            },
            &["internal"],
            true,
        );
        content.resource_type = agent_access_confluence::CONFLUENCE_CONTENT_RESOURCE
            .id()
            .clone();
        for url in [
            "https://other.atlassian.net/wiki/spaces/ENG/folder/123/Private-title",
            "https://example.atlassian.net/wiki/spaces/ENG/folder/456/Private-title",
            "https://example.atlassian.net/wiki/spaces/ENG/pages/123/Private-title",
            "http://example.atlassian.net/wiki/spaces/ENG/folder/123/Private-title",
            "https://user:secret@example.atlassian.net/wiki/spaces/ENG/folder/123",
            "https://example.atlassian.net/wiki/spaces/ENG/folder/123?secret=value",
            "https://example.atlassian.net/wiki/spaces/ENG/folder/123#Private-title",
            "https://example.atlassian.net/wiki/spaces/ENG/folder/123/Private%2Ftitle",
            "https://example.atlassian.net/wiki/spaces/ENG/folder/123/%2e%2e",
            " https://example.atlassian.net/wiki/spaces/ENG/folder/123",
            "https://example.atlassian.net/wiki/spaces/ENG/folder/123\n",
            "",
        ] {
            content.browser_url = Some(url.into());
            let error = content.validate_type(&registry).unwrap_err();
            assert!(!error.contains("Private-title"));
            assert!(!error.contains("secret"));
            assert!(!error.contains("atlassian"));
        }
        content.browser_url = Some(format!(
            "https://example.atlassian.net/wiki/spaces/ENG/folder/123/{}",
            "x".repeat(4096)
        ));
        assert!(ResourceCatalog::new(&[content.clone()], &[]).is_err());
        assert!(content.validate_type(&registry).is_err());
        let mut unsupported = resource("repository", exact("team/project"), &["internal"], true);
        unsupported.browser_url = Some("https://example.test/team/project".into());
        assert!(unsupported.validate_type(&registry).is_err());
        unsupported.browser_url = None;
        assert!(unsupported.validate_type(&registry).is_ok());
    }

    #[test]
    fn browser_url_config_and_json_preserve_metadata_using_their_canonical_field_names() {
        let source = r#"
authority = "toml"
[[resources]]
id = "runbooks"
resource_type = "confluence_content"
selector = { kind = "subtree", value = "https://example.atlassian.net/wiki/content/folder/123" }
browser_url = "https://example.atlassian.net/wiki/spaces/ENG/folder/123/Runbooks"
allowed_execution_contexts = ["internal"]
"#;
        let config: crate::PolicyConfig = toml::from_str(source).unwrap();
        let resource = &config.resources[0];
        assert!(resource.validate_type(&browser_url_registry()).is_ok());
        let json = serde_json::to_value(resource).unwrap();
        assert_eq!(json["browserUrl"], resource.browser_url.as_deref().unwrap());
        assert!(json.get("browser_url").is_none());
        assert_eq!(
            serde_json::from_value::<ResourceDefinition>(json).unwrap(),
            *resource
        );
        assert!(
            toml::from_str::<crate::PolicyConfig>(&source.replace("browser_url", "browserUrl"))
                .is_err()
        );
        let mut absent = resource.clone();
        absent.browser_url = None;
        assert!(
            serde_json::to_value(absent)
                .unwrap()
                .get("browserUrl")
                .is_none()
        );
    }

    fn resource(
        id: &str,
        selector: ResourceSelector,
        contexts: &[&str],
        enabled: bool,
    ) -> ResourceDefinition {
        ResourceDefinition {
            id: id.into(),
            display_name: None,
            browser_url: None,
            resource_type: agent_access_provider::GIT_REPOSITORY_RESOURCE.id().clone(),
            selector,
            allowed_execution_contexts: contexts.iter().map(|c| (*c).into()).collect(),
            enabled,
        }
    }
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
    fn selection(ids: &[&str], groups: &[&str]) -> ResourceSelection {
        ResourceSelection {
            resource_ids: ids.iter().map(|s| (*s).into()).collect(),
            resource_group_ids: groups.iter().map(|s| (*s).into()).collect(),
        }
    }
    #[test]
    fn exclusion_capability_validates_every_member_without_changing_resolution() {
        use agent_access_provider::GIT_REPOSITORY_RESOURCE;
        use std::sync::Arc;
        let registry = ResourceTypeRegistry::from_shared([Arc::new(
            GIT_REPOSITORY_RESOURCE
                .clone()
                .with_supports_exclusions(false),
        )])
        .unwrap();
        // Selector kind, enabled state and execution context do not exempt an
        // excluded member. The same member may also be included.
        for selector in [
            exact("org/repository"),
            namespace("org"),
            ResourceSelector::All,
        ] {
            for enabled in [false, true] {
                let resources = [resource(
                    "selected",
                    selector.clone(),
                    &["external"],
                    enabled,
                )];
                let mut groups = [ResourceGroupDefinition {
                    id: "unused".into(),
                    name: "Unused group".into(),
                    included_resource_ids: vec!["selected".into()],
                    excluded_resource_ids: vec![],
                }];
                assert!(validate_resource_catalog_types(&registry, &resources, &groups).is_empty());
                groups[0].excluded_resource_ids.push("selected".into());
                assert_eq!(
                    validate_resource_catalog_types(&registry, &resources, &groups),
                    [
                        "resource group unused cannot exclude resource selected: resource type git_repository does not support exclusions"
                    ]
                );
                assert!(
                    validate_resource_catalog_types(
                        &crate::tests::test_resource_types(),
                        &resources,
                        &groups
                    )
                    .is_empty()
                );
            }
        }
    }

    #[test]
    fn resource_ids_reject_url_dot_segments() {
        for id in [".", ".."] {
            assert!(
                ResourceSelection {
                    resource_ids: vec![id.into()],
                    resource_group_ids: vec![]
                }
                .validate_structure()
                .is_err()
            );
            assert!(
                ResourceSelection {
                    resource_ids: vec![],
                    resource_group_ids: vec![id.into()]
                }
                .validate_structure()
                .is_err()
            );
            assert!(
                ResourceCatalog::new(
                    &[resource(id, ResourceSelector::All, &["internal"], true)],
                    &[]
                )
                .is_err()
            );
        }
        assert!(
            ResourceSelection {
                resource_ids: vec!["used-by".into(), "a.b".into()],
                resource_group_ids: vec![]
            }
            .validate_structure()
            .is_ok()
        );
    }

    #[test]
    fn catalog_rejects_empty_or_control_selector_values_before_any_type_check() {
        for selector in [
            exact(""),
            namespace(""),
            exact("\u{0}"),
            namespace("engineering\u{0}"),
            exact("ENG\n"),
        ] {
            assert_eq!(
                ResourceCatalog::new(&[resource("empty", selector, &["internal"], true)], &[])
                    .unwrap_err(),
                ["resource empty selector value must be non-empty without control characters"]
            );
        }
    }

    #[test]
    fn namespace_matches_segments_and_new_descendants() {
        let selector = ScalarResourceSelector::try_from(namespace("engineering/platform")).unwrap();
        assert!(selector.matches("engineering/platform/api"));
        assert!(selector.matches("engineering/platform/new/service"));
        assert!(!selector.matches("engineering/platform-tools/api"));
        assert!(!selector.matches("engineering/platform"));
        assert!(!selector.matches("engineering/platform/"));
    }

    #[test]
    fn scalar_catalog_resolution_rejects_subtree_in_both_polarities() {
        let tree = ResourceSelector::Subtree {
            value: "engineering/platform".into(),
        };
        let included =
            ResourceCatalog::new(&[resource("tree", tree.clone(), &["internal"], true)], &[])
                .unwrap();
        assert!(
            included
                .resolve(
                    &selection(&["tree"], &[]),
                    agent_access_provider::GIT_REPOSITORY_RESOURCE.id(),
                    "internal"
                )
                .is_err()
        );
        let excluded = ResourceCatalog::new(
            &[
                resource("all", ResourceSelector::All, &["internal"], true),
                resource("tree", tree, &["external"], false),
            ],
            &[ResourceGroupDefinition {
                id: "filtered".into(),
                name: "Filtered".into(),
                included_resource_ids: vec!["all".into()],
                excluded_resource_ids: vec!["tree".into()],
            }],
        )
        .unwrap();
        assert!(
            excluded
                .resolve(
                    &selection(&[], &["filtered"]),
                    agent_access_provider::GIT_REPOSITORY_RESOURCE.id(),
                    "internal"
                )
                .is_err()
        );
    }
    #[test]
    fn cloudbees_ci_job_selectors_keep_controller_and_folder_boundaries() {
        let mut controller = resource("controller", namespace("team-ci"), &["internal"], true);
        controller.resource_type = agent_access_cloudbees_ci::CLOUDBEES_CI_JOB_RESOURCE
            .id()
            .clone();
        let mut payments = resource(
            "payments",
            namespace("team-ci/payments"),
            &["internal"],
            true,
        );
        payments.resource_type = agent_access_cloudbees_ci::CLOUDBEES_CI_JOB_RESOURCE
            .id()
            .clone();
        let mut exact_job = resource(
            "exact-job",
            exact("team-ci/payments/build-api"),
            &["internal"],
            true,
        );
        exact_job.resource_type = agent_access_cloudbees_ci::CLOUDBEES_CI_JOB_RESOURCE
            .id()
            .clone();
        let catalog = ResourceCatalog::new(&[controller, payments, exact_job], &[]).unwrap();
        let boundary = catalog
            .resolve(
                &selection(&["payments"], &[]),
                agent_access_cloudbees_ci::CLOUDBEES_CI_JOB_RESOURCE.id(),
                "internal",
            )
            .unwrap();
        assert!(boundary.matches("team-ci/payments/build-api"));
        assert!(boundary.matches("team-ci/payments/new/service"));
        for outside in [
            "team-ci/payments",
            "team-ci/payments-other/build-api",
            "team-ci/other/build-api",
            "other-ci/payments/build-api",
        ] {
            assert!(!boundary.matches(outside), "{outside}");
        }
        assert!(
            catalog
                .resolve(
                    &selection(&["controller"], &[]),
                    agent_access_cloudbees_ci::CLOUDBEES_CI_JOB_RESOURCE.id(),
                    "internal",
                )
                .unwrap()
                .matches("team-ci/other/build-api")
        );
        assert!(
            catalog
                .resolve(
                    &selection(&["exact-job"], &[]),
                    agent_access_cloudbees_ci::CLOUDBEES_CI_JOB_RESOURCE.id(),
                    "internal",
                )
                .unwrap()
                .matches("team-ci/payments/build-api")
        );
    }

    #[test]
    fn cloudbees_ci_job_catalog_rejects_wildcards_and_controller_only_exact() {
        for (kind, value) in [
            ("exact", "team-ci"),
            ("exact", "team-ci/payments/*"),
            ("namespace", "team-ci/payments/*"),
            ("namespace", "team-ci/payments/../secret"),
            ("namespace", "team-ci//payments"),
        ] {
            let selector = if kind == "exact" {
                exact(value)
            } else {
                namespace(value)
            };
            let mut entry = resource("invalid", selector, &["internal"], true);
            entry.resource_type = agent_access_cloudbees_ci::CLOUDBEES_CI_JOB_RESOURCE
                .id()
                .clone();
            assert!(
                entry
                    .validate_type(&crate::tests::test_resource_types())
                    .is_err(),
                "{kind} {value}"
            );
        }
        assert!(
            agent_access_cloudbees_ci::CLOUDBEES_CI_JOB_RESOURCE
                .is_canonical_target("team-ci/payments/build-api")
        );
        assert!(
            !agent_access_cloudbees_ci::CLOUDBEES_CI_JOB_RESOURCE.is_canonical_target("team-ci")
        );
    }
    #[test]
    fn exclusions_win_across_selected_groups_even_when_disabled_and_context_ineligible() {
        let resources = vec![
            resource("all", ResourceSelector::All, &["external"], true),
            resource("private", namespace("private"), &["internal"], false),
            resource("special", exact("private/special"), &["external"], true),
        ];
        let groups = vec![
            ResourceGroupDefinition {
                id: "wide".into(),
                name: "Wide".into(),
                included_resource_ids: vec!["all".into()],
                excluded_resource_ids: vec!["private".into()],
            },
            ResourceGroupDefinition {
                id: "special".into(),
                name: "Special".into(),
                included_resource_ids: vec!["special".into()],
                excluded_resource_ids: vec![],
            },
        ];
        let catalog = ResourceCatalog::new(&resources, &groups).unwrap();
        let boundary = catalog
            .resolve(
                &selection(&["special"], &["wide", "special"]),
                agent_access_provider::GIT_REPOSITORY_RESOURCE.id(),
                "external",
            )
            .unwrap();
        assert!(boundary.matches("engineering/new"));
        assert!(!boundary.matches("private/special"));
        assert!(!boundary.is_universe());
        assert!(!boundary.is_empty());
        let separate = catalog
            .resolve(
                &selection(&[], &["special"]),
                agent_access_provider::GIT_REPOSITORY_RESOURCE.id(),
                "external",
            )
            .unwrap();
        assert!(separate.matches("private/special"));
        assert!(!boundary.intersection(&separate).matches("private/special"));
        assert!(boundary.intersection(&separate).is_empty());
    }
    #[test]
    fn empty_and_invalid_selections_fail_closed() {
        let catalog = ResourceCatalog::new(
            &[],
            &[ResourceGroupDefinition {
                id: "empty".into(),
                name: "Empty".into(),
                included_resource_ids: vec![],
                excluded_resource_ids: vec![],
            }],
        )
        .unwrap();
        for selected in [
            selection(&[], &[]),
            selection(&[], &["empty"]),
            selection(&["missing"], &[]),
        ] {
            let boundary = catalog
                .resolve(
                    &selected,
                    agent_access_provider::GIT_REPOSITORY_RESOURCE.id(),
                    "internal",
                )
                .unwrap();
            assert!(boundary.is_empty());
            assert!(!boundary.matches("engineering/repo"));
        }
    }
    #[test]
    fn graph_rejects_duplicate_selectors_and_malformed_references() {
        let all = resource("all", ResourceSelector::All, &["internal"], true);
        let duplicate = resource("other", ResourceSelector::All, &["external"], false);
        assert!(
            ResourceCatalog::new(&[all.clone(), duplicate], &[])
                .unwrap_err()
                .iter()
                .any(|e| e.contains("duplicates a type and selector"))
        );
        let catalog = ResourceCatalog::new(&[all], &[]).unwrap();
        assert!(
            catalog
                .validate_selection(&selection(&["all", "all"], &[]))
                .is_err()
        );
        assert!(
            catalog
                .validate_selection(&selection(&[], &["missing"]))
                .is_err()
        );
        assert!(catalog.validate_contexts(&["external".into()]).is_err());
    }
    #[test]
    fn namespace_selectors_follow_the_resource_type_registry() {
        let registry = crate::tests::test_resource_types();
        let mut entry = resource("bad", namespace("engineering"), &["internal"], true);
        entry.resource_type = agent_access_jira::JIRA_PROJECT_RESOURCE.id().clone();
        assert_eq!(
            entry.validate_type(&registry).unwrap_err(),
            "resource bad selector is invalid for jira_project"
        );
        entry.resource_type = ResourceType::new("jira_issue").unwrap();
        assert_eq!(
            entry.validate_type(&registry).unwrap_err(),
            "resource bad uses unregistered resource type jira_issue"
        );
        for value in [
            "/engineering",
            "engineering/",
            "engineering//platform",
            "engineering/../private",
            "engineering%2fprivate",
        ] {
            assert!(
                resource("bad", namespace(value), &["internal"], true)
                    .validate_type(&registry)
                    .is_err()
            );
        }
    }
    #[test]
    fn selector_wire_rejects_obsolete_and_unknown_shapes() {
        for value in [
            serde_json::json!({"kind":"all","value":"*"}),
            serde_json::json!({"namespace":"engineering"}),
            serde_json::json!({"kind":"exact"}),
            serde_json::json!({"kind":"glob","value":"*"}),
        ] {
            assert!(serde_json::from_value::<ResourceSelector>(value).is_err());
        }
        assert!(
            serde_json::from_value::<ResourceSelection>(serde_json::json!({"resourceScopes":{}}))
                .is_err()
        );
    }
    #[test]
    fn intersections_preserve_namespace_holes() {
        let broad = ResourceBoundary {
            included: vec![ScalarResourceSelector::All],
            excluded: vec![namespace("engineering/private").try_into().unwrap()],
        };
        let engineering = ResourceBoundary {
            included: vec![namespace("engineering").try_into().unwrap()],
            excluded: vec![exact("engineering/special").try_into().unwrap()],
        };
        let intersection = broad.intersection(&engineering);
        assert!(intersection.matches("engineering/payments"));
        assert!(!intersection.matches("engineering/private/secret"));
        assert!(!intersection.matches("engineering/special"));
        assert!(broad.intersects(&engineering));
        assert!(!broad.intersects(&ResourceBoundary {
            included: vec![namespace("engineering/private").try_into().unwrap()],
            excluded: vec![]
        }));
    }
    #[test]
    fn config_uses_snake_case_and_public_json_uses_camel_case() {
        let config: crate::PolicyConfig = toml::from_str(
            r#"
authority = "toml"
[[resources]]
id = "repo"
resource_type = "git_repository"
selector = {kind = "exact", value = "engineering/payments"}
allowed_execution_contexts = ["internal"]
[[resource_groups]]
id = "team"
name = "Team"
included_resource_ids = ["repo"]
[[grants]]
subjects = ["group:team"]
service = "gitlab"
actions = ["project.view"]
credential_mode = "service"
resources = { resource_group_ids = ["team"] }
"#,
        )
        .unwrap();
        assert_eq!(config.grants[0].resources.resource_group_ids, ["team"]);
        assert_eq!(
            config.resources[0].resource_type,
            agent_access_provider::GIT_REPOSITORY_RESOURCE.id().clone()
        );
        let json = serde_json::to_value(&config.resources[0]).unwrap();
        assert_eq!(json["resourceType"], "git_repository");
        assert!(json.get("resource_type").is_none());
        let selection = serde_json::to_value(&config.grants[0].resources).unwrap();
        assert_eq!(selection["resourceGroupIds"], serde_json::json!(["team"]));
    }
    #[test]
    fn token_absent_and_empty_resource_selections_are_distinct_and_legacy_is_rejected() {
        let parse = |restriction| {
            crate::AgentInvokeTokenCaveats::parse_stored(
                &serde_json::json!({"readOnly":false,"allowedServices":["gitlab"],"allowedExecutionContexts":["internal"],"serviceRestrictions":{"gitlab":restriction}}),
            )
        };
        assert!(crate::AgentInvokeTokenCaveats::parse_stored(&serde_json::json!({})).is_err());
        let follow = parse(serde_json::json!({"actions":["project.view"]})).unwrap();
        let empty = parse(serde_json::json!({"actions":["project.view"],"resources":{}})).unwrap();
        assert!(
            follow.service_restrictions.unwrap()["gitlab"]
                .resources
                .is_none()
        );
        assert_eq!(
            empty.service_restrictions.unwrap()["gitlab"].resources,
            Some(ResourceSelection::default())
        );
        assert!(parse(serde_json::json!({"actions":["project.view"],"resources":null})).is_err());
        assert!(parse(serde_json::json!({"actions":["project.view"],"resourceScopes":{"repository":["engineering/payments"]}})).is_err());
    }
    #[test]
    fn canonical_target_validation_rejects_aliases_and_missing_containment() {
        assert!(
            agent_access_provider::GIT_REPOSITORY_RESOURCE
                .is_canonical_target("engineering/payments")
        );
        for invalid in [
            "",
            "42",
            "repo",
            "engineering/../secret",
            "engineering%2fsecret",
            "https://git.example/repo",
            "engineering/a b",
        ] {
            assert!(!agent_access_provider::GIT_REPOSITORY_RESOURCE.is_canonical_target(invalid));
        }
        assert!(agent_access_jira::JIRA_PROJECT_RESOURCE.is_canonical_target("ENG"));
        assert!(!agent_access_jira::JIRA_PROJECT_RESOURCE.is_canonical_target("eng"));
        assert!(!agent_access_jira::JIRA_PROJECT_RESOURCE.is_canonical_target("ENG-123"));
        assert!(agent_access_confluence::CONFLUENCE_SPACE_RESOURCE.is_canonical_target("ENG"));
        assert!(!agent_access_confluence::CONFLUENCE_SPACE_RESOURCE.is_canonical_target(""));
        assert!(
            serde_json::from_value::<ResourceSelector>(
                serde_json::json!({"kind":"all","value":null})
            )
            .is_err()
        );
    }
}
