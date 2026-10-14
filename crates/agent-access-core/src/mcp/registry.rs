use super::*;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

/// An immutable downstream connection selection, independent of its transport.
#[derive(Debug, Clone, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum McpView {
    #[default]
    Aggregate,
    Service(String),
}

impl McpView {
    pub fn service(&self) -> Option<&str> {
        match self {
            Self::Aggregate => None,
            Self::Service(service) => Some(service),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HelperKind {
    ServicesList,
    ResourcesList,
    ActionsList,
    ActionsDescribe,
    ServicesDescribe,
}

impl HelperKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ServicesList => "services_list",
            Self::ResourcesList => "resources_list",
            Self::ActionsList => "actions_list",
            Self::ActionsDescribe => "actions_describe",
            Self::ServicesDescribe => "services_describe",
        }
    }
    fn from_name(name: &str) -> Option<Self> {
        match name {
            "services_list" => Some(Self::ServicesList),
            "resources_list" => Some(Self::ResourcesList),
            "actions_list" => Some(Self::ActionsList),
            "actions_describe" => Some(Self::ActionsDescribe),
            "services_describe" => Some(Self::ServicesDescribe),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ToolTarget {
    Helper(HelperKind),
    Action { service: String, action: String },
}

pub const MAX_AGGREGATE_TOOL_NAME_BYTES: usize = 128;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AggregateMcpIssueCode {
    NameConflict,
    NameTooLong,
    ReservedName,
}

impl AggregateMcpIssueCode {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::NameConflict => "name_conflict",
            Self::NameTooLong => "name_too_long",
            Self::ReservedName => "reserved_name",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AggregateMcpNameIssue {
    pub name: String,
    pub code: AggregateMcpIssueCode,
}

/// Classify the supplied canonical identities before transport filtering.
/// Distinct identities sharing a name are all unavailable. Repeated canonical
/// identities are malformed catalog data, rather than a naming conflict.
pub fn aggregate_name_issues<'a>(
    identities: impl IntoIterator<Item = (&'a str, &'a str)>,
) -> Result<BTreeMap<(String, String), AggregateMcpNameIssue>, ProjectionError> {
    let mut seen = BTreeSet::new();
    let mut names: BTreeMap<String, Vec<(String, String)>> = BTreeMap::new();
    for (service, action) in identities {
        let identity = (service.to_owned(), action.to_owned());
        if !seen.insert(identity.clone()) {
            return Err(ProjectionError(
                "runtime catalog has duplicate action identities",
            ));
        }
        names
            .entry(tool_name(service, action))
            .or_default()
            .push(identity);
    }
    let mut issues = BTreeMap::new();
    for (name, identities) in names {
        let code = if name.len() > MAX_AGGREGATE_TOOL_NAME_BYTES {
            AggregateMcpIssueCode::NameTooLong
        } else if is_helper(&name) {
            AggregateMcpIssueCode::ReservedName
        } else if identities.len() > 1 {
            AggregateMcpIssueCode::NameConflict
        } else {
            continue;
        };
        for identity in identities {
            issues.insert(
                identity,
                AggregateMcpNameIssue {
                    name: name.clone(),
                    code,
                },
            );
        }
    }
    Ok(issues)
}

#[derive(Debug)]
struct ToolEntry {
    definition: Value,
    target: ToolTarget,
}

/// The one mapping used for listing, exact dispatch and action details.
#[derive(Debug)]
pub struct ToolRegistry {
    entries: Vec<ToolEntry>,
    names: BTreeMap<String, usize>,
    unavailable: BTreeMap<(String, String), AggregateMcpNameIssue>,
}

impl ToolRegistry {
    pub fn build(
        catalog: &ApiCatalog,
        view: &McpView,
        mode: ProjectionMode,
        max_bytes: usize,
    ) -> Result<Self, ProjectionError> {
        Self::build_inner(catalog, view, mode, max_bytes, true)
    }

    fn build_inner(
        catalog: &ApiCatalog,
        view: &McpView,
        mode: ProjectionMode,
        max_bytes: usize,
        require_ready: bool,
    ) -> Result<Self, ProjectionError> {
        if let McpView::Service(selected) = view {
            let mut matching = catalog
                .services
                .iter()
                .filter(|service| &service.service == selected);
            let service = matching
                .next()
                .ok_or(ProjectionError("service view is unavailable"))?;
            if !agent_access_provider::is_service_name(selected)
                || matching.next().is_some()
                || service.surface != "invoke"
                || (service.actions.is_empty()
                    && service.availability.as_ref().is_none_or(|availability| {
                        matches!(
                            availability.state,
                            crate::AvailabilityState::Available | crate::AvailabilityState::Partial
                        )
                    }))
                || (require_ready && !service.scoped_mcp_ready)
            {
                return Err(ProjectionError("service view is unavailable"));
            }
            // Check even file actions excluded from HTTP. Readiness is never
            // transport- or caller-relative, and clients validate their own data.
            let mut names = BTreeSet::new();
            let mut identities = BTreeSet::new();
            for action in &service.actions {
                if !identities.insert(&action.action) {
                    return Err(ProjectionError(
                        "runtime catalog has duplicate action identities",
                    ));
                }
                let name = action.scoped_mcp_name.as_deref();
                if scoped_name_issue(name).is_some() || !names.insert(name.unwrap()) {
                    return Err(ProjectionError("service view is unavailable"));
                }
            }
        }
        let mut result = Self {
            entries: Vec::new(),
            names: BTreeMap::new(),
            unavailable: if matches!(view, McpView::Aggregate) {
                aggregate_name_issues(
                    catalog
                        .services
                        .iter()
                        .filter(|service| service.surface == "invoke")
                        .flat_map(|service| {
                            service
                                .actions
                                .iter()
                                .map(|action| (service.service.as_str(), action.action.as_str()))
                        }),
                )?
            } else {
                BTreeMap::new()
            },
        };
        let mut budget = ProjectionBudget::new(max_bytes)?;
        for definition in helper_definitions_for_view(mode, view) {
            let name = definition["name"].as_str().expect("static helper name");
            let helper = HelperKind::from_name(name).expect("static helper kind");
            result.push(definition, ToolTarget::Helper(helper), &mut budget)?;
        }
        for service in &catalog.services {
            if service.surface != "invoke"
                || view
                    .service()
                    .is_some_and(|selected| selected != service.service)
            {
                continue;
            }
            for action in &service.actions {
                validate_catalog_action(&service.service, action)?;
                if !action_eligible(action, mode) {
                    continue;
                }
                let name = match view {
                    McpView::Aggregate => tool_name(&service.service, &action.action),
                    McpView::Service(_) => action
                        .scoped_mcp_name
                        .clone()
                        .ok_or(ProjectionError("service view is unavailable"))?,
                };
                let mut description = format!(
                    "{} — {}.{}: {}",
                    service.display_name, service.service, action.action, action.description
                );
                if action.documentation.is_some() {
                    description.push_str(&format!(
                        " For detailed usage, call actions_describe with service=\"{}\" and action=\"{}\".",
                        service.service, action.action
                    ));
                }
                let definition = json!({
                    "name": name,
                    "description": description,
                    "inputSchema": input_schema(action, mode),
                    "_meta": {
                        "agent-access/service": service.service,
                        "agent-access/action": action.action,
                        "agent-access/sensitive-output-pointers": action.sensitive_output_pointers
                    }
                });
                let target = ToolTarget::Action {
                    service: service.service.clone(),
                    action: action.action.clone(),
                };
                if result
                    .action_unavailable(&service.service, &action.action)
                    .is_some()
                {
                    // Charge omitted definitions too: the complete catalog
                    // budget must remain an upper bound for caller subsets.
                    budget.add(&definition)?;
                    continue;
                }
                result.push(definition, target, &mut budget)?;
            }
        }
        Ok(result)
    }

    fn push(
        &mut self,
        definition: Value,
        target: ToolTarget,
        budget: &mut ProjectionBudget,
    ) -> Result<(), ProjectionError> {
        let name = definition["name"]
            .as_str()
            .expect("projected name")
            .to_owned();
        if self.names.contains_key(&name) {
            return Err(ProjectionError("runtime catalog has duplicate tool names"));
        }
        budget.add(&definition)?;
        self.names.insert(name, self.entries.len());
        self.entries.push(ToolEntry { definition, target });
        Ok(())
    }

    pub fn definitions(&self) -> Vec<Value> {
        self.entries
            .iter()
            .map(|entry| entry.definition.clone())
            .collect()
    }

    pub fn resolve(&self, name: &str) -> Option<&ToolTarget> {
        self.names
            .get(name)
            .map(|index| &self.entries[*index].target)
    }

    pub fn action_detail(&self, service: &str, action: &str) -> Option<Value> {
        self.entries.iter().find_map(|entry| match &entry.target {
            ToolTarget::Action { service: selected_service, action: selected_action }
                if selected_service == service && selected_action == action => {
                    Some(json!({"name":entry.definition["name"],"inputSchema":entry.definition["inputSchema"]}))
                }
            _ => None,
        })
    }

    /// Naming diagnostics contain only this action's name and reason. Callers
    /// should check transport eligibility before displaying a missing-tool hint.
    pub fn action_unavailable(
        &self,
        service: &str,
        action: &str,
    ) -> Option<&AggregateMcpNameIssue> {
        self.unavailable
            .get(&(service.to_owned(), action.to_owned()))
    }
}

struct ProjectionBudget {
    remaining: usize,
    count: usize,
}
impl ProjectionBudget {
    fn new(max_bytes: usize) -> Result<Self, ProjectionError> {
        Ok(Self {
            remaining: max_bytes
                .checked_sub(2)
                .ok_or(ProjectionError("catalog exceeds work limit"))?,
            count: 0,
        })
    }
    fn add(&mut self, definition: &Value) -> Result<(), ProjectionError> {
        if self.count > 0 {
            self.remaining = self
                .remaining
                .checked_sub(1)
                .ok_or(ProjectionError("catalog exceeds work limit"))?;
        }
        serde_json::to_writer(&mut *self, definition)
            .map_err(|_| ProjectionError("catalog exceeds work limit"))?;
        self.count += 1;
        Ok(())
    }
}
impl std::io::Write for ProjectionBudget {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.remaining = self
            .remaining
            .checked_sub(bytes.len())
            .ok_or_else(|| std::io::Error::other("catalog work limit"))?;
        Ok(bytes.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

pub const STDIO_MAX_CATALOG_BYTES: usize = 64 * 1024 * 1024;

pub fn valid_scoped_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 128
        && name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'.' | b'-'))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ScopedMcpIssueCode {
    ServiceUnavailable,
    MissingName,
    InvalidName,
    ReservedName,
    DuplicateName,
    ProjectionBudget,
}

pub fn scoped_name_issue(name: Option<&str>) -> Option<ScopedMcpIssueCode> {
    match name {
        None => Some(ScopedMcpIssueCode::MissingName),
        Some(name) if !valid_scoped_name(name) => Some(ScopedMcpIssueCode::InvalidName),
        Some(name) if is_helper(name) => Some(ScopedMcpIssueCode::ReservedName),
        Some(_) => None,
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ScopedMcpIssue {
    pub code: ScopedMcpIssueCode,
    pub actions: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ScopedMcpReadiness {
    pub ready: bool,
    pub issues: Vec<ScopedMcpIssue>,
    pub truncated: bool,
}

impl ScopedMcpReadiness {
    pub fn unavailable() -> Self {
        Self {
            ready: false,
            issues: vec![ScopedMcpIssue {
                code: ScopedMcpIssueCode::ServiceUnavailable,
                actions: Vec::new(),
            }],
            truncated: false,
        }
    }
    fn issue(&mut self, code: ScopedMcpIssueCode, actions: &[String]) {
        self.ready = false;
        if self.issues.len() == 128 {
            self.truncated = true;
            return;
        }
        if actions.len() > 16 {
            self.truncated = true;
        }
        self.issues.push(ScopedMcpIssue {
            code,
            actions: actions.iter().take(16).cloned().collect(),
        });
    }
}

/// `descriptor` must already contain all active actions before caller filtering.
/// This is infallible: scoped incompatibility never blocks aggregate publication.
pub fn evaluate_scoped_mcp_readiness(
    descriptor: &agent_access_provider::ServiceDescriptor,
    max_bytes: usize,
) -> ScopedMcpReadiness {
    let Some(service) = crate::api_service_spec(descriptor, false) else {
        return ScopedMcpReadiness::unavailable();
    };
    let mut result = ScopedMcpReadiness {
        ready: true,
        issues: Vec::new(),
        truncated: false,
    };
    let mut names: BTreeMap<&str, Vec<String>> = BTreeMap::new();
    for action in &descriptor.actions {
        let name = action.raw_scoped_mcp_name();
        if let Some(code) = scoped_name_issue(name) {
            result.issue(code, std::slice::from_ref(&action.action));
        }
        if let Some(name) = name {
            names.entry(name).or_default().push(action.action.clone());
        }
    }
    for actions in names.values().filter(|actions| actions.len() > 1) {
        result.issue(ScopedMcpIssueCode::DuplicateName, actions);
    }
    if result.ready {
        let view = McpView::Service(service.service.clone());
        let mut catalog = crate::empty_catalog(json!({}));
        catalog.services.push(service);
        for mode in [ProjectionMode::Http, ProjectionMode::Stdio] {
            if ToolRegistry::build_inner(&catalog, &view, mode, max_bytes, false).is_err() {
                result.issue(ScopedMcpIssueCode::ProjectionBudget, &[]);
                break;
            }
        }
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use agent_access_provider::{ActionDescriptor, ScopedMcpNameSource, ServiceDescriptor};

    fn descriptor() -> ServiceDescriptor {
        let mut action = ActionDescriptor::new("accepted.read", "Read", json!({"type":"object"}));
        action.scoped_mcp_name_source = ScopedMcpNameSource::Imported {
            name: Some("Original.Read".into()),
        };
        ServiceDescriptor::new("example", "Example").with_actions(vec![action])
    }
    fn catalog(descriptor: &ServiceDescriptor, ready: bool) -> ApiCatalog {
        let mut catalog = crate::empty_catalog(json!({}));
        catalog
            .services
            .push(crate::api_service_spec(descriptor, ready).unwrap());
        catalog
    }

    #[test]
    fn aggregate_names_are_readable_and_preserve_the_full_128_byte_name() {
        assert_eq!(
            tool_name("cloudbees_ci", "job.build.list"),
            "cloudbees_ci_job_build_list"
        );
        let exact = "a".repeat(126);
        let overlong = "a".repeat(127);
        assert_eq!(tool_name("a", &exact), format!("a_{exact}"));
        assert_eq!(tool_name("a", &overlong), format!("a_{overlong}"));
        let issues =
            aggregate_name_issues([("a", exact.as_str()), ("a", overlong.as_str())]).unwrap();
        assert!(!issues.contains_key(&("a".into(), exact)));
        assert_eq!(
            issues[&("a".into(), overlong)].code,
            AggregateMcpIssueCode::NameTooLong
        );
    }

    #[test]
    fn aggregate_classifier_rejects_every_collision_and_reserves_helpers() {
        let identities = [
            ("example", "file.read"),
            ("example", "file_read"),
            ("example", "file-read"),
            ("example_file", "read"),
            ("services", "list"),
            ("example", "unique"),
        ];
        let issues = aggregate_name_issues(identities).unwrap();
        assert_eq!(issues.len(), 5);
        for (service, action) in &identities[..4] {
            let issue = &issues[&(service.to_string(), action.to_string())];
            assert_eq!(issue.code, AggregateMcpIssueCode::NameConflict);
            assert_eq!(issue.name, "example_file_read");
        }
        assert_eq!(
            issues[&("services".into(), "list".into())].code,
            AggregateMcpIssueCode::ReservedName
        );
        assert!(aggregate_name_issues([("example", "unique"), ("example", "unique")]).is_err());
    }

    fn colliding_descriptor() -> ServiceDescriptor {
        let mut descriptor = descriptor();
        descriptor.actions = ["file.read", "file_read", "unique"]
            .into_iter()
            .map(|name| ActionDescriptor::new(name, "Read", json!({"type":"object"})))
            .collect();
        descriptor
    }

    #[test]
    fn aggregate_omits_conflicting_actions_and_recovers_after_removal() {
        let mut descriptor = colliding_descriptor();
        for mode in [ProjectionMode::Http, ProjectionMode::Stdio] {
            let registry = ToolRegistry::build(
                &catalog(&descriptor, false),
                &McpView::Aggregate,
                mode,
                STDIO_MAX_CATALOG_BYTES,
            )
            .unwrap();
            assert_eq!(registry.definitions().len(), 6);
            assert!(registry.resolve("example_file_read").is_none());
            assert!(registry.action_detail("example", "file.read").is_none());
            assert_eq!(
                registry
                    .action_unavailable("example", "file.read")
                    .unwrap()
                    .code,
                AggregateMcpIssueCode::NameConflict
            );
            assert_eq!(
                registry.resolve("example_unique"),
                Some(&ToolTarget::Action {
                    service: "example".into(),
                    action: "unique".into()
                })
            );
        }
        descriptor.actions.remove(1);
        let registry = ToolRegistry::build(
            &catalog(&descriptor, false),
            &McpView::Aggregate,
            ProjectionMode::Http,
            STDIO_MAX_CATALOG_BYTES,
        )
        .unwrap();
        assert_eq!(
            registry.resolve("example_file_read"),
            Some(&ToolTarget::Action {
                service: "example".into(),
                action: "file.read".into()
            })
        );
        assert!(
            registry
                .action_unavailable("example", "file.read")
                .is_none()
        );
    }

    #[test]
    fn aggregate_classifies_http_ineligible_actions_before_filtering() {
        let mut descriptor = colliding_descriptor();
        descriptor.actions[1].io = agent_access_provider::ActionIo::RawDownload {
            metadata_header: "X-Metadata".into(),
            metadata_encoding: agent_access_provider::HeaderEncoding::Base64Json,
        };
        let mut catalog = catalog(&descriptor, false);
        let registry = ToolRegistry::build(
            &catalog,
            &McpView::Aggregate,
            ProjectionMode::Http,
            STDIO_MAX_CATALOG_BYTES,
        )
        .unwrap();
        assert_eq!(registry.definitions().len(), 6);
        assert!(registry.resolve("example_file_read").is_none());
        assert!(
            registry
                .action_unavailable("example", "file_read")
                .is_some()
        );
        // Even malformed duplicates excluded from HTTP remain catalog errors.
        catalog.services[0].actions[1].action = "file.read".into();
        assert!(
            ToolRegistry::build(
                &catalog,
                &McpView::Aggregate,
                ProjectionMode::Http,
                STDIO_MAX_CATALOG_BYTES
            )
            .is_err()
        );
    }

    #[test]
    fn aggregate_keeps_helpers_and_scoped_names_when_provider_names_are_unavailable() {
        let mut descriptor = descriptor();
        descriptor.service = "services".into();
        descriptor.actions[0].action = "list".into();
        let mut catalog = catalog(&descriptor, true);
        let long_action = "a".repeat(120);
        let second = catalog.services[0].actions[0].clone();
        catalog.services[0].actions.push(second);
        catalog.services[0].actions[1].action = long_action.clone();
        catalog.services[0].actions[1].scoped_mcp_name = Some("LongAction".into());
        let registry = ToolRegistry::build(
            &catalog,
            &McpView::Aggregate,
            ProjectionMode::Http,
            STDIO_MAX_CATALOG_BYTES,
        )
        .unwrap();
        assert_eq!(registry.definitions().len(), 5);
        assert_eq!(
            registry.resolve("services_list"),
            Some(&ToolTarget::Helper(HelperKind::ServicesList))
        );
        assert_eq!(
            registry
                .action_unavailable("services", "list")
                .unwrap()
                .code,
            AggregateMcpIssueCode::ReservedName
        );
        assert_eq!(
            registry
                .action_unavailable("services", &long_action)
                .unwrap()
                .code,
            AggregateMcpIssueCode::NameTooLong
        );
        let scoped = ToolRegistry::build(
            &catalog,
            &McpView::Service("services".into()),
            ProjectionMode::Http,
            STDIO_MAX_CATALOG_BYTES,
        )
        .unwrap();
        assert!(scoped.resolve("Original.Read").is_some());
        assert!(scoped.resolve("LongAction").is_some());
        assert!(scoped.action_unavailable("services", "list").is_none());
    }

    #[test]
    fn aggregate_budget_counts_omitted_definitions() {
        let descriptor = colliding_descriptor();
        let all = catalog(&descriptor, false);
        let registry = ToolRegistry::build(
            &all,
            &McpView::Aggregate,
            ProjectionMode::Http,
            STDIO_MAX_CATALOG_BYTES,
        )
        .unwrap();
        let visible_bytes = serde_json::to_vec(&registry.definitions()).unwrap().len();
        let mut complete = registry.definitions();
        for action in &descriptor.actions[..2] {
            let mut single = descriptor.clone();
            single.actions = vec![action.clone()];
            let single = ToolRegistry::build(
                &catalog(&single, false),
                &McpView::Aggregate,
                ProjectionMode::Http,
                STDIO_MAX_CATALOG_BYTES,
            )
            .unwrap();
            complete.push(single.definitions().last().unwrap().clone());
        }
        let complete_bytes = serde_json::to_vec(&complete).unwrap().len();
        assert!(complete_bytes > visible_bytes);
        assert!(
            ToolRegistry::build(
                &all,
                &McpView::Aggregate,
                ProjectionMode::Http,
                complete_bytes
            )
            .is_ok()
        );
        assert!(
            ToolRegistry::build(
                &all,
                &McpView::Aggregate,
                ProjectionMode::Http,
                complete_bytes - 1
            )
            .is_err()
        );
        assert!(
            ToolRegistry::build(
                &all,
                &McpView::Aggregate,
                ProjectionMode::Http,
                visible_bytes
            )
            .is_err()
        );
    }

    #[test]
    fn raw_names_resolve_only_within_the_selected_view_and_details_share_registry() {
        let descriptor = descriptor();
        let mut catalog = catalog(&descriptor, true);
        let mut other = catalog.services[0].clone();
        other.service = "another".into();
        catalog.services.push(other);
        let view = McpView::Service("example".into());
        let registry = ToolRegistry::build(
            &catalog,
            &view,
            ProjectionMode::Stdio,
            STDIO_MAX_CATALOG_BYTES,
        )
        .unwrap();
        assert_eq!(
            registry.resolve("Original.Read"),
            Some(&ToolTarget::Action {
                service: "example".into(),
                action: "accepted.read".into()
            })
        );
        assert!(
            registry
                .resolve(&tool_name("example", "accepted.read"))
                .is_none()
        );
        let definitions = registry.definitions();
        assert_eq!(definitions.len(), 6);
        let definition = definitions.last().unwrap();
        assert_eq!(
            registry.action_detail("example", "accepted.read").unwrap(),
            json!({"name":"Original.Read","inputSchema":definition["inputSchema"]})
        );
        assert!(registry.action_detail("another", "accepted.read").is_none());
        assert_eq!(definition["_meta"]["agent-access/action"], "accepted.read");
        for helper in definitions.iter().take(5).skip(1) {
            assert_eq!(
                helper["inputSchema"]["properties"]["service"]["const"],
                "example"
            );
            assert!(
                helper["inputSchema"]["required"]
                    .as_array()
                    .unwrap()
                    .contains(&json!("service"))
            );
        }
        assert!(
            validate_helper_arguments_for_view(
                "actions_describe",
                json!({"service":"another","action":"accepted.read"})
                    .as_object()
                    .unwrap(),
                ProjectionMode::Stdio,
                &view
            )
            .is_err()
        );
        catalog.services[0].scoped_mcp_ready = false;
        assert!(
            ToolRegistry::build(
                &catalog,
                &view,
                ProjectionMode::Stdio,
                STDIO_MAX_CATALOG_BYTES
            )
            .is_err()
        );
        assert!(
            ToolRegistry::build(
                &catalog,
                &McpView::Aggregate,
                ProjectionMode::Stdio,
                STDIO_MAX_CATALOG_BYTES
            )
            .is_ok()
        );
    }

    #[test]
    fn readiness_checks_all_names_and_preserves_aggregate_eligibility() {
        for (name, code) in [
            (None, ScopedMcpIssueCode::MissingName),
            (Some("invalid/name"), ScopedMcpIssueCode::InvalidName),
            (Some("resources_list"), ScopedMcpIssueCode::ReservedName),
        ] {
            let mut descriptor = descriptor();
            descriptor.actions[0].scoped_mcp_name_source = ScopedMcpNameSource::Imported {
                name: name.map(str::to_owned),
            };
            let readiness = evaluate_scoped_mcp_readiness(&descriptor, STDIO_MAX_CATALOG_BYTES);
            assert!(!readiness.ready);
            assert_eq!(readiness.issues[0].code, code);
            assert!(
                ToolRegistry::build(
                    &catalog(&descriptor, false),
                    &McpView::Aggregate,
                    ProjectionMode::Http,
                    STDIO_MAX_CATALOG_BYTES
                )
                .is_ok()
            );
        }
        let mut descriptor = descriptor();
        let mut hidden_file = descriptor.actions[0].clone();
        hidden_file.action = "download".into();
        hidden_file.io = agent_access_provider::ActionIo::RawDownload {
            metadata_header: "X-Metadata".into(),
            metadata_encoding: agent_access_provider::HeaderEncoding::Base64Json,
        };
        descriptor.actions.push(hidden_file);
        let readiness = evaluate_scoped_mcp_readiness(&descriptor, STDIO_MAX_CATALOG_BYTES);
        assert_eq!(readiness.issues[0].code, ScopedMcpIssueCode::DuplicateName);
        assert!(!readiness.ready);
        // Even a forged ready catalog cannot hide the HTTP-ineligible collision.
        assert!(
            ToolRegistry::build(
                &catalog(&descriptor, true),
                &McpView::Service("example".into()),
                ProjectionMode::Http,
                STDIO_MAX_CATALOG_BYTES
            )
            .is_err()
        );
    }

    #[test]
    fn projection_budget_counts_the_complete_serialized_array_and_readiness_is_infallible() {
        let descriptor = descriptor();
        let catalog = catalog(&descriptor, true);
        let view = McpView::Service("example".into());
        let registry = ToolRegistry::build(
            &catalog,
            &view,
            ProjectionMode::Stdio,
            STDIO_MAX_CATALOG_BYTES,
        )
        .unwrap();
        let exact = serde_json::to_vec(&registry.definitions()).unwrap().len();
        assert!(ToolRegistry::build(&catalog, &view, ProjectionMode::Stdio, exact).is_ok());
        assert!(ToolRegistry::build(&catalog, &view, ProjectionMode::Stdio, exact - 1).is_err());
        assert_eq!(
            evaluate_scoped_mcp_readiness(&descriptor, 1).issues[0].code,
            ScopedMcpIssueCode::ProjectionBudget
        );
        assert!(evaluate_scoped_mcp_readiness(&descriptor, STDIO_MAX_CATALOG_BYTES).ready);
    }

    #[test]
    fn diagnostic_caps_never_stop_name_validation() {
        let mut descriptor = descriptor();
        descriptor.actions = (0..150)
            .map(|index| {
                let mut action = descriptor.actions[0].clone();
                action.action = format!("action{index}");
                action.scoped_mcp_name_source = ScopedMcpNameSource::Imported {
                    name: Some("invalid/name".into()),
                };
                action
            })
            .collect();
        let readiness = evaluate_scoped_mcp_readiness(&descriptor, STDIO_MAX_CATALOG_BYTES);
        assert!(!readiness.ready);
        assert!(readiness.truncated);
        assert_eq!(readiness.issues.len(), 128);
        assert!(
            readiness
                .issues
                .iter()
                .all(|issue| issue.actions.len() <= 16)
        );
        assert!(
            !serde_json::to_string(&readiness)
                .unwrap()
                .contains("invalid/name")
        );
    }

    #[test]
    fn scoped_name_profile_preserves_case_and_has_an_ascii_byte_bound() {
        for valid in ["Case_.-123", &"x".repeat(128)] {
            assert!(valid_scoped_name(valid));
        }
        for invalid in ["", "name space", "name/path", "é", &"x".repeat(129)] {
            assert!(!valid_scoped_name(invalid));
        }
    }
}
