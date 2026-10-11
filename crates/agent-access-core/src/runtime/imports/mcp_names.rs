//! Admission protects new imports without making retained names a startup gate.
use super::*;
use crate::mcp::{AggregateMcpNameIssue, aggregate_name_issues};

const MAX_NAME_DIAGNOSTICS: usize = 8;

impl BrokerRuntime {
    fn import_mcp_name_issues(
        &self,
        catalog: &ImportedCatalog,
    ) -> Result<BTreeMap<(String, String), AggregateMcpNameIssue>, ManagedStoreError> {
        let builtin = self
            .services
            .values()
            .filter(|service| {
                service.surface == ServiceSurface::Invoke
                    && self.imported_catalog.service(&service.service).is_none()
            })
            .flat_map(|service| {
                service
                    .actions
                    .iter()
                    .map(|action| (service.service.as_str(), action.action.as_str()))
            });
        // Disabled and quarantined actions retain their place in admission, so
        // accepting a new action cannot create a conflict when they return.
        // Retirement is permanent and releases only the presentation name.
        let imported = catalog
            .services
            .iter()
            .filter(|service| service.status != ImportedServiceStatus::Retired)
            .flat_map(|service| {
                service
                    .actions
                    .iter()
                    .filter(|action| action.status != ImportedActionStatus::Retired)
                    .map(|action| {
                        (
                            service.definition.service.as_str(),
                            action.definition.action.as_str(),
                        )
                    })
            });
        aggregate_name_issues(builtin.chain(imported)).map_err(|error| {
            ManagedStoreError::InputInvalid(format!("import catalog cannot be named: {error}"))
        })
    }

    pub(super) fn validate_import_mcp_names(
        &self,
        catalog: &ImportedCatalog,
    ) -> Result<(), ManagedStoreError> {
        let old = self.import_mcp_name_issues(&self.imported_catalog)?;
        let candidate = self.import_mcp_name_issues(catalog)?;
        let rejected_names = candidate
            .iter()
            .filter(|(identity, _)| {
                !old.contains_key(*identity)
                    || (active(catalog, identity) && !active(&self.imported_catalog, identity))
            })
            .map(|(_, issue)| issue.name.as_str())
            .collect::<BTreeSet<_>>();
        if rejected_names.is_empty() {
            return Ok(());
        }
        let affected = candidate
            .iter()
            .filter(|(_, issue)| rejected_names.contains(issue.name.as_str()))
            .collect::<Vec<_>>();
        let mut details = affected
            .iter()
            .take(MAX_NAME_DIAGNOSTICS)
            .map(|((service, action), issue)| {
                format!(
                    "{service}/{action}: {} ({})",
                    issue.name,
                    issue.code.as_str()
                )
            })
            .collect::<Vec<_>>();
        if affected.len() > MAX_NAME_DIAGNOSTICS {
            details.push(format!(
                "{} more affected actions",
                affected.len() - MAX_NAME_DIAGNOSTICS
            ));
        }
        Err(ManagedStoreError::InputInvalid(format!(
            "import would introduce or enable unavailable aggregate MCP tool names; adjust proposed action IDs before acceptance or retire incompatible accepted actions: {}",
            details.join("; ")
        )))
    }

    /// Report current aggregate omissions only after publishing a runtime.
    /// These diagnostics are administrative, never caller-facing discovery data.
    pub fn warn_aggregate_mcp_names(&self) {
        let identities = self
            .services
            .values()
            .filter(|service| service.surface == ServiceSurface::Invoke)
            .flat_map(|service| {
                service
                    .actions
                    .iter()
                    .filter(|action| {
                        self.imported_action_available(&service.service, &action.action)
                    })
                    .map(|action| (service.service.as_str(), action.action.as_str()))
            });
        let Ok(issues) = aggregate_name_issues(identities) else {
            tracing::warn!("aggregate MCP naming diagnostics found malformed catalog identities");
            return;
        };
        for ((service, action), issue) in issues.iter().take(MAX_NAME_DIAGNOSTICS) {
            tracing::warn!(
                service,
                action,
                name = issue.name,
                reason = issue.code.as_str(),
                "action is unavailable in aggregate MCP because of its tool name"
            );
        }
        if issues.len() > MAX_NAME_DIAGNOSTICS {
            tracing::warn!(
                omitted_diagnostics = issues.len() - MAX_NAME_DIAGNOSTICS,
                "additional aggregate MCP naming diagnostics omitted"
            );
        }
    }
}

fn active(catalog: &ImportedCatalog, identity: &(String, String)) -> bool {
    catalog.service(&identity.0).is_some_and(|service| {
        service.status == ImportedServiceStatus::Enabled
            && service.actions.iter().any(|action| {
                action.definition.action == identity.1
                    && action.status == ImportedActionStatus::Enabled
            })
    })
}

#[cfg(test)]
mod tests;
