//! An import change must leave its retained grants valid: publication
//! refuses a change that the next start or reload would reject, so an
//! administrator fixes the grants first instead of finding a Broker that no
//! longer starts.
use super::*;

impl BrokerRuntime {
    /// Checks `service`'s grants in this candidate generation as startup
    /// validates them: against its imported catalog, descriptors, declared
    /// credential modes and the published resource catalog. Grants of other
    /// services are unchanged by an import mutation, and every cross-grant
    /// rule compares grants of one service only.
    pub(in crate::runtime) fn check_retained_import_grants(
        &self,
        service: &str,
    ) -> Result<(), ManagedStoreError> {
        let snapshot = self.policy_snapshot();
        let labels = snapshot
            .grants
            .iter()
            .map(|grant| match (grant.managed_id(), grant.toml_index()) {
                (Some(id), _) => format!("managed policy grant {id}"),
                (None, Some(index)) => format!("policy.grants[{index}]"),
                (None, None) => "policy grant".to_owned(),
            })
            .collect::<Vec<_>>();
        let grants = snapshot
            .grants
            .iter()
            .zip(&labels)
            .filter(|(grant, _)| grant.service == service)
            .map(|(grant, label)| NormalizedPolicyGrant {
                label: format!("{label} subjects[{}]", grant.subject_order),
                service_label: format!("{label} service"),
                actions_label: format!("{label} actions"),
                credential_mode_label: format!("{label} credentialMode"),
                execution_contexts_label: format!("{label} executionContexts"),
                subject_field: format!("subjects[{}]", grant.subject_order),
                subject: &grant.subject,
                service: &grant.service,
                actions: &grant.actions,
                resources: &grant.resources,
                execution_contexts: grant
                    .execution_contexts
                    .iter()
                    .map(|context| context.as_str().to_owned())
                    .collect(),
                credential_mode: &grant.credential_mode,
                priority: grant.priority,
            })
            .collect::<Vec<_>>();
        if grants.is_empty() {
            return Ok(());
        }
        let mut config = retention_config(&self.config, &self.imported_catalog);
        config.policy.resources = snapshot.resource_catalog.resources.clone();
        config.policy.resource_groups = snapshot.resource_catalog.resource_groups.clone();
        let issues = crate::normalized_policy_grant_validation_issues(
            &config,
            &self.services,
            &self.imported_catalog,
            self.resource_types(),
            &grants,
        );
        if issues.is_empty() {
            return Ok(());
        }
        Err(ManagedStoreError::InputInvalid(format!(
            "the change would leave retained grants invalid; update or remove them first: {}",
            issues
                .into_iter()
                .map(|issue| issue.message)
                .collect::<Vec<_>>()
                .join("; ")
        )))
    }
}
