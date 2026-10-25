//! Host-owned request snapshots, prepared once with the published action contract.
use super::*;
use agent_access_provider::host::{AuditInputPlan, prepare_audit_inputs};

pub(super) type AuditInputPlans = BTreeMap<(String, String), Arc<AuditInputPlan>>;

pub(super) fn prepare_plans(
    services: &BTreeMap<String, Arc<ServiceDescriptor>>,
) -> Result<AuditInputPlans, String> {
    let mut plans = BTreeMap::new();
    for (service, descriptor) in services {
        for action in &descriptor.actions {
            if let Some(declaration) = &action.audit_inputs {
                let plan =
                    prepare_audit_inputs(&action.input_schema, declaration).map_err(|_| {
                        format!(
                            "invalid audit input declaration for {service}/{}",
                            action.action
                        )
                    })?;
                plans.insert((service.clone(), action.action.clone()), Arc::new(plan));
            }
        }
    }
    Ok(plans)
}

impl BrokerRuntime {
    pub(super) fn audit_input_plan(
        &self,
        service: &str,
        action: &str,
    ) -> Option<Arc<AuditInputPlan>> {
        self.audit_input_plans
            .get(&(service.to_owned(), action.to_owned()))
            .cloned()
    }
}

#[cfg(test)]
mod tests;
