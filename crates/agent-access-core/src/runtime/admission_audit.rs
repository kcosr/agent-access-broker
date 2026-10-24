//! Bounded host-owned admission facts carried with each operation, including
//! the audit record retained by a response stream after the operation returns.
use super::{AuditRecord, Serialize, Value, json};

/// Host rate-admission outcome. Providers never supply or override these facts.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct InvocationAdmissionAudit {
    waited: bool,
    waited_milliseconds: u64,
    outcome: AdmissionOutcome,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
enum AdmissionOutcome {
    Admitted,
    Rejected,
    Cancelled,
}

impl InvocationAdmissionAudit {
    pub const fn admitted(waited: bool, waited_milliseconds: u64) -> Self {
        Self {
            waited,
            waited_milliseconds,
            outcome: AdmissionOutcome::Admitted,
        }
    }

    pub const fn rejected(waited: bool, waited_milliseconds: u64) -> Self {
        Self {
            waited,
            waited_milliseconds,
            outcome: AdmissionOutcome::Rejected,
        }
    }

    pub const fn cancelled(waited: bool, waited_milliseconds: u64) -> Self {
        Self {
            waited,
            waited_milliseconds,
            outcome: AdmissionOutcome::Cancelled,
        }
    }
}

pub(super) fn attach_admission_audit(
    provider_audit: Option<Value>,
    admission: Option<InvocationAdmissionAudit>,
) -> Option<Value> {
    merge_admission_audit(provider_audit, admission.map(|admission| json!(admission)))
}

/// Gateway progress replaces its provider facts but must retain the host's
/// admission metadata captured when forwarding started.
pub(super) fn preserve_admission_audit(
    provider_audit: Option<Value>,
    previous: Option<&Value>,
) -> Option<Value> {
    merge_admission_audit(
        provider_audit,
        previous.and_then(|audit| audit.get("admission")).cloned(),
    )
}

fn merge_admission_audit(provider_audit: Option<Value>, admission: Option<Value>) -> Option<Value> {
    let Some(admission) = admission else {
        // This name is host-owned even when the request had no rate admission.
        return provider_audit.map(|mut audit| {
            if let Some(fields) = audit.as_object_mut() {
                fields.remove("admission");
            }
            audit
        });
    };
    let mut audit = provider_audit.unwrap_or_else(|| json!({}));
    if !audit.is_object() {
        audit = json!({"providerAudit": audit});
    }
    audit
        .as_object_mut()
        .expect("audit was normalized to an object")
        .insert("admission".into(), admission);
    Some(audit)
}

fn admission_field<'a>(record: &'a AuditRecord, name: &str) -> Option<&'a Value> {
    record.provider_audit.as_ref()?.get("admission")?.get(name)
}

pub(super) fn admission_waited(record: &AuditRecord) -> Option<bool> {
    admission_field(record, "waited").and_then(Value::as_bool)
}

pub(super) fn admission_waited_milliseconds(record: &AuditRecord) -> Option<u64> {
    admission_field(record, "waitedMilliseconds").and_then(Value::as_u64)
}

pub(super) fn admission_outcome(record: &AuditRecord) -> Option<&str> {
    admission_field(record, "outcome").and_then(Value::as_str)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn provider_metadata_cannot_forge_or_replace_admission_facts() {
        let supplied = Some(json!({"admission":{"outcome":"forged"},"providerFact":17}));
        let metadata = InvocationAdmissionAudit::admitted(true, 123);
        let audit = attach_admission_audit(supplied.clone(), Some(metadata)).unwrap();
        assert_eq!(audit["providerFact"], 17);
        assert_eq!(
            audit["admission"],
            json!({
                "waited":true, "waitedMilliseconds":123, "outcome":"admitted"
            })
        );
        assert!(
            attach_admission_audit(supplied, None)
                .unwrap()
                .get("admission")
                .is_none()
        );
    }

    #[test]
    fn gateway_terminal_error_without_gateway_details_keeps_admission_at_top_level() {
        let initial = attach_admission_audit(
            Some(json!({"executionState":"unknown"})),
            Some(InvocationAdmissionAudit::admitted(true, 59)),
        );
        let terminal = super::super::gateway_terminal_audit_value(initial, "failed", None).unwrap();
        assert_eq!(
            terminal["admission"],
            json!({
                "waited":true, "waitedMilliseconds":59, "outcome":"admitted"
            })
        );
        assert_eq!(terminal["providerAudit"]["executionState"], "unknown");
        assert!(terminal["providerAudit"].get("admission").is_none());
    }

    #[test]
    fn gateway_progress_preserves_admission_and_unstructured_provider_audit() {
        let initial =
            attach_admission_audit(None, Some(InvocationAdmissionAudit::admitted(true, 51)));
        let progress =
            preserve_admission_audit(Some(json!(["provider fact"])), initial.as_ref()).unwrap();
        assert_eq!(progress["providerAudit"], json!(["provider fact"]));
        assert_eq!(progress["admission"], initial.unwrap()["admission"]);
    }
}
