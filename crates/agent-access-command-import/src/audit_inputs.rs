//! The command manifest and accepted annotation share the SDK's strict
//! declaration decoder and schema eligibility checks. Only original action
//! inputs are selectable; process stdin and output are outside this contract.
use agent_access_provider::AuditInputProjection;
use serde_json::Value;

pub(crate) fn parse(
    value: Option<&Value>,
    input_schema: &Value,
) -> Result<Option<AuditInputProjection>, String> {
    let Some(value) = value else {
        return Ok(None);
    };
    // Serde errors can quote untrusted declaration values. Keep the diagnostic
    // static, including when accepted metadata is corrupt.
    let projection: AuditInputProjection = serde_json::from_value(value.clone())
        .map_err(|_| "auditInputs must be a valid nonempty declaration array")?;
    agent_access_provider::host::prepare_audit_inputs(input_schema, &projection)
        .map_err(|_| "auditInputs is incompatible with inputSchema or its sensitivity contract")?;
    Ok(Some(projection))
}
