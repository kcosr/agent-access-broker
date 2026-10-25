//! Host-only declaration preparation and bounded projection.
use super::*;
use sha2::{Digest, Sha256};

mod project;
mod schema;

/// Immutable, prepared audit capture contract for one action publication.
/// It owns only reviewed metadata and selectors, never invocation inputs.
#[derive(Debug, Clone)]
pub struct AuditInputPlan {
    rules: Vec<PreparedRule>,
    declaration_sha256: String,
}

#[derive(Debug, Clone)]
struct PreparedRule {
    rule: AuditInputRule,
    path: Vec<String>,
    children: Vec<PreparedRule>,
}

impl AuditInputPlan {
    pub fn declaration_sha256(&self) -> &str {
        &self.declaration_sha256
    }

    /// Capture original inputs after successful admission. No declaration
    /// containing only omissions emits an envelope. Failures affect only this
    /// snapshot and never change invocation authorization or execution.
    pub fn project(&self, inputs: &Value) -> Option<RequestAudit> {
        project::project(self, inputs)
    }
}

/// Validate and compile a reviewed declaration once at action publication.
/// The structural and sensitivity walk deliberately does not compile schema
/// value constraints, infer types or validate invocation values.
pub fn prepare_audit_inputs(
    schema: &Value,
    projection: &AuditInputProjection,
) -> Result<AuditInputPlan, String> {
    projection.validate()?;
    let mut walker = schema::Walker::new(schema);
    let mut rules = Vec::new();
    for rule in projection.rules() {
        let path = parse_pointer(rule.pointer())?;
        walker.check(rule, &path, None)?;
        let mut children = Vec::new();
        for child in rule.fields() {
            let child_path = parse_pointer(child.pointer())?;
            if path.len() + child_path.len() + 1 > 16 {
                return Err("auditInputs record child path exceeds 16 segments".into());
            }
            walker.check(child, &child_path, Some(&path))?;
            children.push(PreparedRule {
                rule: child.clone(),
                path: child_path,
                children: Vec::new(),
            });
        }
        rules.push(PreparedRule {
            rule: rule.clone(),
            path,
            children,
        });
    }
    // serde_json without preserve_order uses sorted object maps. Explicitly
    // canonicalize anyway so the digest does not depend on that Cargo feature.
    let contract = serde_json::json!({"inputSchema": schema, "auditInputs": projection});
    let bytes = serde_json::to_vec(&canonicalize(contract))
        .map_err(|_| "auditInputs canonical serialization failed")?;
    let declaration_sha256 = format!("{:x}", Sha256::digest(bytes));
    Ok(AuditInputPlan {
        rules,
        declaration_sha256,
    })
}

fn canonicalize(value: Value) -> Value {
    match value {
        Value::Object(object) => {
            let sorted: BTreeMap<_, _> = object
                .into_iter()
                .map(|(key, value)| (key, canonicalize(value)))
                .collect();
            Value::Object(sorted.into_iter().collect())
        }
        Value::Array(values) => Value::Array(values.into_iter().map(canonicalize).collect()),
        scalar => scalar,
    }
}

#[cfg(test)]
mod tests;
