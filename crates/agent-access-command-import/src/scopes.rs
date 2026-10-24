//! Admission-time scope resolution: inputs must match the accepted input
//! schema, and a Broker-enforced action's resources are read from its
//! declared input pointers so core checks grants before any process starts.
use crate::mapping::CompiledAction;
use agent_access_provider::{ProviderError, ReasonCode, ResourceScopes};
use serde_json::Value;
use std::collections::{BTreeMap, HashSet};

/// The most distinct resources one call to a Broker-enforced action may
/// name. Policy checks every value before dispatch, and the request passes
/// each one with its entry and attributes within the 1 MiB request bound.
pub(crate) const MAX_RESOURCE_VALUES: usize = 1_000;

fn input_invalid(message: &'static str) -> ProviderError {
    ProviderError::deny(ReasonCode::InputInvalid, message)
}

/// The resources `inputs` name for `action`: for a Broker-enforced action,
/// its declared type's scope with every value at its input pointers, in
/// pointer and array order without duplicates, at most
/// [`MAX_RESOURCE_VALUES`]; for every other action, none. Canonical form and
/// grant coverage are core's to check.
pub(crate) fn resolve(
    action: &CompiledAction,
    inputs: &Value,
) -> Result<ResourceScopes, ProviderError> {
    if !action.input.is_valid(inputs) {
        return Err(input_invalid(
            "inputs do not match the action's input schema",
        ));
    }
    let Some(resources) = action
        .authority
        .resources
        .as_ref()
        .filter(|resources| resources.broker_enforced())
    else {
        return Ok(ResourceScopes::new());
    };
    let mut seen = HashSet::new();
    let mut values = Vec::new();
    for pointer in &resources.inputs {
        let named = match inputs.pointer(pointer) {
            Some(Value::String(value)) => vec![value],
            Some(Value::Array(items)) => items
                .iter()
                .map(|item| match item {
                    Value::String(value) => Some(value),
                    _ => None,
                })
                .collect::<Option<Vec<_>>>()
                .ok_or_else(|| input_invalid("a resource input must hold strings"))?,
            _ => return Err(input_invalid("a resource input is missing")),
        };
        for value in named {
            if seen.insert(value.as_str()) {
                if values.len() == MAX_RESOURCE_VALUES {
                    return Err(input_invalid(
                        "the action names more than 1,000 distinct resources",
                    ));
                }
                values.push(value.clone());
            }
        }
    }
    if values.is_empty() {
        return Err(input_invalid("the action names no resources"));
    }
    Ok(BTreeMap::from([(resources.resource_type.clone(), values)]))
}

#[cfg(test)]
mod tests {
    use super::*;
    use agent_access_core::imports::ImportedActionDefinition;
    use serde_json::json;

    fn action(resources: Value, schema: Value) -> CompiledAction {
        CompiledAction::new(&ImportedActionDefinition {
            action: "issue.view".into(),
            source: json!({"name": "issue.view"}),
            label: None,
            description: "Show issues.".into(),
            input_schema: schema,
            output_schema: None,
            annotations: json!({"command": {"resources": resources}}),
            read_only: true,
            download: false,
        })
        .unwrap()
    }

    fn schema() -> Value {
        json!({"type": "object", "required": ["project", "others", "issue"],
            "properties": {"project": {"type": "string"},
                "others": {"type": "array", "items": {"type": "string"}},
                "issue": {"type": "integer"}},
            "additionalProperties": false})
    }

    #[test]
    fn broker_enforced_actions_resolve_every_declared_input() {
        let view = action(
            json!({"type": "project", "inputs": ["/project", "/others"]}),
            schema(),
        );
        assert_eq!(
            resolve(
                &view,
                &json!({"project": "OPS", "others": ["ENG", "OPS", "SEC"], "issue": 4})
            )
            .unwrap(),
            BTreeMap::from([(
                "project".to_owned(),
                vec!["OPS".to_owned(), "ENG".to_owned(), "SEC".to_owned()]
            )])
        );
        let only_array = action(json!({"type": "project", "inputs": ["/others"]}), schema());
        assert_eq!(
            resolve(
                &only_array,
                &json!({"project": "OPS", "others": [], "issue": 4})
            )
            .unwrap_err()
            .reason_code(),
            ReasonCode::InputInvalid,
            "an empty resource list never bypasses the grant check"
        );
    }

    #[test]
    fn inputs_must_match_the_schema_before_resources_resolve() {
        let view = action(json!({"type": "project", "inputs": ["/project"]}), schema());
        for inputs in [
            json!({"project": 7, "others": [], "issue": 4}),
            json!({"others": [], "issue": 4}),
            json!({"project": "OPS", "others": [], "issue": 4, "extra": true}),
        ] {
            assert_eq!(
                resolve(&view, &inputs).unwrap_err().reason_code(),
                ReasonCode::InputInvalid,
                "{inputs}"
            );
        }
    }

    #[test]
    fn broker_enforced_actions_name_a_bounded_number_of_distinct_resources() {
        let only_array = action(json!({"type": "project", "inputs": ["/others"]}), schema());
        let named = |others: Vec<String>| json!({"project": "OPS", "others": others, "issue": 1});
        let distinct = |count: usize| (0..count).map(|index| format!("P{index}")).collect();
        let resolved = resolve(&only_array, &named(distinct(MAX_RESOURCE_VALUES))).unwrap();
        assert_eq!(resolved["project"].len(), MAX_RESOURCE_VALUES);
        assert_eq!(
            resolve(&only_array, &named(distinct(MAX_RESOURCE_VALUES + 1)))
                .unwrap_err()
                .reason_code(),
            ReasonCode::InputInvalid
        );
        // Duplicates count once, in linear time.
        let mut repeated = distinct(MAX_RESOURCE_VALUES);
        repeated.extend(std::iter::repeat_n("P0".to_owned(), 200_000));
        assert_eq!(
            resolve(&only_array, &named(repeated)).unwrap()["project"].len(),
            MAX_RESOURCE_VALUES
        );
    }

    #[test]
    fn command_enforced_actions_name_no_resources() {
        let search = action(json!({"type": "project"}), schema());
        assert!(
            resolve(
                &search,
                &json!({"project": "OPS", "others": ["ENG"], "issue": 1})
            )
            .unwrap()
            .is_empty()
        );
    }
}
