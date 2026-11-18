//! Strict result-schema conformance for provider and host tests.
//!
//! Strict validation treats every object schema that declares `properties`
//! and no explicit `additionalProperties` as closed, so a passing outcome
//! proves each emitted field is documented. The advertised schemas stay open.
use crate::{
    ActionDescriptor, ProviderError, ProviderResult, shared_failure_result_schema,
    with_shared_failure_properties,
};
use serde_json::{Value, json};

/// `schema` with `additionalProperties: false` added to every object schema
/// that declares `properties` without `additionalProperties`.
pub fn strict_result_schema(schema: &Value) -> Value {
    let mut schema = schema.clone();
    close_objects(&mut schema);
    schema
}

fn close_objects(schema: &mut Value) {
    let Some(object) = schema.as_object_mut() else {
        return;
    };
    if object.contains_key("properties") && !object.contains_key("additionalProperties") {
        object.insert("additionalProperties".into(), Value::Bool(false));
    }
    if let Some(properties) = object.get_mut("properties").and_then(Value::as_object_mut) {
        properties.values_mut().for_each(close_objects);
    }
    for keyword in ["additionalProperties", "items"] {
        if let Some(child) = object.get_mut(keyword) {
            close_objects(child);
        }
    }
    if let Some(branches) = object.get_mut("anyOf").and_then(Value::as_array_mut) {
        branches.iter_mut().for_each(close_objects);
    }
}

/// Validates `value` strictly against `schema`, describing every problem
/// with its instance location, schema location and the validator's message.
pub fn check_strict_conformance(schema: &Value, value: &Value) -> Result<(), String> {
    let validator = jsonschema::validator_for(&strict_result_schema(schema))
        .map_err(|error| format!("result schema does not compile: {error}"))?;
    let problems = validator
        .iter_errors(value)
        .map(|error| {
            format!(
                "at {} (schema {}): {error}",
                display_location(error.instance_path().as_str()),
                display_location(error.schema_path().as_str()),
            )
        })
        .collect::<Vec<_>>();
    if problems.is_empty() {
        Ok(())
    } else {
        Err(problems.join("; "))
    }
}

fn display_location(location: &str) -> &str {
    if location.is_empty() { "/" } else { location }
}

/// The strict failure schema a provider error's `result` follows: the
/// action's error schema merged with the shared failure properties, or the
/// shared failure schema alone.
fn failure_schema(action: &ActionDescriptor) -> Value {
    let shared = shared_failure_result_schema();
    match action
        .result_schemas
        .as_ref()
        .and_then(|schemas| schemas.error())
    {
        Some(error) => json!({"anyOf": [with_shared_failure_properties(error), shared]}),
        None => shared,
    }
}

/// Checks a provider outcome of `action` strictly against its declared
/// result schemas: a success `result` (a download's metadata) against the
/// success schema, and a result-bearing error against the error schema
/// merged with the shared failure properties, or the shared failure schema
/// alone. An error without a `result` conforms. An action that declares no
/// result schemas is an error.
pub fn check_result_conforms(
    action: &ActionDescriptor,
    outcome: &Result<ProviderResult, ProviderError>,
) -> Result<(), String> {
    let schemas = action
        .result_schemas
        .as_ref()
        .ok_or_else(|| format!("action {} declares no result schemas", action.action))?;
    let (kind, schema, value) = match outcome {
        Ok(result) => ("success", schemas.success().clone(), &result.result),
        Err(error) => match error.result.as_deref() {
            Some(result) => ("error", failure_schema(action), result),
            None => return Ok(()),
        },
    };
    check_strict_conformance(&schema, value)
        .map_err(|problems| format!("{} {kind} result: {problems}", action.action))
}

/// Asserts [`check_result_conforms`]. Route provider unit-test invocations
/// through it, so every stub-driven outcome is checked against the action's
/// schemas:
///
/// ```
/// use agent_access_provider::test_support::assert_result_conforms;
/// use agent_access_provider::{ActionDescriptor, ActionResultSchemas, ProviderResult};
/// use serde_json::json;
///
/// let action = ActionDescriptor::new("item.view", "View an item", json!({"type": "object"}))
///     .result_schemas(ActionResultSchemas::new(json!({
///         "type": "object",
///         "properties": {"id": {"type": "string"}},
///         "required": ["id"]
///     })));
/// assert_result_conforms(&action, &Ok(ProviderResult::new(json!({"id": "42"}))));
/// ```
///
/// # Panics
///
/// When the outcome does not conform strictly, or the action declares no
/// result schemas.
#[track_caller]
pub fn assert_result_conforms(
    action: &ActionDescriptor,
    outcome: &Result<ProviderResult, ProviderError>,
) {
    if let Err(problem) = check_result_conforms(action, outcome) {
        panic!("provider outcome does not match its result schemas: {problem}");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{ActionResultSchemas, MutationReceipt, ReasonCode};

    fn action() -> ActionDescriptor {
        ActionDescriptor::new("item.update", "Update", json!({"type": "object"})).result_schemas(
            ActionResultSchemas::new(json!({
                "type": "object",
                "properties": {
                    "id": {"type": "string"},
                    "fields": {"type": "object", "additionalProperties": {"type": "string"}},
                    "raw": {"type": "object"},
                    "items": {"type": "array", "items": {"type": "object", "properties": {"n": {"type": "integer"}}}}
                },
                "required": ["id"]
            }))
            .with_error(json!({"type": "object", "properties": {"conflict": {"type": "boolean"}}})),
        )
    }

    #[test]
    fn strict_schemas_close_only_objects_with_undeclared_openness() {
        let strict = strict_result_schema(&json!({"type": "object", "properties": {
            "open": {"type": "object"},
            "map": {"type": "object", "additionalProperties": {"type": "object", "properties": {"a": {}}}},
            "either": {"anyOf": [{"type": "object", "properties": {"b": {}}}, {"type": "null"}]},
            "list": {"type": "array", "items": {"type": "object", "properties": {"c": {}}}},
            "explicit": {"type": "object", "properties": {"d": {}}, "additionalProperties": true}
        }}));
        assert_eq!(strict["additionalProperties"], false);
        let properties = &strict["properties"];
        assert!(properties["open"].get("additionalProperties").is_none());
        assert_eq!(
            properties["map"]["additionalProperties"]["additionalProperties"],
            false
        );
        assert_eq!(
            properties["either"]["anyOf"][0]["additionalProperties"],
            false
        );
        assert_eq!(properties["list"]["items"]["additionalProperties"], false);
        assert_eq!(properties["explicit"]["additionalProperties"], true);
    }

    #[test]
    fn success_and_failure_outcomes_are_checked_strictly() {
        let action = action();
        let conforming = ProviderResult::new(json!({
            "id": "1", "fields": {"x": "y"}, "raw": {"anything": [1]}, "items": [{"n": 1}]
        }));
        assert_result_conforms(&action, &Ok(conforming));
        let extra = check_result_conforms(
            &action,
            &Ok(ProviderResult::new(
                json!({"id": "1", "items": [{"n": 1, "m": 2}]}),
            )),
        )
        .unwrap_err();
        assert!(
            extra.starts_with("item.update success result: at /items/0"),
            "{extra}"
        );
        assert!(
            check_result_conforms(&action, &Ok(ProviderResult::new(json!({}))))
                .unwrap_err()
                .contains("\"id\" is a required property")
        );
        let receipt = ProviderError::error(ReasonCode::UpstreamTimeout, "timed out")
            .with_result(json!({"conflict": false}))
            .with_mutation_receipt(MutationReceipt::applied_unverified(
                "readback",
                json!({"id": "1", "nested": {"any": true}}),
            ));
        assert_result_conforms(&action, &Err(receipt));
        let undeclared = ProviderError::error(ReasonCode::UpstreamFailed, "failed")
            .with_result(json!({"unexpected": true}));
        assert!(
            check_result_conforms(&action, &Err(undeclared))
                .unwrap_err()
                .starts_with("item.update error result:")
        );
        let bare = ProviderError::deny(ReasonCode::InputInvalid, "invalid");
        assert_result_conforms(&action, &Err(bare));
        // Without an error schema, only the shared failure fields are allowed.
        let mut shared_only = action.clone();
        shared_only.result_schemas = Some(ActionResultSchemas::new(json!({"type": "object"})));
        let throttled = ProviderError::error(ReasonCode::UpstreamFailed, "throttled")
            .with_upstream_rate_limit("example", None);
        assert_result_conforms(&shared_only, &Err(throttled));
        assert!(
            check_result_conforms(
                &shared_only,
                &Err(ProviderError::error(ReasonCode::UpstreamFailed, "x")
                    .with_result(json!({"conflict": true})))
            )
            .is_err()
        );
    }

    #[test]
    #[should_panic(expected = "declares no result schemas")]
    fn actions_without_schemas_cannot_be_asserted() {
        let action = ActionDescriptor::new("item.view", "View", json!({"type": "object"}));
        assert_result_conforms(&action, &Ok(ProviderResult::new(json!({}))));
    }
}
