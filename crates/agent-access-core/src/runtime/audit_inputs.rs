//! The action inputs a descriptor opts into audit, copied from the request.

use agent_access_provider::AuditInput;
use serde::{Deserialize, Serialize};
use serde_json::Value;

/// The most UTF-8 bytes one captured value keeps: a string's own bytes, or
/// any other value's compact JSON text.
const AUDIT_INPUT_VALUE_MAX_BYTES: usize = 1024;
/// The largest integer magnitude a JavaScript number holds exactly.
const MAX_SAFE_INTEGER: u64 = (1 << 53) - 1;

/// One declared input's supplied value in an audit record.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct AuditInputValue {
    pub input: String,
    pub label: String,
    /// The supplied value: a string cut to the size bound, or another value
    /// whose compact JSON exceeded it, as that cut text.
    pub value: Value,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub truncated: bool,
}

/// The supplied values of `declared` inputs present in `inputs`, in
/// declaration order. A supplied `null` is recorded as `null`.
pub(super) fn capture_audit_inputs(
    declared: &[AuditInput],
    inputs: &Value,
) -> Vec<AuditInputValue> {
    let Some(inputs) = inputs.as_object() else {
        return Vec::new();
    };
    declared
        .iter()
        .filter_map(|declared| {
            let (value, truncated) = bounded(exact_integers(inputs.get(declared.input())?));
            Some(AuditInputValue {
                input: declared.input().to_owned(),
                label: declared.label().to_owned(),
                value,
                truncated,
            })
        })
        .collect()
}

/// Integers a JavaScript number would round become decimal strings.
fn exact_integers(value: &Value) -> Value {
    match value {
        Value::Number(number)
            if number
                .as_i64()
                .map(i64::unsigned_abs)
                .or_else(|| number.as_u64())
                .is_some_and(|magnitude| magnitude > MAX_SAFE_INTEGER) =>
        {
            Value::String(number.to_string())
        }
        Value::Array(values) => Value::Array(values.iter().map(exact_integers).collect()),
        Value::Object(fields) => Value::Object(
            fields
                .iter()
                .map(|(key, value)| (key.clone(), exact_integers(value)))
                .collect(),
        ),
        value => value.clone(),
    }
}

fn bounded(value: Value) -> (Value, bool) {
    let text = match value {
        Value::String(text) => text,
        value => {
            let text = value.to_string();
            if text.len() <= AUDIT_INPUT_VALUE_MAX_BYTES {
                return (value, false);
            }
            text
        }
    };
    if text.len() <= AUDIT_INPUT_VALUE_MAX_BYTES {
        return (Value::String(text), false);
    }
    let end = text.floor_char_boundary(AUDIT_INPUT_VALUE_MAX_BYTES);
    (Value::String(text[..end].to_owned()), true)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn declared() -> Vec<AuditInput> {
        vec![
            AuditInput::new("project", "Project"),
            AuditInput::new("issue", "Issue"),
            AuditInput::new("query", "Query"),
        ]
    }

    fn values(inputs: Value) -> Value {
        serde_json::to_value(capture_audit_inputs(&declared(), &inputs)).unwrap()
    }

    #[test]
    fn present_inputs_are_recorded_in_declaration_order() {
        assert_eq!(
            values(json!({"query": null, "body": "not declared", "project": "TEST"})),
            json!([
                {"input": "project", "label": "Project", "value": "TEST"},
                {"input": "query", "label": "Query", "value": null},
            ])
        );
        assert_eq!(values(json!({"body": "not declared"})), json!([]));
        assert!(capture_audit_inputs(&[], &json!({"project": "TEST"})).is_empty());
    }

    #[test]
    fn non_object_inputs_record_nothing() {
        for inputs in [json!(null), json!("project"), json!(["project"]), json!(7)] {
            assert_eq!(values(inputs), json!([]));
        }
    }

    #[test]
    fn long_strings_are_cut_at_a_character_boundary() {
        let exact = "x".repeat(AUDIT_INPUT_VALUE_MAX_BYTES);
        assert_eq!(
            values(json!({"project": exact}))[0],
            json!({"input": "project", "label": "Project", "value": exact})
        );
        // 1023 ASCII bytes then a three-byte character spanning the bound.
        let spanning = format!("{}€tail", "x".repeat(AUDIT_INPUT_VALUE_MAX_BYTES - 1));
        let captured = capture_audit_inputs(&declared(), &json!({"project": spanning}));
        assert_eq!(
            captured[0].value,
            json!("x".repeat(AUDIT_INPUT_VALUE_MAX_BYTES - 1))
        );
        assert!(captured[0].truncated);
        assert_eq!(
            serde_json::to_value(&captured[0]).unwrap()["truncated"],
            true
        );
    }

    #[test]
    fn oversized_other_values_become_cut_compact_json_text() {
        let small = json!({"key": "TEST-1", "labels": ["a", "b"]});
        assert_eq!(values(json!({"issue": small}))[0]["value"], small);
        assert!(
            values(json!({"issue": small}))[0]
                .get("truncated")
                .is_none()
        );

        let large = json!({"keys": vec!["TEST-1"; 200]});
        let text = large.to_string();
        assert!(text.len() > AUDIT_INPUT_VALUE_MAX_BYTES);
        let captured = capture_audit_inputs(&declared(), &json!({"issue": large}));
        assert_eq!(
            captured[0].value,
            json!(&text[..AUDIT_INPUT_VALUE_MAX_BYTES])
        );
        assert!(captured[0].truncated);

        // The compact text is cut at a character boundary too.
        let wide = json!([format!("{}€", "x".repeat(AUDIT_INPUT_VALUE_MAX_BYTES - 3))]);
        let captured = capture_audit_inputs(&declared(), &json!({"query": wide}));
        let Value::String(cut) = &captured[0].value else {
            panic!("an oversized array is recorded as its text");
        };
        assert_eq!(
            cut,
            &format!("[\"{}", "x".repeat(AUDIT_INPUT_VALUE_MAX_BYTES - 3))
        );
        assert!(captured[0].truncated);
    }

    #[test]
    fn unsafe_integers_become_decimal_strings_before_the_size_bound() {
        let safe = MAX_SAFE_INTEGER as i64;
        assert_eq!(
            values(json!({
                "project": safe,
                "issue": -safe - 1,
                "query": {"ids": [u64::MAX, safe, 1.5], "nested": {"id": i64::MIN}}
            })),
            json!([
                {"input": "project", "label": "Project", "value": safe},
                {"input": "issue", "label": "Issue", "value": "-9007199254740992"},
                {"input": "query", "label": "Query", "value": {
                    "ids": ["18446744073709551615", safe, 1.5],
                    "nested": {"id": "-9223372036854775808"}
                }},
            ])
        );
        // Each rewritten integer grows by its quotes, so the bound applies to
        // the rewritten text.
        let ids = vec![u64::MAX; 48];
        let rewritten = json!(ids.iter().map(u64::to_string).collect::<Vec<_>>()).to_string();
        assert!(json!(ids).to_string().len() <= AUDIT_INPUT_VALUE_MAX_BYTES);
        assert!(rewritten.len() > AUDIT_INPUT_VALUE_MAX_BYTES);
        let captured = capture_audit_inputs(&declared(), &json!({"query": ids}));
        assert_eq!(
            captured[0].value,
            json!(&rewritten[..AUDIT_INPUT_VALUE_MAX_BYTES])
        );
        assert!(captured[0].truncated);
    }
}
