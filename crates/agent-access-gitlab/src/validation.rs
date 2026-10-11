//! GitLab's structured validation errors, reduced to bounded field messages.
use agent_access_provider::{
    VALIDATION_MESSAGE_MAX_PARTS, join_message_parts, push_message_part, sanitize_field,
};
use serde_json::Value;
const VALIDATION_NESTING_MAX_DEPTH: usize = 4;

pub(crate) fn gitlab_validation_message(value: &Value, allowed_fields: &[&str]) -> Option<String> {
    let message = value.as_object()?.get("message")?.as_object()?;
    let mut parts = Vec::new();
    let ordered = message.iter().collect::<std::collections::BTreeMap<_, _>>();
    for (field, value) in ordered {
        if !allowed_fields.contains(&field.as_str()) {
            continue;
        }
        collect_gitlab_messages(value, sanitize_field(field), 0, &mut parts);
    }
    join_message_parts(parts)
}

fn collect_gitlab_messages(
    value: &Value,
    field: Option<String>,
    depth: usize,
    parts: &mut Vec<String>,
) {
    if parts.len() >= VALIDATION_MESSAGE_MAX_PARTS || depth > VALIDATION_NESTING_MAX_DEPTH {
        return;
    }
    match value {
        Value::String(message) => push_message_part(parts, field, Some(message)),
        Value::Array(values) => {
            for value in values {
                collect_gitlab_messages(value, field.clone(), depth + 1, parts);
            }
        }
        Value::Object(values) => {
            let ordered = values.iter().collect::<std::collections::BTreeMap<_, _>>();
            for (name, value) in ordered {
                let nested = match (&field, sanitize_field(name)) {
                    (Some(parent), Some(name)) => Some(format!("{parent}.{name}")),
                    (None, name) => name,
                    (field, None) => field.clone(),
                };
                collect_gitlab_messages(value, nested, depth + 1, parts);
            }
        }
        _ => {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn gitlab_validation_flattens_only_the_bounded_message_tree() {
        let message = gitlab_validation_message(
            &json!({
                "message": {
                    "base": ["is invalid", "is invalid"],
                    "commit_message": {"message": ["is too long"]},
                    "project": ["scope secret"]
                },
                "error": "hidden"
            }),
            &["base", "commit_message"],
        )
        .unwrap();
        assert_eq!(
            message,
            "base: is invalid; commit_message.message: is too long"
        );
        assert!(!message.contains("hidden"));
        assert!(!message.contains("scope secret"));
    }

    #[test]
    fn unknown_or_non_string_validation_shapes_are_not_exposed() {
        assert_eq!(
            gitlab_validation_message(&json!({"error": "raw secret"}), &["base"]),
            None
        );
        assert_eq!(
            gitlab_validation_message(&json!({"message": "raw secret"}), &["base"]),
            None
        );
    }
}
