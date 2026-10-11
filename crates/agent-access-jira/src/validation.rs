//! Jira's structured validation errors, reduced to bounded field messages.
use agent_access_provider::{join_message_parts, push_message_part, sanitize_field};
use serde_json::Value;

pub(crate) struct JiraValidationMessage {
    pub(crate) message: String,
    pub(crate) body_malformed: bool,
}

pub(crate) fn jira_validation_message(
    value: &Value,
    allowed_fields: &[&str],
) -> Option<JiraValidationMessage> {
    let object = value.as_object()?;
    let mut parts = Vec::new();
    let mut body_malformed = false;
    if let Some(errors) = object.get("errors").and_then(Value::as_object) {
        let ordered = errors.iter().collect::<std::collections::BTreeMap<_, _>>();
        for (field, message) in ordered {
            if !allowed_fields.contains(&field.as_str()) {
                continue;
            }
            body_malformed |= matches!(field.as_str(), "body" | "description");
            push_message_part(&mut parts, sanitize_field(field), message.as_str());
        }
    }
    join_message_parts(parts).map(|message| JiraValidationMessage {
        message,
        body_malformed,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use agent_access_provider::{
        VALIDATION_FRAGMENT_MAX_BYTES, VALIDATION_MESSAGE_MAX_BYTES, VALIDATION_MESSAGE_MAX_PARTS,
    };
    use serde_json::json;

    #[test]
    fn jira_validation_uses_only_the_documented_bounded_shape() {
        let validation = jira_validation_message(
            &json!({
                "errorMessages": ["ambiguous upstream text is hidden"],
                "errors": {
                    "description": "invalid\u{0000}ADF",
                    "project": "scope detail is hidden"
                },
                "message": "not part of the Jira ErrorCollection schema",
                "secret": "not returned"
            }),
            &["description"],
        )
        .unwrap();
        assert_eq!(validation.message, "description: invalid ADF");
        assert!(validation.body_malformed);
        assert!(!validation.message.contains("secret"));
        assert!(!validation.message.contains("not part"));
        assert!(!validation.message.contains("ambiguous"));
        assert!(!validation.message.contains("scope detail"));
    }

    #[test]
    fn validation_messages_enforce_fragment_part_and_total_bounds() {
        let values = (0..20)
            .map(|index| format!("{index}-{}", "x".repeat(400)))
            .collect::<Vec<_>>();
        let errors = values
            .into_iter()
            .enumerate()
            .map(|(index, value)| (format!("field{index}"), Value::String(value)))
            .collect::<serde_json::Map<_, _>>();
        let allowed_fields = (0..20)
            .map(|index| format!("field{index}"))
            .collect::<Vec<_>>();
        let allowed_fields = allowed_fields
            .iter()
            .map(String::as_str)
            .collect::<Vec<_>>();
        let message = jira_validation_message(&json!({"errors": errors}), &allowed_fields)
            .unwrap()
            .message;
        assert!(message.len() <= VALIDATION_MESSAGE_MAX_BYTES);
        assert!(message.split("; ").count() <= VALIDATION_MESSAGE_MAX_PARTS);
        assert!(
            message
                .split("; ")
                .all(|part| part.len() <= VALIDATION_FRAGMENT_MAX_BYTES)
        );
    }

    #[test]
    fn validation_messages_remove_markup_ansi_and_controls() {
        let validation = jira_validation_message(
            &json!({
                "errors": {
                    "description": "bad <script>hidden()</script>\u{1b}[31m ADF\u{202e}\nvalue"
                }
            }),
            &["description"],
        )
        .unwrap();

        assert_eq!(validation.message, "description: bad hidden() ADF value");
        assert!(!validation.message.contains("<script>"));
        assert!(!validation.message.contains("</script>"));
        assert!(!validation.message.contains("[31m"));
    }

    #[test]
    fn non_string_validation_shapes_are_not_exposed() {
        assert!(
            jira_validation_message(&json!({"errors": {"body": {"raw": "secret"}}}), &["body"])
                .is_none()
        );
    }
}
