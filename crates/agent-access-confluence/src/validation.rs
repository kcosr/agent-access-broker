//! Confluence's structured validation errors, reduced to bounded messages
//! from allowlisted error codes.
use agent_access_provider::{join_message_parts, push_message_part};
use serde_json::Value;

const CONFLUENCE_VALIDATION_CODES: &[&str] = &[
    "INVALID_BODY",
    "INVALID_MESSAGE",
    "INVALID_REQUEST_PARAMETER",
    "VALIDATION_ERROR",
];

pub(crate) fn confluence_validation_message(value: &Value) -> Option<String> {
    let object = value.as_object()?;
    let mut parts = Vec::new();
    if let Some(errors) = object.get("errors").and_then(Value::as_array) {
        for error in errors {
            let Some(error) = error.as_object() else {
                continue;
            };
            let Some(code) = error.get("code").and_then(Value::as_str) else {
                continue;
            };
            if !CONFLUENCE_VALIDATION_CODES.contains(&code) {
                continue;
            }
            push_message_part(&mut parts, None, error.get("title").and_then(Value::as_str));
            push_message_part(
                &mut parts,
                None,
                error.get("detail").and_then(Value::as_str),
            );
        }
    }
    join_message_parts(parts)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn confluence_validation_accepts_only_allowlisted_error_titles_or_details() {
        let message = confluence_validation_message(&json!({
            "message": "unstructured text is hidden",
            "errors": [
                {"code": "INVALID_BODY", "title": "Bad request", "detail": "storage is malformed", "data": "hidden"},
                {"code": "FORBIDDEN", "title": "scope secret", "detail": "hidden"}
            ],
            "data": "hidden"
        }))
        .unwrap();
        assert_eq!(message, "Bad request; storage is malformed");
        assert!(!message.contains("hidden"));
        assert!(!message.contains("scope secret"));
    }

    #[test]
    fn non_array_validation_shapes_are_not_exposed() {
        assert_eq!(
            confluence_validation_message(&json!({"errors": ["raw secret"]})),
            None
        );
    }
}
